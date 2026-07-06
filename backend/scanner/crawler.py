"""Async BFS web crawler — discovers and optionally scans pages on a target site."""

from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import Callable, Awaitable, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

import httpx
from bs4 import BeautifulSoup

from config import settings
from models import CrawledPage, FormData, FormField, ScanRequest
from scanner.api_parser import parse_openapi_schema

async def crawl(
    request: ScanRequest,
    on_page: Callable[[CrawledPage], Awaitable[None]],
    cancel_event: asyncio.Event,
) -> list[CrawledPage]:
    """Main entry point: uses API Parser, Playwright, or httpx."""
    
    if request.is_api_scan:
        pages = await parse_openapi_schema(request)
        for page in pages:
            if cancel_event.is_set():
                break
            await on_page(page)
        return pages
        
    if getattr(request, 'is_graphql_scan', False):
        from scanner.graphql_parser import parse_graphql_endpoint
        pages = await parse_graphql_endpoint(request.target_url, {"headers": request.custom_headers})
        for page in pages:
            if cancel_event.is_set():
                break
            await on_page(page)
        return pages

    headers = {"User-Agent": settings.USER_AGENT}
    if request.custom_headers:
        headers.update(request.custom_headers)

    if request.use_browser:
        return await _crawl_playwright(request, on_page, cancel_event, headers)
    else:
        return await _crawl_httpx(request, on_page, cancel_event, headers)


async def _crawl_httpx(request: ScanRequest, on_page, cancel_event, headers) -> list[CrawledPage]:
    timeout = request.page_timeout_ms / 1000
    max_concurrency = request.max_concurrency

    async with httpx.AsyncClient(
        headers=headers,
        follow_redirects=True,
        verify=False,
        timeout=timeout,
        limits=httpx.Limits(
            max_connections=max_concurrency * 2,
            max_keepalive_connections=max_concurrency,
        ),
    ) as client:
        async def fetcher(url: str, depth: int, timeout_sec: float) -> CrawledPage:
            return await _fetch_page(client, url, depth, timeout_sec)

        return await _run_crawl_loop(request, on_page, cancel_event, fetcher)


async def _crawl_playwright(request: ScanRequest, on_page, cancel_event, headers) -> list[CrawledPage]:
    from playwright.async_api import async_playwright

    max_concurrency = request.max_concurrency
    sem = asyncio.Semaphore(max_concurrency)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=headers
        )

        if request.auth_config:
            login_cfg = request.auth_config
            try:
                login_page = await context.new_page()
                await login_page.goto(login_cfg.login_url, wait_until="networkidle")
                await login_page.fill(login_cfg.username_selector, login_cfg.username)
                await login_page.fill(login_cfg.password_selector, login_cfg.password)
                await login_page.click(login_cfg.submit_selector)
                await login_page.wait_for_load_state("networkidle")
                # Close the login page to free resources, the context keeps the cookies
                await login_page.close()
            except Exception as e:
                print(f"Auto-login failed: {e}")

        async def fetcher(url: str, depth: int, timeout_sec: float) -> CrawledPage:
            async with sem:
                return await _fetch_page_playwright(context, url, depth, timeout_sec)

        pages = await _run_crawl_loop(request, on_page, cancel_event, fetcher)
        await browser.close()
        return pages


async def _run_crawl_loop(
    request: ScanRequest,
    on_page: Callable[[CrawledPage], Awaitable[None]],
    cancel_event: asyncio.Event,
    fetch_func: Callable[[str, int, float], Awaitable[CrawledPage]],
) -> list[CrawledPage]:
    """The generic BFS queue loop, agnostic to how pages are fetched."""
    import random
    
    start_url = _normalize_url(request.target_url)
    target_domain = urlparse(start_url).netloc.lower()
    if target_domain.startswith("www."):
        target_domain = target_domain[4:]

    max_depth = request.max_depth
    max_concurrency = request.max_concurrency
    timeout = request.page_timeout_ms / 1000

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    queue.append((start_url, 0))
    pages: list[CrawledPage] = []
    active_tasks: set[asyncio.Task] = set()

    while queue and not cancel_event.is_set():
        batch: list[tuple[str, int]] = []
        while queue and len(batch) < max_concurrency:
            url, depth = queue.popleft()
            normalized = _normalize_url(url)

            if normalized in visited:
                continue
            if depth > max_depth:
                continue
            if request.same_domain_only:
                page_domain = urlparse(normalized).netloc.lower()
                if page_domain.startswith("www."):
                    page_domain = page_domain[4:]
                if page_domain != target_domain:
                    continue

            visited.add(normalized)
            batch.append((normalized, depth))

        if not batch:
            break

        fetch_tasks = [fetch_func(url, depth, timeout) for url, depth in batch]
        results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for result in results:
            if cancel_event.is_set():
                break

            if isinstance(result, Exception):
                continue

            page: CrawledPage = result
            pages.append(page)

            task = asyncio.create_task(on_page(page))
            active_tasks.add(task)
            task.add_done_callback(active_tasks.discard)

            if page.error is None and page.content_type.startswith("text/html"):
                for link in page.links:
                    link_normalized = _normalize_url(link)
                    if link_normalized not in visited:
                        queue.append((link_normalized, page.depth + 1))

            await asyncio.sleep(0)

        # Stealth Mode Jitter
        if request.stealth_mode:
            delay = random.uniform(0.5, 3.0)
            await asyncio.sleep(delay)
        else:
            await asyncio.sleep(settings.REQUEST_DELAY)

    if active_tasks:
        await asyncio.gather(*active_tasks, return_exceptions=True)

    return pages


async def _fetch_page_playwright(context, url: str, depth: int, timeout: float) -> CrawledPage:
    """Fetch a page using Headless Chromium to execute JS."""
    try:
        page = await context.new_page()
        response = await page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
        
        if not response:
            await page.close()
            return CrawledPage(url=url, depth=depth, status_code=0, error="No response")

        status_code = response.status
        headers = response.headers
        content_type = headers.get("content-type", "")
        final_url = page.url

        if not content_type.startswith(("text/", "application/json", "application/xml", "application/xhtml")):
            await page.close()
            return CrawledPage(
                url=final_url,
                depth=depth,
                status_code=status_code,
                headers=headers,
                content_type=content_type,
            )

        body = await page.content()
        body = body[:settings.MAX_BODY_SIZE]

        links: list[str] = []
        forms: list[FormData] = []
        if content_type.startswith("text/html"):
            links, forms = _parse_html(body, final_url)

        parsed = urlparse(final_url)
        url_params = parse_qs(parsed.query, keep_blank_values=True)

        await page.close()
        return CrawledPage(
            url=final_url,
            depth=depth,
            status_code=status_code,
            headers=headers,
            body=body,
            content_type=content_type,
            forms=forms,
            links=links,
            url_params=url_params,
        )
    except Exception as exc:
        return CrawledPage(url=url, depth=depth, status_code=0, error=str(exc))


async def _fetch_page(
    client: httpx.AsyncClient,
    url: str,
    depth: int,
    timeout: float,
) -> CrawledPage:
    """Fetch a single page and extract all useful data."""
    try:
        resp = await client.get(url, timeout=timeout)
    except Exception as exc:
        return CrawledPage(
            url=url,
            depth=depth,
            status_code=0,
            error=str(exc),
        )

    content_type = resp.headers.get("content-type", "")

    if not content_type.startswith(("text/", "application/json", "application/xml", "application/xhtml")):
        return CrawledPage(
            url=str(resp.url),
            depth=depth,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content_type=content_type,
            set_cookie_headers=resp.headers.get_list("set-cookie"),
        )

    body = resp.text[:settings.MAX_BODY_SIZE]
    final_url = str(resp.url)

    links: list[str] = []
    forms: list[FormData] = []
    if content_type.startswith("text/html"):
        links, forms = _parse_html(body, final_url)

    parsed = urlparse(final_url)
    url_params = parse_qs(parsed.query, keep_blank_values=True)

    return CrawledPage(
        url=final_url,
        depth=depth,
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=body,
        content_type=content_type,
        forms=forms,
        links=links,
        url_params=url_params,
        set_cookie_headers=resp.headers.get_list("set-cookie"),
    )


def _parse_html(html: str, base_url: str) -> tuple[list[str], list[FormData]]:
    """Extract links and form data from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    forms: list[FormData] = []

    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        abs_url = _resolve_url(base_url, href)
        if abs_url:
            links.append(abs_url)

    for tag in soup.find_all("link", href=True):
        href = tag["href"]
        abs_url = _resolve_url(base_url, href)
        if abs_url:
            links.append(abs_url)

    for tag in soup.find_all(["iframe", "frame"], src=True):
        abs_url = _resolve_url(base_url, tag["src"])
        if abs_url:
            links.append(abs_url)

    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        abs_action = _resolve_url(base_url, action) or base_url
        method = (form_tag.get("method") or "GET").upper()

        fields: list[FormField] = []
        for input_tag in form_tag.find_all("input"):
            name = input_tag.get("name", "")
            if not name:
                continue
            fields.append(
                FormField(
                    name=name,
                    field_type=input_tag.get("type", "text").lower(),
                    value=input_tag.get("value", ""),
                )
            )
        for textarea in form_tag.find_all("textarea"):
            name = textarea.get("name", "")
            if name:
                fields.append(FormField(name=name, field_type="textarea", value=textarea.string or ""))
        for select in form_tag.find_all("select"):
            name = select.get("name", "")
            if name:
                first_option = select.find("option")
                value = first_option.get("value", "") if first_option else ""
                fields.append(FormField(name=name, field_type="select", value=value))

        if fields:
            forms.append(FormData(action=abs_action, method=method, fields=fields))

    return links, forms


def _resolve_url(base: str, href: str) -> Optional[str]:
    """Resolve a relative URL to absolute, filtering out non-HTTP schemes."""
    if not href:
        return None

    href = href.strip()

    if re.match(r"^(?:javascript|mailto|tel|data|blob|ftp):", href, re.I):
        return None

    abs_url = urljoin(base, href)
    parsed = urlparse(abs_url)

    if parsed.scheme not in ("http", "https"):
        return None

    abs_url = urlunparse(parsed._replace(fragment=""))
    return abs_url


def _normalize_url(url: str) -> str:
    """Normalize a URL for deduplication."""
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
