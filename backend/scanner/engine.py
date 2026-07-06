"""Scan engine — orchestrates the crawler and all vulnerability modules."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from config import settings
from models import (
    CrawledPage,
    Finding,
    ScanEvent,
    ScanRecord,
    ScanStatus,
    Severity,
)
from scanner.crawler import crawl
from scanner.modules.base import BaseModule
from scanner.modules.headers import HeadersModule
from scanner.modules.cookies import CookiesModule
from scanner.modules.xss import XSSModule
from scanner.modules.sqli import SQLiModule
from scanner.modules.open_redirect import OpenRedirectModule
from scanner.modules.csrf import CSRFModule
from scanner.modules.info_disclosure import InfoDisclosureModule
from scanner.modules.sensitive_files import SensitiveFilesModule
from scanner.modules.ssl_check import SSLCheckModule
from scanner.modules.directory_traversal import DirectoryTraversalModule
from store import ScanStore

logger = logging.getLogger("dast.engine")

from scanner.modules.cmd_injection import scan as scan_cmd_injection
from scanner.modules.ssrf import scan as scan_ssrf
from scanner.modules.lfi import scan as scan_lfi

# Note: Since the newly created modules (cmd_injection, ssrf, lfi) were written with a functional `scan()`
# interface instead of the `BaseModule` class approach used by the other modules, we will wrap them
# to maintain compatibility with the engine's object-oriented list.

class CmdInjectionModule(BaseModule):
    @property
    def name(self) -> str:
        return "Command Injection Module"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        return await scan_cmd_injection(page)

class SSRFModule(BaseModule):
    @property
    def name(self) -> str:
        return "SSRF Module"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        return await scan_ssrf(page)

class LFIModule(BaseModule):
    @property
    def name(self) -> str:
        return "LFI Module"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        return await scan_lfi(page)

from scanner.modules.secrets import SecretsModule
from scanner.modules.idor import IDORModule

# Modules that run on every crawled page
PAGE_MODULES: list[type[BaseModule]] = [
    HeadersModule,
    CookiesModule,
    XSSModule,
    SQLiModule,
    OpenRedirectModule,
    CSRFModule,
    InfoDisclosureModule,
    DirectoryTraversalModule,
    SecretsModule,
    IDORModule,
    CmdInjectionModule,
    SSRFModule,
    LFIModule,
]

# Modules that run once per domain
DOMAIN_MODULES: list[type[BaseModule]] = [
    SensitiveFilesModule,
    SSLCheckModule,
]


async def run_scan(record: ScanRecord, store: ScanStore) -> None:
    """Main entry point: runs the full scan lifecycle."""
    scan_id = record.scan_id

    try:
        record.status = ScanStatus.RUNNING
        record.started_at = datetime.now(timezone.utc)

        await _emit(store, scan_id, "scan_started", {
            "target_url": record.target_url,
            "max_depth": record.request.max_depth,
            "max_concurrency": record.request.max_concurrency,
        })

        # Pre-instantiate modules
        page_modules = [cls() for cls in PAGE_MODULES]
        domain_modules = [cls() for cls in DOMAIN_MODULES]
        scanned_count = 0

        # Shared client for all scan modules
        async with httpx.AsyncClient(
            headers={"User-Agent": settings.USER_AGENT},
            follow_redirects=True,
            verify=False,
            timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
            limits=httpx.Limits(
                max_connections=record.request.max_concurrency * 2,
                max_keepalive_connections=record.request.max_concurrency,
            ),
        ) as scan_client:

            # This callback is executed for EVERY page as soon as the crawler finds it.
            async def on_page_found(page: CrawledPage) -> None:
                nonlocal scanned_count
                record.pages_visited += 1

                await _emit(store, scan_id, "page_visited", {
                    "url": page.url,
                    "status_code": page.status_code,
                    "pages_visited": record.pages_visited,
                    "error": page.error,
                })

                if page.error or record.cancel_event.is_set():
                    return
                
                # Forward the active fuzzing flag so modules know they can launch attacks
                page.is_active_fuzzing = record.request.active_fuzzing

                # Run all page-level modules concurrently on this specific page
                scan_tasks = []
                for module in page_modules:
                    scan_tasks.append(module.scan(page, scan_client))
                
                results = await asyncio.gather(*scan_tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Exception):
                        continue
                    
                    for finding in result:
                        from false_positives import fp_manager
                        if fp_manager.is_false_positive(finding.url, finding.vulnerability_type):
                            # Skip this finding
                            continue
                            
                        record.add_finding(finding)
                        await _emit(store, scan_id, "vulnerability_found", {
                            "finding": finding.model_dump(),
                        })

                scanned_count += 1
                
                # Emit progress update periodically
                if scanned_count % 3 == 0 or record.pages_visited < 5:
                    await _emit(store, scan_id, "scan_progress", {
                        "pages_visited": record.pages_visited,
                        "findings_count": len(record.findings),
                    })

            # Start the crawl. Thanks to the pipelined architecture, `on_page_found` 
            # runs concurrently with the crawl itself.
            crawled_pages = await crawl(
                record.request,
                on_page=on_page_found,
                cancel_event=record.cancel_event,
            )

            if record.cancel_event.is_set():
                raise asyncio.CancelledError()

            # --- Run domain-level modules once at the end ---
            if crawled_pages and not record.cancel_event.is_set():
                root_page = crawled_pages[0]
                domain_tasks = [mod.scan(root_page, scan_client) for mod in domain_modules]
                domain_results = await asyncio.gather(*domain_tasks, return_exceptions=True)
                
                for result in domain_results:
                    if isinstance(result, Exception):
                        continue
                    for finding in result:
                        from false_positives import fp_manager
                        if fp_manager.is_false_positive(finding.url, finding.vulnerability_type):
                            continue
                            
                        record.add_finding(finding)
                        await _emit(store, scan_id, "vulnerability_found", {
                            "finding": finding.model_dump(),
                        })

        # Post-processing: AI Validation
        if getattr(record.request, 'ai_api_key', None):
            await _emit(store, scan_id, "scan_progress", {
                "pages_visited": record.pages_visited,
                "findings_count": len(record.findings),
                "message": "🧠 Analyzing findings with AI..."
            })
            from scanner.ai_validator import validate_findings_with_ai
            validated = await validate_findings_with_ai(record.findings, record.request.ai_api_key)
            record.findings = validated
            
            # Recompute severity counts
            record.severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for f in record.findings:
                record.severity_counts[f.severity.value] += 1

        record.status = ScanStatus.COMPLETED
        record.finished_at = datetime.now(timezone.utc)

        # Post-processing: Webhook Alerts
        webhook_url = getattr(record.request, 'webhook_url', None)
        if webhook_url and (record.severity_counts["Critical"] > 0 or record.severity_counts["High"] > 0):
            try:
                msg = {
                    "content": f"🚨 **Sentinel DAST Alert** 🚨\nScan completed for `{record.target_url}`.\nFindings: **{record.severity_counts['Critical']} Critical**, **{record.severity_counts['High']} High**.\nPlease review the dashboard for details."
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(webhook_url, json=msg)
            except Exception as e:
                logger.error(f"Failed to send webhook: {e}")

        await _emit(store, scan_id, "scan_finished", {
            "pages_visited": record.pages_visited,
            "findings_count": len(record.findings),
            "severity_counts": record.severity_counts,
        })

    except asyncio.CancelledError:
        record.status = ScanStatus.CANCELLED
        record.finished_at = datetime.now(timezone.utc)
        await _emit(store, scan_id, "scan_cancelled", {
            "pages_visited": record.pages_visited,
            "findings_count": len(record.findings),
        })

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        record.status = ScanStatus.FAILED
        record.error = str(exc)
        record.finished_at = datetime.now(timezone.utc)
        await _emit(store, scan_id, "scan_failed", {
            "error": str(exc),
            "pages_visited": record.pages_visited,
        })

    finally:
        store.save_to_disk(scan_id)
        await store.close_subscribers(scan_id)


async def _emit(
    store: ScanStore,
    scan_id: str,
    event_type: str,
    data: dict,
) -> None:
    event = ScanEvent(scan_id=scan_id, event=event_type, data=data)
    await store.publish(scan_id, event)
