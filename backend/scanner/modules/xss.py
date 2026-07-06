"""Detect reflected Cross-Site Scripting (XSS) vulnerabilities."""

from __future__ import annotations

import secrets
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from config import settings
from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# A unique canary that includes HTML special chars.
# If the HTML chars survive unencoded in the response, reflection is unsafe.
_CANARY_PREFIX = "dXsS"


def _make_canary() -> str:
    return f"{_CANARY_PREFIX}{secrets.token_hex(4)}"


def _build_url_with_param(url: str, param: str, value: str) -> str:
    """Replace a single query parameter value in the URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class XSSModule(BaseModule):
    @property
    def name(self) -> str:
        return "Reflected XSS"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []
        if not getattr(page, 'is_active_fuzzing', False):
            return findings

        # --- Test URL query parameters ---
        for param, values in page.url_params.items():
            finding = await self._test_param_reflection(page.url, param, client)
            if finding:
                findings.append(finding)

        # --- Test form fields (GET forms) ---
        for form in page.forms:
            if form.method.upper() != "GET":
                continue
            for field in form.fields:
                if field.field_type in ("submit", "button", "image", "reset"):
                    continue
                finding = await self._test_param_reflection(
                    form.action, field.name, client
                )
                if finding:
                    findings.append(finding)

        return findings

    async def _test_param_reflection(
        self,
        base_url: str,
        param: str,
        client: httpx.AsyncClient,
    ) -> Optional[Finding]:
        """Two-step reflection test: plain canary, then HTML-tagged canary."""

        # Step 1 — check if the parameter value is reflected at all
        canary = _make_canary()
        test_url = _build_url_with_param(base_url, param, canary)

        try:
            resp = await client.get(
                test_url,
                follow_redirects=True,
                timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
            )
            body = resp.text
        except Exception:
            return None

        if canary not in body:
            return None  # not reflected

        # Step 2 — inject an HTML tag canary and check if it survives encoding
        html_canary = f"<{_make_canary()}>"
        test_url2 = _build_url_with_param(base_url, param, html_canary)

        try:
            resp2 = await client.get(
                test_url2,
                follow_redirects=True,
                timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
            )
            body2 = resp2.text
        except Exception:
            return None

        if html_canary in body2:
            # HTML tags are NOT encoded → confirmed reflected XSS
            return Finding(
                url=base_url,
                vulnerability_type="Reflected XSS",
                severity=Severity.HIGH,
                description=(
                    f"Le paramètre « {param} » reflète les entrées utilisateur dans le HTML "
                    "sans encodage. Un attaquant peut injecter du code JavaScript arbitraire "
                    "qui s'exécutera dans le navigateur de la victime."
                ),
                recommendation=(
                    "Encoder systématiquement toute donnée utilisateur insérée dans le HTML "
                    "(utiliser des fonctions d'échappement HTML). "
                    "Mettre en place une Content-Security-Policy stricte."
                ),
            )

        return None
