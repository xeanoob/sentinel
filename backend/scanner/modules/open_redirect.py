"""Detect Open Redirect vulnerabilities."""

from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from config import settings
from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# Parameter names commonly associated with redirects
REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "next_url", "return", "return_url", "returnto",
    "goto", "go", "dest", "destination", "target",
    "redir", "out", "continue", "forward", "ref",
    "callback", "callback_url", "login_url", "logout_url",
}

# The evil external domain we redirect to for testing
EVIL_DOMAIN = "https://evil.dast-test.invalid/"


def _build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class OpenRedirectModule(BaseModule):
    @property
    def name(self) -> str:
        return "Open Redirect"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []

        for param, values in page.url_params.items():
            if param.lower() not in REDIRECT_PARAM_NAMES:
                continue

            test_url = _build_url_with_param(page.url, param, EVIL_DOMAIN)

            try:
                # Don't follow redirects — we want to inspect the redirect itself
                resp = await client.get(
                    test_url,
                    follow_redirects=False,
                    timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
                )

                # Check 3xx redirect
                if 300 <= resp.status_code < 400:
                    location = resp.headers.get("location", "")
                    if "evil.dast-test.invalid" in location:
                        findings.append(self._make_finding(page.url, param, location))
                        continue

                # Check meta refresh
                if "evil.dast-test.invalid" in resp.text:
                    findings.append(self._make_finding(page.url, param, "meta/js redirect"))

            except Exception:
                continue

        return findings

    def _make_finding(self, url: str, param: str, redirect_to: str) -> Finding:
        return Finding(
            url=url,
            vulnerability_type="Open Redirect",
            severity=Severity.MEDIUM,
            description=(
                f"Le paramètre « {param} » permet de rediriger l'utilisateur vers un site "
                f"externe arbitraire (détecté : {redirect_to}). "
                "Un attaquant peut utiliser cela pour du phishing en créant un lien "
                "qui semble légitime mais redirige vers un site malveillant."
            ),
            recommendation=(
                "Valider les URLs de redirection contre une liste blanche de domaines autorisés. "
                "Refuser toute redirection vers des domaines externes. "
                "Utiliser des chemins relatifs au lieu d'URLs absolues."
            ),
        )
