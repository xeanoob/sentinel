"""Detect insecure cookie configurations."""

from __future__ import annotations

import re

import httpx

from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule


def _parse_cookie_name(raw: str) -> str:
    """Extract the cookie name from a raw Set-Cookie header value."""
    return raw.split("=", 1)[0].strip()


def _has_flag(raw: str, flag: str) -> bool:
    """Check whether a Set-Cookie header contains a specific flag (case-insensitive)."""
    return bool(re.search(rf";\s*{flag}\b", raw, re.IGNORECASE))


def _has_samesite(raw: str) -> bool:
    return bool(re.search(r";\s*SameSite\s*=", raw, re.IGNORECASE))


class CookiesModule(BaseModule):
    @property
    def name(self) -> str:
        return "Cookie Security"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []

        for raw_cookie in page.set_cookie_headers:
            cookie_name = _parse_cookie_name(raw_cookie)
            if not cookie_name:
                continue

            # --- Secure flag ---
            if not _has_flag(raw_cookie, "Secure"):
                findings.append(
                    Finding(
                        url=page.url,
                        vulnerability_type="Insecure Cookie: Missing Secure Flag",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Le cookie « {cookie_name} » n'a pas le flag Secure. "
                            "Il peut être transmis en clair sur une connexion HTTP, "
                            "exposant son contenu à une interception réseau."
                        ),
                        recommendation=(
                            f"Ajouter le flag Secure au cookie « {cookie_name} » : "
                            f"Set-Cookie: {cookie_name}=...; Secure"
                        ),
                    )
                )

            # --- HttpOnly flag ---
            if not _has_flag(raw_cookie, "HttpOnly"):
                findings.append(
                    Finding(
                        url=page.url,
                        vulnerability_type="Insecure Cookie: Missing HttpOnly Flag",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Le cookie « {cookie_name} » n'a pas le flag HttpOnly. "
                            "Il est accessible via JavaScript (document.cookie), "
                            "ce qui facilite le vol de session par XSS."
                        ),
                        recommendation=(
                            f"Ajouter le flag HttpOnly : "
                            f"Set-Cookie: {cookie_name}=...; HttpOnly"
                        ),
                    )
                )

            # --- SameSite attribute ---
            if not _has_samesite(raw_cookie):
                findings.append(
                    Finding(
                        url=page.url,
                        vulnerability_type="Insecure Cookie: Missing SameSite Attribute",
                        severity=Severity.LOW,
                        description=(
                            f"Le cookie « {cookie_name} » n'a pas l'attribut SameSite. "
                            "Il peut être envoyé dans des requêtes cross-site, "
                            "facilitant les attaques CSRF."
                        ),
                        recommendation=(
                            f"Ajouter SameSite=Lax ou SameSite=Strict : "
                            f"Set-Cookie: {cookie_name}=...; SameSite=Lax"
                        ),
                    )
                )

        return findings
