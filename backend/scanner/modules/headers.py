"""Detect missing HTTP security headers."""

from __future__ import annotations

import httpx

from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# Each tuple: (header_name, severity, description, recommendation)
REQUIRED_HEADERS: list[tuple[str, Severity, str, str]] = [
    (
        "Content-Security-Policy",
        Severity.MEDIUM,
        "L'en-tête Content-Security-Policy (CSP) est absent. "
        "Cela permet l'injection de scripts malveillants (XSS) et le chargement de ressources non autorisées.",
        "Ajouter un en-tête CSP restrictif, par ex. : "
        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
    ),
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "L'en-tête HSTS (Strict-Transport-Security) est absent. "
        "Les utilisateurs sont vulnérables aux attaques de downgrade HTTPS → HTTP et au MITM.",
        "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "L'en-tête X-Frame-Options est absent. "
        "La page peut être intégrée dans un iframe, exposant à des attaques de clickjacking.",
        "Ajouter : X-Frame-Options: DENY  ou  X-Frame-Options: SAMEORIGIN",
    ),
    (
        "X-Content-Type-Options",
        Severity.LOW,
        "L'en-tête X-Content-Type-Options est absent. "
        "Le navigateur peut interpréter le contenu de manière inattendue (MIME sniffing).",
        "Ajouter : X-Content-Type-Options: nosniff",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "L'en-tête Referrer-Policy est absent. "
        "Les URLs complètes (avec paramètres potentiellement sensibles) peuvent fuiter via le Referer.",
        "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "Permissions-Policy",
        Severity.LOW,
        "L'en-tête Permissions-Policy est absent. "
        "Les fonctionnalités du navigateur (caméra, micro, géoloc) ne sont pas restreintes.",
        "Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
]


class HeadersModule(BaseModule):
    @property
    def name(self) -> str:
        return "Security Headers"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        # Only check HTML pages
        if not page.content_type.startswith("text/html"):
            return []

        findings: list[Finding] = []
        headers_lower = {k.lower(): v for k, v in page.headers.items()}

        for header_name, severity, description, recommendation in REQUIRED_HEADERS:
            if header_name.lower() not in headers_lower:
                findings.append(
                    Finding(
                        url=page.url,
                        vulnerability_type=f"Missing Header: {header_name}",
                        severity=severity,
                        description=description,
                        recommendation=recommendation,
                    )
                )

        return findings
