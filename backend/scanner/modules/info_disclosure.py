"""Detect information disclosure vulnerabilities."""

from __future__ import annotations

import re

import httpx

from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# Server header patterns that reveal version information
SERVER_VERSION_PATTERNS = [
    (re.compile(r"Apache/[\d.]+", re.I), "Apache"),
    (re.compile(r"nginx/[\d.]+", re.I), "nginx"),
    (re.compile(r"Microsoft-IIS/[\d.]+", re.I), "IIS"),
    (re.compile(r"LiteSpeed/[\d.]+", re.I), "LiteSpeed"),
    (re.compile(r"openresty/[\d.]+", re.I), "OpenResty"),
]

# Patterns indicating stack traces or detailed error pages
ERROR_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    # PHP
    (re.compile(r"<b>Fatal error</b>:.*on line \d+", re.I), "PHP Fatal Error", Severity.HIGH),
    (re.compile(r"<b>Warning</b>:.*on line \d+", re.I), "PHP Warning", Severity.MEDIUM),
    (re.compile(r"<b>Notice</b>:.*on line \d+", re.I), "PHP Notice", Severity.LOW),
    (re.compile(r"Stack trace:.*#\d+", re.S), "Stack Trace Exposed", Severity.HIGH),
    # Python / Django
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python Traceback", Severity.HIGH),
    (re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>"), "Django Debug Mode", Severity.CRITICAL),
    # Java
    (re.compile(r"java\.(lang|io|sql)\.\w+Exception", re.I), "Java Exception", Severity.HIGH),
    (re.compile(r"at\s+[\w.]+\([\w]+\.java:\d+\)"), "Java Stack Trace", Severity.HIGH),
    # .NET
    (re.compile(r"Server Error in '/' Application"), ".NET Error Page", Severity.HIGH),
    (re.compile(r"<b>Stack Trace:</b>", re.I), ".NET Stack Trace", Severity.HIGH),
    (re.compile(r"System\.\w+Exception:", re.I), ".NET Exception", Severity.HIGH),
    # Node.js
    (re.compile(r"at\s+\w+\s+\((?:/[\w.-]+)+:\d+:\d+\)"), "Node.js Stack Trace", Severity.HIGH),
    # Generic
    (re.compile(r"(?:mysql_connect|pg_connect|sqlite_open)\(", re.I), "Database Connection Code", Severity.CRITICAL),
    (re.compile(r"/(?:home|var|usr)/[\w/]+\.(?:py|php|rb|js|java)", re.I), "File Path Disclosure", Severity.MEDIUM),
]


class InfoDisclosureModule(BaseModule):
    @property
    def name(self) -> str:
        return "Information Disclosure"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []

        # --- Server version header ---
        server_header = page.headers.get("server", page.headers.get("Server", ""))
        if server_header:
            for pattern, server_name in SERVER_VERSION_PATTERNS:
                match = pattern.search(server_header)
                if match:
                    findings.append(
                        Finding(
                            url=page.url,
                            vulnerability_type="Server Version Disclosure",
                            severity=Severity.LOW,
                            description=(
                                f"Le header Server révèle la version du serveur : « {match.group()} ». "
                                "Cette information facilite le ciblage d'exploits spécifiques à cette version."
                            ),
                            recommendation=(
                                f"Configurer {server_name} pour masquer la version dans le header Server. "
                                "Par ex. pour nginx : server_tokens off; "
                                "Pour Apache : ServerTokens Prod"
                            ),
                        )
                    )
                    break

        # --- X-Powered-By header ---
        powered_by = page.headers.get("x-powered-by", page.headers.get("X-Powered-By", ""))
        if powered_by:
            findings.append(
                Finding(
                    url=page.url,
                    vulnerability_type="Technology Disclosure (X-Powered-By)",
                    severity=Severity.LOW,
                    description=(
                        f"Le header X-Powered-By révèle la technologie utilisée : « {powered_by} ». "
                        "Cela aide un attaquant à identifier les vulnérabilités spécifiques à ce framework."
                    ),
                    recommendation=(
                        "Supprimer le header X-Powered-By dans la configuration du serveur."
                    ),
                )
            )

        # --- Error patterns in body ---
        if page.body and page.content_type.startswith("text/html"):
            for pattern, error_type, severity in ERROR_PATTERNS:
                if pattern.search(page.body):
                    findings.append(
                        Finding(
                            url=page.url,
                            vulnerability_type=f"Information Disclosure: {error_type}",
                            severity=severity,
                            description=(
                                f"La page contient une trace d'erreur de type « {error_type} ». "
                                "Les messages d'erreur détaillés exposent la structure interne de "
                                "l'application (chemins de fichiers, versions, requêtes SQL, etc.)."
                            ),
                            recommendation=(
                                "Désactiver l'affichage des erreurs détaillées en production. "
                                "Utiliser des pages d'erreur génériques (500, 404). "
                                "Logger les erreurs côté serveur uniquement."
                            ),
                        )
                    )
                    break  # One finding per page for errors, to avoid noise

        return findings
