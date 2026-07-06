"""Detect directory traversal (path traversal) vulnerabilities."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from config import settings
from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# Payloads to inject for path traversal testing
TRAVERSAL_PAYLOADS = [
    "../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",  # double encoding
]

# Parameter names that are likely to accept file paths
FILE_PARAM_NAMES = {
    "file", "path", "filepath", "filename", "page", "template",
    "include", "inc", "dir", "folder", "document", "doc",
    "load", "read", "view", "content", "action", "module",
    "lang", "language", "locale", "theme", "skin", "style",
    "src", "source", "conf", "config",
}

# Patterns indicating successful path traversal
UNIX_PASSWD_PATTERN = re.compile(r"root:(?:x|\*|!)?:\d+:\d+:")
WINDOWS_INI_PATTERN = re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I)


class DirectoryTraversalModule(BaseModule):
    @property
    def name(self) -> str:
        return "Directory Traversal"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []
        tested: set[str] = set()

        # Test URL query parameters
        for param in page.url_params:
            if param.lower() not in FILE_PARAM_NAMES:
                continue

            key = f"{page.url}|{param}"
            if key in tested:
                continue
            tested.add(key)

            finding = await self._test_param(page.url, param, client)
            if finding:
                findings.append(finding)

        # Test form fields
        for form in page.forms:
            for field in form.fields:
                if field.name.lower() not in FILE_PARAM_NAMES:
                    continue
                if field.field_type in ("submit", "button", "image", "reset"):
                    continue

                key = f"{form.action}|{field.name}"
                if key in tested:
                    continue
                tested.add(key)

                if form.method.upper() == "GET":
                    finding = await self._test_param(form.action, field.name, client)
                    if finding:
                        findings.append(finding)

        return findings

    async def _test_param(
        self,
        base_url: str,
        param: str,
        client: httpx.AsyncClient,
    ) -> Optional[Finding]:
        for payload in TRAVERSAL_PAYLOADS:
            parsed = urlparse(base_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = await client.get(
                    test_url,
                    follow_redirects=True,
                    timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
                )
                body = resp.text

                if UNIX_PASSWD_PATTERN.search(body):
                    return Finding(
                        url=base_url,
                        vulnerability_type="Directory Traversal (LFI)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Le paramètre « {param} » est vulnérable à la traversée de répertoire. "
                            "Le contenu de /etc/passwd a été lu avec succès. "
                            "Un attaquant peut lire n'importe quel fichier du serveur "
                            "(code source, configuration, données sensibles)."
                        ),
                        recommendation=(
                            "Ne jamais utiliser d'entrées utilisateur directement dans des chemins de fichier. "
                            "Valider les chemins contre une liste blanche. "
                            "Utiliser chroot ou des conteneurs pour isoler le système de fichiers."
                        ),
                    )

                if WINDOWS_INI_PATTERN.search(body):
                    return Finding(
                        url=base_url,
                        vulnerability_type="Directory Traversal (LFI - Windows)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Le paramètre « {param} » est vulnérable à la traversée de répertoire (Windows). "
                            "Le contenu de win.ini a été lu avec succès."
                        ),
                        recommendation=(
                            "Ne jamais utiliser d'entrées utilisateur dans des chemins de fichier. "
                            "Valider contre une liste blanche de fichiers autorisés."
                        ),
                    )

            except Exception:
                continue

        return None
