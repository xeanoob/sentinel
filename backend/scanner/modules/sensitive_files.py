"""Probe for exposed sensitive files and directories."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from config import settings
from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# (relative_path, severity, validation_pattern_or_None, description)
SENSITIVE_PATHS: list[tuple[str, Severity, str | None, str]] = [
    # --- Version control (CRITICAL/HIGH) ---
    (".git/config", Severity.CRITICAL, r"\[core\]", "Dépôt Git exposé — code source, credentials, historique"),
    (".git/HEAD", Severity.CRITICAL, r"ref: refs/", "Dépôt Git exposé — accès à l'historique complet"),
    (".svn/entries", Severity.HIGH, r"dir", "Dépôt SVN exposé — code source et métadonnées"),
    (".hg/dirstate", Severity.HIGH, None, "Dépôt Mercurial exposé"),

    # --- Environment & config (CRITICAL) ---
    (".env", Severity.CRITICAL, r"(?:DB_|APP_|SECRET|KEY|PASSWORD|TOKEN|API).*=", "Fichier .env avec variables sensibles (clés API, mots de passe)"),
    (".env.local", Severity.CRITICAL, r"(?:DB_|APP_|SECRET|KEY|PASSWORD|TOKEN|API).*=", "Fichier .env.local avec configuration locale"),
    (".env.production", Severity.CRITICAL, r"(?:DB_|APP_|SECRET|KEY).*=", "Fichier .env.production exposé"),
    (".env.backup", Severity.CRITICAL, r"(?:DB_|APP_|SECRET|KEY).*=", "Backup de .env exposé"),
    ("wp-config.php", Severity.CRITICAL, r"DB_(?:NAME|USER|PASSWORD|HOST)", "WordPress — config DB et clés secrètes"),
    ("wp-config.php.bak", Severity.CRITICAL, r"DB_(?:NAME|USER|PASSWORD)", "Backup de wp-config.php exposé"),
    ("configuration.php", Severity.CRITICAL, r"\$(?:host|user|password|db)", "Joomla — config DB exposée"),

    # --- PHP info / debug ---
    ("phpinfo.php", Severity.HIGH, r"PHP Version", "phpinfo() exposé — révèle toute la config serveur"),
    ("info.php", Severity.HIGH, r"PHP Version", "phpinfo() exposé"),
    ("test.php", Severity.MEDIUM, None, "Script test.php accessible en production"),

    # --- Database dumps (CRITICAL) ---
    ("database.sql", Severity.CRITICAL, r"(?:INSERT INTO|CREATE TABLE)", "Dump SQL de base de données exposé"),
    ("dump.sql", Severity.CRITICAL, r"(?:INSERT INTO|CREATE TABLE)", "Dump SQL exposé"),
    ("backup.sql", Severity.CRITICAL, r"(?:INSERT INTO|CREATE TABLE)", "Backup SQL exposé"),
    ("db.sql", Severity.CRITICAL, r"(?:INSERT INTO|CREATE TABLE)", "Dump de base de données exposé"),

    # --- Apache / server config ---
    (".htaccess", Severity.MEDIUM, r"(?:Rewrite|Deny|Allow|Auth)", "Fichier .htaccess exposé — règles serveur visibles"),
    (".htpasswd", Severity.CRITICAL, r":", "Fichier .htpasswd exposé — identifiants d'authentification"),

    # --- Admin panels ---
    ("admin/", Severity.MEDIUM, r"(?:login|admin|password|username)", "Panel d'administration accessible"),
    ("administrator/", Severity.MEDIUM, r"(?:login|admin)", "Panel d'administration (Joomla) accessible"),
    ("phpmyadmin/", Severity.HIGH, r"(?:phpMyAdmin|pma)", "phpMyAdmin accessible publiquement"),
    ("adminer.php", Severity.HIGH, r"(?:Adminer|Login)", "Adminer (outil DB) accessible publiquement"),

    # --- Logs ---
    ("error.log", Severity.MEDIUM, r"(?:\[error\]|\[warn\]|Exception|Error)", "Fichier de logs d'erreurs exposé"),
    ("access.log", Severity.MEDIUM, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Fichier de logs d'accès exposé"),
    ("debug.log", Severity.HIGH, r"(?:debug|error|warning)", "Fichier de logs de debug exposé"),

    # --- Backups (archives) ---
    ("backup.zip", Severity.HIGH, None, "Archive backup.zip accessible"),
    ("backup.tar.gz", Severity.HIGH, None, "Archive backup.tar.gz accessible"),
    ("site.zip", Severity.HIGH, None, "Archive du site accessible"),

    # --- Package managers (info) ---
    ("composer.json", Severity.LOW, r'"require"', "composer.json exposé — dépendances PHP visibles"),
    ("package.json", Severity.LOW, r'"dependencies"', "package.json exposé — dépendances Node.js visibles"),

    # --- Other ---
    ("robots.txt", Severity.LOW, r"(?:Disallow|Allow|Sitemap)", "robots.txt trouvé — peut révéler des chemins cachés"),
    (".DS_Store", Severity.LOW, None, "Fichier .DS_Store macOS exposé — révèle la structure de fichiers"),
    ("crossdomain.xml", Severity.MEDIUM, r"<cross-domain-policy", "crossdomain.xml — politique Flash/Silverlight"),
    (".well-known/security.txt", Severity.LOW, r"Contact:", "security.txt trouvé (informatif)"),
    ("web.config", Severity.HIGH, r"<configuration", "web.config IIS exposé — configuration serveur"),
    ("elmah.axd", Severity.HIGH, r"(?:error|exception)", "ELMAH error log (.NET) exposé"),
]


class SensitiveFilesModule(BaseModule):
    """Probes common sensitive file paths on the target domain.

    This is a domain-level module: it runs once per base URL,
    not for every crawled page.
    """

    @property
    def name(self) -> str:
        return "Sensitive Files"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        # We only probe from the root of the domain
        # The engine will call us once with a special "root page"
        findings: list[Finding] = []
        parsed = urlparse(page.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"

        for path, severity, validation_pattern, desc in SENSITIVE_PATHS:
            probe_url = urljoin(base_url, path)

            try:
                resp = await client.get(
                    probe_url,
                    follow_redirects=True,
                    timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
                )

                # Skip non-200 responses
                if resp.status_code != 200:
                    continue

                # Skip if content is too small (likely a custom 404 page)
                if len(resp.text) < 20:
                    continue

                # If a validation pattern is provided, check it
                if validation_pattern:
                    if not re.search(validation_pattern, resp.text, re.IGNORECASE):
                        continue

                # Skip if content-type suggests it's an HTML error page for non-HTML files
                content_type = resp.headers.get("content-type", "")
                if not path.endswith(("/", ".html", ".htm", ".php", ".axd")):
                    if "text/html" in content_type and validation_pattern:
                        # For non-HTML files, if we got HTML back, likely a custom 404
                        # But only skip if the validation pattern didn't match (already checked above)
                        pass

                findings.append(
                    Finding(
                        url=probe_url,
                        vulnerability_type="Sensitive File Exposed",
                        severity=severity,
                        description=f"{desc}. Le fichier « {path} » est accessible publiquement.",
                        recommendation=(
                            f"Bloquer l'accès à « {path} » dans la configuration du serveur web. "
                            "Par ex. dans nginx : location ~* /\\.(?:env|git) { deny all; }"
                        ),
                    )
                )

            except Exception:
                continue

        return findings
