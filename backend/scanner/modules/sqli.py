"""Detect SQL Injection vulnerabilities (error-based detection)."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from config import settings
from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# Payloads designed to trigger SQL syntax errors without causing damage
SQLI_PAYLOADS = [
    "'",
    "''",
    "1' OR '1'='1",
    "1; SELECT 1--",
    "' UNION SELECT NULL--",
    "1' AND '1'='2",
]

# Regex patterns for common SQL error messages across databases
SQL_ERROR_PATTERNS: list[tuple[str, str]] = [
    # MySQL
    (r"You have an error in your SQL syntax", "MySQL"),
    (r"Warning:\s*mysql_", "MySQL"),
    (r"Warning:\s*mysqli_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"com\.mysql\.jdbc", "MySQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    # PostgreSQL
    (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"pg_exec\(\)", "PostgreSQL"),
    (r"PSQLException", "PostgreSQL"),
    (r"org\.postgresql\.util", "PostgreSQL"),
    # SQLite
    (r"SQLite3::query\(\)", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"unrecognized token:", "SQLite"),
    # MSSQL
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
    (r"Microsoft SQL Native Client error", "MSSQL"),
    (r"ODBC SQL Server Driver", "MSSQL"),
    (r"SqlException", "MSSQL"),
    (r"Server Error in '/' Application", "MSSQL/.NET"),
    # Oracle
    (r"ORA-\d{5}", "Oracle"),
    (r"oracle\.jdbc", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    # Generic
    (r"SQL syntax.*?error", "Generic SQL"),
    (r"valid MySQL result", "MySQL"),
    (r"supplied argument is not a valid", "PHP/SQL"),
    (r"on line \d+", "PHP"),  # PHP error with SQL context
]

_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), db) for p, db in SQL_ERROR_PATTERNS]


def _build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _detect_sql_error(body: str) -> Optional[str]:
    """Return the database name if an SQL error pattern is found, else None."""
    for pattern, db_name in _COMPILED_PATTERNS:
        if pattern.search(body):
            return db_name
    return None


class SQLiModule(BaseModule):
    @property
    def name(self) -> str:
        return "SQL Injection"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []
        if not getattr(page, 'is_active_fuzzing', False):
            return findings

        tested_params: set[str] = set()

        # --- URL query parameters ---
        for param in page.url_params:
            if param in tested_params:
                continue
            tested_params.add(param)

            finding = await self._test_param(page.url, param, client)
            if finding:
                findings.append(finding)

        # --- Form fields (GET and POST) ---
        for form in page.forms:
            for field in form.fields:
                if field.field_type in ("submit", "button", "image", "reset", "file"):
                    continue
                key = f"{form.action}|{field.name}"
                if key in tested_params:
                    continue
                tested_params.add(key)

                if form.method.upper() == "GET":
                    finding = await self._test_param(form.action, field.name, client)
                else:
                    finding = await self._test_post_param(
                        form.action, form.fields, field.name, client
                    )
                if finding:
                    findings.append(finding)

        return findings

    async def _test_param(
        self,
        base_url: str,
        param: str,
        client: httpx.AsyncClient,
    ) -> Optional[Finding]:
        """Test a GET query parameter for SQL injection."""
        for payload in SQLI_PAYLOADS:
            test_url = _build_url_with_param(base_url, param, payload)
            try:
                resp = await client.get(
                    test_url,
                    follow_redirects=True,
                    timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
                )
                db = _detect_sql_error(resp.text)
                if db:
                    return Finding(
                        url=base_url,
                        vulnerability_type="SQL Injection",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Le paramètre GET « {param} » est vulnérable à l'injection SQL. "
                            f"Une erreur {db} a été détectée dans la réponse après injection "
                            f"du payload « {payload} ». Un attaquant peut lire, modifier ou "
                            "supprimer des données de la base."
                        ),
                        recommendation=(
                            "Utiliser des requêtes préparées (prepared statements / parameterized queries). "
                            "Ne jamais concaténer des entrées utilisateur dans des requêtes SQL. "
                            "Valider et assainir toutes les entrées."
                        ),
                    )
            except Exception:
                continue

        return None

    async def _test_post_param(
        self,
        action_url: str,
        fields: list,
        target_field: str,
        client: httpx.AsyncClient,
    ) -> Optional[Finding]:
        """Test a POST form field for SQL injection."""
        for payload in SQLI_PAYLOADS:
            form_data = {}
            for f in fields:
                if f.name == target_field:
                    form_data[f.name] = payload
                else:
                    form_data[f.name] = f.value or "test"

            try:
                resp = await client.post(
                    action_url,
                    data=form_data,
                    follow_redirects=True,
                    timeout=settings.DEFAULT_PAGE_TIMEOUT_MS / 1000,
                )
                db = _detect_sql_error(resp.text)
                if db:
                    return Finding(
                        url=action_url,
                        vulnerability_type="SQL Injection (POST)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Le champ POST « {target_field} » du formulaire soumis à {action_url} "
                            f"est vulnérable à l'injection SQL. Erreur {db} détectée. "
                            "Un attaquant peut lire, modifier ou supprimer des données."
                        ),
                        recommendation=(
                            "Utiliser des requêtes préparées (prepared statements). "
                            "Ne jamais concaténer des entrées utilisateur dans des requêtes SQL."
                        ),
                    )
            except Exception:
                continue

        return None
