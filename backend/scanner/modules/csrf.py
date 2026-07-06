"""Detect missing CSRF protections on HTML forms."""

from __future__ import annotations

import re

import httpx

from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule

# Common CSRF token field names
CSRF_FIELD_NAMES = {
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_csrf", "_token", "token", "authenticity_token",
    "__requestverificationtoken", "antiforgerytoken",
    "xsrf", "xsrf_token", "_xsrf",
}

# Common CSRF meta tag names
CSRF_META_NAMES = {
    "csrf-token", "csrf-param", "_csrf_token",
}


def _form_has_csrf_token(form, page_body: str) -> bool:
    """Check if a form includes a CSRF token field."""
    for field in form.fields:
        if field.field_type == "hidden" and field.name.lower() in CSRF_FIELD_NAMES:
            return True
        if field.name.lower() in CSRF_FIELD_NAMES:
            return True

    # Also check for CSRF meta tags in the page (some frameworks use meta + JS)
    for meta_name in CSRF_META_NAMES:
        if re.search(rf'<meta\s[^>]*name=["\']?{re.escape(meta_name)}["\']?', page_body, re.I):
            return True

    return False


class CSRFModule(BaseModule):
    @property
    def name(self) -> str:
        return "CSRF Protection"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []

        for form in page.forms:
            # Only check POST forms (GET forms are generally not CSRF-sensitive)
            if form.method.upper() != "POST":
                continue

            if not _form_has_csrf_token(form, page.body):
                # Build a description of what the form does
                field_names = [f.name for f in form.fields if f.field_type != "hidden"]
                fields_desc = ", ".join(field_names[:5]) or "aucun champ visible"

                findings.append(
                    Finding(
                        url=page.url,
                        vulnerability_type="Missing CSRF Token",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Un formulaire POST pointant vers « {form.action} » "
                            f"ne contient pas de token anti-CSRF. "
                            f"Champs : {fields_desc}. "
                            "Un attaquant peut forger une requête cross-site qui sera "
                            "exécutée avec les droits de l'utilisateur authentifié."
                        ),
                        recommendation=(
                            "Ajouter un token CSRF unique à chaque formulaire POST "
                            "(ex. : champ hidden avec un token aléatoire lié à la session). "
                            "Vérifier ce token côté serveur à chaque soumission."
                        ),
                    )
                )

        return findings
