"""Secret and PII scanning module. Detects leaked API keys, tokens, and personal data."""

import re
import httpx
from scanner.modules.base import BaseModule
from models import CrawledPage, Finding, Severity

class SecretsModule(BaseModule):
    @property
    def name(self) -> str:
        return "Secrets & PII Scanner"

    # A collection of regexes for common secrets and PII
    PATTERNS = {
        "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
        "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Stripe Test Key": r"sk_test_[0-9a-zA-Z]{24}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
        "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
        "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
        "Generic JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "French SSN (NIR)": r"\b[12]\s*\d{2}\s*(0[1-9]|1[0-2])\s*(2[A-B]|[0-9]{2})\s*\d{3}\s*\d{3}\s*\d{2}\b",
    }

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []
        body_text = page.body

        for secret_name, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, body_text)
            # Limit to first 5 matches per type to avoid blowing up the report
            for i, match in enumerate(matches):
                if i >= 5:
                    break
                
                # We redact the actual secret in the finding to avoid logging it
                raw_secret = match.group(0)
                redacted_secret = raw_secret[:4] + "***" + raw_secret[-4:] if len(raw_secret) > 8 else "***"
                
                findings.append(
                    Finding(
                        url=page.url,
                        vulnerability_type=f"Information Disclosure: {secret_name}",
                        severity=Severity.HIGH,
                        description=f"Found a potential {secret_name} leaked in the HTTP response body: {redacted_secret}",
                        recommendation=f"Remove the {secret_name} from the source code or database output. If this is a real key, revoke it immediately.",
                    )
                )

        return findings
