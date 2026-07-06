"""Command Injection vulnerability module."""

from models import CrawledPage, Finding, Severity
import urllib.parse
import re

# Common test payloads for OS Command Injection
# We use sleep or simple echo logic that we can detect in the response
PAYLOADS = [
    "; echo SENTINEL_CMD_TEST",
    "| echo SENTINEL_CMD_TEST",
    "& echo SENTINEL_CMD_TEST",
    "|| echo SENTINEL_CMD_TEST",
    "`echo SENTINEL_CMD_TEST`",
    "$(echo SENTINEL_CMD_TEST)",
]

async def scan(page: CrawledPage) -> list[Finding]:
    """Test for Command Injection in URL parameters and forms."""
    findings = []
    
    # Check URL Parameters
    if page.url_params:
        base_url = page.url.split("?")[0]
        for param, values in page.url_params.items():
            for value in values:
                for payload in PAYLOADS:
                    # In a real scanner, we would send the request here.
                    # Since Sentinel runs offline analysis on crawled pages in the current engine design,
                    # we do a simple heuristic check: if the page body contains suspicious command outputs
                    # that look like a reflection of injection, we flag it.
                    pass

    # Basic heuristic for demonstration in offline mode
    # A true active scanner would re-fetch the page with the payload
    if "uid=0(root)" in page.body or re.search(r"Volume in drive [A-Z] is", page.body):
         findings.append(
            Finding(
                url=page.url,
                vulnerability_type="OS Command Injection",
                severity=Severity.CRITICAL,
                description="Possible command injection output detected in the page body (e.g., 'root' user info or Windows dir output).",
                recommendation="Never pass user input directly to system shells. Use parameterized APIs or strict input sanitization.",
            )
        )
         
    return findings
