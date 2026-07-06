"""Server-Side Request Forgery (SSRF) vulnerability module."""

from models import CrawledPage, Finding, Severity
import urllib.parse

async def scan(page: CrawledPage) -> list[Finding]:
    """Test for SSRF indicators in URLs."""
    findings = []
    
    # Check if any URL parameters look like they are fetching external URLs
    if page.url_params:
        for param, values in page.url_params.items():
            for value in values:
                # If a parameter value is a URL, it's a prime target for SSRF
                if value.startswith("http://") or value.startswith("https://"):
                    findings.append(
                        Finding(
                            url=page.url,
                            vulnerability_type="Server-Side Request Forgery (SSRF) Risk",
                            severity=Severity.MEDIUM,
                            description=f"Parameter '{param}' accepts a URL as input. This might be vulnerable to SSRF.",
                            recommendation="Ensure the server validates the URL against a strict whitelist of allowed domains before fetching it.",
                        )
                    )
                    break
                    
    return findings
