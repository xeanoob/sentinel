"""Local File Inclusion (LFI) vulnerability module."""

from models import CrawledPage, Finding, Severity
import re

async def scan(page: CrawledPage) -> list[Finding]:
    """Test for LFI indicators."""
    findings = []
    
    # Signatures of common local files
    lfi_signatures = [
        (r"root:x:0:0:", "Linux /etc/passwd content exposed"),
        (r"\[boot loader\]", "Windows boot.ini content exposed"),
        (r"DB_PASSWORD=", "Potential environment variable or config file exposed"),
    ]

    for pattern, desc in lfi_signatures:
        if re.search(pattern, page.body):
            findings.append(
                Finding(
                    url=page.url,
                    vulnerability_type="Local File Inclusion (LFI)",
                    severity=Severity.HIGH,
                    description=f"Found indicators of local file inclusion: {desc}.",
                    recommendation="Validate and sanitize all file paths passed as parameters. Do not allow directory traversal characters (../).",
                )
            )
            break
            
    return findings
