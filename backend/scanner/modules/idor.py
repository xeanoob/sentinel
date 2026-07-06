"""IDOR (Insecure Direct Object Reference) and Privilege Escalation Module."""

import httpx
from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule
import urllib.parse

class IDORModule(BaseModule):
    @property
    def name(self) -> str:
        return "IDOR / Privilege Escalation Module"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        findings: list[Finding] = []

        # We can only test IDOR if we have a secondary auth config to replay with
        secondary_headers = getattr(page, 'secondary_auth_headers', None)
        if not secondary_headers:
            return findings
            
        # IDOR usually applies to URLs with IDs (e.g., /api/users/123)
        # For simplicity, we just replay the exact GET request with the secondary user's headers.
        # If we get a 200 OK and the response is suspiciously similar or contains sensitive data, it's an IDOR.
        
        try:
            # We don't want to test static files or unauthenticated endpoints
            if page.status_code != 200 or not page.content_type.startswith(("application/json", "text/html")):
                return findings
                
            # Replay the request with secondary headers
            resp = await client.get(
                page.url,
                headers=secondary_headers,
                timeout=5.0,
                follow_redirects=False
            )
            
            if resp.status_code == 200:
                # We got a 200 OK. Is it the exact same length/content?
                # If so, the secondary user has the exact same access as the primary user to this page.
                
                # Simple heuristic: if the length is within 5% and it's JSON, it's likely an IDOR
                original_len = len(page.body)
                new_len = len(resp.text)
                
                if original_len > 100 and new_len > 100:
                    ratio = min(original_len, new_len) / max(original_len, new_len)
                    if ratio > 0.95:
                        findings.append(
                            Finding(
                                url=page.url,
                                vulnerability_type="Insecure Direct Object Reference (IDOR) / Privilege Escalation",
                                severity=Severity.CRITICAL,
                                description=f"The endpoint returned the exact same content (ratio: {ratio:.2f}) when accessed with a secondary, unprivileged user profile. This indicates a failure to validate authorization.",
                                recommendation="Implement strict Access Control Checks (RBAC/ABAC). Verify that the currently authenticated user owns or has explicit permission to view the requested resource.",
                            )
                        )
                        
        except Exception as e:
            pass
            
        return findings
