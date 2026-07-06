"""Check SSL/TLS certificate validity and configuration."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from models import CrawledPage, Finding, Severity
from scanner.modules.base import BaseModule


class SSLCheckModule(BaseModule):
    """Domain-level module: checks the SSL/TLS certificate of the target."""

    @property
    def name(self) -> str:
        return "SSL/TLS Check"

    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        parsed = urlparse(page.url)

        # Only check HTTPS sites
        if parsed.scheme != "https":
            return [
                Finding(
                    url=page.url,
                    vulnerability_type="No HTTPS",
                    severity=Severity.HIGH,
                    description=(
                        f"Le site {parsed.netloc} n'utilise pas HTTPS. "
                        "Toutes les communications sont en clair et peuvent être interceptées (MITM)."
                    ),
                    recommendation=(
                        "Activer HTTPS avec un certificat TLS valide (Let's Encrypt est gratuit). "
                        "Rediriger tout le trafic HTTP vers HTTPS."
                    ),
                )
            ]

        findings: list[Finding] = []
        hostname = parsed.hostname or parsed.netloc
        port = parsed.port or 443

        try:
            # Create an SSL context that does NOT verify — we want to inspect the cert ourselves
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    # getpeercert returns None when verify_mode is CERT_NONE in some versions
                    # Use binary form + decode as fallback
                    if cert is None:
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            # We can at least check expiry via a verifying context
                            pass

                    protocol_version = ssock.version()

            # Try with verification to catch self-signed / expired certs
            try:
                ctx_verify = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock2:
                    with ctx_verify.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                        verified_cert = ssock2.getpeercert()
            except ssl.SSLCertVerificationError as e:
                err_msg = str(e)
                if "CERTIFICATE_VERIFY_FAILED" in err_msg:
                    if "self-signed" in err_msg.lower() or "self signed" in err_msg.lower():
                        findings.append(
                            Finding(
                                url=page.url,
                                vulnerability_type="Self-Signed SSL Certificate",
                                severity=Severity.HIGH,
                                description=(
                                    f"Le certificat SSL de {hostname} est auto-signé. "
                                    "Les navigateurs afficheront un avertissement de sécurité "
                                    "et les connexions sont vulnérables au MITM."
                                ),
                                recommendation=(
                                    "Remplacer par un certificat émis par une autorité de certification reconnue "
                                    "(Let's Encrypt, DigiCert, etc.)."
                                ),
                            )
                        )
                    elif "expired" in err_msg.lower():
                        findings.append(
                            Finding(
                                url=page.url,
                                vulnerability_type="Expired SSL Certificate",
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Le certificat SSL de {hostname} a expiré. "
                                    "Les visiteurs voient un avertissement de sécurité."
                                ),
                                recommendation="Renouveler immédiatement le certificat SSL.",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                url=page.url,
                                vulnerability_type="SSL Certificate Error",
                                severity=Severity.HIGH,
                                description=f"Erreur de vérification SSL pour {hostname} : {err_msg[:200]}",
                                recommendation="Vérifier et corriger la configuration SSL du serveur.",
                            )
                        )
            except Exception:
                pass
            else:
                # Certificate verified OK — check expiry date
                if verified_cert:
                    not_after = verified_cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            days_left = (expiry - datetime.now(timezone.utc)).days
                            if days_left < 0:
                                findings.append(
                                    Finding(
                                        url=page.url,
                                        vulnerability_type="Expired SSL Certificate",
                                        severity=Severity.CRITICAL,
                                        description=f"Le certificat SSL a expiré il y a {abs(days_left)} jours.",
                                        recommendation="Renouveler immédiatement le certificat SSL.",
                                    )
                                )
                            elif days_left < 30:
                                findings.append(
                                    Finding(
                                        url=page.url,
                                        vulnerability_type="SSL Certificate Expiring Soon",
                                        severity=Severity.MEDIUM,
                                        description=f"Le certificat SSL expire dans {days_left} jours ({not_after}).",
                                        recommendation="Renouveler le certificat SSL avant expiration.",
                                    )
                                )
                        except ValueError:
                            pass

            # Check for weak protocol versions
            if protocol_version and protocol_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append(
                    Finding(
                        url=page.url,
                        vulnerability_type=f"Weak TLS Version: {protocol_version}",
                        severity=Severity.HIGH,
                        description=(
                            f"Le serveur utilise {protocol_version}, un protocole obsolète et vulnérable. "
                            "Des attaques connues (POODLE, BEAST, etc.) exploitent ces versions."
                        ),
                        recommendation=(
                            "Désactiver SSLv2, SSLv3, TLSv1.0 et TLSv1.1. "
                            "Utiliser uniquement TLSv1.2 et TLSv1.3."
                        ),
                    )
                )

        except (socket.timeout, ConnectionRefusedError, OSError):
            # Can't connect — not necessarily a finding, might be a network issue
            pass

        return findings
