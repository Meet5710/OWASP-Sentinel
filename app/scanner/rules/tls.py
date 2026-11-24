"""OWASP Sentinel - TLS / SSL Configuration Check

Validates transport layer encryption, negotiated protocol version,
certificate expiration window, and cipher suite strength.
"""

import socket
import ssl
from datetime import datetime, timezone

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class TlsConfigurationCheck(BaseDetectionRule):
    """Audits TLS/SSL protocol versions, certificate expiration, and cipher strengths."""

    rule_id = "RULE-SEC-002"
    name = "TLS/SSL Cryptographic Configuration Audit"
    description = "Tests the target's TLS/SSL handshake, supported protocol version, and certificate validity."
    why_it_matters = (
        "Inadequate cryptographic configurations, obsolete TLS versions (1.0, 1.1), or expired certificates "
        "expose user traffic to man-in-the-middle (MITM) attacks and credential eavesdropping."
    )
    evidence_description = (
        "Records negotiated TLS protocol, cipher suite, certificate subject, issuer, and expiry date."
    )
    owasp_category_mappings = {
        "2025": "A04:2025-Cryptographic Failures",
        "2021": "A02:2021-Cryptographic Failures",
        "2017": "A3:2017-Sensitive Data Exposure",
        "2013": "A6:2013-Sensitive Data Exposure",
        "2010": "A9:2010-Insufficient Transport Layer Protection",
        "2007": "A9:2007-Insecure Communications",
        "2004": "A8:2004-Insecure Storage",
        "2003": "A8:2003-Insecure Storage",
    }
    required_permissions = "TCP network connection to target TLS port (typically 443/8443)."
    known_limitations = (
        "Server Name Indication (SNI) is used during handshake. If target uses unusual SNI routing, "
        "the certificate returned may differ."
    )
    potential_false_positives = (
        "Internal test environments with self-signed certificates will flag untrusted issuer warnings."
    )
    remediation_guidance = (
        "Disable TLS 1.0 and TLS 1.1 on your web servers. Enable TLS 1.2 and TLS 1.3 exclusively. "
        "Ensure SSL certificates are renewed before expiry, and use modern AEAD cipher suites (e.g. AES-GCM or ChaCha20)."
    )
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        "https://ssl-config.mozilla.org/",
        "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []

        if context.scheme != "https":
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="Unencrypted HTTP Protocol in Use",
                    technical_issue_type="CLEARTEXT_TRANSMISSION",
                    severity="HIGH",
                    confidence="CERTAIN",
                    evidence={"scheme": context.scheme, "url": context.canonical_url},
                    remediation="Migrate target application entirely to HTTPS and enforce automatic HTTP-to-HTTPS redirection.",
                    references=self.references,
                )
            )
            return findings

        # 1. Connect and inspect TLS handshake (or reuse context reconnaissance if available)
        tls_version = context.tls_version
        cipher_info = (context.tls_cipher, "", 256) if context.tls_cipher else None
        peercert = getattr(context, "certificate_info", {})

        if not tls_version:
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE  # Safe inspection even if cert is self-signed in test labs

                with socket.create_connection((context.host, context.port), timeout=min(context.timeout_seconds, 3.5)) as sock:
                    with ssl_context.wrap_socket(sock, server_hostname=context.host) as ssock:
                        tls_version = ssock.version()
                        cipher_info = ssock.cipher()
                        peercert = ssock.getpeercert(binary_form=False)
            except Exception as e:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="TLS Handshake Probing Notice",
                        technical_issue_type="OBSOLETE_TLS_VERSION",
                        severity="MEDIUM",
                        confidence="FIRM",
                        evidence={"error": str(e), "host": context.host, "port": context.port},
                        remediation="Verify target TLS endpoint availability and support for standard TLS 1.2 / TLS 1.3.",
                        references=self.references,
                    )
                )
                return findings

        try:
            # 1. Obsolete TLS Version Check
            if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title=f"Obsolete TLS Protocol Supported: {tls_version}",
                        technical_issue_type="OBSOLETE_TLS_VERSION",
                        severity="HIGH",
                        confidence="CERTAIN",
                        evidence={
                            "negotiated_version": tls_version,
                            "host": context.host,
                            "port": context.port,
                        },
                        remediation="Disable TLS 1.0 and TLS 1.1. Restrict server configuration to TLS 1.2 and TLS 1.3 only.",
                        references=self.references,
                    )
                )

            # 2. Cipher Suite Strength Check
            if cipher_info:
                cipher_name, _, secret_bits = cipher_info
                if secret_bits and secret_bits < 128:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title=f"Weak TLS Cipher Key Length: {secret_bits} bits",
                            technical_issue_type="WEAK_CIPHER_SUITE",
                            severity="HIGH",
                            confidence="CERTAIN",
                            evidence={"cipher": cipher_name, "key_bits": secret_bits},
                            remediation="Configure server to use strong cipher suites with at least 128-bit key lengths (prefer 256-bit AES-GCM).",
                            references=self.references,
                        )
                    )

                    # 3. Certificate Expiration Check (if binary cert parsed)
                    if peercert and "notAfter" in peercert and isinstance(peercert["notAfter"], str):
                        expiry_str: str = peercert["notAfter"]
                        # SSL date format: 'Apr 25 12:00:00 2027 GMT'
                        try:
                            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(
                                tzinfo=timezone.utc
                            )
                            now = datetime.now(timezone.utc)
                            days_remaining = (expiry_dt - now).days

                            if days_remaining < 0:
                                findings.append(
                                    CheckFinding(
                                        rule_id=self.rule_id,
                                        title="Expired SSL/TLS Certificate",
                                        technical_issue_type="EXPIRED_CERTIFICATE",
                                        severity="HIGH",
                                        confidence="CERTAIN",
                                        evidence={
                                            "expired_on": expiry_dt.isoformat(),
                                            "days_past": abs(days_remaining),
                                        },
                                        remediation="Immediately renew and deploy a valid TLS certificate.",
                                        references=self.references,
                                    )
                                )
                            elif days_remaining <= 30:
                                findings.append(
                                    CheckFinding(
                                        rule_id=self.rule_id,
                                        title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} days)",
                                        technical_issue_type="CERTIFICATE_EXPIRING_SOON",
                                        severity="LOW",
                                        confidence="CERTAIN",
                                        evidence={
                                            "expires_on": expiry_dt.isoformat(),
                                            "days_remaining": days_remaining,
                                        },
                                        remediation="Schedule certificate renewal before the 30-day expiration window.",
                                        references=self.references,
                                    )
                                )
                        except Exception:
                            pass

        except Exception as e:
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="TLS Handshake Failed",
                    technical_issue_type="TLS_CONNECTION_ERROR",
                    severity="MEDIUM",
                    confidence="CERTAIN",
                    evidence={"error": str(e), "host": context.host, "port": context.port},
                    remediation="Verify target host is accepting TLS connections and firewall allows outbound TLS on specified port.",
                    references=self.references,
                )
            )

        return findings
