"""OWASP Sentinel - Identification & Authentication Failures Detection Rule

Audits authentication surfaces for unencrypted credential transport,
exposed administrative authentication gateways, and insecure basic auth challenges.
"""

from urllib.parse import urljoin

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class AuthenticationHardeningCheck(BaseDetectionRule):
    """Detects authentication transport weaknesses and exposed administrative authentication gateways."""

    rule_id = "RULE-SEC-011"
    name = "Identification & Authentication Defense Audit"
    description = (
        "Audits target endpoints for unencrypted credential submission channels, publicly exposed administrative "
        "login portals, and missing multi-factor or lockout indicators."
    )
    why_it_matters = (
        "Identification and Authentication Failures (A07:2021) allow adversaries to compromise credentials, "
        "execute automated credential stuffing attacks, or bypass session controls to impersonate legitimate users."
    )
    evidence_description = "Records transport protocol, exposed login routes, HTTP authentication challenge headers."
    owasp_category_mappings = {
        "2025": "A07:2025-Authentication Failures",
        "2021": "A07:2021-Identification and Authentication Failures",
        "2017": "A2:2017-Broken Authentication",
        "2013": "A2:2013-Broken Authentication and Session Management",
        "2010": "A3:2010-Broken Authentication and Session Management",
        "2007": "A7:2007-Broken Authentication and Session Management",
        "2004": "A3:2004-Broken Authentication and Session Management",
        "2003": "A3:2003-Broken Account and Session Management",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Non-destructive audit does not test password strength or execute brute force attempts."
    )
    potential_false_positives = (
        "Intentionally public demo or registration landing pages."
    )
    remediation_guidance = (
        "Enforce TLS (HTTPS) on all authentication endpoints, restrict administrative login portals to corporate "
        "VPNs or IP allowlists, implement Multi-Factor Authentication (MFA), and apply rate-limiting controls."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ]

    AUTH_PORTALS = [
        "/admin/login",
        "/administrator",
        "/wp-login.php",
        "/user/login",
        "/auth/login",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        base_url = context.canonical_url

        # Check 1: Insecure HTTP Scheme for Authentication Surfaces
        if context.scheme.lower() == "http":
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="Insecure Cleartext HTTP Protocol for Authentication Surface",
                    technical_issue_type="CLEARTEXT_AUTH_TRANSPORT",
                    severity="HIGH",
                    confidence="CERTAIN",
                    evidence={"url": base_url, "scheme": context.scheme},
                    remediation="Migrate all application traffic to HTTPS (TLS 1.2 or TLS 1.3) and enforce HSTS.",
                    references=self.references,
                )
            )

        if getattr(context, "_target_unreachable", False):
            return findings

        async with httpx.AsyncClient(verify=False) as client:
            # Check 2: Audit for Public Administrative Portals
            for portal_path in self.AUTH_PORTALS:
                test_url = urljoin(base_url, portal_path)
                try:
                    resp = await client.get(
                        test_url,
                        timeout=context.timeout_seconds,
                        headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                        follow_redirects=False,
                    )
                    # 200 OK on an admin login portal indicates public exposure
                    if resp.status_code == 200 and len(resp.content) > 50:
                        text_lower = resp.text.lower()
                        if any(term in text_lower for term in ("password", "username", "login", "authenticate")):
                            findings.append(
                                CheckFinding(
                                    rule_id=self.rule_id,
                                    title=f"Publicly Exposed Administrative Login Portal ({portal_path})",
                                    technical_issue_type="EXPOSED_ADMIN_PORTAL",
                                    severity="MEDIUM",
                                    confidence="FIRM",
                                    evidence={
                                        "portal_path": portal_path,
                                        "url": test_url,
                                        "vulnerable_url": test_url,
                                        "affected_url": test_url,
                                        "status_code": resp.status_code,
                                    },
                                    remediation=(
                                        f"Restrict public web access to '{portal_path}' using IP allowlists, "
                                        "a VPN gateway, or a zero-trust access proxy with enforced MFA."
                                    ),
                                    references=self.references,
                                )
                            )
                            break
                except Exception:
                    continue

            # Check 3: Check for WWW-Authenticate Header on Protected Endpoints
            try:
                root_resp = await context.get_target_response(client)
                www_auth = root_resp.headers.get("www-authenticate", "")
                if "basic" in www_auth.lower() and context.scheme.lower() == "http":
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="HTTP Basic Authentication Offered Over Cleartext Channel",
                            technical_issue_type="CLEARTEXT_BASIC_AUTH",
                            severity="HIGH",
                            confidence="CERTAIN",
                            evidence={"header": www_auth, "url": base_url},
                            remediation="Do not challenge clients with Basic Authentication over unencrypted HTTP.",
                            references=self.references,
                        )
                    )
            except Exception:
                pass

        return findings

