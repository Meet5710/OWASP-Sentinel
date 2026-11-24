"""OWASP Sentinel - Cookie Security Attributes Check

Evaluates HTTP response cookies for mandatory defense flags:
Secure, HttpOnly, and SameSite controls.
"""

from http.cookies import SimpleCookie

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class CookieSecurityCheck(BaseDetectionRule):
    """Audits Set-Cookie headers for Secure, HttpOnly, and SameSite attributes."""

    rule_id = "RULE-SEC-003"
    name = "HTTP Cookie Security Flags Audit"
    description = "Checks that all application cookies enforce Secure, HttpOnly, and appropriate SameSite protections."
    why_it_matters = (
        "Cookies lacking 'Secure' can be intercepted in cleartext. Cookies lacking 'HttpOnly' can be stolen "
        "by Cross-Site Scripting (XSS) scripts. Cookies lacking 'SameSite' leave the application vulnerable "
        "to Cross-Site Request Forgery (CSRF)."
    )
    evidence_description = "Records cookie names, raw directives, and missing security attributes."
    owasp_category_mappings = {
        "2025": "A02:2025-Security Misconfiguration, A07:2025-Authentication Failures",
        "2021": "A01:2021-Broken Access Control, A05:2021-Security Misconfiguration, A07:2021-Identification and Authentication Failures",
        "2017": "A2:2017-Broken Authentication, A5:2017-Broken Access Control",
        "2013": "A2:2013-Broken Authentication and Session Management, A8:2013-Cross-Site Request Forgery (CSRF)",
        "2010": "A3:2010-Broken Authentication and Session Management",
        "2007": "A7:2007-Broken Authentication and Session Management",
        "2004": "A3:2004-Broken Authentication and Session Management",
        "2003": "A3:2003-Broken Account and Session Management",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = (
        "Only evaluates cookies issued on the initial landing endpoint. "
        "Post-login session cookies require authenticated scanning profiles."
    )
    potential_false_positives = (
        "Non-sensitive client-side preference cookies (e.g. theme preference) may not require HttpOnly."
    )
    remediation_guidance = (
        "Configure session management to add 'Secure; HttpOnly; SameSite=Lax' (or SameSite=Strict) "
        "to all session tokens and sensitive state cookies."
    )
    references = [
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
        "https://owasp.org/www-community/HttpOnly",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies-attributes",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await context.get_target_response(client)
            except Exception:
                return findings  # Connection failures already logged by headers rule

        raw_cookie_headers = response.headers.get_list("set-cookie")
        if not raw_cookie_headers:
            return findings

        for cookie_str in raw_cookie_headers:
            try:
                cookie: SimpleCookie = SimpleCookie()
                cookie.load(cookie_str)

                for name, _morsel in cookie.items():
                    raw_flags = cookie_str.lower()

                    # 1. Missing 'Secure' flag on HTTPS
                    if context.scheme == "https" and "secure" not in raw_flags:
                        findings.append(
                            CheckFinding(
                                rule_id=self.rule_id,
                                title=f"Cookie Lacks 'Secure' Flag: '{name}'",
                                technical_issue_type="COOKIE_MISSING_SECURE",
                                severity="MEDIUM",
                                confidence="CERTAIN",
                                evidence={"cookie_name": name, "raw_directive": cookie_str, "scheme": context.scheme},
                                remediation=f"Add the 'Secure' attribute to cookie '{name}' so browsers only transmit it over encrypted HTTPS.",
                                references=self.references,
                            )
                        )

                    # 2. Missing 'HttpOnly' flag
                    if "httponly" not in raw_flags:
                        findings.append(
                            CheckFinding(
                                rule_id=self.rule_id,
                                title=f"Cookie Lacks 'HttpOnly' Flag: '{name}'",
                                technical_issue_type="COOKIE_MISSING_HTTPONLY",
                                severity="LOW",
                                confidence="CERTAIN",
                                evidence={"cookie_name": name, "raw_directive": cookie_str},
                                remediation=f"Add the 'HttpOnly' attribute to cookie '{name}' to protect it from JavaScript access via document.cookie.",
                                references=self.references,
                            )
                        )

                    # 3. Missing or weak 'SameSite' attribute
                    if "samesite" not in raw_flags:
                        findings.append(
                            CheckFinding(
                                rule_id=self.rule_id,
                                title=f"Cookie Lacks 'SameSite' Attribute: '{name}'",
                                technical_issue_type="COOKIE_MISSING_SAMESITE",
                                severity="LOW",
                                confidence="CERTAIN",
                                evidence={"cookie_name": name, "raw_directive": cookie_str},
                                remediation=f"Set 'SameSite=Lax' or 'SameSite=Strict' on cookie '{name}' to mitigate Cross-Site Request Forgery (CSRF).",
                                references=self.references,
                            )
                        )
                    elif "samesite=none" in raw_flags and "secure" not in raw_flags:
                        findings.append(
                            CheckFinding(
                                rule_id=self.rule_id,
                                title=f"Cookie Specifies 'SameSite=None' Without 'Secure': '{name}'",
                                technical_issue_type="COOKIE_SAMESITE_NONE_INSECURE",
                                severity="MEDIUM",
                                confidence="CERTAIN",
                                evidence={"cookie_name": name, "raw_directive": cookie_str},
                                remediation="When using 'SameSite=None', the 'Secure' attribute is mandatory.",
                                references=self.references,
                            )
                        )
            except Exception:
                continue

        return findings
