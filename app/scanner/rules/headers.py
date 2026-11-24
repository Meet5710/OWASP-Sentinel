"""OWASP Sentinel - HTTP Security Headers Detection Rule

Evaluates response headers against OWASP Secure Headers Project best practices.
"""

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class HttpSecurityHeadersCheck(BaseDetectionRule):
    """Audits HTTP security response headers (HSTS, CSP, XFO, nosniff, Referrer-Policy)."""

    rule_id = "RULE-SEC-001"
    name = "HTTP Security Headers Configuration Audit"
    description = "Inspects target response headers to ensure modern browser defense headers are configured."
    why_it_matters = (
        "Security headers instruct browsers how to handle content, enforce encrypted transport, "
        "prevent framing/clickjacking, stop MIME-type confusion, and mitigate Cross-Site Scripting (XSS)."
    )
    evidence_description = "Collects missing headers, weak directive values, and observed header names."
    owasp_category_mappings = {
        "2025": "A02:2025-Security Misconfiguration",
        "2021": "A05:2021-Security Misconfiguration",
        "2017": "A6:2017-Security Misconfiguration, A7:2017-Cross-Site Scripting (XSS)",
        "2013": "A5:2013-Security Misconfiguration, A3:2013-Cross-Site Scripting (XSS), A8:2013-Cross-Site Request Forgery (CSRF)",
        "2010": "A6:2010-Security Misconfiguration",
        "2004": "A10:2004-Insecure Configuration Management",
        "2003": "A10:2003-Insecure Configuration Management",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS port."
    known_limitations = (
        "Headers may vary across different sub-paths or authentication states. "
        "This check evaluates the root landing response."
    )
    potential_false_positives = (
        "If Content-Security-Policy defines frame-ancestors, X-Frame-Options is intentionally obsolete. "
        "The rule accounts for this standard."
    )
    remediation_guidance = (
        "Configure your reverse proxy (Nginx, Apache, Cloudflare) or application framework "
        "to return standard defensive headers: Strict-Transport-Security, Content-Security-Policy, "
        "X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and Referrer-Policy."
    )
    references = [
        "https://owasp.org/www-project-secure-headers/",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await context.get_target_response(client)
            except Exception as e:
                # Target offline or connection refused
                return [
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="HTTP Target Connection Failed",
                        technical_issue_type="CONNECTION_FAILURE",
                        severity="INFO",
                        confidence="CERTAIN",
                        evidence={"error": str(e), "target": context.canonical_url},
                        remediation="Verify target availability, firewall rules, and DNS configuration.",
                        references=self.references,
                    )
                ]

        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # 1. Strict-Transport-Security (HSTS)
        if context.scheme == "https":
            hsts = headers_lower.get("strict-transport-security")
            if not hsts:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Missing HTTP Strict Transport Security (HSTS) Header",
                        technical_issue_type="MISSING_HSTS_HEADER",
                        severity="MEDIUM",
                        confidence="CERTAIN",
                        evidence={"scheme": context.scheme, "header": "Strict-Transport-Security", "status": "missing"},
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                        ],
                    )
                )
            elif "max-age" in hsts:
                # Check for weak max-age (< 180 days = 15552000s)
                try:
                    parts = [p.strip() for p in hsts.split(";")]
                    for p in parts:
                        if p.startswith("max-age="):
                            seconds = int(p.split("=")[1])
                            if seconds < 15552000:
                                findings.append(
                                    CheckFinding(
                                        rule_id=self.rule_id,
                                        title="Short HSTS Max-Age Duration",
                                        technical_issue_type="WEAK_HSTS_MAX_AGE",
                                        severity="LOW",
                                        confidence="CERTAIN",
                                        evidence={
                                            "observed_value": hsts,
                                            "max_age_seconds": seconds,
                                            "recommended_min": 15552000,
                                        },
                                        remediation="Increase HSTS max-age to at least 31536000 seconds (1 year).",
                                        references=self.references,
                                    )
                                )
                except Exception:
                    pass

        # 2. Content-Security-Policy (CSP)
        csp = headers_lower.get("content-security-policy")
        if not csp:
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="Missing Content Security Policy (CSP) Header",
                    technical_issue_type="MISSING_CSP_HEADER",
                    severity="MEDIUM",
                    confidence="CERTAIN",
                    evidence={"header": "Content-Security-Policy", "status": "missing"},
                    remediation="Define a strong Content-Security-Policy restricting allowed origins for scripts, styles, and objects.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                )
            )
        else:
            if "'unsafe-inline'" in csp and "nonce-" not in csp and "hash-" not in csp:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Insecure Content Security Policy: 'unsafe-inline' Detected",
                        technical_issue_type="WEAK_CSP_DIRECTIVE",
                        severity="LOW",
                        confidence="CERTAIN",
                        evidence={
                            "observed_csp": csp,
                            "flaw": "'unsafe-inline' permits inline script execution without nonce",
                        },
                        remediation="Remove 'unsafe-inline' and implement cryptographic nonces or SHA hashes for inline scripts.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                        ],
                    )
                )

        # 3. X-Content-Type-Options
        xcto = headers_lower.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="Missing or Invalid X-Content-Type-Options Header",
                    technical_issue_type="MISSING_X_CONTENT_TYPE_OPTIONS",
                    severity="LOW",
                    confidence="CERTAIN",
                    evidence={"header": "X-Content-Type-Options", "observed": xcto, "expected": "nosniff"},
                    remediation="Set 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing the response away from the declared Content-Type.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                )
            )

        # 4. Anti-Clickjacking: X-Frame-Options (unless CSP frame-ancestors is present)
        has_frame_ancestors = csp is not None and "frame-ancestors" in csp
        xfo = headers_lower.get("x-frame-options")
        if not xfo and not has_frame_ancestors:
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    technical_issue_type="MISSING_ANTI_CLICKJACKING_HEADER",
                    severity="MEDIUM",
                    confidence="CERTAIN",
                    evidence={"header": "X-Frame-Options", "csp_frame_ancestors": False, "status": "missing"},
                    remediation="Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN') and 'frame-ancestors 'none'' in CSP to prevent clickjacking.",
                    references=["https://owasp.org/www-community/attacks/Clickjacking"],
                )
            )

        # 5. Referrer-Policy
        referrer = headers_lower.get("referrer-policy")
        if not referrer:
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="Missing Referrer-Policy Header",
                    technical_issue_type="MISSING_REFERRER_POLICY",
                    severity="INFO",
                    confidence="CERTAIN",
                    evidence={"header": "Referrer-Policy", "status": "missing"},
                    remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                )
            )

        return findings
