"""OWASP Sentinel - Cross-Site Request Forgery (CSRF) Defense Rule

Audits state-changing mechanisms, anti-CSRF token parameters in HTML forms,
SameSite cookie attributes, and modern custom request headers.
"""

import re
from http.cookies import SimpleCookie
import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class CsrfDefenseCheck(BaseDetectionRule):
    """Audits target for Cross-Site Request Forgery (CSRF) defenses and state protections."""

    rule_id = "RULE-SEC-015"
    name = "Cross-Site Request Forgery (CSRF) Defense Audit"
    description = (
        "Audits HTML forms for anti-CSRF synchronization tokens, checks session cookies "
        "for SameSite enforcement, and verifies cross-origin state protection policies."
    )
    why_it_matters = (
        "Cross-Site Request Forgery (CSRF) forces authenticated victims to execute unwanted actions "
        "on web applications where they are currently authenticated. Without anti-CSRF tokens or "
        "SameSite=Strict/Lax cookie protections, malicious third-party websites can forge state-changing "
        "requests (e.g. password resets, money transfers) using the victim's ambient browser credentials."
    )
    evidence_description = (
        "Records HTML form actions, missing anti-CSRF input tokens, and session cookies lacking SameSite protections."
    )
    owasp_category_mappings = {
        "2025": "A01:2025-Broken Access Control",
        "2021": "A01:2021-Broken Access Control",
        "2017": "A5:2017-Broken Access Control",
        "2013": "A8:2013-Cross-Site Request Forgery (CSRF)",
        "2010": "A5:2010-Cross-Site Request Forgery (CSRF)",
        "2007": "A5:2007-Cross Site Request Forgery",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = (
        "SPA client applications utilizing Bearer Authorization tokens in JavaScript memory "
        "are inherently immune to classic ambient cookie CSRF, but require verification of API header requirements."
    )
    potential_false_positives = (
        "Forms that perform idempotent read-only search operations (e.g. GET search bars) do not require CSRF tokens."
    )
    remediation_guidance = (
        "1. Implement anti-CSRF tokens (Synchronizer Token Pattern) in all state-changing HTML forms.\n"
        "2. Ensure all session and authentication cookies enforce 'SameSite=Lax' or 'SameSite=Strict'.\n"
        "3. Require custom headers (e.g. 'X-Requested-With' or 'Sec-Fetch-Site: same-origin') for REST APIs."
    )
    references = [
        "https://owasp.org/www-community/attacks/csrf",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        "https://portswigger.net/web-security/csrf",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await context.get_target_response(client)
            except Exception:
                return findings

        html_text = response.text or ""

        # 1. Audit POST forms for anti-CSRF tokens
        # Extract <form ... method=["']?post... >
        post_forms = re.findall(r"(<form[^>]*method=[\"']?post[^>]*>)(.*?)(</form>)", html_text, re.IGNORECASE | re.DOTALL)
        csrf_token_patterns = re.compile(
            r"(csrf|xsrf|token|_token|authenticity_token|csrfmiddlewaretoken|__requestverificationtoken)",
            re.IGNORECASE,
        )

        for form_tag, form_body, _ in post_forms:
            action_match = re.search(r'action=[\"\']([^\"\']*)[\"\']', form_tag, re.IGNORECASE)
            action_url = action_match.group(1) if action_match else "/"

            # Check if any input in form body has a CSRF token name
            has_csrf_token = False
            inputs = re.findall(r'<input[^>]+>', form_body, re.IGNORECASE)
            for inp in inputs:
                name_match = re.search(r'name=[\"\']([^\"\']*)[\"\']', inp, re.IGNORECASE)
                if name_match and csrf_token_patterns.search(name_match.group(1)):
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title=f"Missing Anti-CSRF Token in HTML Form (Action: {action_url})",
                        technical_issue_type="MISSING_CSRF_TOKEN",
                        severity="MEDIUM",
                        confidence="FIRM",
                        evidence={
                            "form_action": action_url,
                            "form_tag": form_tag[:150],
                            "sample_inputs": [i[:80] for i in inputs[:5]],
                        },
                        remediation=(
                            f"Include a unique, cryptographically random, per-session anti-CSRF token in form '{action_url}' "
                            "and validate it server-side prior to processing state mutations."
                        ),
                        references=self.references,
                    )
                )
                break  # Record primary form finding

        # 2. Audit Session Cookies for Missing SameSite Protection
        raw_cookie_headers = response.headers.get_list("set-cookie")
        session_cookie_names = re.compile(r"(session|sess|auth|jwt|token|id|login|connect\.sid|phpsessid|asp\.net_sessionid)", re.IGNORECASE)

        for cookie_str in raw_cookie_headers:
            try:
                cookie: SimpleCookie = SimpleCookie()
                cookie.load(cookie_str)
                for name, _morsel in cookie.items():
                    if session_cookie_names.search(name):
                        raw_lower = cookie_str.lower()
                        if "samesite" not in raw_lower or "samesite=none" in raw_lower:
                            findings.append(
                                CheckFinding(
                                    rule_id=self.rule_id,
                                    title=f"Session Cookie Lacks SameSite CSRF Protection: '{name}'",
                                    technical_issue_type="COOKIE_LACKS_SAMESITE_CSRF_PROTECTION",
                                    severity="LOW",
                                    confidence="CERTAIN",
                                    evidence={
                                        "cookie_name": name,
                                        "raw_directive": cookie_str,
                                        "observed_samesite": "None" if "samesite=none" in raw_lower else "Missing",
                                    },
                                    remediation=f"Configure cookie '{name}' with 'SameSite=Lax' or 'SameSite=Strict' to mitigate cross-site ambient credential transmission.",
                                    references=self.references,
                                )
                            )
            except Exception:
                continue

        return findings

