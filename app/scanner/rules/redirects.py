"""OWASP Sentinel - Unvalidated Redirects & Forwards Rule

Audits target for open redirection parameters, arbitrary destination forwards,
and verifies URL destination validation controls.
"""

import re
from urllib.parse import urlparse
import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class UnvalidatedRedirectsCheck(BaseDetectionRule):
    """Audits target for unvalidated URL redirection and open forward vulnerabilities."""

    rule_id = "RULE-SEC-018"
    name = "Unvalidated Redirects & Destination URL Audit"
    description = (
        "Audits web parameters, links, and redirection logic for open redirect vulnerabilities "
        "that allow attackers to trick users into navigating to untrusted external phishing sites."
    )
    why_it_matters = (
        "Unvalidated Redirects and Forwards (OWASP Top 10 2010/2013 A10, CWE-601) occur when an application "
        "accepts untrusted destination inputs without validating against an allowed domain whitelist. "
        "Attackers exploit these flaws in phishing campaigns to lend credibility to malicious links, "
        "bypassing URL reputation filters by using trusted corporate domains."
    )
    evidence_description = (
        "Records redirect query parameters, HTTP 3xx Location responses, and external target reflections."
    )
    owasp_category_mappings = {
        "2025": "A01:2025-Broken Access Control",
        "2021": "A01:2021-Broken Access Control",
        "2017": "A5:2017-Broken Access Control",
        "2013": "A10:2013-Unvalidated Redirects and Forwards",
        "2010": "A10:2010-Unvalidated Redirects and Forwards",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = (
        "Some single-page applications perform client-side JavaScript redirects (window.location) "
        "that are not visible in pure server-side HTTP 3xx Location headers."
    )
    potential_false_positives = (
        "Explicit external link portals that display intermediate user confirmation screens "
        "('You are now leaving this site') are safe by design."
    )
    remediation_guidance = (
        "1. Avoid accepting direct destination URLs in query parameters whenever possible.\n"
        "2. If redirection is necessary, validate destination URLs against a strict server-side whitelist.\n"
        "3. Enforce relative path redirection only (e.g. starting with a single '/' and not '//')."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/601.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "https://portswigger.net/web-security/open-redirect",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        base_url = (getattr(context, "canonical_url", None) or getattr(context, "target_url", "")).rstrip("/")

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8.0) as client:
            try:
                response = await context.get_target_response(client)
            except Exception:
                return findings

            html_text = response.text or ""

            # 1. Scan for open redirect query parameters in HTML links
            redirect_param_regex = re.compile(
                r"[?&](redirect|url|next|return|returnUrl|dest|destination|forward|goto|target)=([^&\"'>\s]+)",
                re.IGNORECASE,
            )
            detected_params = redirect_param_regex.findall(html_text)

            # 2. Test common redirect parameter names with a safe external probe
            probe_domain = "https://example.com"
            candidate_params = ["redirect", "url", "next", "return", "dest", "target"]

            # If specific params were found in HTML, prioritize those
            if detected_params:
                candidate_params = list(dict.fromkeys([p[0] for p in detected_params] + candidate_params))

            for param in candidate_params[:3]:  # Limit to top 3 to keep check fast and light
                delimiter = "&" if "?" in base_url else "?"
                test_url = f"{base_url}{delimiter}{param}={probe_domain}"
                try:
                    probe_resp = await client.get(test_url)
                    if probe_resp.status_code in [301, 302, 303, 307, 308]:
                        location = probe_resp.headers.get("location", "")
                        loc_parsed = urlparse(location)
                        # Check if location redirects directly to the probed external domain
                        if loc_parsed.netloc.lower() == "example.com" or "example.com" in location:
                            findings.append(
                                CheckFinding(
                                    rule_id=self.rule_id,
                                    title=f"Unvalidated Open Redirect via Parameter '{param}'",
                                    technical_issue_type="UNVALIDATED_OPEN_REDIRECT",
                                    severity="HIGH",
                                    confidence="CERTAIN",
                                    evidence={
                                        "parameter": param,
                                        "probed_url": test_url,
                                        "status_code": probe_resp.status_code,
                                        "location_header": location,
                                    },
                                    remediation=(
                                        f"Sanitize and restrict parameter '{param}' to relative site paths only, "
                                        "or validate against a strict internal domain whitelist before issuing 3xx redirects."
                                    ),
                                    references=self.references,
                                )
                            )
                            break
                except Exception:
                    continue

        return findings
