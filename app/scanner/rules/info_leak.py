"""OWASP Sentinel - Server Information Leakage Check

Identifies verbose Server banners, X-Powered-By headers, and framework fingerprints.
"""

import re

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext

VERSION_DIGIT_REGEX = re.compile(r"\d+(\.\d+)+")


class ServerInformationLeakCheck(BaseDetectionRule):
    """Detects software version disclosure in Server, X-Powered-By, and framework headers."""

    rule_id = "RULE-SEC-004"
    name = "Server & Framework Information Disclosure Audit"
    description = "Checks for detailed server software versions and backend technology headers."
    why_it_matters = (
        "Verbose banners leak exact patch levels and software products, allowing attackers "
        "to look up known CVEs and tailor automated exploit payloads."
    )
    evidence_description = "Records detected header names and exact version banner strings."
    owasp_category_mappings = {
        "2025": "A02:2025-Security Misconfiguration, A10:2025-Mishandling of Exceptional Conditions",
        "2021": "A05:2021-Security Misconfiguration",
        "2017": "A6:2017-Security Misconfiguration, A9:2017-Using Components with Known Vulnerabilities",
        "2013": "A5:2013-Security Misconfiguration, A9:2013-Using Components with Known Vulnerabilities",
        "2010": "A6:2010-Security Misconfiguration",
        "2007": "A6:2007-Information Leakage and Improper Error Handling",
        "2004": "A7:2004-Improper Error Handling",
        "2003": "A7:2003-Improper Error Handling",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = "Custom reverse proxies may strip headers on root but expose them on error pages."
    potential_false_positives = "Generic banners (e.g. 'nginx' without version) are rated as INFO or ignored."
    remediation_guidance = (
        "Disable banner emissions: in Apache set 'ServerTokens Prod' and 'ServerSignature Off'; "
        "in Nginx set 'server_tokens off;'; in Express set 'app.disable('x-powered-by')'."
    )
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await context.get_target_response(client)
            except Exception:
                return findings

        headers = response.headers

        # 1. Server Header with version disclosure
        server_val = headers.get("server")
        if server_val:
            # Check if it leaks version numbers
            if VERSION_DIGIT_REGEX.search(server_val):
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title=f"Detailed Web Server Version Disclosed: '{server_val}'",
                        technical_issue_type="SERVER_BANNER_DISCLOSURE",
                        severity="LOW",
                        confidence="CERTAIN",
                        evidence={"header": "Server", "banner": server_val},
                        remediation="Configure the web server to suppress granular version numbers (e.g. 'ServerTokens Prod' or 'server_tokens off').",
                        references=self.references,
                    )
                )

        # 2. X-Powered-By Header
        powered_by = headers.get("x-powered-by")
        if powered_by:
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title=f"Backend Technology Stack Disclosed: 'X-Powered-By: {powered_by}'",
                    technical_issue_type="X_POWERED_BY_DISCLOSURE",
                    severity="LOW",
                    confidence="CERTAIN",
                    evidence={"header": "X-Powered-By", "technology": powered_by},
                    remediation="Disable or remove the 'X-Powered-By' header in framework configuration.",
                    references=self.references,
                )
            )

        # 3. ASP.NET Specific Headers
        for asp_header in ("x-aspnet-version", "x-aspnetmvc-version"):
            val = headers.get(asp_header)
            if val:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title=f"ASP.NET Version Disclosed: '{asp_header}: {val}'",
                        technical_issue_type="FRAMEWORK_VERSION_DISCLOSURE",
                        severity="LOW",
                        confidence="CERTAIN",
                        evidence={"header": asp_header, "version": val},
                        remediation="Disable version emission in web.config via <httpRuntime enableVersionHeader='false' />.",
                        references=self.references,
                    )
                )

        return findings
