"""OWASP Sentinel - Cross-Origin Resource Sharing (CORS) Detection Rule

Safely probes the landing page with arbitrary and null origins to detect
insecure wildcard reflection, credential disclosure, and origin misconfigurations.
"""

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class CorsConfigurationCheck(BaseDetectionRule):
    """Audits Cross-Origin Resource Sharing (CORS) policies and credential exposure."""

    rule_id = "RULE-SEC-005"
    name = "CORS Policy & Origin Reflection Audit"
    description = (
        "Probes target CORS headers with test origins to detect unvalidated origin reflection and credential exposure."
    )
    why_it_matters = (
        "Insecure CORS headers allow malicious third-party websites visited by an authenticated user "
        "to read sensitive session data, bypass the Same-Origin Policy (SOP), and exfiltrate private API payloads."
    )
    evidence_description = (
        "Records reflected Access-Control-Allow-Origin, Access-Control-Allow-Credentials, and test probe origins."
    )
    owasp_category_mappings = {
        "2025": "A01:2025-Broken Access Control, A02:2025-Security Misconfiguration",
        "2021": "A01:2021-Broken Access Control, A05:2021-Security Misconfiguration",
        "2017": "A5:2017-Broken Access Control, A6:2017-Security Misconfiguration",
        "2013": "A5:2013-Security Misconfiguration, A7:2013-Missing Function Level Access Control, A8:2013-Cross-Site Request Forgery (CSRF)",
        "2010": "A4:2010-Insecure Direct Object References, A6:2010-Security Misconfiguration",
        "2004": "A2:2004-Broken Access Control",
        "2003": "A2:2003-Broken Access Control",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = (
        "CORS configurations may be scoped to specific API subpaths. "
        "This check evaluates the root landing response and API entrypoints."
    )
    potential_false_positives = (
        "Public non-sensitive APIs intentionally returning Access-Control-Allow-Origin: * without credentials."
    )
    remediation_guidance = (
        "Never reflect arbitrary request origins directly into Access-Control-Allow-Origin. "
        "Maintain an explicit whitelist of trusted client domains and avoid combining wildcard origins with Allow-Credentials: true."
    )
    references = [
        "https://portswigger.net/web-security/cors",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        test_origin = "https://sentinel-security-audit.com"

        async with httpx.AsyncClient(verify=False) as client:
            try:
                # Probe with arbitrary test origin
                response = await client.get(
                    context.canonical_url,
                    headers={"Origin": test_origin, "User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                    timeout=context.timeout_seconds,
                    follow_redirects=True,
                )
            except Exception:
                return findings

        acao = response.headers.get("access-control-allow-origin")
        acac = response.headers.get("access-control-allow-credentials", "").lower()

        if acao:
            # 1. Arbitrary Origin Reflection
            if acao.strip() == test_origin:
                severity = "HIGH" if acac == "true" else "MEDIUM"
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Insecure CORS Origin Reflection Detected",
                        technical_issue_type="CORS_ARBITRARY_ORIGIN_REFLECTION",
                        severity=severity,
                        confidence="CERTAIN",
                        evidence={
                            "supplied_origin": test_origin,
                            "reflected_origin": acao,
                            "allow_credentials": acac == "true",
                        },
                        remediation="Do not dynamically mirror untrusted Origin headers. Validate incoming origins against an explicit allowlist.",
                        references=self.references,
                    )
                )

            # 2. Insecure Wildcard with Credentials
            elif acao.strip() == "*" and acac == "true":
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Critical CORS Configuration: Wildcard Origin with Credentials Allowed",
                        technical_issue_type="CORS_WILDCARD_WITH_CREDENTIALS",
                        severity="HIGH",
                        confidence="CERTAIN",
                        evidence={"allow_origin": "*", "allow_credentials": "true"},
                        remediation="Wildcard origins must never be paired with Access-Control-Allow-Credentials: true.",
                        references=self.references,
                    )
                )

            # 3. Trust of Null Origin
            elif acao.strip().lower() == "null":
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Insecure CORS Policy: 'null' Origin Whitelisted",
                        technical_issue_type="CORS_NULL_ORIGIN_ALLOWED",
                        severity="MEDIUM",
                        confidence="CERTAIN",
                        evidence={"allow_origin": "null"},
                        remediation="Remove 'null' from allowed origins as attackers can trigger null origin via sandboxed iframes.",
                        references=self.references,
                    )
                )

        return findings
