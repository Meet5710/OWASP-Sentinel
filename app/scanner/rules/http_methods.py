"""OWASP Sentinel - HTTP Methods & Verb Security Detection Rule

Evaluates supported HTTP verbs and detects dangerous methods (TRACE, TRACK, arbitrary PUT/DELETE).
"""

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class HttpMethodSecurityCheck(BaseDetectionRule):
    """Audits allowed HTTP methods to identify dangerous or unnecessary verbs."""

    rule_id = "RULE-SEC-007"
    name = "HTTP Methods & Verb Configuration Audit"
    description = (
        "Queries endpoint options and checks for dangerous verbs like TRACE (Cross-Site Tracing) or open PUT/DELETE."
    )
    why_it_matters = (
        "The HTTP TRACE method reflects request headers back to the client, allowing Cross-Site Scripting (XSS) "
        "attackers to bypass HttpOnly flags and steal cookies (Cross-Site Tracing / XST). "
        "Unauthenticated PUT and DELETE methods allow arbitrary file modification."
    )
    evidence_description = "Records allowed HTTP methods from OPTIONS responses and direct TRACE probes."
    owasp_category_mappings = {
        "2025": "A01:2025-Broken Access Control, A02:2025-Security Misconfiguration",
        "2021": "A01:2021-Broken Access Control, A05:2021-Security Misconfiguration",
        "2017": "A5:2017-Broken Access Control, A6:2017-Security Misconfiguration",
        "2013": "A5:2013-Security Misconfiguration, A7:2013-Missing Function Level Access Control",
        "2010": "A6:2010-Security Misconfiguration, A8:2010-Failure to Restrict URL Access",
        "2007": "A10:2007-Failure to Restrict URL Access",
        "2004": "A2:2004-Broken Access Control, A10:2004-Insecure Configuration Management",
        "2003": "A2:2003-Broken Access Control, A10:2003-Insecure Configuration Management",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = "Some proxies strip the Allow header from OPTIONS responses."
    potential_false_positives = (
        "APIs that support RESTful PUT/DELETE on resource subpaths with mandatory authentication."
    )
    remediation_guidance = (
        "Disable HTTP TRACE and TRACK in web server configuration (e.g. 'TraceEnable off' in Apache). "
        "Restrict HTTP methods on public routes to GET, POST, and HEAD."
    )
    references = [
        "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        async with httpx.AsyncClient(verify=False) as client:
            # 1. Query OPTIONS for advertised methods
            try:
                opt_resp = await client.options(
                    context.canonical_url,
                    timeout=context.timeout_seconds,
                    headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                )
                allow_header = opt_resp.headers.get("allow", "")
                methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

                if "TRACE" in methods or "TRACK" in methods:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="Dangerous HTTP Method Enabled: TRACE/TRACK",
                            technical_issue_type="HTTP_TRACE_METHOD_ENABLED",
                            severity="MEDIUM",
                            confidence="CERTAIN",
                            evidence={"allow_header": allow_header, "methods": methods},
                            remediation="Disable TRACE and TRACK on your web server to prevent Cross-Site Tracing (XST) attacks.",
                            references=self.references,
                        )
                    )
            except Exception:
                pass

            # 2. Direct probe for TRACE method
            try:
                trace_resp = await client.request(
                    "TRACE",
                    context.canonical_url,
                    timeout=context.timeout_seconds,
                    headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0", "X-Sentinel-Probe": "TraceTest"},
                )
                if trace_resp.status_code == 200 and "X-Sentinel-Probe" in trace_resp.text:
                    if not any(f.technical_issue_type == "HTTP_TRACE_METHOD_ENABLED" for f in findings):
                        findings.append(
                            CheckFinding(
                                rule_id=self.rule_id,
                                title="Active HTTP TRACE Reflection Verified",
                                technical_issue_type="HTTP_TRACE_METHOD_ENABLED",
                                severity="MEDIUM",
                                confidence="CERTAIN",
                                evidence={"status_code": 200, "reflected_header": "X-Sentinel-Probe"},
                                remediation="Disable TRACE method in web server configuration (TraceEnable off).",
                                references=self.references,
                            )
                        )
            except Exception:
                pass

        return findings
