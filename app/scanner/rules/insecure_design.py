"""OWASP Sentinel - Insecure Design & Rate Limiting Detection Rule

Audits endpoints for lack of anti-automation defenses, missing rate limiting controls,
and public exposure of architectural debug/management interfaces.
"""

from urllib.parse import urljoin

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class InsecureDesignCheck(BaseDetectionRule):
    """Detects missing anti-automation rate limiting and exposure of administrative debug endpoints."""

    rule_id = "RULE-SEC-009"
    name = "Insecure Design & Rate Limiting Audit"
    description = (
        "Evaluates the application architecture for anti-automation headers (RateLimit, Retry-After) "
        "and checks for exposed framework actuators and diagnostic management interfaces."
    )
    why_it_matters = (
        "Insecure Design (A04:2021) focuses on risks related to architectural design flaws. "
        "Missing rate limiting allows automated brute force and credential stuffing attacks, while "
        "exposed actuator/profiler endpoints disclose internal state and environment configurations."
    )
    evidence_description = "Records response headers, missing rate-limiting directives, and status of debug endpoints."
    owasp_category_mappings = {
        "2025": "A06:2025-Insecure Design",
        "2021": "A04:2021-Insecure Design",
        "2017": "A4:2017-XML External Entities (XXE)",
        "2013": "A7:2013-Missing Function Level Access Control",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Rate limiting may be enforced selectively on specific API endpoints or login routes "
        "rather than globally on the landing page."
    )
    potential_false_positives = (
        "Reverse proxies or CDNs that enforce rate limiting silently by IP without exposing HTTP headers."
    )
    remediation_guidance = (
        "Implement defense-in-depth architectural controls including global rate limiting with standard "
        "RateLimit headers, disable Spring Boot Actuators or debug profilers in production, and enforce "
        "CAPTCHA or Proof-of-Work mechanisms on high-value business logic workflows."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
        "https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers",
    ]

    DEBUG_ENDPOINTS = [
        "/actuator",
        "/actuator/env",
        "/debug/vars",
        "/server-status",
        "/_profiler/",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        base_url = context.canonical_url

        async with httpx.AsyncClient(verify=False) as client:
            try:
                root_resp = await context.get_target_response(client)
            except Exception:
                return findings

            # 1. Check for Rate Limiting Headers
            headers_lower = {k.lower(): v for k, v in root_resp.headers.items()}
            rate_limit_headers = [
                "x-ratelimit-limit",
                "ratelimit-limit",
                "x-rate-limit-limit",
                "retry-after",
            ]
            has_rate_limit = any(h in headers_lower for h in rate_limit_headers)

            if not has_rate_limit:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Missing Anti-Automation Rate Limiting Headers",
                        technical_issue_type="MISSING_RATE_LIMITING",
                        severity="LOW",
                        confidence="TENTATIVE",
                        evidence={
                            "url": base_url,
                            "checked_headers": rate_limit_headers,
                            "observed_headers": list(headers_lower.keys())[:10],
                        },
                        remediation=(
                            "Configure an API Gateway or web application firewall with rate limiting rules, "
                            "and advertise RateLimit-Limit and RateLimit-Remaining headers to clients."
                        ),
                        references=self.references,
                    )
                )

            # 2. Check for Exposed Management & Debug Endpoints
            if not getattr(context, "_target_unreachable", False):
                for endpoint in self.DEBUG_ENDPOINTS:
                    test_url = urljoin(base_url, endpoint)
                    try:
                        resp = await client.get(
                            test_url,
                            timeout=context.timeout_seconds,
                            headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                            follow_redirects=False,
                        )
                        # If endpoint responds with 200 OK and JSON/HTML content
                        if resp.status_code == 200 and len(resp.content) > 30:
                            ct = resp.headers.get("content-type", "").lower()
                            # Avoid generic SPA 200 catch-alls by checking for actuator or debug patterns
                            text_sample = resp.text[:1000]
                            if any(marker in text_sample for marker in ("_links", "jvm", "memstats", "Apache Server Status", "profiler")):
                                findings.append(
                                    CheckFinding(
                                        rule_id=self.rule_id,
                                        title=f"Exposed Framework Management Interface ({endpoint})",
                                        technical_issue_type="EXPOSED_DEBUG_INTERFACE",
                                        severity="HIGH",
                                        confidence="CERTAIN",
                                        evidence={
                                            "endpoint": endpoint,
                                            "url": test_url,
                                            "status_code": resp.status_code,
                                            "content_type": ct,
                                        },
                                        remediation=(
                                            f"Restrict access to '{endpoint}' to internal maintenance networks only, "
                                            "or disable diagnostic endpoints in production deployment profiles."
                                        ),
                                        references=self.references,
                                    )
                                )
                                break
                    except Exception:
                        continue

        return findings

