"""OWASP Sentinel - Denial of Service (DoS) Resilience & Rate Limiting Rule

Audits target for rate-limiting defenses, HTTP request throttling headers,
and application availability controls to mitigate denial-of-service risks.
"""

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class DosResilienceCheck(BaseDetectionRule):
    """Audits target for Denial of Service resilience and request rate throttling."""

    rule_id = "RULE-SEC-017"
    name = "Denial of Service (DoS) Resilience & Rate Limits Audit"
    description = (
        "Audits target web services and API endpoints for rate-limiting headers (IETF RFC 6585, RateLimit-Limit), "
        "anti-automation controls, and edge availability protections."
    )
    why_it_matters = (
        "Application Denial of Service (OWASP Top 10 2004 A9, CWE-400 / CWE-799) allows malicious actors to exhaust "
        "computational resources, database connection pools, or worker threads. Without rate limiting and connection "
        "throttling, web endpoints can be easily degraded or rendered unavailable by high-volume automated requests."
    )
    evidence_description = (
        "Inspects HTTP response headers for RateLimit-Limit, X-RateLimit-Limit, Retry-After, and CDN/WAF availability defenses."
    )
    owasp_category_mappings = {
        "2025": "A10:2025-Mishandling of Exceptional Conditions",
        "2021": "A05:2021-Security Misconfiguration",
        "2017": "A6:2017-Security Misconfiguration",
        "2013": "A5:2013-Security Misconfiguration",
        "2004": "A9:2004-Application Denial of Service",
        "2003": "A9:2003-Remote Administration Flaws",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = (
        "Rate limiting might be enforced selectively on authentication routes (e.g. /login) rather than general "
        "root endpoints. Internal private proxies may strip rate-limit headers before delivering to external clients."
    )
    potential_false_positives = (
        "Static marketing sites or read-only CDNs often deliberately omit rate limits on public informational pages."
    )
    remediation_guidance = (
        "1. Implement rate limiting on all public API and web endpoints using token bucket or sliding window algorithms.\n"
        "2. Return standard HTTP 429 (Too Many Requests) responses with 'Retry-After' and 'RateLimit-Limit' headers.\n"
        "3. Deploy reverse proxy or Cloud WAF (e.g. Cloudflare, AWS WAF) layer-7 DDoS shielding."
    )
    references = [
        "https://owasp.org/www-community/attacks/Denial_of_Service",
        "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
        "https://datatracker.ietff.org/doc/html/rfc6585",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await context.get_target_response(client)
            except Exception:
                return findings

        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # 1. Look for standard or common rate limit headers
        has_rate_limit = any(
            h in headers_lower
            for h in [
                "ratelimit-limit",
                "ratelimit-remaining",
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-rate-limit-limit",
                "retry-after",
            ]
        )

        # 2. Check for CDN / WAF edge protection indicators
        edge_protection = None
        if "cf-ray" in headers_lower:
            edge_protection = "Cloudflare Edge Shield"
        elif "x-amz-cf-id" in headers_lower:
            edge_protection = "AWS CloudFront WAF"
        elif "x-akamai-transformed" in headers_lower:
            edge_protection = "Akamai Kona Site Defender"
        elif "x-fastly-request-id" in headers_lower:
            edge_protection = "Fastly Edge Cloud"

        # If no rate-limiting headers and no edge protection found, flag as advisory
        if not has_rate_limit and not edge_protection:
            findings.append(
                CheckFinding(
                    rule_id=self.rule_id,
                    title="Missing HTTP Rate-Limiting & Throttling Headers",
                    technical_issue_type="MISSING_RATE_LIMITING_CONTROLS",
                    severity="LOW",
                    confidence="FIRM",
                    evidence={
                        "checked_headers": [
                            "RateLimit-Limit",
                            "RateLimit-Remaining",
                            "X-RateLimit-Limit",
                            "Retry-After",
                        ],
                        "status_code": response.status_code,
                        "edge_protection_detected": "None detected",
                    },
                    remediation=(
                        "Configure API and web application rate limiting (e.g. 100 requests/minute per IP) "
                        "and emit standard 'RateLimit-Limit' and 'Retry-After' response headers to prevent request flooding."
                    ),
                    references=self.references,
                )
            )

        return findings

