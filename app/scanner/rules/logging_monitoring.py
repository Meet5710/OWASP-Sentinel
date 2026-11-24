"""OWASP Sentinel - Security Logging & Monitoring Failures Detection Rule

Audits HTTP response headers for transaction correlation IDs (X-Request-ID, traceparent)
and probes for publicly accessible log files (access.log, error.log).
"""

from urllib.parse import urljoin

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class SecurityLoggingMonitoringCheck(BaseDetectionRule):
    """Detects missing request telemetry tracking headers and public exposure of server log files."""

    rule_id = "RULE-SEC-013"
    name = "Security Logging & Telemetry Audit"
    description = (
        "Audits HTTP headers for transaction correlation IDs (X-Request-ID, X-Correlation-ID, traceparent) "
        "and checks for exposed log files that could reveal system internals to attackers."
    )
    why_it_matters = (
        "Security Logging and Monitoring Failures (A09:2021) prevent incident response teams from detecting "
        "breaches in real time. Without transaction tracing IDs, correlation across distributed microservices "
        "fails during forensics. Additionally, publicly exposed log files leak sensitive user data and credentials."
    )
    evidence_description = "Records observed tracing headers and status of sensitive log endpoint probes."
    owasp_category_mappings = {
        "2025": "A09:2025-Security Logging and Alerting Failures",
        "2021": "A09:2021-Security Logging and Monitoring Failures",
        "2017": "A10:2017-Insufficient Logging & Monitoring",
        "2013": "A5:2013-Security Misconfiguration",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Internal SIEM ingestion and log retention policies cannot be fully audited from external black-box vantage points."
    )
    potential_false_positives = (
        "API gateways that log internally but strip trace headers before returning responses to public clients."
    )
    remediation_guidance = (
        "Enforce standardized correlation IDs (e.g. X-Request-ID or W3C TraceContext traceparent) on all inbound "
        "and outbound requests, stream application logs to a centralized SIEM, and strictly restrict access to log files."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
        "https://www.w3.org/TR/trace-context/",
    ]

    TRACING_HEADERS = [
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
        "traceparent",
        "x-amzn-trace-id",
    ]

    LOG_PATHS = [
        "/app.log",
        "/error.log",
        "/access.log",
        "/debug.log",
        "/logs/",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        base_url = context.canonical_url

        async with httpx.AsyncClient(verify=False) as client:
            try:
                root_resp = await context.get_target_response(client)
            except Exception:
                return findings

            # 1. Audit for Request Correlation / Tracing Header
            headers_lower = {k.lower(): v for k, v in root_resp.headers.items()}
            has_trace = any(h in headers_lower for h in self.TRACING_HEADERS)

            if not has_trace:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Missing Distributed Request Correlation ID Header",
                        technical_issue_type="MISSING_CORRELATION_ID",
                        severity="LOW",
                        confidence="FIRM",
                        evidence={
                            "url": base_url,
                            "checked_headers": self.TRACING_HEADERS,
                            "observed_headers": list(headers_lower.keys())[:8],
                        },
                        remediation=(
                            "Configure your API gateway or web server to assign and propagate a unique transaction ID "
                            "(e.g. X-Request-ID or traceparent) for every request to facilitate security auditing."
                        ),
                        references=self.references,
                    )
                )

            # 2. Check for Publicly Exposed Application Logs
            if not getattr(context, "_target_unreachable", False):
                for log_path in self.LOG_PATHS:
                    test_url = urljoin(base_url, log_path)
                    try:
                        resp = await client.get(
                            test_url,
                            timeout=context.timeout_seconds,
                            headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                            follow_redirects=False,
                        )
                        if resp.status_code == 200 and len(resp.content) > 30:
                            sample = resp.text[:500]
                            # Verify log file signatures (timestamps, log levels)
                            if any(level in sample for level in ("INFO", "ERROR", "WARN", "DEBUG", "GET /", "POST /")):
                                findings.append(
                                    CheckFinding(
                                        rule_id=self.rule_id,
                                        title=f"Publicly Accessible Application Log File ({log_path})",
                                        technical_issue_type="EXPOSED_LOG_FILE",
                                        severity="HIGH",
                                        confidence="CERTAIN",
                                        evidence={
                                            "path": log_path,
                                            "url": test_url,
                                            "status_code": resp.status_code,
                                            "sample": sample[:200],
                                        },
                                        remediation=(
                                            f"Immediately restrict public access to '{log_path}' and store application "
                                            "log files outside the web server document root."
                                        ),
                                        references=self.references,
                                    )
                                )
                                break
                    except Exception:
                        continue

        return findings

