"""OWASP Sentinel - Buffer Overflow & Request Line Limits Rule

Audits web server resilience against oversized URI query strings, large HTTP headers,
and evaluates buffer overrun protections and request boundary limit enforcement.
"""

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class BufferOverflowResilienceCheck(BaseDetectionRule):
    """Audits target for memory boundary protections and oversized URI/header limits."""

    rule_id = "RULE-SEC-016"
    name = "Buffer Overflow & URI Request Limits Audit"
    description = (
        "Audits web server and reverse proxy handling of oversized request URIs and large HTTP header "
        "fields to verify proper request line bounding, preventing memory exhaustion or buffer overruns."
    )
    why_it_matters = (
        "Historically one of the most critical vulnerabilities (OWASP Top 10 2003/2004 A5), buffer overflows "
        "allow attackers to overwrite memory structures, crash web services, or achieve remote code execution. "
        "While modern managed languages mitigate direct memory corruption, unhardened web servers and legacy "
        "native proxy extensions that fail to enforce request line boundaries risk unhandled buffer faults or DoS."
    )
    evidence_description = (
        "Records HTTP status codes and responses when probing boundary limits with controlled 4KB URI and header payloads."
    )
    owasp_category_mappings = {
        "2025": "A02:2025-Security Misconfiguration",
        "2021": "A05:2021-Security Misconfiguration",
        "2017": "A6:2017-Security Misconfiguration",
        "2013": "A5:2013-Security Misconfiguration",
        "2004": "A5:2004-Buffer Overflow",
        "2003": "A5:2003-Buffer Overflow",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = (
        "Cloud-based WAFs (Cloudflare, AWS CloudFront) typically filter oversized request lines at edge proxies "
        "before reaching origin origin web servers."
    )
    potential_false_positives = (
        "Web servers intentionally tuned for extremely large enterprise SSO tokens or complex graph queries "
        "may permit large headers by architectural design."
    )
    remediation_guidance = (
        "1. Configure explicit web server request line limits (e.g. 'LimitRequestLine 4094' in Apache, "
        "'large_client_header_buffers 4 8k' in Nginx).\n"
        "2. Ensure web server and upstream proxies return HTTP 414 (URI Too Long) or 431 (Request Header Fields Too Large) "
        "instead of 500 Internal Server Errors.\n"
        "3. Ensure all underlying web service binaries and C-extensions are compiled with modern stack canaries and ASLR."
    )
    references = [
        "https://cwe.mitre.org/data/definitions/120.html",
        "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow",
        "https://cheatsheetseries.owasp.org/cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.html",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        base_url = (getattr(context, "canonical_url", None) or getattr(context, "target_url", "")).rstrip("/")

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            # 1. Test controlled large URI query parameter (4096 bytes)
            probe_param = "ovf_test=" + ("A" * 4096)
            delimiter = "&" if "?" in base_url else "?"
            test_url = f"{base_url}{delimiter}{probe_param}"

            try:
                uri_resp = await client.get(test_url)
                if uri_resp.status_code == 500:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="Server Returned 500 Internal Error on Oversized Request Line",
                            technical_issue_type="UNHANDLED_BUFFER_EXCEPTION",
                            severity="MEDIUM",
                            confidence="FIRM",
                            evidence={
                                "tested_url_length": len(test_url),
                                "status_code": uri_resp.status_code,
                                "response_snippet": uri_resp.text[:300],
                            },
                            remediation=(
                                "Configure web server request line limits to reject oversized URIs gracefully "
                                "with HTTP 414 (URI Too Long) rather than unhandled 500 internal errors."
                            ),
                            references=self.references,
                        )
                    )
            except (httpx.RemoteProtocolError, httpx.ReadError):
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Connection Reset During Oversized URI Buffer Probe",
                        technical_issue_type="ABRUPT_BUFFER_CONNECTION_RESET",
                        severity="LOW",
                        confidence="TENTATIVE",
                        evidence={
                            "tested_url_length": len(test_url),
                            "observation": "Socket was closed abruptly without standard HTTP error code",
                        },
                        remediation="Configure web server reverse proxy to return proper HTTP 414/400 status codes on oversized inputs.",
                        references=self.references,
                    )
                )
            except Exception:
                pass

            # 2. Test oversized HTTP Header (4096 bytes)
            large_header = {"X-Buffer-Probe": "B" * 4096}
            try:
                hdr_resp = await client.get(base_url, headers=large_header)
                if hdr_resp.status_code == 500:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="Server Returned 500 Internal Error on Oversized HTTP Header",
                            technical_issue_type="UNHANDLED_HEADER_BUFFER_EXCEPTION",
                            severity="MEDIUM",
                            confidence="FIRM",
                            evidence={
                                "header_size_bytes": 4096,
                                "status_code": hdr_resp.status_code,
                                "response_snippet": hdr_resp.text[:300],
                            },
                            remediation="Ensure reverse proxy enforces HTTP 431 Request Header Fields Too Large for oversized headers.",
                            references=self.references,
                        )
                    )
            except Exception:
                pass

        return findings
