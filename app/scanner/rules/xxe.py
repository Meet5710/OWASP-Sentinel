"""OWASP Sentinel - XML External Entities (XXE) & Insecure Parser Audit Rule

Audits target endpoints for XML input acceptance, external entity expansion,
and vulnerable XML parser configurations.
"""

import re
import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class XxeInjectionCheck(BaseDetectionRule):
    """Audits target for XML External Entity (XXE) vulnerabilities and parser configurations."""

    rule_id = "RULE-SEC-019"
    name = "XML External Entities (XXE) & Insecure Parser Audit"
    description = (
        "Audits web applications and API endpoints for insecure XML parsing, XML entity expansion (Billion Laughs / XXE), "
        "and exposed XML-RPC or SOAP endpoints."
    )
    why_it_matters = (
        "XML External Entities (OWASP Top 10 2017 A4, CWE-611) occur when weakly configured XML parsers process "
        "user input containing references to external entities or DTD definitions. Attackers can exploit XXE to "
        "read local server files (/etc/passwd, win.ini), perform internal port scanning, trigger denial of service, "
        "or execute remote server-side request forgery."
    )
    evidence_description = (
        "Records XML parser responses, entity reflection, exposed XML-RPC interfaces, and parser error stack traces."
    )
    owasp_category_mappings = {
        "2025": "A02:2025-Security Misconfiguration",
        "2021": "A05:2021-Security Misconfiguration",
        "2017": "A4:2017-XML External Entities (XXE)",
        "2013": "A5:2013-Security Misconfiguration",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoint."
    known_limitations = (
        "Modern JSON-only RESTful APIs that completely reject Content-Type 'application/xml' are immune to XXE "
        "at the perimeter."
    )
    potential_false_positives = (
        "Endpoints that log raw input strings into debug outputs without actually parsing or expanding entities."
    )
    remediation_guidance = (
        "1. Disable XML external entity resolution (DOCTYPE / DTD) completely in all application XML parsers.\n"
        "2. For Java: set XMLConstants.FEATURE_SECURE_PROCESSING to true and disallow DOCTYPE declarations.\n"
        "3. Prefer modern, safe data serialization formats like JSON or Protocol Buffers over complex XML schemas."
    )
    references = [
        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        "https://portswigger.net/web-security/xxe",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        base_url = (getattr(context, "canonical_url", None) or getattr(context, "target_url", "")).rstrip("/")

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            # 1. Check for exposed XML-RPC or SOAP endpoints
            xml_endpoints = ["/xmlrpc.php", "/soap", "/services"]
            for path in xml_endpoints:
                test_url = f"{base_url}{path}"
                try:
                    r = await client.get(test_url)
                    if r.status_code in [200, 405] and ("xml" in r.headers.get("content-type", "").lower() or "xml-rpc" in r.text.lower()):
                        findings.append(
                            CheckFinding(
                                rule_id=self.rule_id,
                                title=f"Exposed XML-RPC / Legacy XML Service: {path}",
                                technical_issue_type="EXPOSED_XML_SERVICE",
                                severity="MEDIUM",
                                confidence="FIRM",
                                evidence={
                                    "url": test_url,
                                    "status_code": r.status_code,
                                    "content_type": r.headers.get("content-type", ""),
                                },
                                remediation=f"Disable or restrict public network access to '{path}' if XML-RPC/SOAP services are not required.",
                                references=self.references,
                            )
                        )
                        break
                except Exception:
                    pass

            # 2. Test safe non-destructive XML entity expansion probe
            safe_xml_payload = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE test [ <!ENTITY sentinel "VulnSentinelSafetyCheck"> ]>\n'
                '<root><data>&sentinel;</data></root>'
            )

            try:
                probe_resp = await client.post(
                    base_url,
                    content=safe_xml_payload,
                    headers={"Content-Type": "application/xml"},
                )

                # Check if entity was expanded and reflected
                if "VulnSentinelSafetyCheck" in probe_resp.text:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="XML Entity Expansion Enabled (Potential XXE Risk)",
                            technical_issue_type="XML_ENTITY_EXPANSION_RESOLVED",
                            severity="HIGH",
                            confidence="CERTAIN",
                            evidence={
                                "url": base_url,
                                "status_code": probe_resp.status_code,
                                "reflected_entity": "VulnSentinelSafetyCheck",
                            },
                            remediation="Configure XML parsers with external DTD and entity processing completely disabled (e.g. disallow-doctype-decl).",
                            references=self.references,
                        )
                    )

                # Check for XML parser stack trace leakage
                xml_error_patterns = [
                    r"SAXParseException",
                    r"XMLReader",
                    r"libxml",
                    r"SimpleXMLElement",
                    r"DOMDocument",
                    r"org\.xml\.sax",
                    r"javax\.xml\.parsers",
                ]
                for pattern in xml_error_patterns:
                    if re.search(pattern, probe_resp.text, re.IGNORECASE):
                        findings.append(
                            CheckFinding(
                                rule_id=self.rule_id,
                                title="XML Parser Diagnostic Error Disclosure",
                                technical_issue_type="XML_PARSER_ERROR_DISCLOSURE",
                                severity="LOW",
                                confidence="FIRM",
                                evidence={
                                    "matched_pattern": pattern,
                                    "status_code": probe_resp.status_code,
                                    "error_snippet": probe_resp.text[:300],
                                },
                                remediation="Disable verbose XML parser error responses and suppress internal XML exception details.",
                                references=self.references,
                            )
                        )
                        break

            except Exception:
                pass

        return findings
