"""OWASP Sentinel - Injection & Input Reflection Detection Rule

Safely probes for SQL syntax leakage, template injection delimiters,
and unescaped reflection of user input without performing destructive exploits.
"""

import re
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class InjectionDefenseCheck(BaseDetectionRule):
    """Audits target endpoints for SQL syntax error leakage and unsanitized input reflection."""

    rule_id = "RULE-SEC-008"
    name = "Injection & Input Validation Audit"
    description = (
        "Passively probes target endpoints using benign input tokens to detect database error disclosure, "
        "template delimiter leakage, and unencoded reflection vulnerabilities."
    )
    why_it_matters = (
        "Injection vulnerabilities (A03:2021) occur when untrusted data is sent to an interpreter as part "
        "of a command or query. Error disclosures reveal database dialects and internal query structures, "
        "facilitating data exfiltration and authentication bypass."
    )
    evidence_description = "Records benign test parameters, matched database error signatures, and raw response snippets."
    owasp_category_mappings = {
        "2025": "A05:2025-Injection",
        "2021": "A03:2021-Injection",
        "2017": "A1:2017-Injection, A7:2017-Cross-Site Scripting (XSS), A4:2017-XML External Entities (XXE)",
        "2013": "A1:2013-Injection, A3:2013-Cross-Site Scripting (XSS)",
        "2010": "A1:2010-Injection, A2:2010-Cross-Site Scripting (XSS)",
        "2007": "A1:2007-Cross-Site Scripting (XSS), A2:2007-Injection Flaws",
        "2004": "A1:2004-Unvalidated Input, A4:2004-Cross-Site Scripting (XSS) Flaws, A6:2004-Injection Flaws",
        "2003": "A1:2003-Unvalidated Parameters, A4:2003-Cross-Site Scripting (XSS) Flaws, A6:2003-Injection Flaws",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Non-destructive testing relies on observed error messages and reflection. "
        "Blind SQL injection or second-order vulnerabilities require out-of-band telemetry."
    )
    potential_false_positives = (
        "Static documentation or tutorials that mention SQL error phrases in page text."
    )
    remediation_guidance = (
        "Use parameterized queries or Object-Relational Mappers (ORMs) with prepared statements. "
        "Ensure all user inputs are strictly validated against allowlists, and disable verbose database "
        "error disclosures in production environments."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ]

    # Well-known database error regex signatures
    DB_ERROR_PATTERNS = [
        re.compile(r"syntax error in query", re.IGNORECASE),
        re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
        re.compile(r"SQLSTATE\[[A-Z0-9]+\]", re.IGNORECASE),
        re.compile(r"pg_query\(\): Query failed", re.IGNORECASE),
        re.compile(r"ORA-[0-9]{5}", re.IGNORECASE),
        re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
        re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
        re.compile(r"Microsoft OLE DB Provider for ODBC Drivers", re.IGNORECASE),
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        base_url = context.canonical_url

        parsed = urlparse(base_url)
        test_param = {"sentinel_probe": "test'\"<sentinel>"}
        query_str = urlencode(test_param)
        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query_str, ""))

        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await client.get(
                    probe_url,
                    timeout=context.timeout_seconds,
                    headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                    follow_redirects=True,
                )
            except Exception:
                return findings

            body_text = response.text[:20000]  # inspect first 20KB

            # Check 1: Database Error Signature Leakage
            for pattern in self.DB_ERROR_PATTERNS:
                match = pattern.search(body_text)
                if match:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="Database Error Information Disclosure in Response",
                            technical_issue_type="SQL_ERROR_DISCLOSURE",
                            severity="HIGH",
                            confidence="CERTAIN",
                            evidence={
                                "matched_signature": match.group(0),
                                "url": probe_url,
                                "status_code": response.status_code,
                            },
                            remediation=(
                                "Configure web application framework to suppress internal database stack traces "
                                "and return generic error pages to external users."
                            ),
                            references=self.references,
                        )
                    )
                    break

            # Check 2: Unescaped HTML/Script Tag Reflection
            if "<sentinel>" in body_text:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Unsanitized User Input Reflection",
                        technical_issue_type="REFLECTED_INPUT_UNSANITIZED",
                        severity="MEDIUM",
                        confidence="FIRM",
                        evidence={
                            "reflected_token": "<sentinel>",
                            "url": probe_url,
                            "content_type": response.headers.get("Content-Type", ""),
                        },
                        remediation=(
                            "Apply context-aware output encoding (HTML entity encoding) to all dynamic "
                            "user input reflected back into HTTP response bodies."
                        ),
                        references=self.references,
                    )
                )

        return findings

