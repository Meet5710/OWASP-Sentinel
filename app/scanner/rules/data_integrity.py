"""OWASP Sentinel - Software & Data Integrity Failures Detection Rule

Audits external CDN script references for missing Subresource Integrity (SRI)
and checks for exposed CI/CD automation deployment definitions.
"""

import re
from urllib.parse import urljoin, urlparse

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class SubresourceDataIntegrityCheck(BaseDetectionRule):
    """Detects missing Subresource Integrity (SRI) on external scripts and exposed CI/CD definitions."""

    rule_id = "RULE-SEC-012"
    name = "Software & Subresource Data Integrity Audit"
    description = (
        "Audits HTML markup for third-party CDN scripts loaded without Subresource Integrity (SRI) hashes, "
        "and probes for publicly exposed continuous integration/continuous delivery (CI/CD) pipeline files."
    )
    why_it_matters = (
        "Software and Data Integrity Failures (A08:2021) occur when code or infrastructure relies on plugins, "
        "libraries, or build pipelines without verifying their cryptographic integrity. If a third-party CDN is "
        "compromised, attackers can inject malicious JavaScript into all visitor sessions (supply chain attack)."
    )
    evidence_description = "Records external script URLs, missing SRI attributes, and status of CI/CD configuration paths."
    owasp_category_mappings = {
        "2025": "A08:2025-Software or Data Integrity Failures",
        "2021": "A08:2021-Software and Data Integrity Failures",
        "2017": "A8:2017-Insecure Deserialization",
        "2013": "A6:2013-Sensitive Data Exposure",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Scripts dynamically injected via tag managers or client bundles at runtime require DOM execution profiling."
    )
    potential_false_positives = (
        "Scripts hosted on self-managed first-party domains matching the apex domain."
    )
    remediation_guidance = (
        "Add cryptographic Subresource Integrity (SRI) hashes (e.g. integrity='sha384-...' crossorigin='anonymous') "
        "to all externally referenced third-party JavaScript files, and block public web access to CI/CD files."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures/",
        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
    ]

    SCRIPT_SRC_PATTERN = re.compile(r"<script\b([^>]*src=['\"]([^'\"]+)['\"][^>]*)>", re.IGNORECASE)
    KNOWN_CDNS = ("cdn.jsdelivr.net", "cdnjs.cloudflare.com", "code.jquery.com", "stackpath.bootstrapcdn.com", "unpkg.com")
    CICD_PATHS = ["/.gitlab-ci.yml", "/Jenkinsfile", "/.travis.yml"]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        base_url = context.canonical_url

        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await context.get_target_response(client)
            except Exception:
                return findings

            html_text = response.text[:60000]

            # 1. Audit Script Tags for Missing SRI Attributes
            missing_sri_scripts: list[str] = []
            for match in self.SCRIPT_SRC_PATTERN.finditer(html_text):
                tag_attributes = match.group(1)
                src_url = match.group(2)

                # Check if script points to a known external CDN
                parsed_src = urlparse(src_url)
                if any(cdn in parsed_src.netloc.lower() for cdn in self.KNOWN_CDNS):
                    if "integrity=" not in tag_attributes.lower():
                        missing_sri_scripts.append(src_url)

            if missing_sri_scripts:
                findings.append(
                    CheckFinding(
                        rule_id=self.rule_id,
                        title="Third-Party CDN Scripts Missing Subresource Integrity (SRI)",
                        technical_issue_type="MISSING_SUBRESOURCE_INTEGRITY",
                        severity="MEDIUM",
                        confidence="CERTAIN",
                        evidence={
                            "page_url": base_url,
                            "affected_scripts": missing_sri_scripts[:5],
                            "count": len(missing_sri_scripts),
                        },
                        remediation=(
                            "Generate cryptographic hashes (SHA-384 or SHA-512) for all external CDN resources "
                            "and enforce the 'integrity' and 'crossorigin' attributes on script tags."
                        ),
                        references=self.references,
                    )
                )

            # 2. Check for Exposed CI/CD Automation Files
            if not getattr(context, "_target_unreachable", False):
                for cicd_path in self.CICD_PATHS:
                    test_url = urljoin(base_url, cicd_path)
                    try:
                        resp = await client.get(
                            test_url,
                            timeout=context.timeout_seconds,
                            headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                            follow_redirects=False,
                        )
                        if resp.status_code == 200 and len(resp.content) > 20:
                            sample = resp.text[:500]
                            if any(marker in sample for marker in ("stages:", "image:", "pipeline", "job")):
                                findings.append(
                                    CheckFinding(
                                        rule_id=self.rule_id,
                                        title=f"Publicly Exposed CI/CD Pipeline Definition ({cicd_path})",
                                        technical_issue_type="EXPOSED_CICD_CONFIGURATION",
                                        severity="HIGH",
                                        confidence="CERTAIN",
                                        evidence={
                                            "path": cicd_path,
                                            "url": test_url,
                                            "status_code": resp.status_code,
                                            "sample": sample[:200],
                                        },
                                        remediation=(
                                            f"Ensure that '{cicd_path}' is excluded from web server deployments and "
                                            "never accessible via public HTTP requests."
                                        ),
                                        references=self.references,
                                    )
                                )
                                break
                    except Exception:
                        continue

        return findings

