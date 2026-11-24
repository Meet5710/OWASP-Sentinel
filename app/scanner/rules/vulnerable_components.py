"""OWASP Sentinel - Vulnerable and Outdated Components Detection Rule

Audits web applications for outdated frontend client libraries and publicly
exposed software dependency manifests (package.json, composer.json).
"""

import re
from urllib.parse import urljoin

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class VulnerableComponentsCheck(BaseDetectionRule):
    """Detects outdated frontend client-side libraries and exposed dependency manifest files."""

    rule_id = "RULE-SEC-010"
    name = "Vulnerable & Outdated Components Audit"
    description = (
        "Inspects loaded scripts and HTML markup for outdated third-party libraries (e.g. vulnerable jQuery, AngularJS) "
        "and audits for publicly accessible dependency configuration files."
    )
    why_it_matters = (
        "Vulnerable and Outdated Components (A06:2021) occur when an application uses third-party libraries with known "
        "CVEs. Attackers frequently exploit published vulnerabilities in legacy JavaScript frameworks to execute DOM-based XSS "
        "or compromise client sessions."
    )
    evidence_description = "Records library names, detected versions, CVE risks, and paths of exposed manifest files."
    owasp_category_mappings = {
        "2025": "A03:2025-Software Supply Chain Failures",
        "2021": "A06:2021-Vulnerable and Outdated Components",
        "2017": "A9:2017-Using Components with Known Vulnerabilities",
        "2013": "A9:2013-Using Components with Known Vulnerabilities",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Minified and bundled web assets (e.g. Webpack or Vite chunks) may obscure version strings."
    )
    potential_false_positives = (
        "Custom patched vendor forks maintaining legacy version strings for backwards compatibility."
    )
    remediation_guidance = (
        "Upgrade outdated frontend and backend libraries to currently supported releases. "
        "Integrate automated Software Composition Analysis (SCA) such as Dependabot, Snyk, or npm audit into CI/CD pipelines, "
        "and block public access to package.json or composer.json files."
    )
    references = [
        "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
    ]

    OUTDATED_LIB_PATTERNS = [
        (
            re.compile(r"jquery[.-](1\.[0-9]+|2\.[0-9]+|3\.[0-4]\.[0-9]+)(\.min)?\.js", re.IGNORECASE),
            "jQuery (version < 3.5.0)",
            "Known Prototype Pollution and Cross-Site Scripting (CVE-2020-11022, CVE-2020-11023).",
        ),
        (
            re.compile(r"angular(\.min)?\.js", re.IGNORECASE),
            "AngularJS 1.x (End of Life)",
            "AngularJS 1.x reached official End-of-Life and contains multiple sandbox escape vulnerabilities.",
        ),
        (
            re.compile(r"bootstrap[.-](3\.[0-9]+\.[0-9]+)(\.min)?\.js", re.IGNORECASE),
            "Bootstrap 3.x (Legacy)",
            "Legacy Bootstrap releases are vulnerable to XSS in tooltip and popover data attributes (CVE-2019-8331).",
        ),
    ]

    MANIFEST_PATHS = [
        "/package.json",
        "/composer.json",
        "/requirements.txt",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        base_url = context.canonical_url

        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await context.get_target_response(client)
            except Exception:
                return findings

            html_text = response.text[:50000]

            # 1. Audit Script Tags for Outdated Library Signatures
            for pattern, lib_name, vulnerability_note in self.OUTDATED_LIB_PATTERNS:
                match = pattern.search(html_text)
                if match:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title=f"Outdated Vulnerable JavaScript Library Detected: {lib_name}",
                            technical_issue_type="OUTDATED_FRONTEND_COMPONENT",
                            severity="MEDIUM",
                            confidence="FIRM",
                            evidence={
                                "library": lib_name,
                                "matched_string": match.group(0),
                                "vulnerability_risk": vulnerability_note,
                                "page_url": base_url,
                            },
                            remediation=(
                                f"Update {lib_name} to the latest stable release. Replace deprecated libraries "
                                "with actively maintained modern alternatives."
                            ),
                            references=self.references,
                        )
                    )

            # 2. Audit for Exposed Dependency Manifests
            if not getattr(context, "_target_unreachable", False):
                for manifest_path in self.MANIFEST_PATHS:
                    test_url = urljoin(base_url, manifest_path)
                    try:
                        resp = await client.get(
                            test_url,
                            timeout=context.timeout_seconds,
                            headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                            follow_redirects=False,
                        )
                        if resp.status_code == 200 and len(resp.content) > 15:
                            sample = resp.text[:500]
                            # Verify valid manifest structure
                            is_manifest = False
                            if "dependencies" in sample or "name" in sample:
                                is_manifest = True
                            elif manifest_path == "/requirements.txt" and ("==" in sample or ">=" in sample):
                                is_manifest = True

                            if is_manifest:
                                findings.append(
                                    CheckFinding(
                                        rule_id=self.rule_id,
                                        title=f"Exposed Software Dependency Manifest ({manifest_path})",
                                        technical_issue_type="EXPOSED_DEPENDENCY_MANIFEST",
                                        severity="MEDIUM",
                                        confidence="CERTAIN",
                                        evidence={
                                            "path": manifest_path,
                                            "url": test_url,
                                            "status_code": resp.status_code,
                                            "snippet": sample[:200],
                                        },
                                        remediation=(
                                            f"Ensure that '{manifest_path}' is not accessible via the public web root. "
                                            "Configure web server rules to deny access to package and build files."
                                        ),
                                        references=self.references,
                                    )
                                )
                                break
                    except Exception:
                        continue

        return findings

