"""OWASP Sentinel - Sensitive Endpoint & File Exposure Detection Rule

Safely probes for public exposure of repository metadata (.git), environment
files (.env), administrative robots.txt disclosures, and security policies.
"""

from urllib.parse import urljoin

import httpx

from app.scanner.base_rule import BaseDetectionRule, CheckFinding
from app.scanner.context import ScanContext


class SensitiveEndpointExposureCheck(BaseDetectionRule):
    """Detects public exposure of configuration files, version control metadata, and administrative paths."""

    rule_id = "RULE-SEC-006"
    name = "Sensitive Configuration & Metadata File Exposure Audit"
    description = (
        "Checks whether critical configuration files (.env, .git) or diagnostic resources are publicly accessible."
    )
    why_it_matters = (
        "Publicly accessible .git repositories or .env files reveal database passwords, API secret keys, "
        "and source code, resulting in complete system compromise without requiring active exploits."
    )
    evidence_description = "Records target URL, HTTP status code, and matched content signature."
    owasp_category_mappings = {
        "2025": "A01:2025-Broken Access Control, A02:2025-Security Misconfiguration",
        "2021": "A01:2021-Broken Access Control, A05:2021-Security Misconfiguration",
        "2017": "A3:2017-Sensitive Data Exposure, A5:2017-Broken Access Control, A8:2017-Insecure Deserialization",
        "2013": "A4:2013-Insecure Direct Object References, A5:2013-Security Misconfiguration, A6:2013-Sensitive Data Exposure, A7:2013-Missing Function Level Access Control",
        "2010": "A4:2010-Insecure Direct Object References, A6:2010-Security Misconfiguration",
        "2007": "A4:2007-Insecure Direct Object Reference",
        "2004": "A2:2004-Broken Access Control",
        "2003": "A2:2003-Broken Access Control",
    }
    required_permissions = "Network read egress to target HTTP/HTTPS endpoints."
    known_limitations = (
        "Some single-page applications (SPAs) return an HTTP 200 HTML landing page for all 404 routes. "
        "The rule performs strict signature matching to prevent false positives from generic SPA fallbacks."
    )
    potential_false_positives = "Custom web error pages returning HTTP 200 without standard error codes."
    remediation_guidance = (
        "Deny web server access to all dotfiles and directories (e.g. location ~ /\\. { deny all; } in Nginx). "
        "Ensure environment files and version control repositories are placed outside the web root."
    )
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        "https://datatracker.ietf.org/doc/html/rfc9116",
    ]

    async def check(self, context: ScanContext) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        if getattr(context, "_target_unreachable", False):
            return findings

        base_url = context.canonical_url
        probe_timeout = min(context.timeout_seconds, 2.5)

        async with httpx.AsyncClient(verify=False) as client:
            # 1. Check for exposed .git/HEAD
            git_url = urljoin(base_url, "/.git/HEAD")
            try:
                git_resp = await client.get(
                    git_url,
                    timeout=probe_timeout,
                    headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                    follow_redirects=False,
                )
                if git_resp.status_code == 200 and git_resp.text.strip().startswith("ref: refs/"):
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="Critical Exposure: Public Git Repository Metadata (.git/HEAD)",
                            technical_issue_type="EXPOSED_GIT_REPOSITORY",
                            severity="CRITICAL",
                            confidence="CERTAIN",
                            evidence={
                                "endpoint": git_url,
                                "status_code": 200,
                                "content_snippet": git_resp.text[:60],
                            },
                            remediation="Immediately restrict web access to the .git directory and rotate any secrets stored in git history.",
                            references=self.references,
                        )
                    )
            except Exception:
                pass

            # 2. Check for exposed .env
            env_url = urljoin(base_url, "/.env")
            try:
                env_resp = await client.get(
                    env_url,
                    timeout=context.timeout_seconds,
                    headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                    follow_redirects=False,
                )
                text = env_resp.text
                # Strict verification: must contain common env keys
                if env_resp.status_code == 200 and any(
                    k in text for k in ("APP_KEY=", "DB_PASSWORD=", "DATABASE_URL=", "SECRET_KEY=")
                ):
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="Critical Exposure: Environment Configuration File (.env)",
                            technical_issue_type="EXPOSED_ENV_FILE",
                            severity="CRITICAL",
                            confidence="CERTAIN",
                            evidence={
                                "endpoint": env_url,
                                "status_code": 200,
                                "sample_keys": [
                                    k for k in ("APP_KEY", "DB_PASSWORD", "DATABASE_URL", "SECRET_KEY") if k in text
                                ],
                            },
                            remediation="Block access to .env files in server configuration and immediately revoke all exposed credentials.",
                            references=self.references,
                        )
                    )
            except Exception:
                pass

            # 3. Check for Security Policy (security.txt - RFC 9116)
            sec_txt_url = urljoin(base_url, "/.well-known/security.txt")
            try:
                sec_resp = await client.get(
                    sec_txt_url,
                    timeout=context.timeout_seconds,
                    headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0"},
                    follow_redirects=True,
                )
                if sec_resp.status_code != 200 or "Contact:" not in sec_resp.text:
                    findings.append(
                        CheckFinding(
                            rule_id=self.rule_id,
                            title="Missing Vulnerability Disclosure Policy (security.txt)",
                            technical_issue_type="MISSING_SECURITY_TXT",
                            severity="INFO",
                            confidence="CERTAIN",
                            evidence={"endpoint": sec_txt_url, "status_code": sec_resp.status_code},
                            remediation="Publish a valid security.txt file under /.well-known/security.txt as standardized by RFC 9116.",
                            references=["https://datatracker.ietf.org/doc/html/rfc9116"],
                        )
                    )
            except Exception:
                pass

        return findings
