"""OWASP Top 10 Security Assessment Orchestrator.

Implements the unified `scan` orchestrator function coordinating HTTP non-destructive
audits (scan_http), external CLI tooling wrappers (external_wrappers), and category-specific
or manual review checks (checks.py) according to CHECK_REGISTRY.
"""

from typing import Any
import argparse
import json
import re
import sys

from owasp_registry import CHECK_REGISTRY, OWASP_CATEGORIES
import scan_http
import checks
from external_wrappers import run_sqlmap_cli, run_xsstrike_cli, run_pip_audit


def _parse_sqlmap_findings(target_url: str, sqlmap_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse sqlmap execution result into A05 vulnerability findings.

    Args:
        target_url: The scanned URL target.
        sqlmap_result: Dictionary returned from run_sqlmap_cli containing stdout, stderr, exit_code.

    Returns:
        List of findings formatted with owasp_id="A05".
    """
    findings: list[dict[str, Any]] = []
    stdout = sqlmap_result.get("stdout") or ""

    if not stdout:
        return findings

    stdout_lower = stdout.lower()
    vuln_markers = [
        "is vulnerable",
        "identified the following injection point",
        "heuristic (basic) test shows that",
        "sqlmap resumed the following injection point",
        "parameter appears to be dynamic",
        "parameter appears to be injectable",
    ]

    is_vulnerable = any(marker in stdout_lower for marker in vuln_markers) or "parameter:" in stdout_lower

    if is_vulnerable:
        param_matches = re.findall(r"Parameter:\s*([^\s\(\)]+)", stdout, re.IGNORECASE)
        if param_matches:
            for param in dict.fromkeys(param_matches):
                findings.append(
                    {
                        "owasp_id": "A05",
                        "title": f"SQL Injection Detected on Parameter '{param}'",
                        "severity": "high",
                        "evidence": f"sqlmap confirmed injectable parameter '{param}' on {target_url}.",
                        "source": "scanner",
                    }
                )
        else:
            findings.append(
                {
                    "owasp_id": "A05",
                    "title": "SQL Injection Detected via sqlmap",
                    "severity": "high",
                    "evidence": f"sqlmap identified injection vulnerabilities on {target_url}.",
                    "source": "scanner",
                }
            )

    return findings


def _parse_pip_audit_findings(pip_audit_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse pip-audit vulnerabilities list into A03 supply chain findings.

    Args:
        pip_audit_result: Dictionary returned from run_pip_audit containing 'vulnerabilities'.

    Returns:
        List of findings formatted with owasp_id="A03".
    """
    findings: list[dict[str, Any]] = []
    vulnerabilities = pip_audit_result.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        cve_id = vuln.get("id") or vuln.get("cve") or "CVE-Unknown"
        pkg_name = vuln.get("package") or vuln.get("name") or "dependency"
        version = vuln.get("version") or ""
        desc = vuln.get("description") or f"Known vulnerability in {pkg_name}."
        fix_versions = vuln.get("fix_versions") or []
        fix_str = f" Fixed in: {', '.join(fix_versions)}." if fix_versions else ""

        findings.append(
            {
                "owasp_id": "A03",
                "cve": cve_id,
                "package": pkg_name,
                "title": f"Vulnerable Dependency: {pkg_name} ({cve_id})",
                "severity": "high",
                "evidence": f"Package '{pkg_name}' {version} is affected by {cve_id}. {desc}{fix_str}".strip(),
                "source": "scanner",
            }
        )

    return findings


def scan(
    target_url: str,
    selected_ids: list[str],
    auth: dict | None = None,
    tools: dict | None = None,
) -> dict:
    """Execute unified security assessment for selected OWASP Top 10 categories.

    Orchestrates checks based on CHECK_REGISTRY:
    - A01, A02, A05, A07: Invokes corresponding HTTP checks from scan_http.py.
    - A05 additionally: If tools.get("sqlmap_path"), runs run_sqlmap_cli and parses findings.
    - A03: If tools.get("requirements_path"), runs run_pip_audit and maps CVEs; else returns manual review.
    - A06, A09, A10: Calls manual review stubs from checks.py.
    - A04, A08: Calls corresponding implementations from checks.py.

    Args:
        target_url: Canonical target URL to be evaluated.
        selected_ids: List of OWASP category IDs (e.g. ['A01', 'A02', 'A05']).
        auth: Optional dictionary of authentication credentials (token, cookies, headers).
        tools: Optional dictionary of paths to external binaries/files (sqlmap_path, requirements_path).

    Returns:
        Dictionary structured as:
        {
            "target": target_url,
            "findings": list of finding dicts,
            "summary": {
                "total": total findings count,
                "by_owasp": {owasp_id: count}
            }
        }
    """
    if auth is None:
        auth = {}
    if tools is None:
        tools = {}

    findings: list[dict] = []

    # Initialize count for all selected categories
    by_owasp: dict[str, int] = {cat_id: 0 for cat_id in selected_ids}

    for cat_id in selected_ids:
        # 1. Look up CHECK_REGISTRY
        check_func_name = CHECK_REGISTRY.get(cat_id)
        if not check_func_name:
            continue

        # 2. Category dispatch
        if cat_id == "A01":
            # Broken Access Control: non-destructive endpoint inspection
            if hasattr(scan_http, "check_access_control"):
                a01_findings = scan_http.check_access_control(target_url, auth=auth)
            else:
                a01_findings = checks.run_access_control_checks(target_url, auth=auth)
            findings.extend(a01_findings)

        elif cat_id == "A02":
            # Security Misconfiguration: missing defense-in-depth headers
            a02_findings = scan_http.check_security_headers(target_url)
            findings.extend(a02_findings)

        elif cat_id == "A03":
            # Software Supply Chain Failures: pip-audit on requirements if provided, else manual review
            req_path = tools.get("requirements_path")
            if req_path:
                pip_audit_res = run_pip_audit(req_path)
                a03_findings = _parse_pip_audit_findings(pip_audit_res)
                findings.extend(a03_findings)
            else:
                findings.extend(checks.run_supply_chain_checks(target_url, auth=auth))

        elif cat_id == "A04":
            # Cryptographic Failures: checks.py implementation
            findings.extend(checks.run_crypto_checks(target_url, auth=auth))

        elif cat_id == "A05":
            # Injection: scan_http parameter reflection check
            if hasattr(scan_http, "check_reflected_parameters"):
                a05_http_findings = scan_http.check_reflected_parameters(target_url)
            else:
                probe_res = scan_http.check_reflected_probe(target_url, param="q")
                a05_http_findings = []
                if probe_res.get("reflected"):
                    a05_http_findings.append(
                        {
                            "owasp_id": "A05",
                            "title": "Unfiltered Parameter Reflection",
                            "severity": "medium",
                            "evidence": f"Canary probe string reflected unencoded in response from {probe_res['url']}.",
                            "source": "scanner",
                        }
                    )
            findings.extend(a05_http_findings)

            # 3. For A05 additionally: if sqlmap_path provided, run sqlmap CLI
            sqlmap_path = tools.get("sqlmap_path")
            if sqlmap_path:
                sqlmap_res = run_sqlmap_cli(target_url, sqlmap_path=sqlmap_path)
                sqlmap_findings = _parse_sqlmap_findings(target_url, sqlmap_res)
                findings.extend(sqlmap_findings)

            # If xsstrike_path provided, run XSStrike CLI
            xsstrike_path = tools.get("xsstrike_path")
            if xsstrike_path:
                xsstrike_res = run_xsstrike_cli(target_url, xsstrike_path=xsstrike_path)
                if xsstrike_res.get("vulnerable"):
                    findings.append(
                        {
                            "owasp_id": "A05",
                            "title": "Cross-Site Scripting (XSS) Vulnerability Detected (XSStrike)",
                            "severity": "high",
                            "evidence": f"XSStrike identified XSS vulnerability on {target_url}.",
                            "source": "scanner",
                        }
                    )

        elif cat_id == "A06":
            # Insecure Design: manual review stub
            findings.extend(checks.run_design_checks(target_url, auth=auth))

        elif cat_id == "A07":
            # Authentication Failures: scan_http cookie flags check
            a07_findings = scan_http.check_cookie_flags(target_url)
            findings.extend(a07_findings)

        elif cat_id == "A08":
            # Software or Data Integrity Failures: checks.py SRI check
            findings.extend(checks.run_integrity_checks(target_url, auth=auth))

        elif cat_id == "A09":
            # Security Logging and Alerting Failures: manual review stub
            findings.extend(checks.run_logging_checks(target_url, auth=auth))

        elif cat_id == "A10":
            # Mishandling of Exceptional Conditions: manual review stub
            findings.extend(checks.run_exception_checks(target_url, auth=auth))

    # Calculate summary metrics
    for finding in findings:
        oid = finding.get("owasp_id")
        if oid:
            by_owasp[oid] = by_owasp.get(oid, 0) + 1

    return {
        "target": target_url,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_owasp": by_owasp,
        },
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for scanner_main."""
    parser = argparse.ArgumentParser(
        prog="scanner_main",
        description="OWASP Top 10 Automated Assessment Scanner Orchestrator.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run security assessment scan.")
    scan_parser.add_argument("--target", required=True, help="Target URL to assess.")
    scan_parser.add_argument(
        "--checks",
        default=",".join(CHECK_REGISTRY.keys()),
        help="Comma-separated OWASP category IDs (e.g. A01,A02,A05).",
    )
    scan_parser.add_argument("--auth-token", default=None, help="Bearer authorization token.")
    scan_parser.add_argument("--sqlmap-path", default=None, help="Path to sqlmap.py.")
    scan_parser.add_argument("--requirements-path", default=None, help="Path to requirements.txt.")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    return parser


def main() -> None:
    """CLI execution entrypoint for scanner_main."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.command == "scan":
        selected_ids = [c.strip().upper() for c in args.checks.split(",") if c.strip()]
        auth = {}
        if args.auth_token:
            auth["token"] = args.auth_token

        tools = {}
        if args.sqlmap_path:
            tools["sqlmap_path"] = args.sqlmap_path
        if args.requirements_path:
            tools["requirements_path"] = args.requirements_path

        results = scan(
            target_url=args.target,
            selected_ids=selected_ids,
            auth=auth,
            tools=tools,
        )

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\nScan results for: {results['target']}")
            print(f"Total findings: {results['summary']['total']}")
            print("Findings by OWASP category:")
            for cat, count in results["summary"]["by_owasp"].items():
                print(f"  {cat} ({OWASP_CATEGORIES.get(cat, 'Unknown')}): {count}")
            print("\nFindings list:")
            for idx, finding in enumerate(results["findings"], 1):
                print(
                    f"  [{idx}] [{finding.get('owasp_id')}] [{finding.get('severity', '').upper()}] "
                    f"{finding.get('title')}: {finding.get('evidence')}"
                )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

