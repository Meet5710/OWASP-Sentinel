"""OWASP Sentinel - Unified CLI Assessment Platform and Service Runner.

Provides CLI command execution for automated and manual security reviews,
including the `scan` subcommand with authorization enforcement, external tool
orchestration, JSON report serialization, and summary reporting.
"""

from typing import Any
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from owasp_registry import OWASP_CATEGORIES
from scanner_main import scan

ALL_OWASP_IDS: list[str] = list(OWASP_CATEGORIES.keys())


def load_and_validate_auth(auth_file_path: str | Path) -> dict[str, Any]:
    """Load JSON authorization file and validate approval and expiry timestamps.

    Args:
        auth_file_path: File system path to authorization JSON file.

    Returns:
        Loaded dictionary containing authorization credentials and metadata.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If JSON is invalid, missing required fields, or if authorization has expired.
    """
    path = Path(auth_file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Authorization file not found: {auth_file_path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in auth file: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Authorization file must contain a top-level JSON object.")

    approved_by = data.get("approved_by")
    if not approved_by or not str(approved_by).strip():
        raise ValueError("Authorization file missing required field: 'approved_by'.")

    expiry = data.get("expiry")
    if expiry is None:
        raise ValueError("Authorization file missing required field: 'expiry'.")

    # Parse and validate expiry timestamp or string
    expiry_dt: datetime | None = None
    if isinstance(expiry, (int, float)):
        expiry_dt = datetime.fromtimestamp(expiry, tz=timezone.utc)
    elif isinstance(expiry, str):
        cleaned = expiry.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            expiry_dt = datetime.fromisoformat(cleaned)
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d"):
                try:
                    expiry_dt = datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    pass

    if expiry_dt is None:
        raise ValueError(f"Unrecognized date/time format for 'expiry': '{expiry}'.")

    now = datetime.now(timezone.utc)
    if now > expiry_dt:
        raise ValueError(
            f"Authorization expired on {expiry_dt.isoformat()} (current UTC: {now.isoformat()}). "
            f"Approved by: {approved_by}."
        )

    return data


def format_summary_table(
    selected_ids: list[str],
    results: dict[str, Any],
    tools: dict[str, Any] | None = None,
) -> str:
    """Format assessment summary table with category metadata, count, and scan status.

    Columns: OWASP ID | Category | Findings Count | Status (scanned/manual)

    Args:
        selected_ids: Ordered list of evaluated OWASP IDs.
        results: Assessment results dictionary returned by scan().
        tools: Optional dictionary of tools configured for the scan.

    Returns:
        Formatted ASCII summary table string.
    """
    tools = tools or {}
    findings: list[dict[str, Any]] = results.get("findings", [])
    by_owasp: dict[str, int] = results.get("summary", {}).get("by_owasp", {})

    header_id = "OWASP ID"
    header_cat = "Category"
    header_count = "Findings Count"
    header_status = "Status"

    id_width = 8
    cat_width = 41
    count_width = 14
    status_width = 10

    lines: list[str] = []
    header_line = (
        f"{header_id:<{id_width}} | "
        f"{header_cat:<{cat_width}} | "
        f"{header_count:<{count_width}} | "
        f"{header_status:<{status_width}}"
    )
    separator = "-" * len(header_line)
    lines.append(header_line)
    lines.append(separator)

    manual_categories = {"A06", "A09", "A10"}

    for oid in selected_ids:
        category_name = OWASP_CATEGORIES.get(oid, "Unknown Category")
        count = by_owasp.get(oid, 0)

        # Determine if category evaluation was automated or manual
        cat_findings = [f for f in findings if f.get("owasp_id") == oid]
        if any(f.get("source") == "manual" for f in cat_findings):
            status = "manual"
        elif oid in manual_categories:
            status = "manual"
        elif oid == "A03" and not tools.get("requirements_path"):
            status = "manual"
        else:
            status = "scanned"

        lines.append(
            f"{oid:<{id_width}} | "
            f"{category_name:<{cat_width}} | "
            f"{str(count):<{count_width}} | "
            f"{status:<{status_width}}"
        )

    lines.append(separator)
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct argument parser with `scan` and server options.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="OWASP Sentinel - Automated Security Assessment Platform.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Execute OWASP Top 10 security assessment.")
    scan_parser.add_argument(
        "--target",
        required=True,
        type=str,
        help="Target URL to assess (required).",
    )
    scan_parser.add_argument(
        "--checks",
        default=",".join(ALL_OWASP_IDS),
        type=str,
        help="Comma-separated OWASP IDs to execute (default: all 10).",
    )
    scan_parser.add_argument(
        "--auth-file",
        default=None,
        type=str,
        help="Path to authorization JSON file containing 'approved_by' and 'expiry'.",
    )
    scan_parser.add_argument(
        "--sqlmap-path",
        default=None,
        type=str,
        help="Optional path to sqlmap CLI entrypoint script.",
    )
    scan_parser.add_argument(
        "--xsstrike-path",
        default=None,
        type=str,
        help="Optional path to XSStrike CLI entrypoint script.",
    )
    scan_parser.add_argument(
        "--requirements-path",
        default=None,
        type=str,
        help="Optional path to requirements.txt for pip-audit dependency analysis.",
    )
    scan_parser.add_argument(
        "--output",
        default="report.json",
        type=str,
        help="Output report JSON file path (default: report.json).",
    )

    # Subcommand: serve (preserve development web dashboard)
    subparsers.add_parser("serve", help="Start the FastAPI web server dashboard.")

    return parser


def run_scan_command(args: argparse.Namespace) -> int:
    """Execute the scan subcommand flow with validation, scanning, output, and summary reporting.

    Args:
        args: Parsed CLI namespace arguments.

    Returns:
        Process exit code integer (0 on success, non-zero on failure).
    """
    # 1. Load auth file and check expiry if provided
    auth_data: dict[str, Any] = {}
    if args.auth_file:
        try:
            auth_data = load_and_validate_auth(args.auth_file)
            print(f"[AUTH] Authorization verified: approved by '{auth_data.get('approved_by')}'.")
        except (FileNotFoundError, ValueError) as exc:
            print(f"[AUTH ERROR] {exc}", file=sys.stderr)
            return 1

    # 2. Parse selected checks
    selected_ids = [c.strip().upper() for c in args.checks.split(",") if c.strip()]
    if not selected_ids:
        print("[ERROR] No valid OWASP category IDs provided in --checks.", file=sys.stderr)
        return 1

    # 3. Assemble tools dictionary
    tools: dict[str, Any] = {}
    if args.sqlmap_path:
        tools["sqlmap_path"] = args.sqlmap_path
    if args.xsstrike_path:
        tools["xsstrike_path"] = args.xsstrike_path
    if args.requirements_path:
        tools["requirements_path"] = args.requirements_path

    # 4. Call scan()
    print(f"[SCAN] Initiating assessment on {args.target} for {len(selected_ids)} categories...")
    results = scan(
        target_url=args.target,
        selected_ids=selected_ids,
        auth=auth_data,
        tools=tools,
    )

    # 5. Write JSON output
    output_path = Path(args.output)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[OUTPUT] Detailed assessment report written to {output_path.resolve()}")
    except OSError as exc:
        print(f"[OUTPUT ERROR] Failed to write report to {args.output}: {exc}", file=sys.stderr)
        return 1

    # 6. Print summary table
    print("\n" + "=" * 76)
    print("                    OWASP TOP 10 ASSESSMENT SUMMARY                    ")
    print("=" * 76)
    table_str = format_summary_table(selected_ids=selected_ids, results=results, tools=tools)
    print(table_str)
    print(f"Total Findings: {results.get('summary', {}).get('total', 0)}")
    print("=" * 76 + "\n")

    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI application entrypoint.

    Args:
        argv: Optional list of argument strings. Uses sys.argv[1:] if None.

    Returns:
        Process exit code integer.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)
    elif args.command == "serve":
        try:
            import uvicorn
            from app.core.config import settings

            print(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}...")
            uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
            return 0
        except Exception as exc:
            print(f"[SERVER ERROR] Failed to start server: {exc}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
