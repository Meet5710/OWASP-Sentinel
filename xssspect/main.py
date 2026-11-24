"""OWASP Sentinel - XSSSpect CLI Entry Point.

Command-line interface for running reflected XSS assessments against authorized targets.
"""

import argparse
import json
import sys
from typing import Sequence

from xssspect.scanner import scan_url


def build_parser() -> argparse.ArgumentParser:
    """Builds the argument parser for the XSSSpect CLI.

    Returns:
        argparse.ArgumentParser: Configured argument parser with subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="xssspect",
        description="XSSSpect - Authorized Reflected XSS Assessment Scanner CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a target URL for reflected XSS vulnerabilities",
    )
    scan_parser.add_argument(
        "--url",
        required=True,
        type=str,
        help="The target URL with query parameters to test (e.g., https://example.com/search?q=test)",
    )
    scan_parser.add_argument(
        "--payload-file",
        required=False,
        default=None,
        type=str,
        help="Path to an optional custom payload file (one probe per line)",
    )
    scan_parser.add_argument(
        "--delay",
        required=False,
        default=0.5,
        type=float,
        help="Delay in seconds between payload requests (default: 0.5)",
    )
    scan_parser.add_argument(
        "--xsstrike-path",
        required=False,
        default=None,
        type=str,
        help="Path to xsstrike.py to run XSStrike as an additional scanner pass",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI execution routine.

    Args:
        argv: Command-line arguments. Defaults to sys.argv[1:].

    Returns:
        int: Exit status code (0 if safe/no vulnerability found, 1 if vulnerable).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        result = scan_url(
            url=args.url,
            payload_file=args.payload_file,
            delay=args.delay,
            xsstrike_path=args.xsstrike_path,
        )
        print(json.dumps(result, indent=2))
        return 1 if result.get("vulnerable") else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

