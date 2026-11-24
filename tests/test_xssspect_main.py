"""Unit tests for xssspect.main CLI entry point."""

import json
from unittest.mock import patch
import pytest

from xssspect.main import build_parser, main


def test_build_parser_scan_subcommand():
    parser = build_parser()
    args = parser.parse_args(["scan", "--url", "https://example.com/test?q=hello", "--delay", "1.2"])
    assert args.command == "scan"
    assert args.url == "https://example.com/test?q=hello"
    assert args.delay == 1.2
    assert args.payload_file is None


@patch("xssspect.main.scan_url")
def test_main_scan_non_vulnerable_returns_zero(mock_scan, capsys):
    mock_scan.return_value = {
        "url": "https://example.com/search?q=test",
        "parameters_tested": ["q"],
        "findings": [],
        "vulnerable": False,
    }

    exit_code = main(["scan", "--url", "https://example.com/search?q=test"])
    assert exit_code == 0

    captured = capsys.readouterr()
    output_data = json.loads(captured.out)
    assert output_data["vulnerable"] is False
    assert output_data["url"] == "https://example.com/search?q=test"


@patch("xssspect.main.scan_url")
def test_main_scan_vulnerable_returns_one(mock_scan, capsys):
    mock_scan.return_value = {
        "url": "https://example.com/search?q=test",
        "parameters_tested": ["q"],
        "findings": [
            {
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
                "executed": True,
                "reflected": True,
                "dialog_message": "1",
            }
        ],
        "vulnerable": True,
    }

    exit_code = main(["scan", "--url", "https://example.com/search?q=test", "--delay", "0.2"])
    assert exit_code == 1

    captured = capsys.readouterr()
    output_data = json.loads(captured.out)
    assert output_data["vulnerable"] is True
    mock_scan.assert_called_once_with(
        url="https://example.com/search?q=test",
        payload_file=None,
        delay=0.2,
        xsstrike_path=None,
    )


@patch("xssspect.main.scan_url")
def test_main_scan_with_payload_file(mock_scan, capsys):
    mock_scan.return_value = {
        "url": "https://example.com/search?q=test",
        "parameters_tested": ["q"],
        "findings": [],
        "vulnerable": False,
    }

    exit_code = main(["scan", "--url", "https://example.com/search?q=test", "--payload-file", "probes.txt"])
    assert exit_code == 0

    mock_scan.assert_called_once_with(
        url="https://example.com/search?q=test",
        payload_file="probes.txt",
        delay=0.5,
        xsstrike_path=None,
    )

