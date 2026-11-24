"""OWASP Sentinel - XSSSpect Scanner Engine.

Orchestrates URL parameter extraction, test URL generation, payload dispatch,
and headless browser execution verification for reflected XSS vulnerability assessment.
"""

import time
from typing import Any

from xssspect.browser_check import check_payload_execution
from xssspect.external_runner import run_xsstrike
from xssspect.param_parser import build_test_url, parse_url_params
from xssspect.payloads import load_payloads


def scan_url(
    url: str,
    payload_file: str | None = None,
    delay: float = 0.5,
    mode: str | None = None,
    xsstrike_path: str | None = None,
) -> dict[str, Any]:
    """Scans a target URL for reflected XSS vulnerabilities across its query parameters.

    Extracts query parameters from the URL, iterates through configured assessment
    payloads for each parameter, verifies browser reflection and script execution,
    and returns an aggregated vulnerability posture summary.  Optionally invokes
    XSStrike as an external subprocess for additional coverage.

    Args:
        url: The full target URL to assess.
        payload_file: Optional path to a file containing custom probes.
            If None, standard DEFAULT_PAYLOADS or suite for mode are used.
        delay: Seconds to pause between subsequent payload checks for rate-limiting.
        mode: Optional detection suite mode ('STANDARD', 'DEEP', 'DOM').
        xsstrike_path: Optional filesystem path to ``xsstrike.py``.  When
            provided, XSStrike is run as a subprocess and its results are
            merged into the return dictionary under the ``"xsstrike"`` key.

    Returns:
        dict[str, Any]: Assessment summary containing:
            - "url" (str): The target URL scanned.
            - "parameters_tested" (list[str]): Names of query parameters tested.
            - "findings" (list[dict[str, Any]]): Test outcomes per parameter and payload probe.
            - "vulnerable" (bool): True if any injected probe triggered JavaScript execution.
            - "xsstrike" (dict, optional): XSStrike subprocess result when *xsstrike_path* is set.
            - "error" (str, optional): Error message if no parameters exist or scan failed.
    """
    params = parse_url_params(url)
    if not params:
        return {
            "url": url,
            "error": "no parameters found",
            "findings": [],
        }

    if mode is not None:
        payloads = load_payloads(payload_file, mode=mode)
    else:
        payloads = load_payloads(payload_file)
    parameters_tested = list(params.keys())
    findings: list[dict[str, Any]] = []
    is_vulnerable = False

    for param in parameters_tested:
        for payload in payloads:
            test_url = build_test_url(url, param, payload)
            result = check_payload_execution(test_url, payload)

            executed = bool(result.get("executed", False))
            reflected = bool(result.get("reflected", False))
            dialog_message = result.get("dialog_message")

            finding: dict[str, Any] = {
                "parameter": param,
                "payload": payload,
                "executed": executed,
                "reflected": reflected,
                "dialog_message": dialog_message,
            }
            if "error" in result:
                finding["error"] = result["error"]

            findings.append(finding)

            if executed:
                is_vulnerable = True

            if delay > 0:
                time.sleep(delay)

    result: dict[str, Any] = {
        "url": url,
        "parameters_tested": parameters_tested,
        "findings": findings,
        "vulnerable": is_vulnerable,
    }

    # --- Optional XSStrike pass ------------------------------------------------
    if xsstrike_path is not None:
        xsstrike_result = run_xsstrike(
            target_url=url,
            xsstrike_path=xsstrike_path,
            delay=int(delay) if delay >= 1 else 1,
        )
        result["xsstrike"] = xsstrike_result
        if xsstrike_result.get("vulnerable"):
            result["vulnerable"] = True

    return result

