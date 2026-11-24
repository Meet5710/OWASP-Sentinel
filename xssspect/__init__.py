"""XSSSpect - Authorized Reflected XSS Detection Module.

Provides automated reflected cross-site scripting (XSS) detection
and verification against authorized target web applications only.
"""

from xssspect.browser_check import check_payload_execution
from xssspect.param_parser import build_test_url, parse_url_params
from xssspect.payloads import (
    DEEP_PAYLOADS,
    DEFAULT_PAYLOADS,
    DOM_PAYLOADS,
    STANDARD_PAYLOADS,
    load_payloads,
)
from xssspect.external_runner import run_xsstrike
from xssspect.scanner import scan_url

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "parse_url_params",
    "build_test_url",
    "DEFAULT_PAYLOADS",
    "STANDARD_PAYLOADS",
    "DEEP_PAYLOADS",
    "DOM_PAYLOADS",
    "load_payloads",
    "check_payload_execution",
    "scan_url",
    "run_xsstrike",
]

