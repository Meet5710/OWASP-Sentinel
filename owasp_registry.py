"""OWASP Top 10:2025 Registry & Command Builder Module.

Defines the canonical OWASP Top 10:2025 category mappings, execution check function
registry, and shell command generation for authorized security assessment scanning.
"""

from typing import Final

# 1. Mapping IDs to names for OWASP Top 10:2025
OWASP_CATEGORIES: Final[dict[str, str]] = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# 2. Mapping each ID to check function name (as a string)
CHECK_REGISTRY: Final[dict[str, str]] = {
    "A01": "run_access_control_checks",
    "A02": "run_misconfig_checks",
    "A03": "run_supply_chain_checks",
    "A04": "run_crypto_checks",
    "A05": "run_injection_checks",
    "A06": "run_design_checks",
    "A07": "run_auth_checks",
    "A08": "run_integrity_checks",
    "A09": "run_logging_checks",
    "A10": "run_exception_checks",
}


def build_scan_command(target_url: str, selected_ids: list[str]) -> str:
    """Build a CLI scanner command string for authorized target assessment.

    Args:
        target_url: Canonical target URL to be evaluated.
        selected_ids: List of OWASP category IDs to execute (e.g. ['A01', 'A05']).

    Returns:
        Shell command string formatted as:
        `python -m scanner.main scan --target <url> --checks <comma-separated-ids>`
    """
    checks_arg = ",".join(selected_ids)
    return f"python -m scanner.main scan --target {target_url} --checks {checks_arg}"

