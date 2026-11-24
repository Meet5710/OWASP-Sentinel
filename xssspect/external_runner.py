"""OWASP Sentinel - XSStrike External Runner.

Wraps XSStrike v3.1.5 as a subprocess, capturing its CLI output and parsing
it for vulnerability indicators. XSStrike is never modified — it is invoked
exactly as a user would run it in a terminal.
"""

import re
import subprocess
import sys
from typing import Any


# Strings XSStrike prints to stdout when it confirms a successful XSS vector.
# Derived from XSStrike/modes/scan.py lines 107-118 and core/colors.py.
_SUCCESS_MARKERS: list[str] = [
    "Payload:",                           # logger.good('Payload: %s')
    "Efficiency:",                        # logger.info('Efficiency: %i')
    "Confidence:",                        # logger.info('Confidence: %i')
    "Potentially vulnerable objects found",  # DOM check hit
]

# ANSI escape-code pattern used to strip color sequences from XSStrike output.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from *text*.

    Args:
        text: Raw string potentially containing ANSI color codes.

    Returns:
        str: Cleaned string with all escape sequences removed.
    """
    return _ANSI_RE.sub("", text)


def run_xsstrike(
    target_url: str,
    xsstrike_path: str,
    delay: int = 1,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run XSStrike against *target_url* as a subprocess and return results.

    XSStrike is invoked through its original CLI — no source files are
    modified.  The wrapper passes arguments in and captures stdout/stderr out.

    CLI invocation::

        python <xsstrike_path> -u <target_url> --skip --skip-dom -d <delay>

    Args:
        target_url: The full URL (including query parameters) to scan.
        xsstrike_path: Filesystem path to ``xsstrike.py`` (e.g.
            ``"XSStrike/xsstrike.py"``).
        delay: Seconds between XSStrike requests.  Passed as ``-d``.
        timeout: Maximum wall-clock seconds before the subprocess is killed.

    Returns:
        dict[str, Any]: A result dictionary with keys:
            - ``stdout`` (str): XSStrike's stdout (ANSI codes stripped).
            - ``stderr`` (str): XSStrike's stderr (ANSI codes stripped).
            - ``exit_code`` (int): Process exit code.
            - ``vulnerable`` (bool): True if any success marker appeared in
              stdout, indicating at least one XSS vector was confirmed.
            - ``error`` (str, optional): Present only when the subprocess
              raised an exception (e.g. timeout).
    """
    cmd: list[str] = [
        sys.executable,
        xsstrike_path,
        "-u", target_url,
        "--skip",
        "--skip-dom",
        "-d", str(delay),
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout_clean = _strip_ansi(completed.stdout)
        stderr_clean = _strip_ansi(completed.stderr)

        vulnerable = any(marker in stdout_clean for marker in _SUCCESS_MARKERS)

        return {
            "stdout": stdout_clean,
            "stderr": stderr_clean,
            "exit_code": completed.returncode,
            "vulnerable": vulnerable,
        }

    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "vulnerable": False,
            "error": f"XSStrike timed out after {timeout}s",
        }
    except FileNotFoundError as exc:
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "vulnerable": False,
            "error": f"XSStrike not found: {exc}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "vulnerable": False,
            "error": str(exc),
        }

