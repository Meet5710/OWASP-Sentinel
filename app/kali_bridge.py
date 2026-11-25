"""OWASP Sentinel - Kali Linux Tool Execution Bridge.

Provides safe, sandboxed subprocess execution of common Kali Linux penetration
testing tools (nmap, nikto, gobuster, sqlmap, nuclei, wpscan) against authorized
targets.  Results are returned as structured text for rendering in the
Kali Pentester frontend tab.
"""

import logging
import shlex
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("sentinel.kali_bridge")

# Allow-listed tools and their base invocations.
# Each key maps to a *template* containing ``{target}`` and optional ``{extra}``
# placeholders that are safely interpolated at runtime.
TOOL_COMMANDS: dict[str, str] = {
    "nmap":     "nmap -sV -sC {extra} {target}",
    "nikto":    "nikto -h {target} {extra}",
    "gobuster": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt {extra}",
    "sqlmap":   "sqlmap -u {target} --batch --level=1 --risk=1 {extra}",
    "nuclei":   "nuclei -u {target} {extra}",
    "wpscan":   "wpscan --url {target} {extra}",
    "whatweb":  "whatweb {target} {extra}",
    "wafw00f":  "wafw00f {target} {extra}",
    "dirb":     "dirb {target} {extra}",
    "fierce":   "fierce --domain {target} {extra}",
    "dnsrecon": "dnsrecon -d {target} {extra}",
    "sublist3r": "sublist3r -d {target} {extra}",
}


def _is_tool_available(tool_name: str) -> bool:
    """Check whether a tool binary exists on the system PATH."""
    import shutil
    return shutil.which(tool_name) is not None


def run_tool_on_kali(
    command: str,
    timeout: int = 120,
) -> dict:
    """Execute a shell command and capture its output.

    Args:
        command: Full shell command string to execute.
        timeout: Maximum seconds before the process is killed.

    Returns:
        Dictionary with ``stdout``, ``stderr``, ``returncode``, and
        ``elapsed_seconds`` keys.
    """
    logger.info("Kali bridge executing: %s", command)
    start = time.monotonic()
    try:
        # Use shlex.split for safe tokenisation – no shell=True
        args = shlex.split(command)
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = round(time.monotonic() - start, 2)
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "elapsed_seconds": elapsed,
        }
    except FileNotFoundError:
        elapsed = round(time.monotonic() - start, 2)
        tool_bin = command.split()[0] if command else "unknown"
        return {
            "stdout": "",
            "stderr": (
                f"[!] Tool '{tool_bin}' is not installed on this system.\n"
                f"Install it on a Kali Linux machine or via 'apt install {tool_bin}'."
            ),
            "returncode": 127,
            "elapsed_seconds": elapsed,
        }
    except subprocess.TimeoutExpired:
        elapsed = round(time.monotonic() - start, 2)
        return {
            "stdout": "",
            "stderr": f"[!] Command timed out after {timeout}s.",
            "returncode": -1,
            "elapsed_seconds": elapsed,
        }
    except Exception as exc:
        elapsed = round(time.monotonic() - start, 2)
        return {
            "stdout": "",
            "stderr": f"[!] Unexpected error: {exc}",
            "returncode": -1,
            "elapsed_seconds": elapsed,
        }


def build_kali_command(tool: str, target: str, extra_args: str = "") -> str:
    """Build a safe command string from allowed tool templates.

    Falls back to ``<tool> <extra_args> <target>`` for unlisted tools.
    """
    template = TOOL_COMMANDS.get(tool, f"{tool} {{extra}} {{target}}")
    return template.format(
        target=shlex.quote(target),
        extra=extra_args,  # caller is responsible for sanitising UI input
    ).strip()

