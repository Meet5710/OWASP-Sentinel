"""OWASP Sentinel - Kali Linux MCP Bridge.

Forwards penetration-testing tool commands to the Kali Linux Tools API / MCP
server running behind the local SSH tunnel (default ``http://127.0.0.1:5001``)
or configured via ``KALI_API_URL``.
"""

from __future__ import annotations

import logging
import os
import shlex
import time
from urllib.parse import urlparse

import requests

logger = logging.getLogger("sentinel.kali_bridge")

# Points to the local SSH tunnel forwarding the Kali MCP API server.
DEFAULT_KALI_API_URL = "http://127.0.0.1:5001"


def get_kali_api_url() -> str:
    """Return the configured Kali MCP server base URL."""
    return os.environ.get("KALI_API_URL", DEFAULT_KALI_API_URL).strip().rstrip("/")


TOOL_COMMANDS: dict[str, str] = {
    "nmap": "nmap -sV -sC {extra} {target}",
    "rustscan": "rustscan -a {target} {extra}",
    "masscan": "masscan {target} {extra}",
    "amass": "amass enum -d {target} {extra}",
    "subfinder": "subfinder -d {target} {extra}",
    "fierce": "fierce --domain {target} {extra}",
    "dnsrecon": "dnsrecon -d {target} {extra}",
    "sublist3r": "sublist3r -d {target} {extra}",
    "theharvester": "theHarvester -d {target} -b all {extra}",
    "nikto": "nikto -h {target} {extra}",
    "gobuster": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt {extra}",
    "feroxbuster": "feroxbuster -u {target} {extra}",
    "ffuf": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt {extra}",
    "dirsearch": "dirsearch -u {target} {extra}",
    "sqlmap": "sqlmap -u {target} --batch --level=1 --risk=1 {extra}",
    "nuclei": "nuclei -u {target} {extra}",
    "wpscan": "wpscan --url {target} {extra}",
    "whatweb": "whatweb {extra} {target}",
    "wafw00f": "wafw00f {extra} {target}",
    "dirb": "dirb {target} {extra}",
    "httpx": "httpx -u {target} {extra}",
    "katana": "katana -u {target} {extra}",
    "dalfox": "dalfox url {target} {extra}",
}

# Tools that expect a bare hostname, domain, or IP instead of a full http(s):// URL.
HOST_ONLY_TOOLS = {
    "nmap",
    "rustscan",
    "masscan",
    "autorecon",
    "amass",
    "subfinder",
    "fierce",
    "dnsenum",
    "dnsrecon",
    "sublist3r",
    "theharvester",
    "enum4linux-ng",
    "subjack",
    "waybackurls",
    "gau",
}


def normalize_target_for_tool(tool: str, target: str) -> str:
    """Strip URL scheme/path for tools like nmap/subfinder that expect a hostname or IP."""
    cleaned = target.strip()
    if tool.lower() in HOST_ONLY_TOOLS and "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.hostname:
            return parsed.hostname
    return cleaned


def build_kali_command(tool: str, target: str, extra_args: str = "") -> str:
    """Build a safe command string for the selected Kali tool."""
    tool_key = tool.strip().lower()
    normalized_target = normalize_target_for_tool(tool_key, target)
    safe_target = shlex.quote(normalized_target)
    extra = extra_args.strip()

    # If user explicitly supplied subcommand/flag prefixes matching our default template,
    # avoid duplicating them (e.g. gobuster "dir -w ...", nmap "-sV -sC", amass "enum -d").
    if extra and tool_key == "gobuster" and extra.startswith("dir "):
        return " ".join(f"gobuster {extra} -u {safe_target}".split())
    if extra and tool_key == "amass" and extra.startswith("enum "):
        return " ".join(f"amass {extra} {safe_target}".split())
    if extra and tool_key == "nmap" and ("-sV" in extra or "-sC" in extra):
        return " ".join(f"nmap {extra} {safe_target}".split())
    if extra and tool_key in {"rustscan", "subfinder", "fierce", "theharvester"} and extra in {"-a", "-d", "--domain", "-b all -d"}:
        return " ".join(f"{tool_key} {extra} {safe_target}".split())

    template = TOOL_COMMANDS.get(tool_key, f"{tool.strip()} {{extra}} {{target}}")
    cmd = template.format(target=safe_target, extra=extra)
    return " ".join(cmd.split())


def check_kali_health(timeout: float = 2.0) -> tuple[bool, dict[str, bool]]:
    """Query the Kali MCP server /health endpoint for live connectivity and tool status."""
    base_url = get_kali_api_url()
    try:
        resp = requests.get(
            f"{base_url}/health",
            headers={"ngrok-skip-browser-warning": "true"},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        tools_status = data.get("tools_status")
        if isinstance(tools_status, dict):
            return True, {str(k).lower(): bool(v) for k, v in tools_status.items()}
        return True, {}
    except Exception as exc:
        logger.debug("Kali MCP health check failed (%s): %s", base_url, exc)
        return False, {}


def run_tool_on_kali(command: str, timeout: int = 600) -> dict:
    """Execute a command via the Kali MCP server."""
    base_url = get_kali_api_url()
    logger.info("Sending to Kali MCP (%s): %s", base_url, command)
    started = time.monotonic()
    try:
        response = requests.post(
            f"{base_url}/api/command",
            json={"command": command},
            headers={"ngrok-skip-browser-warning": "true"},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        elapsed = round(
            float(data.get("elapsed_seconds") or (time.monotonic() - started)),
            2,
        )

        output = data.get("output") or data.get("stdout") or ""
        stderr = data.get("stderr") or ""
        returncode = data.get("return_code")
        if returncode is None:
            returncode = data.get("returncode", 0)

        return {
            "stdout": output,
            "stderr": stderr,
            "returncode": int(returncode),
            "elapsed_seconds": elapsed,
        }
    except Exception as exc:
        elapsed = round(time.monotonic() - started, 2)
        logger.error("Kali bridge error: %s", exc)
        return {
            "stdout": "",
            "stderr": (
                f"[!] Failed to connect to Kali MCP Server at {base_url}. "
                f"Is the SSH tunnel running?\nError: {exc}"
            ),
            "returncode": -1,
            "elapsed_seconds": elapsed,
        }
