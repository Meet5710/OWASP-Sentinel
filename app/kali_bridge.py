"""OWASP Sentinel - Kali Linux MCP Bridge.

Forwards penetration-testing tool commands to the Kali Linux Tools API / MCP
server running behind the local SSH tunnel (``127.0.0.1:5001`` or ``5000``)
or via the ngrok bridge URL when running in production on Render.
"""

from __future__ import annotations

import logging
import os
import shlex
import time
from urllib.parse import urlparse

import requests

logger = logging.getLogger("sentinel.kali_bridge")

# Local SSH tunnel ports on the host running the Kali VM connection.
DEFAULT_LOCAL_KALI_URLS = ("http://127.0.0.1:5001", "http://127.0.0.1:5000")
# Public ngrok bridge URL used automatically by production (Render) when KALI_API_URL is unset.
DEFAULT_REMOTE_KALI_URL = "https://paltry-graded-landslide.ngrok-free.dev"

_TOOL_AVAILABILITY_CACHE: dict[str, object] = {"ts": 0.0, "status": {}}
_CACHE_TTL_SECONDS = 60.0


def _candidate_kali_urls() -> list[str]:
    """Return ordered Kali MCP candidate URLs for the active runtime environment."""
    env_url = os.environ.get("KALI_API_URL", "").strip().rstrip("/")
    if env_url:
        return [env_url]

    app_env = os.environ.get("APP_ENV", "development").strip().lower()
    if app_env == "production":
        return [DEFAULT_REMOTE_KALI_URL]

    return list(DEFAULT_LOCAL_KALI_URLS)


def get_kali_api_url() -> str:
    """Return the primary Kali MCP server base URL."""
    return _candidate_kali_urls()[0]


TOOL_COMMANDS: dict[str, str] = {
    "nmap": "nmap -sT -sV -T4 -F {extra} {target}",
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
    "ffuf": "ffuf -u {fuzz_target} -w /usr/share/wordlists/dirb/common.txt {extra}",
    "dirsearch": "dirsearch -u {target} {extra}",
    "sqlmap": "sqlmap -u {target} --batch --level=1 --risk=1 {extra}",
    "nuclei": "nuclei -u {target} {extra}",
    "wpscan": "wpscan --url {target} {extra}",
    "whatweb": "whatweb {extra} {target}",
    "wafw00f": "wafw00f {extra} {target}",
    "dirb": "dirb {target} {extra}",
    "httpx": "httpx {extra} {target}",
    "katana": "katana -u {target} {extra}",
    "dalfox": "dalfox url {target} {extra}",
}

# Map catalog names to actual executable names on Kali Linux when they differ.
TOOL_BINARY_ALIASES: dict[str, list[str]] = {
    "theharvester": ["theHarvester", "theharvester"],
    "crackmapexec": ["crackmapexec", "netexec", "nxc"],
    "radare2": ["radare2", "r2"],
    "jwt-tool": ["jwt_tool", "jwt-tool"],
    "pwntools": ["pwn", "pwntools"],
    "scout-suite": ["scout", "scout-suite"],
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
    fuzz_url = normalized_target.rstrip("/") + "/FUZZ"
    safe_fuzz_target = shlex.quote(fuzz_url)
    extra = extra_args.strip()

    # Avoid duplicating flags/subcommands when user/example_args supply them directly.
    if extra and tool_key == "gobuster" and extra.startswith("dir "):
        return " ".join(f"gobuster {extra} -u {safe_target}".split())
    if extra and tool_key == "ffuf":
        base = f"ffuf -u {safe_fuzz_target}"
        if "-w " not in extra and "--wordlist" not in extra:
            base += " -w /usr/share/wordlists/dirb/common.txt"
        return " ".join(f"{base} {extra}".split())
    if extra and tool_key == "feroxbuster" and ("-w " in extra or "--wordlist" in extra):
        return " ".join(f"feroxbuster -u {safe_target} {extra}".split())
    if extra and tool_key == "sqlmap" and ("--batch" in extra or "--level" in extra or "--risk" in extra):
        batch_flag = "" if "--batch" in extra else "--batch"
        return " ".join(f"sqlmap -u {safe_target} {batch_flag} {extra}".split())
    if extra and tool_key == "amass" and extra.startswith("enum "):
        return " ".join(f"amass {extra} {safe_target}".split())
    if extra and tool_key == "nmap" and any(f in extra for f in ("-sV", "-sC", "-sS", "-sT", "-A")):
        return " ".join(f"nmap {extra} {safe_target}".split())
    if extra and tool_key in {"rustscan", "subfinder", "fierce", "theharvester"} and extra in {"-a", "-d", "--domain", "-b all -d"}:
        bin_name = "theHarvester" if tool_key == "theharvester" else tool_key
        return " ".join(f"{bin_name} {extra} {safe_target}".split())

    template = TOOL_COMMANDS.get(tool_key, f"{tool.strip()} {{extra}} {{target}}")
    cmd = template.format(target=safe_target, fuzz_target=safe_fuzz_target, extra=extra)
    return " ".join(cmd.split())


def check_kali_health(timeout: float = 2.0) -> tuple[bool, dict[str, bool]]:
    """Query the Kali MCP server /health endpoint for live connectivity and tool status."""
    for base_url in _candidate_kali_urls():
        try:
            resp = requests.get(
                f"{base_url}/health",
                headers={"ngrok-skip-browser-warning": "true"},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("kali_connected") is False or data.get("status") == "offline":
                continue
            tools_status = data.get("tools_status")
            if isinstance(tools_status, dict):
                return True, {str(k).lower(): bool(v) for k, v in tools_status.items()}
            return True, {}
        except Exception as exc:
            logger.debug("Kali MCP health check failed (%s): %s", base_url, exc)
    return False, {}


def check_catalog_tools_on_kali(tool_names: list[str], force: bool = False) -> dict[str, bool]:
    """Check which catalog tools are actually installed on the remote Kali VM (cached 60s)."""
    now = time.monotonic()
    cached_ts = float(_TOOL_AVAILABILITY_CACHE.get("ts") or 0.0)
    cached_status = _TOOL_AVAILABILITY_CACHE.get("status")
    if not force and isinstance(cached_status, dict) and cached_status and (now - cached_ts) < _CACHE_TTL_SECONDS:
        return dict(cached_status)

    # Expand catalog names into all candidate binary names
    candidates_to_check: list[str] = []
    for name in tool_names:
        key = name.lower()
        for alias in TOOL_BINARY_ALIASES.get(key, [name]):
            if alias not in candidates_to_check:
                candidates_to_check.append(alias)

    quoted_list = " ".join(shlex.quote(c) for c in candidates_to_check)
    probe_cmd = f"which {quoted_list}"
    res = run_tool_on_kali(probe_cmd, timeout=8)
    stdout = res.get("stdout") or ""
    if res.get("returncode") == -1 or not stdout.strip():
        return {}

    found_bins = {os.path.basename(line.strip()) for line in stdout.splitlines() if line.strip()}
    result_map: dict[str, bool] = {}
    for name in tool_names:
        key = name.lower()
        aliases = TOOL_BINARY_ALIASES.get(key, [name])
        result_map[key] = any(a in found_bins for a in aliases)

    _TOOL_AVAILABILITY_CACHE["ts"] = now
    _TOOL_AVAILABILITY_CACHE["status"] = result_map
    return dict(result_map)


def get_kali_mcp_logs_and_processes(lines: int = 40, known_tools: list[str] | None = None) -> dict:
    """Fetch recent Kali MCP server logs and active tool/server processes from the Kali VM."""
    log_res = run_tool_on_kali(f"tail -n {max(lines * 2, 60)} /tmp/kali-server-mcp.log", timeout=5)
    ps_res = run_tool_on_kali("ps -u lucy -o pid,pcpu,etime,args", timeout=5)

    connected = log_res.get("returncode") != -1 or ps_res.get("returncode") != -1
    if not connected:
        return {
            "connected": False,
            "mcp_running": False,
            "active_processes": [],
            "logs": [],
            "error": log_res.get("stderr") or "Kali MCP Server unreachable",
        }

    # Filter repetitive health-check / self-poll log lines so real tool runs stand out
    noise_markers = (
        "GET /health HTTP",
        "Executing command: ['which',",
        "Executing command: which ",
        "Executing command: tail -n ",
        "Executing command: ps -u lucy",
    )
    filtered_logs: list[str] = []
    for raw_line in (log_res.get("stdout") or "").splitlines():
        if any(m in raw_line for m in noise_markers):
            continue
        filtered_logs.append(raw_line)

    tool_tokens = {t.lower() for t in (known_tools or [])} | {
        "kali-server-mcp",
        "nmap",
        "gobuster",
        "feroxbuster",
        "ffuf",
        "nikto",
        "sqlmap",
        "nuclei",
        "wpscan",
        "whatweb",
        "wafw00f",
        "amass",
        "masscan",
        "fierce",
        "hydra",
        "theharvester",
    }

    active_processes: list[dict[str, str]] = []
    mcp_running = False
    for raw_line in (ps_res.get("stdout") or "").splitlines()[1:]:
        parts = raw_line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        pid, cpu, elapsed, cmd = parts
        cmd_lower = cmd.lower()
        if "tail -n " in cmd_lower or "ps -u lucy" in cmd_lower:
            continue
        if "kali-server-mcp" in cmd_lower:
            mcp_running = True
        first_bin = os.path.basename(cmd.split()[0]).lower()
        if "kali-server-mcp" in cmd_lower or first_bin in tool_tokens:
            active_processes.append(
                {
                    "pid": pid,
                    "cpu": cpu,
                    "elapsed": elapsed,
                    "command": cmd,
                }
            )

    return {
        "connected": True,
        "mcp_running": mcp_running,
        "active_processes": active_processes,
        "logs": filtered_logs[-lines:],
        "error": None,
    }


def run_tool_on_kali(command: str, timeout: int = 600) -> dict:
    """Execute a command via the Kali MCP server."""
    candidates = _candidate_kali_urls()
    last_exc: Exception | None = None
    last_url = candidates[0]
    started = time.monotonic()

    for base_url in candidates:
        last_url = base_url
        logger.info("Sending to Kali MCP (%s): %s", base_url, command)
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
            stderr = data.get("stderr") or data.get("error") or ""
            returncode = data.get("return_code")
            if returncode is None:
                returncode = data.get("returncode", 0)

            return {
                "stdout": output,
                "stderr": stderr,
                "returncode": int(returncode),
                "elapsed_seconds": elapsed,
            }
        except requests.ConnectionError as exc:
            last_exc = exc
            continue
        except Exception as exc:
            last_exc = exc
            break

    elapsed = round(time.monotonic() - started, 2)
    logger.error("Kali bridge error (%s): %s", last_url, last_exc)
    return {
        "stdout": "",
        "stderr": (
            f"[!] Failed to connect to Kali MCP Server at {last_url}. "
            f"Is the SSH tunnel running?\nError: {last_exc}"
        ),
        "returncode": -1,
        "elapsed_seconds": elapsed,
    }
