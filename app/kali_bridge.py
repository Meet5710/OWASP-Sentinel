"""OWASP Sentinel - Kali Linux MCP Bridge.

Forwards penetration-testing tool commands to the Kali Linux Tools API / MCP
server running behind the local SSH tunnel or unified Docker container
(``127.0.0.1:5001`` / ``kali:5000``) or via the ngrok bridge URL on Render.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shlex
import socket
import time
from urllib.parse import urlparse

import requests

logger = logging.getLogger("sentinel.kali_bridge")

# Local container/tunnel ports on the host running the Kali MCP service.
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
    "theharvester",
    "enum4linux-ng",
    "whois",
    "showmount",
    "crackmapexec",
    "smbmap",
    "evil-winrm",
    "kube-hunter",
    "spiderfoot",
    "shodan",
    "censys",
    "subjack",
    "waybackurls",
    "gau",
    "sherlock",
}

# Tools that expect a full http(s):// URL (if omitted, https:// is prepended automatically).
URL_TOOLS = {
    "gobuster",
    "feroxbuster",
    "ffuf",
    "dirsearch",
    "nuclei",
    "nikto",
    "sqlmap",
    "wpscan",
    "dalfox",
    "commix",
    "whatweb",
    "wafw00f",
    "arjun",
    "httpx",
    "katana",
    "gospider",
    "testssl.sh",
    "zap-cli",
    "jwt-tool",
}

# Map catalog names to actual executable names inside the Kali environment.
TOOL_BINARY_ALIASES: dict[str, list[str]] = {
    "theharvester": ["theHarvester", "theharvester"],
    "crackmapexec": ["crackmapexec", "netexec", "nxc"],
    "radare2": ["radare2", "r2"],
    "jwt-tool": ["jwt_tool", "jwt-tool"],
    "pwntools": ["pwn", "pwntools"],
    "scout-suite": ["scout", "scout-suite"],
    "volatility": ["vol", "volatility", "volatility3"],
    "zap-cli": ["zaproxy", "zap.sh", "zap-cli"],
    "testssl.sh": ["testssl.sh", "testssl"],
    "hash-identifier": ["hashid", "hash-identifier"],
    "sleuthkit": ["fls", "mmls", "sleuthkit"],
    "ghidra": ["analyzeHeadless", "ghidra"],
}


def _is_ip_or_cidr(value: str) -> bool:
    """Return True if value is a valid IPv4/IPv6 address or CIDR range."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _resolve_ipv4_if_hostname(target: str) -> str:
    """Resolve a domain name to IPv4 for tools like masscan that reject hostnames."""
    if _is_ip_or_cidr(target):
        return target
    try:
        return socket.gethostbyname(target)
    except OSError:
        return target


def normalize_target_for_tool(tool: str, target: str) -> str:
    """Normalize any user-entered target (URL, domain, IP, path, token) for the chosen tool."""
    cleaned = target.strip()
    tool_key = tool.strip().lower()

    if tool_key in HOST_ONLY_TOOLS:
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            if parsed.hostname:
                return parsed.hostname
        # Strip trailing path/slashes on bare domain inputs like example.com/login
        return cleaned.split("/")[0].split(":")[0] if "/" in cleaned else cleaned

    if tool_key in URL_TOOLS:
        # Preserve raw JWT tokens when passed directly to jwt-tool
        if tool_key == "jwt-tool" and cleaned.startswith("eyJ") and cleaned.count(".") >= 2:
            return cleaned
        if "://" not in cleaned:
            return f"https://{cleaned}"
        return cleaned

    return cleaned


def build_kali_command(tool: str, target: str, extra_args: str = "") -> str:
    """Build a reliable, non-interactive command string for any of the 72 Kali tools."""
    tool_key = tool.strip().lower()
    norm_target = normalize_target_for_tool(tool_key, target)
    safe_target = shlex.quote(norm_target)
    fuzz_target = shlex.quote(norm_target.rstrip("/") + "/FUZZ")
    extra = extra_args.strip()

    # ------------------------------------------------------------------
    # Network Reconnaissance & Scanning
    # ------------------------------------------------------------------
    if tool_key == "nmap":
        if any(f in extra for f in ("-sV", "-sC", "-sS", "-sT", "-A", "-sn")):
            return " ".join(f"nmap {extra} {safe_target}".split())
        return " ".join(f"nmap -sT -sV -T4 -F {extra} {safe_target}".split())

    if tool_key == "rustscan":
        flags = extra if extra else "--ulimit 5000"
        if flags == "-a":
            flags = "--ulimit 5000"
        return " ".join(f"rustscan -a {safe_target} {flags}".split())

    if tool_key == "masscan":
        ip_target = shlex.quote(_resolve_ipv4_if_hostname(norm_target))
        flags = extra if extra else "-p80,443 --rate=1000"
        if "--rate" not in flags:
            flags = f"{flags} --rate=1000"
        return " ".join(f"masscan {ip_target} {flags}".split())

    if tool_key == "autorecon":
        base = "autorecon --disable-keyboard-control --disable-sanity-checks -o /tmp/autorecon_out --only-scans-dir"
        if "--target-timeout" not in extra:
            base += " --target-timeout 3"
        return " ".join(f"{base} {extra} {safe_target}".split())

    if tool_key == "amass":
        if extra.startswith("enum "):
            return " ".join(f"amass {extra} {safe_target}".split())
        if "-d" in extra:
            return " ".join(f"amass enum {extra} {safe_target}".split())
        return " ".join(f"amass enum -d {safe_target} {extra}".split())

    if tool_key == "subfinder":
        if extra == "-d":
            extra = "-silent"
        return " ".join(f"subfinder -d {safe_target} {extra or '-silent'}".split())

    if tool_key == "fierce":
        if extra == "--domain":
            extra = ""
        return " ".join(f"fierce --domain {safe_target} {extra}".split())

    if tool_key == "dnsenum":
        flags = extra if extra else "--noreverse"
        return " ".join(f"dnsenum {flags} {safe_target}".split())

    if tool_key == "theharvester":
        if extra in {"-b all -d", "-d"}:
            extra = "-b crtsh,duckduckgo,hackertarget"
        elif "-b" not in extra:
            extra = f"-b crtsh,duckduckgo,hackertarget {extra}".strip()
        return " ".join(f"theHarvester -d {safe_target} {extra}".split())

    if tool_key == "responder":
        flags = extra if extra else "-I eth0 -A"
        return " ".join(f"responder {flags}".split())

    if tool_key == "enum4linux-ng":
        return " ".join(f"enum4linux-ng {extra or '-A'} {safe_target}".split())

    if tool_key == "whois":
        return " ".join(f"whois {extra} {safe_target}".split())

    if tool_key == "showmount":
        if "-e" in extra:
            return " ".join(f"showmount {extra} {safe_target}".split())
        return " ".join(f"showmount -e {safe_target} {extra}".split())

    # ------------------------------------------------------------------
    # Web Application Security
    # ------------------------------------------------------------------
    if tool_key == "gobuster":
        if extra.startswith(("dir ", "dns ", "vhost ", "fuzz ")):
            if "-u " in extra:
                return " ".join(f"gobuster {extra}".split())
            return " ".join(f"gobuster {extra} -u {safe_target}".split())
        return " ".join(
            f"gobuster dir -u {safe_target} -w /usr/share/wordlists/dirb/common.txt -k --no-error {extra}".split()
        )

    if tool_key == "feroxbuster":
        base = f"feroxbuster -u {safe_target} -k --no-state"
        if "-w " not in extra and "--wordlist" not in extra:
            base += " -w /usr/share/wordlists/dirb/common.txt"
        if "--depth" not in extra and "-d " not in extra:
            base += " --depth 1"
        return " ".join(f"{base} {extra}".split())

    if tool_key == "ffuf":
        base = f"ffuf -u {fuzz_target}"
        if "-w " not in extra and "--wordlist" not in extra:
            base += " -w /usr/share/wordlists/dirb/common.txt"
        if "-mc" not in extra:
            base += " -mc 200,301,302"
        return " ".join(f"{base} {extra}".split())

    if tool_key == "dirsearch":
        flags = extra if extra else "-e php,html,js"
        return " ".join(f"dirsearch -u {safe_target} {flags}".split())

    if tool_key == "nuclei":
        flags = extra if extra else "-severity critical,high,medium"
        return " ".join(f"nuclei -u {safe_target} {flags}".split())

    if tool_key == "nikto":
        flags = extra if extra else "-maxtime 60s"
        return " ".join(f"nikto -h {safe_target} {flags}".split())

    if tool_key == "sqlmap":
        parts = [f"sqlmap -u {safe_target}"]
        if "--batch" not in extra:
            parts.append("--batch")
        if "?" not in norm_target and "--forms" not in extra and "--crawl" not in extra:
            parts.append("--forms --crawl=1")
        if "--level" not in extra and "--risk" not in extra:
            parts.append(extra or "--level=1 --risk=1")
        elif extra:
            parts.append(extra)
        return " ".join(" ".join(parts).split())

    if tool_key == "wpscan":
        flags = extra if extra else "--enumerate vp"
        return " ".join(f"wpscan --url {safe_target} --no-banner {flags}".split())

    if tool_key == "dalfox":
        return " ".join(f"dalfox url {safe_target} --silence {extra}".split())

    if tool_key == "commix":
        batch_flag = "" if "--batch" in extra else "--batch"
        return " ".join(f"commix -u {safe_target} {batch_flag} {extra}".split())

    if tool_key == "whatweb":
        return " ".join(f"whatweb {extra} {safe_target}".split())

    if tool_key == "wafw00f":
        return " ".join(f"wafw00f {extra} {safe_target}".split())

    if tool_key == "arjun":
        return " ".join(f"arjun -u {safe_target} {extra}".split())

    if tool_key == "httpx":
        flags = extra if extra else "-tech-detect -status-code -title -silent"
        return " ".join(f"httpx -u {safe_target} {flags}".split())

    if tool_key == "katana":
        flags = extra if extra else "-jc -d 2 -silent"
        return " ".join(f"katana -u {safe_target} {flags}".split())

    if tool_key == "gospider":
        flags = extra if extra else "-d 2 -c 5"
        return " ".join(f"gospider -s {safe_target} {flags}".split())

    if tool_key == "testssl.sh":
        flags = extra if extra else "--fast"
        return " ".join(f"testssl.sh --color 0 {flags} {safe_target}".split())

    if tool_key == "jwt-tool":
        if norm_target.startswith("eyJ") and norm_target.count(".") >= 2:
            return " ".join(f"jwt_tool {safe_target} {extra}".split())
        return " ".join(f"jwt_tool -t {safe_target} {extra}".split())

    if tool_key == "zap-cli":
        return " ".join(f"zaproxy -cmd -quickurl {safe_target} -quickout /tmp/zap_report.html {extra}".split())

    # ------------------------------------------------------------------
    # Authentication & Password Security
    # ------------------------------------------------------------------
    if tool_key == "hydra":
        return " ".join(f"hydra {extra} {safe_target}".split())

    if tool_key == "john":
        return " ".join(f"john {extra} {safe_target}".split())

    if tool_key == "hashcat":
        return " ".join(f"hashcat {extra} {safe_target}".split())

    if tool_key == "medusa":
        return " ".join(f"medusa -h {safe_target} {extra}".split())

    if tool_key == "patator":
        return " ".join(f"patator {extra}".split()) if extra else "patator --help"

    if tool_key == "crackmapexec":
        if extra.startswith(("smb ", "winrm ", "ssh ", "ldap ", "ftp ", "mssql ", "rdp ")):
            return " ".join(f"crackmapexec {extra} {safe_target}".split())
        return " ".join(f"crackmapexec smb {safe_target} {extra}".split())

    if tool_key == "smbmap":
        if "-H" in extra:
            return " ".join(f"smbmap {extra}".split())
        return " ".join(f"smbmap -H {safe_target} {extra}".split())

    if tool_key == "evil-winrm":
        if "-i" in extra:
            return " ".join(f"evil-winrm {extra}".split())
        return " ".join(f"evil-winrm -i {safe_target} {extra}".split())

    if tool_key == "hash-identifier":
        return " ".join(f"hashid {extra} {safe_target}".split())

    # ------------------------------------------------------------------
    # Binary Analysis & Reverse Engineering
    # ------------------------------------------------------------------
    if tool_key == "gdb":
        return " ".join(f'gdb -batch -ex "info functions" {extra} {safe_target}'.split())

    if tool_key == "radare2":
        return " ".join(f'r2 -q -c "aaa;afl" {extra} {safe_target}'.split())

    if tool_key == "ghidra":
        return " ".join(f"analyzeHeadless /tmp ghidra_proj -import {safe_target} -deleteProject {extra}".split())

    if tool_key == "binwalk":
        return " ".join(f"binwalk {extra} {safe_target}".split())

    if tool_key in {"checksec", "pwntools"}:
        return " ".join(f"pwn checksec {extra} {safe_target}".split())

    if tool_key == "strings":
        return " ".join(f"strings {extra or '-n 8'} {safe_target}".split())

    if tool_key == "objdump":
        return " ".join(f"objdump {extra or '-d'} {safe_target}".split())

    if tool_key == "ropgadget":
        return " ".join(f"ROPgadget --binary {safe_target} {extra}".split())

    # ------------------------------------------------------------------
    # Cloud & Container Security
    # ------------------------------------------------------------------
    if tool_key == "prowler":
        providers = ("aws", "azure", "gcp", "kubernetes", "m365", "github", "iac", "image", "llm")
        if extra.startswith(providers):
            return " ".join(f"prowler {extra}".split())
        if norm_target.lower() in providers:
            return " ".join(f"prowler {safe_target} {extra}".split())
        return " ".join(f"prowler {extra} {safe_target}".split())

    if tool_key == "scout-suite":
        return " ".join(f"scout {extra} {safe_target}".split())

    if tool_key == "trivy":
        if extra.startswith(("image ", "fs ", "repo ", "config ", "k8s ")):
            return " ".join(f"trivy {extra} {safe_target}".split())
        subcmd = "repo" if norm_target.startswith(("http://", "https://")) else ("fs" if norm_target.startswith("/") else "image")
        return " ".join(f"trivy {subcmd} {extra} {safe_target}".split())

    if tool_key == "kube-hunter":
        if "--remote" in extra:
            return " ".join(f"kube-hunter {extra} {safe_target}".split())
        return " ".join(f"kube-hunter --remote {safe_target} {extra}".split())

    if tool_key == "kube-bench":
        return " ".join(f"kube-bench {extra}".split())

    if tool_key == "docker-bench-security":
        return f"sh -c {shlex.quote(f'cd /opt/docker-bench-security && sh docker-bench-security.sh {extra}'.strip())}"

    if tool_key == "checkov":
        if "-d " in extra or "-f " in extra:
            return " ".join(f"checkov {extra}".split())
        return " ".join(f"checkov -d {safe_target} {extra}".split())

    # ------------------------------------------------------------------
    # CTF & Forensics
    # ------------------------------------------------------------------
    if tool_key == "volatility":
        return " ".join(f"vol -f {safe_target} {extra or 'windows.info'}".split())

    if tool_key == "foremost":
        return " ".join(f"foremost -i {safe_target} -o /tmp/foremost_out {extra}".split())

    if tool_key == "steghide":
        return " ".join(f"steghide {extra or 'info'} -sf {safe_target}".split())

    if tool_key == "exiftool":
        return " ".join(f"exiftool {extra} {safe_target}".split())

    if tool_key == "autopsy":
        return " ".join(f"autopsy {extra}".split()) if extra else "autopsy -h"

    if tool_key == "sleuthkit":
        return " ".join(f"fls {extra} {safe_target}".split())

    # ------------------------------------------------------------------
    # Bug Bounty & OSINT Arsenal
    # ------------------------------------------------------------------
    if tool_key == "sherlock":
        return " ".join(f"sherlock --timeout 5 --print-found {extra} {safe_target}".split())

    if tool_key == "spiderfoot":
        flags = extra if extra else "-u passive -o tab -q"
        return " ".join(f"spiderfoot -s {safe_target} {flags}".split())

    if tool_key == "shodan":
        if extra.startswith(("host ", "domain ", "search ", "count ", "stats ")):
            return " ".join(f"shodan {extra} {safe_target}".split())
        subcmd = "host" if _is_ip_or_cidr(norm_target) else "domain"
        return " ".join(f"shodan {subcmd} {safe_target} {extra}".split())

    if tool_key == "censys":
        if extra.startswith(("search ", "view ", "subdomains ", "asm ")):
            return " ".join(f"censys {extra} {safe_target}".split())
        return " ".join(f"censys search {safe_target} {extra}".split())

    if tool_key == "subjack":
        return " ".join(f"subjack -d {safe_target} -a {extra}".split())

    if tool_key == "trufflehog":
        if extra.startswith(("git ", "github ", "filesystem ", "s3 ")):
            return " ".join(f"trufflehog {extra} {safe_target}".split())
        subcmd = "git" if norm_target.startswith(("http://", "https://", "git@")) else "filesystem"
        return " ".join(f"trufflehog {subcmd} {safe_target} {extra}".split())

    if tool_key == "waybackurls":
        inner = f"printf '%s\\n' {safe_target} | waybackurls {extra}".strip()
        return f"sh -c {shlex.quote(inner)}"

    if tool_key == "gau":
        flags = extra if extra else "--threads 4"
        return " ".join(f"gau {flags} {safe_target}".split())

    return " ".join(f"{tool.strip()} {extra} {safe_target}".split())


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
    """Check which catalog tools are actually installed on the remote Kali host (cached 60s)."""
    now = time.monotonic()
    cached_ts = float(_TOOL_AVAILABILITY_CACHE.get("ts") or 0.0)
    cached_status = _TOOL_AVAILABILITY_CACHE.get("status")
    if not force and isinstance(cached_status, dict) and cached_status and (now - cached_ts) < _CACHE_TTL_SECONDS:
        return dict(cached_status)

    candidates_to_check: list[str] = []
    for name in tool_names:
        key = name.lower()
        for alias in TOOL_BINARY_ALIASES.get(key, [name]):
            if alias not in candidates_to_check:
                candidates_to_check.append(alias)

    quoted_list = " ".join(shlex.quote(c) for c in candidates_to_check)
    probe_cmd = f'PATH="$PATH:/usr/local/bin:/root/go/bin:/root/.local/bin" which {quoted_list}'
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
    """Fetch recent Kali MCP server logs and active tool/server processes from Docker or VM."""
    base_url = get_kali_api_url()
    tool_tokens = {t.lower() for t in (known_tools or [])} | {
        "kali-server-mcp",
        "kali_server.py",
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
        "subfinder",
        "katana",
        "httpx",
        "masscan",
        "fierce",
        "hydra",
        "theharvester",
        "msfconsole",
    }

    active_processes: list[dict[str, str]] = []
    mcp_running = False
    connected = False

    # 1. Prefer structured /api/ps endpoint (provided by zebbern-kali Docker container)
    try:
        ps_api = requests.get(
            f"{base_url}/api/ps",
            headers={"ngrok-skip-browser-warning": "true"},
            timeout=3,
        )
        if ps_api.status_code == 200:
            connected = True
            for proc in ps_api.json().get("processes", []):
                cmd = str(proc.get("command") or "")
                cmd_lower = cmd.lower()
                is_mcp = "kali_server.py" in cmd_lower or "kali-server-mcp" in cmd_lower or ("server.py" in cmd_lower and "5000" in cmd_lower)
                if is_mcp:
                    mcp_running = True
                cmd_words = {os.path.basename(w).lower() for w in cmd.split()[:3]}
                if is_mcp or any(w in tool_tokens for w in cmd_words):
                    active_processes.append(
                        {
                            "pid": str(proc.get("pid", "")),
                            "cpu": f"{round(float(proc.get('rss_kb', 0)) / 1024, 1)}M",
                            "elapsed": str(proc.get("elapsed", "")),
                            "command": cmd,
                        }
                    )
    except Exception:
        pass

    # 2. Fallback to `ps -eo` if /api/ps is unavailable
    if not active_processes:
        ps_res = run_tool_on_kali("ps -eo pid,pcpu,etime,args", timeout=5)
        if ps_res.get("returncode") != -1:
            connected = True
            for raw_line in (ps_res.get("stdout") or "").splitlines()[1:]:
                parts = raw_line.strip().split(None, 3)
                if len(parts) < 4:
                    continue
                pid, cpu, elapsed, cmd = parts
                cmd_lower = cmd.lower()
                if "tail -n " in cmd_lower or "ps -eo" in cmd_lower:
                    continue
                is_mcp = "kali_server.py" in cmd_lower or "kali-server-mcp" in cmd_lower or ("server.py" in cmd_lower and "5000" in cmd_lower)
                if is_mcp:
                    mcp_running = True
                cmd_words = {os.path.basename(w).lower() for w in cmd.split()[:3]}
                if is_mcp or any(w in tool_tokens for w in cmd_words):
                    active_processes.append(
                        {
                            "pid": pid,
                            "cpu": cpu,
                            "elapsed": elapsed,
                            "command": cmd,
                        }
                    )

    if not connected:
        return {
            "connected": False,
            "mcp_running": False,
            "active_processes": [],
            "logs": [],
            "error": "Kali MCP Server unreachable",
        }

    # 3. Fetch logs from Docker /app/tmp/jobs or VMware /tmp/kali-server-mcp.log
    log_res = run_tool_on_kali(
        f"sh -c 'if [ -f /tmp/kali-server-mcp.log ]; then tail -n {max(lines * 2, 60)} /tmp/kali-server-mcp.log; "
        f"elif [ -d /app/tmp/jobs ]; then ls -lt /app/tmp/jobs 2>/dev/null | head -n 20; fi'",
        timeout=5,
    )

    noise_markers = (
        "GET /health HTTP",
        "GET /live HTTP",
        "Executing command: ['which',",
        "Executing command: which ",
        "which ",
        "tail -n ",
        "ps -eo",
    )
    filtered_logs: list[str] = []
    for raw_line in (log_res.get("stdout") or "").splitlines():
        if any(m in raw_line for m in noise_markers):
            continue
        filtered_logs.append(raw_line)

    if not filtered_logs and active_processes:
        filtered_logs = [f"[active] PID {p['pid']} ({p['elapsed']}): {p['command']}" for p in active_processes]

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
            f"Is the container running?\nError: {last_exc}"
        ),
        "returncode": -1,
        "elapsed_seconds": elapsed,
    }
