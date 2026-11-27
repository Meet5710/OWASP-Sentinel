"""OWASP Sentinel - Kali Linux Docker Container Bridge.

Forwards penetration-testing tool commands to the unified Kali Docker container API
(``127.0.0.1:5001`` / ``kali:5000``) or via the ngrok bridge URL on Render.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
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
    "dnsrecon",
    "theharvester",
    "enum4linux-ng",
    "whois",
    "showmount",
    "crackmapexec",
    "smbmap",
    "evil-winrm",
    "hydra",
    "medusa",
    "patator",
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
    "nosqlmap",
    "jaeles",
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
        flags = extra if extra else "-p- -sV -sC -A -T4 -Pn --script vuln,vulners --script-args mincvss=7.0"
        return " ".join(f"nmap {flags} {safe_target}".split())

    if tool_key == "rustscan":
        if "-a " in extra:
            return " ".join(f"rustscan {extra}".split())
        flags = extra if extra else "--ulimit 5000 -- -sV -sC -A"
        return " ".join(f"rustscan -a {safe_target} {flags}".split())

    if tool_key == "masscan":
        ip_target = shlex.quote(_resolve_ipv4_if_hostname(norm_target))
        flags = extra if extra else "-p1-65535 --rate 10000 -oJ /tmp/masscan_out.json"
        if "--rate" not in flags:
            flags = f"{flags} --rate 10000"
        run_cmd = " ".join(f"masscan {ip_target} {flags}".split())
        if "-oJ /tmp/masscan_out.json" in flags:
            return f"sh -c {shlex.quote(f'rm -f /tmp/masscan_out.json; {run_cmd}; rc=$?; [ -s /tmp/masscan_out.json ] && cat /tmp/masscan_out.json; exit $rc')}"
        return run_cmd

    if tool_key == "autorecon":
        extra_tokens = extra.split()
        base = (
            "autorecon --disable-keyboard-control --disable-sanity-checks "
            "-o /tmp/autorecon_out --only-scans-dir --heartbeat 15"
        )
        if "--timeout" not in extra_tokens:
            base += " --timeout 5"
        if "--target-timeout" not in extra_tokens:
            base += " --target-timeout 5"
        nmap_append = "" if ("--nmap-append" in extra or "--nmap" in extra_tokens) else '--nmap-append="-p- -sV -sC -A"'
        run_cmd = " ".join(f"{base} {nmap_append} {extra} {safe_target}".split())
        out_dir = shlex.quote(f"/tmp/autorecon_out/{norm_target}")
        scan_dir = shlex.quote(f"/tmp/autorecon_out/{norm_target}/scans")
        inner = (
            f"rm -rf {out_dir}; {run_cmd}; rc=$?; "
            f"if [ -d {scan_dir} ]; then "
            f"echo ''; echo '=== AutoRecon Scan Results ==='; "
            f"for f in $(find {scan_dir} -maxdepth 2 -type f -name '*.txt' ! -name '_manual_commands.txt' ! -name '_commands.log' | sort); do "
            f"[ -s \"$f\" ] && echo \"\\n--- $f ---\" && head -n 80 \"$f\"; "
            f"done; fi; exit $rc"
        )
        return f"sh -c {shlex.quote(inner)}"

    if tool_key == "amass":
        extra_tokens = extra.split()
        extra_flags = extra if extra else "-active -brute -oA /tmp/amass_out"
        if "-nocolor" not in extra_tokens:
            extra_flags = f"-nocolor {extra_flags}".strip()
        if "-timeout" not in extra_tokens:
            extra_flags = f"-timeout 3 {extra_flags}".strip()
        if extra.startswith("enum "):
            amass_cmd = " ".join(f"amass {extra_flags} {safe_target}".split())
        elif "-d " in extra or "-d" in extra_tokens:
            amass_cmd = " ".join(f"amass enum {extra_flags} {safe_target}".split())
        else:
            amass_cmd = " ".join(f"amass enum -d {safe_target} {extra_flags}".split())
        inner = f"{amass_cmd}; rc=$?; pkill -f '[a]mass engine' 2>/dev/null || true; exit $rc"
        return f"sh -c {shlex.quote(inner)}"

    if tool_key == "subfinder":
        flags = extra if extra else "-all -silent -o /tmp/subfinder_out.txt"
        return " ".join(f"subfinder -d {safe_target} {flags}".split())

    if tool_key == "fierce":
        flags = extra if extra else "--wide"
        return " ".join(f"fierce --domain {safe_target} {flags}".split())

    if tool_key == "dnsenum":
        flags = extra if extra else "-f /usr/share/wordlists/dnsmap.txt --threads 10"
        return " ".join(f"dnsenum {flags} {safe_target}".split())

    if tool_key == "dnsrecon":
        flags = extra if extra else "-t std,brt,axfr -D /usr/share/wordlists/dnsmap.txt"
        return " ".join(f"dnsrecon -d {safe_target} {flags}".split())

    if tool_key == "theharvester":
        flags = extra if extra else "-b all -l 500 -f /tmp/theharvester_out.html"
        if "-b" not in flags:
            flags = f"-b all {flags}"
        return " ".join(f"theHarvester -d {safe_target} {flags}".split())

    if tool_key == "responder":
        flags = extra if extra else "-I eth0 -wdv"
        return " ".join(f"responder {flags}".split())

    if tool_key == "enum4linux-ng":
        flags = extra if extra else "-A -oJ /tmp/enum4linux_out"
        return " ".join(f"enum4linux-ng {flags} {safe_target}".split())

    if tool_key == "whois":
        extra_tokens = extra.split()
        flags = extra
        if (
            "--no-recursion" not in extra_tokens
            and "-I" not in extra_tokens
            and "-h" not in extra_tokens
            and "--host" not in extra_tokens
        ):
            flags = f"--no-recursion -H {flags}".strip()
        return " ".join(f"whois {flags} {safe_target}".split())

    if tool_key == "showmount":
        if "-e" in extra:
            return " ".join(f"showmount {extra} {safe_target}".split())
        return " ".join(f"showmount -e {safe_target} {extra}".split())

    # ------------------------------------------------------------------
    # Web Application Security
    # ------------------------------------------------------------------
    if tool_key == "gobuster":
        if extra.startswith(("dir ", "dns ", "vhost ", "fuzz ")):
            subcmd = extra.split()[0]
            if subcmd == "dns":
                if "-d " in extra or "--domain " in extra:
                    return " ".join(f"gobuster {extra}".split())
                dns_host = normalize_target_for_tool("subfinder", target)
                return " ".join(f"gobuster {extra} -d {shlex.quote(dns_host)}".split())
            if "-u " in extra or "--url " in extra:
                return " ".join(f"gobuster {extra}".split())
            return " ".join(f"gobuster {extra} -u {safe_target}".split())

        extra_tokens = extra.split()
        parts = [f"gobuster dir -u {safe_target}"]
        if "-w " not in extra and "-w" not in extra_tokens and "--wordlist" not in extra:
            parts.append("-w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt")
        if "-x " not in extra and "-x" not in extra_tokens and "--extensions" not in extra:
            parts.append("-x php,html,js")
        if "-t " not in extra and "-t" not in extra_tokens and "--threads" not in extra:
            parts.append("-t 50")
        if "-k" not in extra_tokens and "--no-tls-validation" not in extra:
            parts.append("-k")
        if "--no-error" not in extra and "--ne" not in extra_tokens:
            parts.append("--no-error")
        if "--np" not in extra_tokens and "--no-progress" not in extra:
            parts.append("--np")
        if extra:
            parts.append(extra)
        return " ".join(" ".join(parts).split())

    if tool_key == "feroxbuster":
        extra_tokens = extra.split()
        base = f"feroxbuster -u {safe_target}"
        if "-w " not in extra and "-w" not in extra_tokens and "--wordlist" not in extra:
            base += " -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
        if "-x " not in extra and "-x" not in extra_tokens and "--extensions" not in extra:
            base += " -x php,html,txt,js,json"
        if "-t " not in extra and "-t" not in extra_tokens and "--threads" not in extra:
            base += " -t 50"
        if "-d " not in extra and "-d" not in extra_tokens and "--depth" not in extra:
            base += " -d 4"
        if "-k" not in extra_tokens and "--insecure" not in extra:
            base += " -k"
        if "--smart" not in extra_tokens:
            base += " --smart"
        if "--no-state" not in extra:
            base += " --no-state"
        return " ".join(f"{base} {extra}".split())

    if tool_key == "ffuf":
        extra_tokens = extra.split()
        ffuf_url = shlex.quote(norm_target if "FUZZ" in norm_target else norm_target.rstrip("/") + "/FUZZ")
        base = f"ffuf -u {ffuf_url}"
        if "-w " not in extra and "--wordlist" not in extra:
            base += " -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
        if "-mc" not in extra:
            base += " -mc 200,204,301,302,307,401,403"
        if "-t " not in extra and "-t" not in extra_tokens:
            base += " -t 50"
        if "-recursion" not in extra_tokens:
            base += " -recursion -recursion-depth 2"
        return " ".join(f"{base} {extra}".split())

    if tool_key == "dirsearch":
        extra_tokens = extra.split()
        flags = extra if extra else "-e '*' -r -R 4 -t 50 --crawl --random-agent"
        if "-q" not in extra_tokens and "--quiet-mode" not in extra_tokens:
            flags = f"-q {flags}"
        if "--no-color" not in extra_tokens:
            flags = f"--no-color {flags}"
        if "--max-time" not in extra:
            flags = f"--max-time=480 {flags}"
        return " ".join(f"dirsearch -u {safe_target} {flags}".split())

    if tool_key == "nuclei":
        flags = extra if extra else "-severity critical,high,medium -stats -rl 100 -c 50"
        return " ".join(f"nuclei -u {safe_target} {flags}".split())

    if tool_key == "nikto":
        flags = extra if extra else "-C all -Tuning 1234567890bde -maxtime 9m"
        return " ".join(f"nikto -h {safe_target} {flags}".split())

    if tool_key == "sqlmap":
        parts = [f"sqlmap -u {safe_target}"]
        if "--batch" not in extra:
            parts.append("--batch")
        if extra:
            parts.append(extra)
        else:
            parts.append("--level=5 --risk=3 --dbs --threads=10 --random-agent")
        return " ".join(" ".join(parts).split())

    if tool_key == "wpscan":
        flags = extra if extra else "--enumerate vp,vt,u,dbe --plugins-detection aggressive --random-user-agent"
        banner_flag = "" if "--no-banner" in flags else "--no-banner"
        return " ".join(f"wpscan --url {safe_target} {banner_flag} {flags}".split())

    if tool_key == "dalfox":
        flags = extra if extra else "--deep-domxss --mining-dom"
        silence_flag = "" if "--silence" in flags else "--silence"
        return " ".join(f"dalfox url {safe_target} {silence_flag} {flags}".split())

    if tool_key == "commix":
        flags = extra if extra else "--batch --level=3"
        batch_flag = "" if "--batch" in flags else "--batch"
        return " ".join(f"commix --url={safe_target} {batch_flag} {flags}".split())

    if tool_key == "nosqlmap":
        flags = extra if extra else "--attack 2"
        return " ".join(f"nosqlmap -u {safe_target} {flags}".split())

    if tool_key == "jaeles":
        flags = extra if extra else "-c 20"
        return " ".join(f"jaeles scan {flags} -u {safe_target}".split())

    if tool_key == "whatweb":
        flags = extra if extra else "-a 3 --log-verbose=/tmp/whatweb_out.txt"
        return " ".join(f"whatweb {flags} {safe_target}".split())

    if tool_key == "wafw00f":
        flags = extra if extra else "-a -v"
        return " ".join(f"wafw00f {safe_target} {flags}".split())

    if tool_key == "arjun":
        flags = extra if extra else "-m GET,POST,JSON --stable"
        return " ".join(f"arjun -u {safe_target} {flags}".split())

    if tool_key == "httpx":
        flags = extra if extra else "-tech-detect -status-code -title -web-server -cdn -vhost"
        return " ".join(f"httpx -u {safe_target} {flags}".split())

    if tool_key == "katana":
        flags = extra if extra else "-jc -kf all -d 5 -ef woff,css,png,svg,jpg,woff2,jpeg,gif -jsonl -o /tmp/katana_out.jsonl"
        return " ".join(f"katana -u {safe_target} {flags}".split())

    if tool_key == "gospider":
        flags = extra if extra else "-d 5 -t 20 -c 10 --js --sitemap --robots -o /tmp/gospider_out"
        return " ".join(f"gospider -s {safe_target} {flags}".split())

    if tool_key == "testssl.sh":
        flags = extra if extra else "--full --vulnerable --headers"
        if "--warnings" not in flags:
            flags = f"--warnings off {flags}"
        return " ".join(f"testssl --color 0 {flags} {safe_target}".split())

    if tool_key == "jwt-tool":
        noproxy = "" if ("-np" in extra.split() or "--noproxy" in extra) else "-np"
        if norm_target.startswith("eyJ") and norm_target.count(".") >= 2:
            flags = extra if extra else "-M at"
            return " ".join(f"jwt_tool {safe_target} {flags} {noproxy}".split())
        return " ".join(f"jwt_tool {extra or '-M at'} -t {safe_target} {noproxy}".split())

    if tool_key == "zap-cli":
        return " ".join(f"zaproxy -cmd -quickurl {safe_target} -quickout /tmp/zap_report.html {extra}".split())

    # ------------------------------------------------------------------
    # Authentication & Password Security
    # ------------------------------------------------------------------
    if tool_key == "hydra":
        flags = extra if extra else "-L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -f"
        tokens = flags.split()
        known_svcs = ("ssh", "ftp", "http-get", "http-post-form", "smb", "rdp", "mysql", "postgres", "telnet")
        if tokens and tokens[-1].lower() in known_svcs:
            service = tokens.pop()
            flags = " ".join(tokens)
            return " ".join(f"hydra {flags} {safe_target} {service}".split())
        return " ".join(f"hydra {flags} {safe_target}".split())

    if tool_key == "john":
        flags = extra if extra else "--wordlist=/usr/share/wordlists/rockyou.txt --rules=jumbo"
        return " ".join(f"john {flags} {safe_target}".split())

    if tool_key == "hashcat":
        flags = extra if extra else "-m 0 -a 0 /usr/share/wordlists/rockyou.txt -O -w 4"
        if "/usr/share/wordlists" in flags and "-m " in flags:
            tokens = flags.split()
            wl_idx = next((i for i, t in enumerate(tokens) if t.startswith("/")), None)
            if wl_idx is not None:
                before = " ".join(tokens[:wl_idx])
                after = " ".join(tokens[wl_idx:])
                return " ".join(f"hashcat {before} {safe_target} {after}".split())
        return " ".join(f"hashcat {flags} {safe_target}".split())

    if tool_key == "medusa":
        flags = extra if extra else "-U /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -M ssh -t 4 -f"
        return " ".join(f"medusa -h {safe_target} {flags}".split())

    if tool_key == "patator":
        if extra:
            if "host=" in extra:
                return " ".join(f"patator {extra}".split())
            parts = extra.split()
            return " ".join(f"patator {parts[0]} host={safe_target} {' '.join(parts[1:])}".split())
        return f"patator ssh_login host={safe_target} user=FILE0 password=FILE1 0=/usr/share/wordlists/metasploit/unix_users.txt 1=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Authentication failed.'"

    if tool_key == "crackmapexec":
        if extra.startswith(("smb ", "winrm ", "ssh ", "ldap ", "ftp ", "mssql ", "rdp ", "wmi ", "vnc ")):
            sub, rest = extra.split(None, 1) if " " in extra else (extra, "")
            return " ".join(f"nxc {sub} {safe_target} {rest}".split())
        flags = extra if extra else "--shares --users --pass-pol"
        return " ".join(f"nxc smb {safe_target} {flags}".split())

    if tool_key == "smbmap":
        if "-H" in extra:
            return " ".join(f"smbmap {extra}".split())
        flags = extra if extra else "-u '' -p '' -r"
        return " ".join(f"smbmap -H {safe_target} {flags}".split())

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
        flags = extra if extra else '-q -batch -ex "set disassembly-flavor intel" -ex "disassemble main"'
        if "-batch" not in flags:
            flags = f"-batch {flags}"
        return " ".join(f"gdb {flags} {safe_target}".split())

    if tool_key == "radare2":
        flags = extra if extra else '-A -q -c "aaa; afl; pdf @ main; izz"'
        return " ".join(f"r2 {flags} {safe_target}".split())

    if tool_key == "ghidra":
        return " ".join(f"/usr/share/ghidra/support/analyzeHeadless /tmp ghidra_proj -import {safe_target} -deleteProject {extra}".split())

    if tool_key == "binwalk":
        flags = extra if extra else "-e -M -A"
        return " ".join(f"binwalk {flags} {safe_target}".split())

    if tool_key in {"checksec", "pwntools"}:
        return " ".join(f"pwn checksec --file={safe_target} {extra}".split())

    if tool_key == "strings":
        flags = extra if extra else "-a -n 8"
        return " ".join(f"strings {flags} {safe_target}".split())

    if tool_key == "objdump":
        flags = extra if extra else "-d -M intel"
        return " ".join(f"objdump {flags} {safe_target}".split())

    if tool_key == "ropgadget":
        flags = extra if extra else "--depth 10 --all"
        return " ".join(f"ROPgadget --binary {safe_target} {flags}".split())

    # ------------------------------------------------------------------
    # Cloud & Container Security
    # ------------------------------------------------------------------
    if tool_key == "prowler":
        providers = ("aws", "azure", "gcp", "kubernetes", "m365", "github", "iac", "image", "llm")
        flags = extra if extra else "aws -M csv json-ocsf -S -F prowler_out"
        if flags.startswith(providers):
            return " ".join(f"prowler {flags}".split())
        if norm_target.lower() in providers:
            return " ".join(f"prowler {safe_target} {flags}".split())
        return " ".join(f"prowler {flags} {safe_target}".split())

    if tool_key == "scout-suite":
        providers = ("aws", "azure", "gcp", "aliyun", "oci")
        flags = extra if extra else "aws --report-dir /tmp/scout_out --quiet"
        if flags.startswith(providers):
            return " ".join(f"scout {flags}".split())
        return " ".join(f"scout {flags} {safe_target}".split())

    if tool_key == "trivy":
        flags = extra if extra else "--severity HIGH,CRITICAL --format json -o /tmp/trivy_out.json"
        if flags.startswith(("image ", "fs ", "repo ", "config ", "k8s ")):
            run_cmd = " ".join(f"trivy {flags} {safe_target}".split())
        else:
            subcmd = "repo" if norm_target.startswith(("http://", "https://")) else ("fs" if norm_target.startswith("/") else "image")
            run_cmd = " ".join(f"trivy {subcmd} {flags} {safe_target}".split())
        if "-o /tmp/trivy_out.json" in flags:
            return f"sh -c {shlex.quote(f'rm -f /tmp/trivy_out.json; {run_cmd}; rc=$?; [ -s /tmp/trivy_out.json ] && head -n 120 /tmp/trivy_out.json; exit $rc')}"
        return run_cmd

    if tool_key == "kube-hunter":
        flags = extra if extra else "--active"
        if "--remote" in flags:
            return " ".join(f"kube-hunter {flags} {safe_target}".split())
        return " ".join(f"kube-hunter --remote {safe_target} {flags}".split())

    if tool_key == "kube-bench":
        flags = extra if extra else "run --targets master,node --json"
        return " ".join(f"kube-bench {flags}".split())

    if tool_key == "docker-bench-security":
        flags = extra if extra else "-l /tmp/docker_bench.log -c container_images"
        return f"sh -c {shlex.quote(f'cd /opt/docker-bench-security && sh docker-bench-security.sh {flags}'.strip())}"

    if tool_key == "checkov":
        flags = extra if extra else "--output json --output-file-path /tmp/checkov_out"
        if "-d " in flags or "-f " in flags:
            return " ".join(f"checkov {flags}".split())
        return " ".join(f"checkov -d {safe_target} {flags}".split())

    # ------------------------------------------------------------------
    # CTF & Forensics
    # ------------------------------------------------------------------
    if tool_key == "volatility":
        return " ".join(f"vol -f {safe_target} {extra or 'windows.info'}".split())

    if tool_key == "foremost":
        flags = extra if extra else "-T -v -o /tmp/foremost_out"
        return " ".join(f"foremost {flags} -i {safe_target}".split())

    if tool_key == "steghide":
        flags = extra if extra else 'extract -p "" -f'
        return " ".join(f"steghide {flags} -sf {safe_target}".split())

    if tool_key == "exiftool":
        flags = extra if extra else "-a -u -g1 -s"
        return " ".join(f"exiftool {flags} {safe_target}".split())

    if tool_key == "autopsy":
        return " ".join(f"autopsy {extra}".split()) if extra else "autopsy -h"

    if tool_key == "sleuthkit":
        flags = extra if extra else "-r -p"
        return " ".join(f"fls {flags} {safe_target}".split())

    # ------------------------------------------------------------------
    # Bug Bounty & OSINT Arsenal
    # ------------------------------------------------------------------
    if tool_key == "sherlock":
        flags = extra if extra else "--print-found --csv"
        return " ".join(f"sherlock --timeout 5 {flags} {safe_target}".split())

    if tool_key == "spiderfoot":
        flags = extra if extra else "-t DOMAIN_NAME,IP_ADDRESS -m all -o csv -q"
        return " ".join(f"spiderfoot -s {safe_target} {flags}".split())

    if tool_key == "shodan":
        sub = extra.strip().split()[0] if extra.strip() else ""
        if sub in {"host", "domain", "search", "count", "stats"}:
            return " ".join(f"shodan {extra} {safe_target}".split())
        subcmd = "host" if _is_ip_or_cidr(norm_target) else "domain"
        return " ".join(f"shodan {subcmd} {safe_target} {extra}".split())

    if tool_key == "censys":
        sub = extra.strip().split()[0] if extra.strip() else ""
        if sub in {"search", "view", "subdomains", "asm"}:
            return " ".join(f"censys {extra} {safe_target}".split())
        return " ".join(f"censys view {safe_target} {extra}".split())

    if tool_key == "subjack":
        flags = extra if extra else "-w /usr/share/wordlists/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt -t 100 -timeout 30 -ssl -v"
        if "-w " in flags or "--wordlist" in flags:
            return " ".join(f"subjack {flags}".split())
        verbose = "" if "-v" in flags.split() else "-v"
        return " ".join(f"subjack -d {safe_target} -a {verbose} {flags}".split())

    if tool_key == "trufflehog":
        flags = extra if extra else "--json"
        if flags.startswith(("git ", "github ", "filesystem ", "s3 ")):
            return " ".join(f"trufflehog {flags} {safe_target}".split())
        if norm_target.startswith(("http://", "https://", "git@")):
            return " ".join(f"trufflehog git {safe_target} {flags}".split())
        return " ".join(f"trufflehog filesystem --directory={safe_target} {flags}".split())

    if tool_key == "waybackurls":
        inner = f"printf '%s\\n' {safe_target} | waybackurls {extra} | tee /tmp/wayback_out.txt".strip()
        return f"sh -c {shlex.quote(inner)}"

    if tool_key == "gau":
        flags = extra if extra else "--threads 5 --subs --blacklist png,jpg,gif,css,woff"
        return " ".join(f"gau {safe_target} {flags}".split())

    if tool_key == "searchsploit":
        query = norm_target
        if "://" in query:
            parsed_q = urlparse(query)
            query = parsed_q.hostname or query
        safe_q = shlex.quote(query)
        is_cve = bool(re.match(r"^(?:cve[- ]?)?\d{4}-\d{4,}$", query, re.IGNORECASE))
        if extra in {"--cve", "--id --cve"} and not is_cve:
            return " ".join(f"searchsploit --disable-colour --id {safe_q}".split())
        flags = extra if extra else "--id"
        return " ".join(f"searchsploit --disable-colour {flags} {safe_q}".split())

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


def _is_active_tool_process(cmd: str, tool_tokens: set[str]) -> bool:
    """Return True if cmd is an active security tool process (excluding shell wrappers)."""
    cmd_lower = cmd.strip().lower()
    if not cmd_lower:
        return False
    if cmd_lower.startswith(("/bin/sh -c ", "sh -c ", "/bin/bash -c ", "bash -c ")):
        return False
    cmd_words = {os.path.basename(w).lower() for w in cmd.split()[:3]}
    return any(w in tool_tokens for w in cmd_words)


def get_kali_mcp_logs_and_processes(lines: int = 40, known_tools: list[str] | None = None) -> dict:
    """Fetch active processes and background jobs running inside the Kali Docker container."""
    base_url = get_kali_api_url()
    tool_tokens = {t.lower() for t in (known_tools or [])} | {
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
    }

    active_processes: list[dict[str, str]] = []
    mcp_running = False
    connected = False

    # 1. Prefer structured /api/ps endpoint (provided by sentinel_kali Docker container)
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
                is_server = "kali_server.py" in cmd_lower or ("server.py" in cmd_lower and "5000" in cmd_lower)
                if is_server:
                    mcp_running = True
                    continue
                if _is_active_tool_process(cmd, tool_tokens):
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

    # 2. Fallback to `ps -eo` only if /api/ps was unreachable
    if not connected:
        ps_res = run_tool_on_kali("ps -eo pid,pcpu,etime,args", timeout=5)
        if ps_res.get("returncode") != -1:
            connected = True
            for raw_line in (ps_res.get("stdout") or "").splitlines()[1:]:
                parts = raw_line.strip().split(None, 3)
                if len(parts) < 4:
                    continue
                pid, cpu, elapsed, cmd = parts
                cmd_lower = cmd.lower()
                if "ps -eo" in cmd_lower:
                    continue
                is_server = "kali_server.py" in cmd_lower or ("server.py" in cmd_lower and "5000" in cmd_lower)
                if is_server:
                    mcp_running = True
                    continue
                if _is_active_tool_process(cmd, tool_tokens):
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
            "error": "Kali Docker container unreachable",
        }

    # 3. Fetch structured background jobs from /api/jobs inside sentinel_kali
    filtered_logs: list[str] = []
    try:
        jobs_resp = requests.get(
            f"{base_url}/api/jobs",
            headers={"ngrok-skip-browser-warning": "true"},
            timeout=3,
        )
        if jobs_resp.status_code == 200:
            for job in jobs_resp.json().get("jobs", []):
                job_id = job.get("job_id", "?")
                status_str = job.get("status", "unknown")
                job_cmd = job.get("command", "")
                filtered_logs.append(f"[{status_str}] job={job_id}: {job_cmd}")
    except Exception:
        pass

    return {
        "connected": True,
        "mcp_running": mcp_running,
        "active_processes": active_processes,
        "logs": filtered_logs[-lines:],
        "error": None,
    }


_ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]"
)


def _sanitize_terminal_output(text: str) -> str:
    """Strip ANSI escape sequences and collapse carriage-return progress overwrites."""
    if not text:
        return ""
    cleaned = _ANSI_ESCAPE_RE.sub("", text).replace("\r\n", "\n")
    lines = [line.rsplit("\r", 1)[-1] for line in cleaned.split("\n")]
    return "\n".join(lines).strip("\n")


def _parse_sse_command_response(body: str) -> dict:
    """Aggregate Server-Sent Events returned by /api/command when a tool streams."""
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    returncode: int | None = None
    error_messages: list[str] = []

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        payload_str = line[len("data:"):].strip()
        if not payload_str:
            continue
        try:
            event = json.loads(payload_str)
        except ValueError:
            continue
        ev_type = event.get("type")
        if ev_type == "output":
            source = event.get("source", "stdout")
            text_line = str(event.get("line", ""))
            if source == "stderr":
                stderr_lines.append(text_line)
            else:
                stdout_lines.append(text_line)
        elif ev_type == "result":
            if event.get("return_code") is not None:
                returncode = int(event["return_code"])
            elif event.get("returncode") is not None:
                returncode = int(event["returncode"])
        elif ev_type == "error":
            error_messages.append(str(event.get("message") or "Unknown SSE execution error"))

    if error_messages and not stderr_lines:
        stderr_lines.extend(error_messages)

    return {
        "stdout": "\n".join(stdout_lines),
        "stderr": "\n".join(stderr_lines),
        "returncode": returncode if returncode is not None else (-1 if error_messages else 0),
    }


def run_tool_on_kali(command: str, timeout: int = 600) -> dict:
    """Execute a command inside the Kali Docker container API."""
    candidates = _candidate_kali_urls()
    last_exc: Exception | None = None
    last_url = candidates[0]
    started = time.monotonic()
    container_timeout = max(int(timeout) - 5, 5)
    headers = {"ngrok-skip-browser-warning": "true"}

    for base_url in candidates:
        last_url = base_url
        logger.info("Sending to Kali Container (%s): %s", base_url, command)
        try:
            # Prefer /api/exec so streaming tools (gobuster/ffuf/feroxbuster/dirsearch/nikto)
            # return structured JSON rather than SSE text/event-stream frames.
            response = requests.post(
                f"{base_url}/api/exec",
                json={"command": command, "timeout": container_timeout},
                headers=headers,
                timeout=timeout,
            )
            if response.status_code == 404:
                response = requests.post(
                    f"{base_url}/api/command",
                    json={"command": command, "streaming": False, "timeout": container_timeout},
                    headers=headers,
                    timeout=timeout,
                )

            response.raise_for_status()
            content_type = (response.headers.get("content-type") or "").lower()
            raw_text = response.text or ""

            if "text/event-stream" in content_type or raw_text.lstrip().startswith("data:"):
                parsed = _parse_sse_command_response(raw_text)
                return {
                    "stdout": _sanitize_terminal_output(parsed.get("stdout", "")),
                    "stderr": _sanitize_terminal_output(parsed.get("stderr", "")),
                    "returncode": parsed.get("returncode", 0),
                    "elapsed_seconds": round(time.monotonic() - started, 2),
                }

            try:
                data = response.json()
            except ValueError as json_exc:
                elapsed = round(time.monotonic() - started, 2)
                snippet = raw_text.strip()[:400] or "(empty response body)"
                logger.error("Kali Container returned non-JSON (%s, HTTP %s): %s", base_url, response.status_code, snippet)
                return {
                    "stdout": "",
                    "stderr": f"[!] Kali Container Server returned non-JSON response (HTTP {response.status_code}): {json_exc}\n{snippet}",
                    "returncode": -1,
                    "elapsed_seconds": elapsed,
                }

            elapsed = round(
                float(data.get("elapsed_seconds") or data.get("execution_time") or (time.monotonic() - started)),
                2,
            )

            output = _sanitize_terminal_output(data.get("output") or data.get("stdout") or "")
            stderr = _sanitize_terminal_output(data.get("stderr") or data.get("error") or "")
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
        except requests.Timeout as exc:
            elapsed = round(time.monotonic() - started, 2)
            logger.error("Kali command timed out after %ss (%s): %s", timeout, base_url, exc)
            return {
                "stdout": "",
                "stderr": f"[!] Tool execution timed out after {timeout}s on Kali Container ({base_url}). Pass tighter flags/wordlist in Extra Arguments.",
                "returncode": -1,
                "elapsed_seconds": elapsed,
            }
        except requests.HTTPError as exc:
            elapsed = round(time.monotonic() - started, 2)
            resp_obj = exc.response
            status_code = resp_obj.status_code if resp_obj is not None else "unknown"
            body_preview = (resp_obj.text or "").strip()[:400] if resp_obj is not None else str(exc)
            logger.error("Kali HTTP error %s (%s): %s", status_code, base_url, body_preview)
            return {
                "stdout": "",
                "stderr": f"[!] Kali Container Server HTTP {status_code} error:\n{body_preview}",
                "returncode": -1,
                "elapsed_seconds": elapsed,
            }
        except Exception as exc:
            elapsed = round(time.monotonic() - started, 2)
            logger.error("Kali execution error (%s): %s", base_url, exc)
            return {
                "stdout": "",
                "stderr": f"[!] Kali execution error ({base_url}): {exc}",
                "returncode": -1,
                "elapsed_seconds": elapsed,
            }

    elapsed = round(time.monotonic() - started, 2)
    logger.error("Kali bridge error (%s): %s", last_url, last_exc)
    return {
        "stdout": "",
        "stderr": (
            f"[!] Failed to connect to Kali Docker container at {last_url}. "
            f"Is the sentinel_kali container running?\nError: {last_exc}"
        ),
        "returncode": -1,
        "elapsed_seconds": elapsed,
    }
