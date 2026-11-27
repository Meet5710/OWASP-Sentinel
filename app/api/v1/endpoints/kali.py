"""OWASP Sentinel - Kali Pentester API Endpoint."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.kali_bridge import (
    build_kali_command,
    check_catalog_tools_on_kali,
    check_kali_health,
    get_kali_api_url,
    get_kali_mcp_logs_and_processes,
    run_tool_on_kali,
)

logger = logging.getLogger("sentinel.kali")
router = APIRouter()


class KaliScanRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, or hostname to scan")
    tool: str = Field(..., description="Name of the Kali tool to execute")
    extra_args: str = Field("", description="Additional CLI flags to append")


class KaliScanResult(BaseModel):
    target: str
    tool_executed: str
    command_ran: str
    output: str
    stderr: str
    returncode: int
    elapsed_seconds: float
    timestamp: str
    tool_available: bool


TOOL_CATALOG: dict[str, list[dict[str, str]]] = {
    "Network Reconnaissance & Scanning": [
        {"name": "nmap", "description": "Network mapper & service scanner", "example_args": "-sT -sV -T4 -F"},
        {"name": "rustscan", "description": "Ultra-fast port scanner", "example_args": "--ulimit 5000"},
        {"name": "masscan", "description": "High-speed internet-scale port scanner", "example_args": "-p80,443 --rate=1000"},
        {"name": "autorecon", "description": "Comprehensive automated recon", "example_args": ""},
        {"name": "amass", "description": "Subdomain enumeration & OSINT", "example_args": ""},
        {"name": "subfinder", "description": "Fast passive subdomain discovery", "example_args": "-silent"},
        {"name": "fierce", "description": "DNS reconnaissance", "example_args": ""},
        {"name": "dnsenum", "description": "DNS information gathering", "example_args": "--noreverse"},
        {"name": "theharvester", "description": "Email and subdomain harvesting", "example_args": "-b crtsh,duckduckgo,hackertarget"},
        {"name": "responder", "description": "LLMNR, NBT-NS and MDNS poisoner", "example_args": "-I eth0 -A"},
        {"name": "enum4linux-ng", "description": "Advanced SMB enumeration", "example_args": "-A"},
        {"name": "whois", "description": "Domain & IP WHOIS ownership lookup", "example_args": ""},
        {"name": "showmount", "description": "NFS mount & share enumeration", "example_args": "-e"},
    ],
    "Web Application Security": [
        {"name": "gobuster", "description": "Directory/file brute-forcer", "example_args": "-w /usr/share/wordlists/dirb/common.txt"},
        {"name": "feroxbuster", "description": "Recursive content discovery", "example_args": "-w /usr/share/wordlists/dirb/common.txt --depth 1"},
        {"name": "ffuf", "description": "Fast web fuzzer", "example_args": "-w /usr/share/wordlists/dirb/common.txt -mc 200,301,302"},
        {"name": "dirsearch", "description": "Advanced directory discovery", "example_args": "-e php,html,js"},
        {"name": "nuclei", "description": "Template-based vulnerability scanner", "example_args": "-severity critical,high,medium"},
        {"name": "nikto", "description": "Web server vulnerability scanner", "example_args": "-maxtime 60s"},
        {"name": "sqlmap", "description": "Automated SQL injection tool", "example_args": "--batch --level=1 --risk=1"},
        {"name": "wpscan", "description": "WordPress security scanner", "example_args": "--enumerate vp"},
        {"name": "dalfox", "description": "Advanced XSS vulnerability scanner", "example_args": ""},
        {"name": "commix", "description": "Command injection exploitation", "example_args": "--batch"},
        {"name": "whatweb", "description": "Web technology fingerprinter", "example_args": ""},
        {"name": "wafw00f", "description": "WAF detector", "example_args": ""},
        {"name": "arjun", "description": "HTTP parameter discovery", "example_args": ""},
        {"name": "httpx", "description": "Fast HTTP probing & tech detection", "example_args": "-tech-detect"},
        {"name": "katana", "description": "Next-generation crawling", "example_args": "-jc -d 2"},
        {"name": "gospider", "description": "Fast web spidering & link discovery", "example_args": "-d 2"},
        {"name": "testssl.sh", "description": "SSL/TLS cipher, protocol & vulnerability auditor", "example_args": "--fast"},
        {"name": "jwt-tool", "description": "JSON Web Token testing", "example_args": ""},
        {"name": "zap-cli", "description": "OWASP ZAP automated quick scan", "example_args": ""},
    ],
    "Authentication & Password Security": [
        {"name": "hydra", "description": "Network login cracker", "example_args": "-L users.txt -P pass.txt"},
        {"name": "john", "description": "John the Ripper password cracker", "example_args": ""},
        {"name": "hashcat", "description": "GPU-accelerated password recovery", "example_args": "-m 0"},
        {"name": "medusa", "description": "Parallel login brute-forcer", "example_args": ""},
        {"name": "patator", "description": "Multi-purpose brute-forcer", "example_args": ""},
        {"name": "crackmapexec", "description": "Network service exploitation (NetExec)", "example_args": ""},
        {"name": "smbmap", "description": "SMB share enumeration", "example_args": ""},
        {"name": "evil-winrm", "description": "Windows Remote Management shell", "example_args": ""},
        {"name": "hash-identifier", "description": "Hash type identification", "example_args": ""},
    ],
    "Binary Analysis & Reverse Engineering": [
        {"name": "gdb", "description": "GNU Debugger", "example_args": ""},
        {"name": "radare2", "description": "Advanced reverse engineering framework", "example_args": ""},
        {"name": "ghidra", "description": "NSA reverse engineering suite (headless)", "example_args": ""},
        {"name": "binwalk", "description": "Firmware analysis and extraction", "example_args": "-e"},
        {"name": "checksec", "description": "Binary security property checker", "example_args": ""},
        {"name": "strings", "description": "Extract printable strings", "example_args": "-n 8"},
        {"name": "objdump", "description": "Display object file information", "example_args": "-d"},
        {"name": "ROPgadget", "description": "ROP/JOP gadget finder", "example_args": ""},
        {"name": "pwntools", "description": "CTF framework and exploit library", "example_args": ""},
    ],
    "Cloud & Container Security": [
        {"name": "prowler", "description": "AWS/Azure/GCP security assessment", "example_args": ""},
        {"name": "scout-suite", "description": "Multi-cloud security auditing", "example_args": ""},
        {"name": "trivy", "description": "Container/repo/fs vulnerability scanner", "example_args": ""},
        {"name": "kube-hunter", "description": "Kubernetes penetration testing", "example_args": ""},
        {"name": "kube-bench", "description": "CIS Kubernetes benchmark checker", "example_args": ""},
        {"name": "docker-bench-security", "description": "Docker security assessment", "example_args": ""},
        {"name": "checkov", "description": "Infrastructure as code security", "example_args": ""},
    ],
    "CTF & Forensics": [
        {"name": "volatility", "description": "Memory forensics framework", "example_args": ""},
        {"name": "foremost", "description": "File carving and data recovery", "example_args": ""},
        {"name": "steghide", "description": "Steganography detection and extraction", "example_args": "info"},
        {"name": "exiftool", "description": "Metadata reader", "example_args": ""},
        {"name": "binwalk", "description": "Firmware analysis", "example_args": ""},
        {"name": "autopsy", "description": "Digital forensics platform", "example_args": ""},
        {"name": "sleuthkit", "description": "Digital forensics tools (fls)", "example_args": ""},
    ],
    "Bug Bounty & OSINT Arsenal": [
        {"name": "sherlock", "description": "Username investigation across social networks", "example_args": ""},
        {"name": "spiderfoot", "description": "OSINT automation (passive scan)", "example_args": "-u passive -o tab -q"},
        {"name": "shodan", "description": "Internet-connected device search", "example_args": ""},
        {"name": "censys", "description": "Internet asset discovery", "example_args": ""},
        {"name": "subjack", "description": "Subdomain takeover checker", "example_args": ""},
        {"name": "trufflehog", "description": "Git/filesystem secret scanning", "example_args": ""},
        {"name": "waybackurls", "description": "Historical URL discovery", "example_args": ""},
        {"name": "gau", "description": "Get All URLs from multiple sources", "example_args": "--threads 4"},
        {"name": "searchsploit", "description": "Exploit-DB CVE & vulnerability advisory lookup", "example_args": ""},
    ],
}


@router.get("/tools")
def list_kali_tools():
    """Return the categorized Kali tool catalog directly."""
    return TOOL_CATALOG


@router.get("/status")
def get_kali_bridge_status():
    """Check live connectivity and full per-tool availability on the Kali Docker container."""
    connected, tools_status = check_kali_health()
    if connected:
        all_names = [t["name"] for tools in TOOL_CATALOG.values() for t in tools]
        catalog_status = check_catalog_tools_on_kali(all_names)
        if catalog_status:
            tools_status = {**tools_status, **catalog_status}
    return {
        "connected": connected,
        "kali_api_url": get_kali_api_url(),
        "tools_status": tools_status,
    }


@router.get("/logs")
def get_kali_logs(lines: int = 40):
    """Fetch live processes and background jobs running inside the Kali Docker container."""
    all_names = [t["name"] for tools in TOOL_CATALOG.values() for t in tools]
    return get_kali_mcp_logs_and_processes(lines=lines, known_tools=all_names)


@router.post("/execute", response_model=KaliScanResult)
def execute_kali_tool(request: KaliScanRequest):
    target = request.target.strip()
    tool = request.tool.strip()
    extra = request.extra_args.strip()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL or IP is required.",
        )

    cmd = build_kali_command(tool, target, extra)
    result = run_tool_on_kali(cmd)

    output_text = result.get("stdout", "")
    stderr_text = result.get("stderr", "")
    returncode = result.get("returncode", 0)
    bridge_failed = returncode == -1 and "Failed to connect" in stderr_text
    missing_binary = (
        returncode == 127
        or "No such file or directory" in stderr_text
        or ": not found" in stderr_text
    )

    if bridge_failed and not output_text:
        output_text = (
            f"{stderr_text}\n\n"
            "If you are viewing the hosted Render UI (owasp-sentinel.onrender.com), "
            "Render cannot access your laptop's local 127.0.0.1:5001 Docker container directly.\n"
            "Connect your local backend (port 8001) via ngrok or ensure the sentinel_kali Docker container is running."
        )
    elif missing_binary and not output_text:
        output_text = (
            f"⚠️ Tool '{tool}' is not installed in the active Kali container/host.\n\n"
            f"Add it to docker/kali/Dockerfile (e.g. apt-get install -y {tool}) and rebuild, "
            f"or switch to an 'Installed' tool in the dropdown (check 'Installed only')."
        )

    combined_msg = f"{output_text}\n{stderr_text}"
    tool_lower = tool.lower()
    if tool_lower == "jwt-tool" and "No JWT provided" in combined_msg:
        output_text = (
            f"{output_text.rstrip()}\n\n"
            "[Hint] jwt-tool expects a JWT token (eyJ...). Paste a JWT in Target URL/IP or Extra Arguments (e.g. eyJ... -M at)."
        ).lstrip()
    elif tool_lower == "shodan" and "shodan init" in combined_msg:
        output_text = (
            f"{output_text.rstrip()}\n\n"
            "[Hint] Shodan CLI requires an API key. Run 'docker exec sentinel_kali shodan init <API_KEY>' once to enable queries."
        ).lstrip()
    elif tool_lower == "censys" and "No API ID or API secret configured" in combined_msg:
        output_text = (
            f"{output_text.rstrip()}\n\n"
            "[Hint] Censys CLI requires API credentials configured inside sentinel_kali ('censys config' or CENSYS_API_ID/CENSYS_API_SECRET)."
        ).lstrip()

    return KaliScanResult(
        target=target,
        tool_executed=tool,
        command_ran=cmd,
        output=output_text,
        stderr=stderr_text,
        returncode=returncode,
        elapsed_seconds=result.get("elapsed_seconds", 0.0),
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool_available=not bridge_failed and not missing_binary,
    )
