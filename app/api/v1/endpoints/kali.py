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
        {"name": "nmap", "description": "Network mapper & service scanner", "example_args": "-p- -sV -sC -A -T4 -Pn --script vuln,vulners --script-args mincvss=7.0"},
        {"name": "rustscan", "description": "Ultra-fast port scanner", "example_args": "--ulimit 5000 -- -sV -sC -A"},
        {"name": "masscan", "description": "High-speed internet-scale port scanner", "example_args": "-p1-65535 --rate 10000 -oJ /tmp/masscan_out.json"},
        {"name": "autorecon", "description": "Comprehensive automated recon", "example_args": '--nmap-append="-p- -sV -sC -A"'},
        {"name": "amass", "description": "Subdomain enumeration & OSINT", "example_args": "-active -brute -oA /tmp/amass_out"},
        {"name": "subfinder", "description": "Fast passive subdomain discovery", "example_args": "-all -silent -o /tmp/subfinder_out.txt"},
        {"name": "fierce", "description": "DNS reconnaissance", "example_args": "--wide"},
        {"name": "dnsenum", "description": "DNS information gathering", "example_args": "-f /usr/share/wordlists/dnsmap.txt --threads 10"},
        {"name": "dnsrecon", "description": "DNS enumeration & zone transfer", "example_args": "-t std,brt,axfr -D /usr/share/wordlists/dnsmap.txt"},
        {"name": "theharvester", "description": "Email and subdomain harvesting", "example_args": "-b all -l 500 -f /tmp/theharvester_out.html"},
        {"name": "responder", "description": "LLMNR, NBT-NS and MDNS poisoner", "example_args": "-I eth0 -wdv"},
        {"name": "enum4linux-ng", "description": "Advanced SMB enumeration", "example_args": "-A -oJ /tmp/enum4linux_out"},
        {"name": "whois", "description": "Domain & IP WHOIS ownership lookup", "example_args": ""},
        {"name": "showmount", "description": "NFS mount & share enumeration", "example_args": "-e"},
    ],
    "Web Application Security": [
        {"name": "gobuster", "description": "Directory/file brute-forcer", "example_args": "-w /usr/share/wordlists/dirb/big.txt -x php,html,txt,js,json,bak -t 50 -k"},
        {"name": "feroxbuster", "description": "Recursive content discovery", "example_args": "-w /usr/share/wordlists/dirb/big.txt -x php,html,js -t 50 -k --smart"},
        {"name": "ffuf", "description": "Fast web fuzzer", "example_args": "-w /usr/share/wordlists/dirb/big.txt -mc 200,204,301,302,307,401,403 -t 50"},
        {"name": "dirsearch", "description": "Advanced directory discovery", "example_args": "-e '*' -r -R 3 -t 50 --random-agent"},
        {"name": "nuclei", "description": "Template-based vulnerability scanner", "example_args": "-severity critical,high,medium -stats -rl 100 -c 50"},
        {"name": "nikto", "description": "Web server vulnerability scanner", "example_args": "-C all -Tuning 1234567890bde -maxtime 9m"},
        {"name": "sqlmap", "description": "Automated SQL injection tool", "example_args": "--batch --level=5 --risk=3 --dbs --threads=10 --random-agent"},
        {"name": "wpscan", "description": "WordPress security scanner", "example_args": "--enumerate vp,vt,u,dbe --plugins-detection aggressive --random-user-agent"},
        {"name": "dalfox", "description": "Advanced XSS vulnerability scanner", "example_args": "--deep-domxss --mining-dom"},
        {"name": "commix", "description": "Command injection vulnerability scanner", "example_args": "--batch --level=3"},
        {"name": "whatweb", "description": "Web technology fingerprinter", "example_args": "-a 3 --log-verbose=/tmp/whatweb_out.txt"},
        {"name": "wafw00f", "description": "WAF detector", "example_args": "-a -v"},
        {"name": "arjun", "description": "HTTP parameter discovery", "example_args": "-m GET,POST,JSON --stable"},
        {"name": "httpx", "description": "Fast HTTP probing & tech detection", "example_args": "-tech-detect -status-code -title -web-server -cdn -vhost"},
        {"name": "katana", "description": "Next-generation crawling", "example_args": "-jc -kf all -d 5 -ef woff,css,png,svg,jpg,woff2,jpeg,gif -jsonl -o /tmp/katana_out.jsonl"},
        {"name": "gospider", "description": "Fast web spidering & link discovery", "example_args": "-d 5 -t 20 -c 10 --js --sitemap --robots -o /tmp/gospider_out"},
        {"name": "testssl.sh", "description": "SSL/TLS cipher, protocol & vulnerability auditor", "example_args": "--full --vulnerable --headers"},
        {"name": "jwt-tool", "description": "JSON Web Token testing", "example_args": "-M at"},
        {"name": "zap-cli", "description": "OWASP ZAP automated quick scan", "example_args": ""},
    ],
    "Authentication & Password Security": [
        {"name": "hydra", "description": "Network login cracker", "example_args": "-L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -f ssh"},
        {"name": "john", "description": "John the Ripper password cracker", "example_args": "--wordlist=/usr/share/wordlists/rockyou.txt --rules=jumbo"},
        {"name": "hashcat", "description": "GPU-accelerated password recovery", "example_args": "-m 0 -a 0 /usr/share/wordlists/rockyou.txt -O -w 4"},
        {"name": "medusa", "description": "Parallel login brute-forcer", "example_args": "-U /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -M ssh -t 4 -f"},
        {"name": "patator", "description": "Multi-purpose brute-forcer", "example_args": "ssh_login user=FILE0 password=FILE1 0=/usr/share/wordlists/metasploit/unix_users.txt 1=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Authentication failed.'"},
        {"name": "crackmapexec", "description": "Network service enumeration (NetExec)", "example_args": "smb --shares --users --pass-pol"},
        {"name": "smbmap", "description": "SMB share enumeration", "example_args": "-u '' -p '' -r"},
        {"name": "evil-winrm", "description": "Windows Remote Management shell", "example_args": ""},
        {"name": "hash-identifier", "description": "Hash type identification", "example_args": ""},
    ],
    "Binary Analysis & Reverse Engineering": [
        {"name": "gdb", "description": "GNU Debugger", "example_args": '-q -batch -ex "set disassembly-flavor intel" -ex "disassemble main"'},
        {"name": "radare2", "description": "Advanced reverse engineering framework", "example_args": '-A -q -c "aaa; afl; pdf @ main; izz"'},
        {"name": "ghidra", "description": "NSA reverse engineering suite (headless)", "example_args": ""},
        {"name": "binwalk", "description": "Firmware analysis and extraction", "example_args": "-e -M -A"},
        {"name": "checksec", "description": "Binary security property checker", "example_args": ""},
        {"name": "strings", "description": "Extract printable strings", "example_args": "-a -n 8"},
        {"name": "objdump", "description": "Display object file information", "example_args": "-d -M intel"},
        {"name": "ROPgadget", "description": "ROP/JOP gadget finder", "example_args": "--depth 10 --all"},
        {"name": "pwntools", "description": "CTF framework and exploit library", "example_args": ""},
    ],
    "Cloud & Container Security": [
        {"name": "prowler", "description": "AWS/Azure/GCP security assessment", "example_args": "aws -M csv json-ocsf -S -F prowler_out"},
        {"name": "scout-suite", "description": "Multi-cloud security auditing", "example_args": "aws --report-dir /tmp/scout_out --quiet"},
        {"name": "trivy", "description": "Container/repo/fs vulnerability scanner", "example_args": "--severity HIGH,CRITICAL --format json -o /tmp/trivy_out.json"},
        {"name": "kube-hunter", "description": "Kubernetes penetration testing", "example_args": "--active"},
        {"name": "kube-bench", "description": "CIS Kubernetes benchmark checker", "example_args": "run --targets master,node --json"},
        {"name": "docker-bench-security", "description": "Docker security assessment", "example_args": "-l /tmp/docker_bench.log -c container_images"},
        {"name": "checkov", "description": "Infrastructure as code security", "example_args": "--output json --output-file-path /tmp/checkov_out"},
    ],
    "CTF & Forensics": [
        {"name": "volatility", "description": "Memory forensics framework (Volatility 3)", "example_args": "windows.info"},
        {"name": "foremost", "description": "File carving and data recovery", "example_args": "-T -v -o /tmp/foremost_out"},
        {"name": "steghide", "description": "Steganography detection and extraction", "example_args": 'extract -p "" -f'},
        {"name": "exiftool", "description": "Metadata reader", "example_args": "-a -u -g1 -s"},
        {"name": "binwalk", "description": "Firmware analysis and extraction", "example_args": "-e -M -A"},
        {"name": "autopsy", "description": "Digital forensics platform", "example_args": ""},
        {"name": "sleuthkit", "description": "Digital forensics tools (fls)", "example_args": "-r -p"},
    ],
    "Bug Bounty & OSINT Arsenal": [
        {"name": "sherlock", "description": "Username investigation across social networks", "example_args": "--print-found --csv"},
        {"name": "spiderfoot", "description": "OSINT automation scan", "example_args": "-t DOMAIN_NAME,IP_ADDRESS -m all -o csv -q"},
        {"name": "shodan", "description": "Internet-connected device search", "example_args": "host"},
        {"name": "censys", "description": "Internet asset discovery", "example_args": "view"},
        {"name": "subjack", "description": "Subdomain takeover checker", "example_args": "-w /usr/share/wordlists/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt -t 100 -timeout 30 -ssl -v"},
        {"name": "trufflehog", "description": "Git/filesystem secret scanning", "example_args": "--json"},
        {"name": "waybackurls", "description": "Historical URL discovery", "example_args": ""},
        {"name": "gau", "description": "Get All URLs from multiple sources", "example_args": "--threads 5 --subs --blacklist png,jpg,gif,css,woff"},
        {"name": "searchsploit", "description": "Exploit-DB CVE & vulnerability advisory lookup", "example_args": "--id --cve"},
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
