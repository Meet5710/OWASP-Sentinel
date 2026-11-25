"""OWASP Sentinel - Kali Pentester API Endpoint."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

# We only import what we actually need now
from app.kali_bridge import build_kali_command, run_tool_on_kali

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

class KaliToolInfo(BaseModel):
    name: str
    description: str
    available: bool
    example_args: str

TOOL_CATALOG: list[dict] = [
    {"name": "nmap",      "description": "Network mapper & service/version scanner",     "example_args": "-T4 -A"},
    {"name": "nikto",     "description": "Web server vulnerability scanner",             "example_args": "-C all"},
    {"name": "gobuster",  "description": "Directory & file brute-forcer",                "example_args": "-t 50"},
    {"name": "sqlmap",    "description": "Automated SQL injection & DB takeover tool",   "example_args": "--threads=4"},
    {"name": "nuclei",    "description": "Template-based vulnerability scanner",         "example_args": "-t cves/"},
    {"name": "wpscan",    "description": "WordPress security scanner",                   "example_args": "--enumerate vp"},
    {"name": "whatweb",   "description": "Web technology fingerprinter",                 "example_args": "-a 3"},
    {"name": "wafw00f",   "description": "Web Application Firewall detector",            "example_args": ""},
    {"name": "dirb",      "description": "URL brute-forcer / content discovery",         "example_args": ""},
    {"name": "fierce",    "description": "DNS reconnaissance & subdomain scanner",       "example_args": ""},
    {"name": "dnsrecon",  "description": "DNS enumeration & zone transfer auditor",      "example_args": "-t std"},
    {"name": "sublist3r", "description": "Fast subdomain enumeration tool",              "example_args": ""},
]

@router.get("/tools", response_model=list[KaliToolInfo])
async def list_kali_tools():
    """
    Return every supported tool. We hardcode 'available: True' because 
    the tools are on the Kali VM, not the Windows machine running this backend.
    """
    return [
        KaliToolInfo(
            name=t["name"],
            description=t["description"],
            available=True, # Force True so the UI enables the Execute button
            example_args=t["example_args"],
        )
        for t in TOOL_CATALOG
    ]

@router.post("/execute", response_model=KaliScanResult)
async def execute_kali_tool(request: KaliScanRequest):
    target = request.target.strip()
    tool = request.tool.strip().lower()
    extra = request.extra_args.strip()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL or IP is required.",
        )

    cmd = build_kali_command(tool, target, extra)
    
    # This calls the kali_bridge.py we updated earlier
    result = run_tool_on_kali(cmd)

    output_text = result.get("stdout", "")
    stderr_text = result.get("stderr", "")
    returncode = result.get("returncode", 0)

    # If the bridge couldn't reach Kali (e.g. SSH tunnel is down)
    if returncode == -1 and "Failed to connect" in stderr_text:
        output_text = stderr_text

    return KaliScanResult(
        target=target,
        tool_executed=tool,
        command_ran=cmd,
        output=output_text,
        stderr=stderr_text,
        returncode=returncode,
        elapsed_seconds=result.get("elapsed_seconds", 0.0),
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool_available=True,
    )