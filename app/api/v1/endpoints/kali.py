"""OWASP Sentinel - Kali Pentester API Endpoint.

Exposes a POST endpoint that accepts a tool name, target, and optional
arguments, executes the tool via the Kali bridge, and returns structured
results to the frontend.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.kali_bridge import (
    TOOL_COMMANDS,
    build_kali_command,
    run_tool_on_kali,
    _is_tool_available,
)

logger = logging.getLogger("sentinel.kali")

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class KaliScanRequest(BaseModel):
    """Payload sent by the Kali Pentester frontend tab."""
    target: str = Field(..., description="Target URL, IP, or hostname to scan")
    tool: str = Field(..., description="Name of the Kali tool to execute (e.g. nmap, nikto, gobuster)")
    extra_args: str = Field("", description="Additional CLI flags to append to the tool command")


class KaliScanResult(BaseModel):
    """Structured response returned to the frontend."""
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
    """Metadata about a single supported tool."""
    name: str
    description: str
    available: bool
    example_args: str


# ---------------------------------------------------------------------------
# Tool Catalog (displayed in the UI tool selector)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/tools",
    response_model=list[KaliToolInfo],
    summary="List available Kali penetration-testing tools",
)
async def list_kali_tools():
    """Return every supported tool with its availability on this host."""
    return [
        KaliToolInfo(
            name=t["name"],
            description=t["description"],
            available=_is_tool_available(t["name"]),
            example_args=t["example_args"],
        )
        for t in TOOL_CATALOG
    ]


@router.post(
    "/execute",
    response_model=KaliScanResult,
    summary="Execute a Kali tool against an authorized target",
)
async def execute_kali_tool(request: KaliScanRequest):
    """
    Run a Kali Linux penetration-testing tool and return its output.

    The tool must be installed on the server.  On Render (Linux containers
    without Kali tools) the endpoint will return a helpful error message
    suggesting the user connect via ngrok from a local Kali machine.
    """
    target = request.target.strip()
    tool = request.tool.strip().lower()
    extra = request.extra_args.strip()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL or IP is required.",
        )

    cmd = build_kali_command(tool, target, extra)
    tool_avail = _is_tool_available(tool)

    result = run_tool_on_kali(cmd)

    output_text = result["stdout"] or ""
    stderr_text = result["stderr"] or ""

    # If tool is missing, provide a friendly hint
    if result["returncode"] == 127 or (not tool_avail and not output_text):
        output_text = (
            f"⚠️  Tool '{tool}' is not installed on this server.\n\n"
            f"To use real Kali tools, run OWASP Sentinel locally on a "
            f"Kali Linux machine and connect via the ngrok tunnel, or "
            f"SSH into your Kali box and start the backend there.\n\n"
            f"Command that would have been executed:\n  {cmd}\n"
        )

    return KaliScanResult(
        target=target,
        tool_executed=tool,
        command_ran=cmd,
        output=output_text,
        stderr=stderr_text,
        returncode=result["returncode"],
        elapsed_seconds=result["elapsed_seconds"],
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool_available=tool_avail,
    )

