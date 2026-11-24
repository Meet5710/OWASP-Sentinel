"""OWASP Sentinel - Kali Terminal Execution Schemas

Pydantic schemas for real-time target assessment command execution.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class TerminalExecuteRequest(BaseModel):
    command: str = Field(..., description="Raw command entered into terminal")
    target_host: Optional[str] = Field(None, description="Active target hostname or IP")
    target_port: Optional[str] = Field("443", description="Active target TCP port")
    target_url: Optional[str] = Field(None, description="Active target canonical URL")
    target_scheme: Optional[str] = Field("https", description="Target scheme (http/https)")
    target_id: Optional[str] = Field(None, description="Associated authorized asset ID")
    custom_script_name: Optional[str] = Field(None, description="Optional custom script file name")
    custom_script_content: Optional[str] = Field(None, description="Optional custom script code content")
    current_dir: Optional[str] = Field("target-assessment", description="Current working directory path in Kali")


class TerminalExecuteResponse(BaseModel):
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_ms: float
    execution_type: str
    is_upgraded: Optional[bool] = None
    fs_entries: Optional[List[Dict[str, Any]]] = None
    current_dir: Optional[str] = None

