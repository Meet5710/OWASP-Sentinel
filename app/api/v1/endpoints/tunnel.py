"""OWASP Sentinel - Ngrok Public Tunnel Management Endpoint

Manages the local ngrok executable to expose the OWASP Sentinel platform
(FastAPI backend and React frontend) to the public internet securely.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()

# Global process tracker
_ngrok_process: Optional[subprocess.Popen] = None

# Local inspection API
NGROK_INSPECT_URL = "http://127.0.0.1:4040/api/tunnels"


# -------------------------------------------------------------------------
# Schemas
# -------------------------------------------------------------------------

class NgrokTunnelInfo(BaseModel):
    name: str = "sentinel-http"
    public_url: str
    proto: str = "https"
    addr: Optional[str] = None


class NgrokStatusResponse(BaseModel):
    is_running: bool
    public_url: Optional[str] = None
    proto: Optional[str] = None
    tunnels: list[NgrokTunnelInfo] = Field(default_factory=list)
    authtoken_configured: bool = False
    error: Optional[str] = None


class NgrokStartRequest(BaseModel):
    authtoken: Optional[str] = None


class NgrokAuthtokenRequest(BaseModel):
    authtoken: str


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def get_project_root() -> Path:
    """Return the absolute path to the project root directory."""
    return Path(__file__).resolve().parent.parent.parent.parent


def find_ngrok_binary() -> Optional[Path]:
    """Find the ngrok executable binary in project root or system PATH."""
    root = get_project_root()
    # 1. Project root binary (ngrok.exe or ngrok)
    candidates = [
        root / "ngrok.exe",
        root / "ngrok",
    ]
    for c in candidates:
        if c.is_file():
            return c

    # 2. Check PATH
    system_ngrok = shutil.which("ngrok.exe") or shutil.which("ngrok")
    if system_ngrok:
        return Path(system_ngrok)

    return None


def get_default_config_path() -> Path:
    """Return standard ngrok.yml location for current user."""
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "ngrok" / "ngrok.yml"
        user_profile = os.environ.get("USERPROFILE", "")
        return Path(user_profile) / "AppData" / "Local" / "ngrok" / "ngrok.yml"
    return Path.home() / ".config" / "ngrok" / "ngrok.yml"


def is_authtoken_configured() -> bool:
    """Check if an authtoken exists in env or config file."""
    # 1. Environment variable
    if os.environ.get("NGROK_AUTHTOKEN", "").strip():
        return True

    # 2. Check config file content
    cfg = get_default_config_path()
    if cfg.exists():
        try:
            content = cfg.read_text(encoding="utf-8")
            if "authtoken:" in content:
                # verify it's not empty
                for line in content.splitlines():
                    if line.strip().startswith("authtoken:"):
                        token = line.split(":", 1)[1].strip().strip('"').strip("'")
                        if token and token != "none" and len(token) > 8:
                            return True
        except Exception:
            pass

    return False


def save_authtoken(token: str) -> None:
    """Configure authtoken via ngrok binary and update .env file."""
    token = token.strip()
    if not token:
        raise ValueError("Authtoken cannot be empty")

    ngrok_bin = find_ngrok_binary()
    if not ngrok_bin:
        raise FileNotFoundError("ngrok binary not found in project root")

    # Run ngrok config add-authtoken
    res = subprocess.run(
        [str(ngrok_bin), "config", "add-authtoken", token],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        logger.warning(f"ngrok config add-authtoken failed: {res.stderr}")

    # Set in memory
    os.environ["NGROK_AUTHTOKEN"] = token

    # Append or update in .env file
    env_file = get_project_root() / ".env"
    try:
        lines = []
        if env_file.exists():
            lines = env_file.read_text(encoding="utf-8").splitlines()

        token_updated = False
        new_lines = []
        for line in lines:
            if line.startswith("NGROK_AUTHTOKEN="):
                new_lines.append(f"NGROK_AUTHTOKEN={token}")
                token_updated = True
            else:
                new_lines.append(line)

        if not token_updated:
            new_lines.append(f"NGROK_AUTHTOKEN={token}")

        env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not persist authtoken to .env: {e}")


def query_ngrok_api() -> Optional[dict[str, Any]]:
    """Query local ngrok inspection API for active tunnels."""
    try:
        with httpx.Client(timeout=0.8) as client:
            resp = client.get(NGROK_INSPECT_URL)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


def get_current_status() -> NgrokStatusResponse:
    """Fetch live status of the ngrok tunnel."""
    auth_ok = is_authtoken_configured()
    api_data = query_ngrok_api()

    if not api_data or not api_data.get("tunnels"):
        return NgrokStatusResponse(
            is_running=False,
            public_url=None,
            proto=None,
            tunnels=[],
            authtoken_configured=auth_ok,
            error=None,
        )

    raw_tunnels = api_data.get("tunnels", [])
    parsed_tunnels: list[NgrokTunnelInfo] = []
    preferred_url: Optional[str] = None
    preferred_proto: Optional[str] = None

    for t in raw_tunnels:
        pub_url = t.get("public_url", "")
        proto = t.get("proto", "https")
        name = t.get("name", "tunnel")
        addr = t.get("config", {}).get("addr", "")

        parsed_tunnels.append(
            NgrokTunnelInfo(
                name=name,
                public_url=pub_url,
                proto=proto,
                addr=addr,
            )
        )

        # Favor https tunnel for sharing
        if proto == "https" and not preferred_url:
            preferred_url = pub_url
            preferred_proto = proto
        elif not preferred_url:
            preferred_url = pub_url
            preferred_proto = proto

    return NgrokStatusResponse(
        is_running=True,
        public_url=preferred_url,
        proto=preferred_proto,
        tunnels=parsed_tunnels,
        authtoken_configured=auth_ok,
        error=None,
    )


# -------------------------------------------------------------------------
# Router Endpoints
# -------------------------------------------------------------------------

@router.get("/status", response_model=NgrokStatusResponse)
def get_ngrok_tunnel_status() -> NgrokStatusResponse:
    """Get the current live status and public shareable URL of the ngrok tunnel."""
    return get_current_status()


@router.post("/start", response_model=NgrokStatusResponse)
def start_ngrok_tunnel(payload: NgrokStartRequest) -> NgrokStatusResponse:
    """Launch the ngrok tunnel in the background forwarding port 8001.

    If an authtoken is passed or previously configured, it applies it automatically.
    """
    global _ngrok_process

    # 1. If user supplied an authtoken in request, configure it first
    if payload.authtoken and payload.authtoken.strip():
        try:
            save_authtoken(payload.authtoken.strip())
        except Exception as e:
            return NgrokStatusResponse(
                is_running=False,
                public_url=None,
                authtoken_configured=is_authtoken_configured(),
                error=f"Failed to configure authtoken: {str(e)}",
            )

    # 2. Check if already active and responding
    active_status = get_current_status()
    if active_status.is_running and active_status.public_url:
        return active_status

    # 3. Locate ngrok executable
    ngrok_bin = find_ngrok_binary()
    if not ngrok_bin:
        return NgrokStatusResponse(
            is_running=False,
            public_url=None,
            authtoken_configured=is_authtoken_configured(),
            error="ngrok.exe binary not found in project directory. Please ensure ngrok.exe is present.",
        )

    # 4. Check if authtoken configured
    if not is_authtoken_configured():
        return NgrokStatusResponse(
            is_running=False,
            public_url=None,
            authtoken_configured=False,
            error=(
                "Ngrok session is not authenticated (ERR_NGROK_4018). "
                "Please configure your free authtoken from https://dashboard.ngrok.com/get-started/your-authtoken."
            ),
        )

    # 5. Build execution command
    port = settings.PORT
    cmd = [
        str(ngrok_bin),
        "http",
        str(port),
        "--log=stdout",
        "--log-format=term",
    ]

    # If env has authtoken, pass directly as fallback
    token = os.environ.get("NGROK_AUTHTOKEN", "").strip()
    if token:
        cmd.extend(["--authtoken", token])

    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NO_WINDOW

    try:
        _ngrok_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
        )
    except Exception as exc:
        return NgrokStatusResponse(
            is_running=False,
            public_url=None,
            authtoken_configured=is_authtoken_configured(),
            error=f"Failed to launch ngrok process: {str(exc)}",
        )

    # 6. Poll the local ngrok API until the tunnel is ready (up to 6.5s)
    deadline = time.time() + 6.5
    while time.time() < deadline:
        # Check if process crashed immediately
        if _ngrok_process.poll() is not None:
            stdout, stderr = _ngrok_process.communicate()
            err_msg = stdout or stderr or "Process terminated prematurely"
            if "ERR_NGROK_4018" in err_msg or "authentication failed" in err_msg:
                return NgrokStatusResponse(
                    is_running=False,
                    public_url=None,
                    authtoken_configured=False,
                    error=(
                        "Authentication failed: ngrok requires an authtoken. "
                        "Sign up and get yours free at https://dashboard.ngrok.com/get-started/your-authtoken"
                    ),
                )
            return NgrokStatusResponse(
                is_running=False,
                public_url=None,
                authtoken_configured=is_authtoken_configured(),
                error=f"Ngrok failed to start: {err_msg.strip()[:300]}",
            )

        status_check = get_current_status()
        if status_check.is_running and status_check.public_url:
            return status_check

        time.sleep(0.3)

    return get_current_status()


@router.post("/stop", response_model=NgrokStatusResponse)
def stop_ngrok_tunnel() -> NgrokStatusResponse:
    """Terminate the running ngrok tunnel process."""
    global _ngrok_process

    if _ngrok_process:
        try:
            _ngrok_process.terminate()
            _ngrok_process.wait(timeout=2.0)
        except Exception:
            try:
                _ngrok_process.kill()
            except Exception:
                pass
        _ngrok_process = None

    # On Windows, kill any detached or orphaned ngrok.exe processes
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "ngrok.exe"],
                capture_output=True,
                check=False,
            )
        except Exception:
            pass

    time.sleep(0.3)
    return get_current_status()


@router.post("/authtoken")
def set_ngrok_authtoken(payload: NgrokAuthtokenRequest) -> dict[str, Any]:
    """Save an authtoken for ngrok to configuration and .env."""
    token = payload.authtoken.strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authtoken must be a valid non-empty string.",
        )

    try:
        save_authtoken(token)
        return {
            "success": True,
            "message": "Ngrok authtoken successfully configured and saved.",
            "authtoken_configured": True,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save ngrok authtoken: {str(exc)}",
        )

