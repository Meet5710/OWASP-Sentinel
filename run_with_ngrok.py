"""OWASP Sentinel - One-Click Internet Launcher with Ngrok

Runs the OWASP Sentinel platform (FastAPI backend + React frontend)
and exposes it to the public internet via the included ngrok executable.
Provides a shareable public URL that anyone on any PC or phone can access.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent
NGROK_BIN = PROJECT_ROOT / "ngrok.exe" if sys.platform == "win32" else PROJECT_ROOT / "ngrok"
CONFIG_PATH_WIN = Path(os.environ.get("LOCALAPPDATA", "")) / "ngrok" / "ngrok.yml"
BACKEND_PORT = 8001
HEALTH_URL = f"http://127.0.0.1:{BACKEND_PORT}/api/v1/health"
NGROK_API_URL = "http://127.0.0.1:4040/api/tunnels"


def print_banner() -> None:
    banner = r"""
================================================================================
   ____ _       __ ___    _____ ____     _____            __  _            __
  / __ \ |     / //   |  / ___// __ \   / ___/___  ____  / /_(_)___  ___  / /
 / / / / | /| / // /| |  \__ \/ /_/ /   \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ / 
/ /_/ /| |/ |/ // ___ | ___/ / ____/   ___/ /  __/ / / / /_/ / / / /  __/ /  
\____/ |__/|__//_/  |_|/____/_/       /____/\___/_/ /_/\__/_/_/ /_/\___/_/   
                                                                              
           Standalone Cybersecurity Posture & Assessment Platform             
================================================================================
"""
    print(banner)


def check_prerequisites() -> None:
    """Verify ngrok.exe and built frontend exist."""
    if not NGROK_BIN.exists():
        fallback = shutil.which("ngrok.exe") or shutil.which("ngrok")
        if not fallback:
            print(f"[!] Error: ngrok executable not found at {NGROK_BIN}")
            print("    Please keep ngrok.exe in the project root folder.")
            sys.exit(1)

    frontend_index = PROJECT_ROOT / "frontend" / "dist" / "index.html"
    if not frontend_index.exists():
        print("[*] Notice: Built frontend dist/ not found. Building now...")
        cmd = ["cmd", "/c", "npm --prefix frontend run build"] if sys.platform == "win32" else ["npm", "--prefix", "frontend", "run", "build"]
        res = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
        if res.returncode != 0:
            print("[!] Warning: Frontend build failed. Run 'npm --prefix frontend run build' manually.")


def is_authtoken_configured() -> bool:
    """Check whether an authtoken has already been registered."""
    # 1. Environment variable
    if os.environ.get("NGROK_AUTHTOKEN", "").strip():
        return True

    # 2. Check .env file
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("NGROK_AUTHTOKEN=") and len(line.split("=", 1)[1].strip()) > 8:
                    return True
        except Exception:
            pass

    # 3. Check ngrok config file
    if sys.platform == "win32" and CONFIG_PATH_WIN.exists():
        try:
            content = CONFIG_PATH_WIN.read_text(encoding="utf-8")
            for line in content.splitlines():
                if line.strip().startswith("authtoken:"):
                    tok = line.split(":", 1)[1].strip().strip('"').strip("'")
                    if tok and len(tok) > 8:
                        return True
        except Exception:
            pass

    return False


def ensure_authtoken() -> None:
    """Ensure an authtoken is present, prompting the user if interactive."""
    if is_authtoken_configured():
        return

    print("\n[!] Ngrok requires a free one-time authentication token to start.")
    print("    1. Sign up / log in at: https://dashboard.ngrok.com/signup")
    print("    2. Copy your token from: https://dashboard.ngrok.com/get-started/your-authtoken\n")

    token = ""
    if sys.stdin.isatty():
        try:
            token = input(">> Paste your Ngrok Authtoken here: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if token:
        print("[*] Configuring ngrok authtoken...")
        cmd = [str(NGROK_BIN), "config", "add-authtoken", token]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] Authtoken saved successfully!")
            # Update .env
            env_file = PROJECT_ROOT / ".env"
            try:
                lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
                lines = [l for l in lines if not l.startswith("NGROK_AUTHTOKEN=")]
                lines.append(f"NGROK_AUTHTOKEN={token}")
                env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            except Exception:
                pass
        else:
            print(f"[!] Could not set authtoken: {res.stderr}")
    else:
        print("[!] No authtoken entered. Attempting to start (will fail if unauthenticated).")


def is_server_running() -> bool:
    """Check if the FastAPI backend is already responding."""
    try:
        req = urllib.request.Request(HEALTH_URL, headers={"User-Agent": "OWASP-Sentinel-Launcher"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_server_if_needed() -> subprocess.Popen | None:
    """Start the FastAPI backend if not already running."""
    if is_server_running():
        print(f"[+] OWASP Sentinel backend is already running on http://127.0.0.1:{BACKEND_PORT}")
        return None

    print(f"[*] Starting OWASP Sentinel backend on port {BACKEND_PORT}...")
    cmd = [sys.executable, "main.py"]
    proc = subprocess.Popen(
        cmd,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for server to come up
    for _ in range(30):
        if is_server_running():
            print(f"[+] OWASP Sentinel backend started successfully on port {BACKEND_PORT}.")
            return proc
        time.sleep(0.3)

    print("[!] Warning: Backend took longer than expected to respond. Continuing...")
    return proc


def get_ngrok_public_url() -> str | None:
    """Fetch public tunnel URL from the ngrok inspection API."""
    try:
        req = urllib.request.Request(NGROK_API_URL, headers={"User-Agent": "OWASP-Sentinel-Launcher"})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                tunnels = data.get("tunnels", [])
                for t in tunnels:
                    url = t.get("public_url", "")
                    if url.startswith("https://"):
                        return url
                if tunnels:
                    return tunnels[0].get("public_url")
    except Exception:
        pass
    return None


def copy_to_clipboard(text: str) -> bool:
    """Copy string to Windows/system clipboard."""
    if sys.platform == "win32":
        try:
            ps_cmd = f"Set-Clipboard -Value '{text}'"
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return True
        except Exception:
            pass
    return False


def main() -> None:
    print_banner()
    check_prerequisites()
    ensure_authtoken()

    # 1. Start server
    backend_proc = start_server_if_needed()

    # 2. Check if ngrok is already running
    existing_url = get_ngrok_public_url()
    ngrok_proc = None

    if existing_url:
        print(f"[+] Existing ngrok tunnel detected: {existing_url}")
        public_url = existing_url
    else:
        print("[*] Launching ngrok tunnel forwarding port 8001...")
        cmd = [
            str(NGROK_BIN),
            "http",
            str(BACKEND_PORT),
            "--log=stdout",
            "--log-format=term",
        ]

        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW

        ngrok_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
        )

        # Poll for public URL
        public_url = None
        for _ in range(30):
            if ngrok_proc.poll() is not None:
                stdout, stderr = ngrok_proc.communicate()
                err_text = stdout or stderr or "Unknown error"
                print(f"\n[!] Ngrok process stopped with code {ngrok_proc.returncode}:")
                print(f"    {err_text.strip()}")
                if "ERR_NGROK_4018" in err_text:
                    print("\n    --> Token missing! Run: ngrok.exe config add-authtoken <YOUR_TOKEN>")
                sys.exit(1)

            public_url = get_ngrok_public_url()
            if public_url:
                break
            time.sleep(0.3)

    if not public_url:
        print("[!] Could not retrieve public tunnel URL from ngrok API.")
        print("    Please check if port 4040 is blocked or ngrok crashed.")
        sys.exit(1)

    shareable_app_url = f"{public_url}/app"
    copied = copy_to_clipboard(shareable_app_url)

    print("\n" + "=" * 80)
    print("   OWASP SENTINEL - PUBLIC INTERNET TUNNEL READY TO SHARE")
    print("=" * 80)
    print(f"   * Public Shareable URL : \033[92m{shareable_app_url}\033[0m")
    print(f"   * Local Network URL    : http://127.0.0.1:{BACKEND_PORT}/app")
    print(f"   * Swagger API Docs     : {public_url}/docs")
    print(f"   * Ngrok Web Inspector  : http://127.0.0.1:4040")
    print("=" * 80)
    if copied:
        print("   [+] Public URL copied to clipboard automatically!")
    print("   [+] Share this URL with anyone: it runs directly in their browser!")
    print("   [i] Press Ctrl+C in this terminal window to stop the tunnel.")
    print("=" * 80 + "\n")

    # Open in browser
    try:
        webbrowser.open(shareable_app_url)
    except Exception:
        pass

    # Keep alive until Ctrl+C
    def cleanup(signum=None, frame=None):
        print("\n[*] Shutting down ngrok tunnel...")
        if ngrok_proc:
            try:
                ngrok_proc.terminate()
            except Exception:
                pass
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/IM", "ngrok.exe"], capture_output=True, check=False)
        if backend_proc:
            print("[*] Stopping local backend server...")
            try:
                backend_proc.terminate()
            except Exception:
                pass
        print("[+] Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        while True:
            time.sleep(1)
            # Monitor ngrok process if we spawned it
            if ngrok_proc and ngrok_proc.poll() is not None:
                print("\n[!] Ngrok process terminated.")
                break
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()

