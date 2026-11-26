@echo off
setlocal
echo ==============================================================================
echo   OWASP Sentinel - Starting All Services (3 Terminals)
echo ==============================================================================

REM Terminal 1: FastAPI Backend (8001) + automatic Ngrok tunnel startup
start "1. OWASP Sentinel - Backend (8001) + Ngrok" powershell -NoExit -Command "Set-Location '%~dp0'; Start-Job -ScriptBlock { Start-Sleep -Seconds 3; try { Invoke-RestMethod -Uri 'http://127.0.0.1:8001/api/v1/tunnel/start' -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 15 | Out-Null; Write-Host '[+] Ngrok tunnel active on port 8001' -ForegroundColor Green } catch { Write-Host '[!] Ngrok auto-start skipped:' $_.Exception.Message -ForegroundColor Yellow } } | Out-Null; python -m uvicorn app.main:app --host 127.0.0.1 --port 8001"

REM Terminal 2: Vite React Frontend (5173)
start "2. OWASP Sentinel - Frontend (5173)" cmd /k "cd /d %~dp0frontend && npm.cmd run dev"

REM Terminal 3: Ensure kali-server-mcp is running on Kali VM, hold SSH Tunnel (5001 -> 5000), and stream live MCP logs
start "3. OWASP Sentinel - Kali SSH Tunnel + MCP Logs (lucy@192.168.253.133)" cmd /k ssh -tt -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 5001:127.0.0.1:5000 lucy@192.168.253.133 "ss -tln | grep -q ':5000 ' || (nohup /usr/bin/kali-server-mcp --ip 127.0.0.1 --port 5000 >/tmp/kali-server-mcp.log 2>&1 </dev/null &); sleep 1; touch /tmp/kali-server-mcp.log; echo [+] Kali SSH Tunnel active (127.0.0.1:5001 -^> Kali:5000) - Streaming MCP logs:; tail -n 30 -F /tmp/kali-server-mcp.log"

echo Three terminals launched:
echo   1. FastAPI Backend (http://127.0.0.1:8001) + Ngrok Tunnel
echo   2. Vite Frontend   (http://localhost:5173)
echo   3. Kali SSH Tunnel + Live MCP Logs (lucy@192.168.253.133)
echo ==============================================================================
