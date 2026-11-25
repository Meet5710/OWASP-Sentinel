@echo off
setlocal
echo ==============================================================================
echo   OWASP Sentinel - Starting All Services (3 Terminals)
echo ==============================================================================

REM Terminal 1: FastAPI Backend (8001) + automatic Ngrok tunnel startup
start "1. OWASP Sentinel - Backend (8001) + Ngrok" powershell -NoExit -Command "Set-Location '%~dp0'; Start-Job -ScriptBlock { Start-Sleep -Seconds 3; try { Invoke-RestMethod -Uri 'http://127.0.0.1:8001/api/v1/tunnel/start' -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 15 | Out-Null; Write-Host '[+] Ngrok tunnel active on port 8001' -ForegroundColor Green } catch { Write-Host '[!] Ngrok auto-start skipped:' $_.Exception.Message -ForegroundColor Yellow } } | Out-Null; python -m uvicorn app.main:app --host 127.0.0.1 --port 8001"

REM Terminal 2: Vite React Frontend (5173)
start "2. OWASP Sentinel - Frontend (5173)" cmd /k "cd /d %~dp0frontend && npm.cmd run dev"

REM Terminal 3: Kali VM SSH Tunnel (local 5001 -> Kali 127.0.0.1:5000)
start "3. OWASP Sentinel - Kali SSH Tunnel (lucy@192.168.253.133)" cmd /k "ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -N -L 5001:127.0.0.1:5000 lucy@192.168.253.133"

echo Three terminals launched:
echo   1. FastAPI Backend (http://127.0.0.1:8001) + Ngrok Tunnel
echo   2. Vite Frontend   (http://localhost:5173)
echo   3. Kali SSH Tunnel (127.0.0.1:5001 -> lucy@192.168.253.133:5000)
echo ==============================================================================
