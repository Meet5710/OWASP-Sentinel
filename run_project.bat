@echo off
setlocal
echo ==============================================================================
echo   OWASP Sentinel - Starting All Services (3 Terminals)
echo ==============================================================================

REM Terminal 1: FastAPI Backend (8001) + automatic Ngrok tunnel startup
start "1. OWASP Sentinel - Backend (8001) + Ngrok" powershell -NoExit -Command "Set-Location '%~dp0'; Start-Job -ScriptBlock { Start-Sleep -Seconds 3; try { Invoke-RestMethod -Uri 'http://127.0.0.1:8001/api/v1/tunnel/start' -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 15 | Out-Null; Write-Host '[+] Ngrok tunnel active on port 8001' -ForegroundColor Green } catch { Write-Host '[!] Ngrok auto-start skipped:' $_.Exception.Message -ForegroundColor Yellow } } | Out-Null; python -m uvicorn app.main:app --host 127.0.0.1 --port 8001"

REM Terminal 2: Vite React Frontend (5173)
start "2. OWASP Sentinel - Frontend (5173)" cmd /k "cd /d %~dp0frontend && npm.cmd run dev"

REM Terminal 3: Unified Kali Docker Container (127.0.0.1:5001 -> kali:5000) + Live Logs
start "3. OWASP Sentinel - Kali Docker Container + Logs" cmd /k "cd /d %~dp0 && set DOCKER_BUILDKIT=0 && set COMPOSE_DOCKER_CLI_BUILD=0 && docker compose up -d kali && docker compose logs -f --tail 40 kali"

echo Three terminals launched:
echo   1. FastAPI Backend   (http://127.0.0.1:8001) + Ngrok Tunnel
echo   2. Vite Frontend     (http://localhost:5173)
echo   3. Kali Docker MCP   (127.0.0.1:5001 -^> sentinel_kali:5000) + Live Logs
echo ==============================================================================
