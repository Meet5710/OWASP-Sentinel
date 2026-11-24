@echo off
echo ==============================================
echo   OWASP Sentinel - Starting All Services
echo ==============================================

start "OWASP Sentinel - FastAPI Backend (Port 8001)" cmd /k "cd /d %~dp0 && python main.py"
start "OWASP Sentinel - Vite Frontend (Port 5173)" cmd /k "cd /d %~dp0frontend && npm run dev"

echo Services dispatched in separate terminal windows.
echo   - Backend API: http://127.0.0.1:8001
echo   - Frontend UI: http://localhost:5173
echo ==============================================

