@echo off
echo ========================================================
echo   Starting CYBERGUARD Threat Detection & Response Platform
echo ========================================================

echo Starting FastAPI Backend on port 8000...
start "CYBERGUARD Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn app.main:app --port 8000 --reload"

echo Starting React Frontend on port 5173...
start "CYBERGUARD Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ========================================================
echo Both servers initiated!
echo Frontend Dashboard: http://localhost:5173/
echo Backend Swagger API: http://127.0.0.1:8000/docs
echo ========================================================
