@echo off
setlocal enabledelayedexpansion
title QuantumVault Endpoint Security Agent [Single-Device Mode]
color 0B

echo ===============================================================================
echo                QUANTUMVAULT AI ENDPOINT PROTECTION AGENT
echo                Single-Device Endpoint Security Architecture
echo ===============================================================================
echo.
echo [*] Mode: Single-Device Protection (1 Device Active Lock)
echo [*] Checking local environment...

:: Check for administrative rights
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running with Administrator Privileges (Full Defender/Firewall telemetry active)
) else (
    echo [!] Notice: Running in standard user mode.
    echo     For full Windows Defender and system inspection, consider 'Run as Administrator'.
)
echo.

:: 1. Handle Backend URL resolution
:: Priority 1: Argument passed to script (e.g. run_agent.bat https://my-backend.com)
if not "%~1"=="" (
    set "QUANTUMVAULT_BACKEND_URL=%~1"
    echo [*] Target Backend URL passed as argument: %~1
)

:: Priority 2: Check for existing agent_config.json
if "%QUANTUMVAULT_BACKEND_URL%"=="" (
    if exist "%~dp0agent_config.json" (
        for /f "tokens=2 delims=:, " %%a in ('findstr "backend_url" "%~dp0agent_config.json"') do (
            set "CACHED_URL=%%~a"
        )
    )
)

:: Priority 3: Interactive prompt if URL is not set
if "%QUANTUMVAULT_BACKEND_URL%"=="" (
    if not "!CACHED_URL!"=="" (
        set "FALLBACK_URL=!CACHED_URL!"
    ) else (
        set "FALLBACK_URL=http://127.0.0.1:8000"
    )

    echo [?] Specify your QuantumVault Backend URL:
    echo     (If deployed to Cloud, enter e.g.: https://your-quantumvault-backend.onrender.com)
    echo     (Or press ENTER to connect to default: !FALLBACK_URL!)
    echo.
    set /p "USER_URL=>> Backend URL [!FALLBACK_URL!]: "
    if "!USER_URL!"=="" (
        set "QUANTUMVAULT_BACKEND_URL=!FALLBACK_URL!"
    ) else (
        set "QUANTUMVAULT_BACKEND_URL=!USER_URL!"
    )

    :: Save to agent_config.json for convenience next time
    (
        echo {
        echo   "backend_url": "!QUANTUMVAULT_BACKEND_URL!"
        echo }
    ) > "%~dp0agent_config.json"
    echo [+] Configuration saved to agent_config.json
)

echo.
echo [*] Connecting Agent to Target Backend: %QUANTUMVAULT_BACKEND_URL%
echo.

:: 2. Launch compiled standalone executable if present
if exist "%~dp0dist\QuantumVault-Agent.exe" (
    echo [*] Launching standalone agent: dist\QuantumVault-Agent.exe...
    "%~dp0dist\QuantumVault-Agent.exe" --backend "%QUANTUMVAULT_BACKEND_URL%"
    goto :end
)

if exist "%~dp0QuantumVault-Agent.exe" (
    echo [*] Launching standalone agent: QuantumVault-Agent.exe...
    "%~dp0QuantumVault-Agent.exe" --backend "%QUANTUMVAULT_BACKEND_URL%"
    goto :end
)

:: 3. Launch via Python runtime fallback
where python >nul 2>&1
if %errorLevel% == 0 (
    echo [*] Python detected. Launching local agent via Python runtime...
    python "%~dp0agent_launcher.py" --backend "%QUANTUMVAULT_BACKEND_URL%"
    goto :end
)

echo.
echo [ERROR] Neither QuantumVault-Agent.exe nor Python was found on this system.
echo Please download QuantumVault-Agent.exe or install Python 3.10+.
echo.
pause

:end
