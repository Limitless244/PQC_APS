@echo off
setlocal
cd /d "%~dp0"

echo ==============================================================================
echo   PQC-APS :: Starting Chat Lab Hub (All-in-One: Alice, Mallory, Bob on :8090)
echo ==============================================================================

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-chat-lab-hub.ps1"
if errorlevel 1 (
    echo.
    echo [ERROR] Chat Lab Hub launcher failed or encountered startup errors.
    pause
)
