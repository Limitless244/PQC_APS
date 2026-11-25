@echo off
setlocal
cd /d "%~dp0"

echo ==============================================================================
echo   PQC-APS :: Starting Evaluation Dashboard (:8080)
echo ==============================================================================

java -jar benchmark-dashboard\target\benchmark-dashboard-1.0.0-SNAPSHOT.jar
if errorlevel 1 (
    echo.
    echo [ERROR] Benchmark Dashboard encountered an error or failed to start.
    pause
)
