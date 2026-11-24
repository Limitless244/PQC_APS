@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ==============================================================================
echo   PQC-APS :: Starting Chat Lab Hub (All-in-One: Alice, Mallory, Bob on :8090)
echo ==============================================================================

set JAR_FILE=chat-lab\target\chat-lab-1.0.0-SNAPSHOT.jar

if not exist "%JAR_FILE%" (
    echo [INFO] JAR not found at %JAR_FILE%. Building project first...
    call mvnw.cmd package -DskipTests -pl chat-lab -am
    if errorlevel 1 (
        echo [ERROR] Build failed.
        pause
        exit /b 1
    )
)

echo Starting Chat Lab Hub process (--role=all)...
start "PQC-APS Chat Lab Hub (:8090)" java -jar "%JAR_FILE%" --role=all

echo Waiting for Chat Lab Hub to answer at http://127.0.0.1:8090 ...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ready = $false; for ($i=0; $i -lt 45; $i++) { try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8090/api/info' -UseBasicParsing -TimeoutSec 1; if ($r.StatusCode -eq 200) { $ready = $true; break } } catch { Start-Sleep -Milliseconds 1000 } }; if ($ready) { Write-Host 'Chat Lab Hub is UP!' -ForegroundColor Green } else { Write-Host 'Timeout waiting for port 8090' -ForegroundColor Yellow }"

echo Opening browser at http://127.0.0.1:8090 ...
start http://127.0.0.1:8090

echo.
echo ==============================================================================
echo   Chat Lab Hub is running at: http://127.0.0.1:8090
echo   Alice  : Client    (connected via Mallory :9000)
echo   Mallory: TCP Proxy (listening :9000, forwarding to Bob :9001)
echo   Bob    : Server    (TCP listening on :9001)
echo ==============================================================================
