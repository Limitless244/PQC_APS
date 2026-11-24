<#
.SYNOPSIS
    Starts the PQC-APS Chat Lab applications in separate PowerShell windows.
.DESCRIPTION
    Launches Alice (Client :8081), Mallory (Attacker Proxy :8082), and Bob (Server :8083)
    communicating over real localhost TCP sockets.
    Supports a -Direct switch for client-to-server connection without an attacker proxy.
.PARAMETER Direct
    When specified, connects Alice directly to Bob on TCP port 9001 (skips Mallory).
.PARAMETER JarPath
    Path to the compiled chat-lab JAR file.
#>
[CmdletBinding()]
param(
    [switch]$Direct,
    [string]$JarPath = "chat-lab/target/chat-lab-1.0.0-SNAPSHOT.jar"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  PQC-APS :: DISTRIBUTED CHAT LAB LAUNCHER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (-not (Test-Path $JarPath)) {
    Write-Host "JAR not found at $JarPath. Building chat-lab module..." -ForegroundColor Yellow
    & .\mvnw.cmd package -DskipTests -pl chat-lab -am
}

if ($Direct) {
    Write-Host "`nMode: DIRECT (Alice -> Bob on 9001, no attacker proxy)`n" -ForegroundColor Green

    Write-Host "1. Starting Bob (Server) on http://127.0.0.1:8083 (TCP :9001)..." -ForegroundColor White
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '=== BOB (SERVER :8083) ===' -ForegroundColor Cyan; java -jar $JarPath --role=server"

    Start-Sleep -Seconds 2

    Write-Host "2. Starting Alice (Client) on http://127.0.0.1:8081 (Target TCP :9001)..." -ForegroundColor White
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '=== ALICE (CLIENT :8081) ===' -ForegroundColor Green; java -jar $JarPath --role=client --client.tcp.targetPort=9001"

    Write-Host "`nActive URLs:" -ForegroundColor Cyan
    Write-Host "  Alice (Client) : http://127.0.0.1:8081" -ForegroundColor Green
    Write-Host "  Bob   (Server) : http://127.0.0.1:8083" -ForegroundColor Blue
} else {
    Write-Host "`nMode: FULL PROXY (Alice :8081 -> Mallory :9000 -> Bob :9001)`n" -ForegroundColor Green

    Write-Host "1. Starting Bob (Server) on http://127.0.0.1:8083 (TCP :9001)..." -ForegroundColor White
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '=== BOB (SERVER :8083) ===' -ForegroundColor Cyan; java -jar $JarPath --role=server"

    Start-Sleep -Seconds 2

    Write-Host "2. Starting Mallory (Attacker Proxy) on http://127.0.0.1:8082 (Listen :9000 -> Forward :9001)..." -ForegroundColor White
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '=== MALLORY (ATTACKER PROXY :8082) ===' -ForegroundColor Magenta; java -jar $JarPath --role=attacker"

    Start-Sleep -Seconds 2

    Write-Host "3. Starting Alice (Client) on http://127.0.0.1:8081 (Target TCP :9000)..." -ForegroundColor White
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '=== ALICE (CLIENT :8081) ===' -ForegroundColor Green; java -jar $JarPath --role=client --client.tcp.targetPort=9000"

    Write-Host "`nActive URLs:" -ForegroundColor Cyan
    Write-Host "  Alice   (Client)        : http://127.0.0.1:8081" -ForegroundColor Green
    Write-Host "  Mallory (Attacker Proxy): http://127.0.0.1:8082" -ForegroundColor Magenta
    Write-Host "  Bob     (Server)        : http://127.0.0.1:8083" -ForegroundColor Blue
}

Write-Host "`nAll roles bound strictly to 127.0.0.1 (Localhost only)." -ForegroundColor Gray
