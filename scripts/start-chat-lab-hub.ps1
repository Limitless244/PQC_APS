<#
.SYNOPSIS
    Starts the PQC-APS Chat Lab Hub (All-in-One) web application on port 8090.
.DESCRIPTION
    Runs Alice, Mallory, and Bob in a single JVM with --role=all, polls until port 8090 answers,
    and opens the default web browser.
#>
[CmdletBinding()]
param(
    [string]$JarPath = "chat-lab/target/chat-lab-1.0.0-SNAPSHOT.jar"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  PQC-APS :: CHAT LAB HUB LAUNCHER (:8090)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (-not (Test-Path $JarPath)) {
    Write-Host "JAR not found at $JarPath. Building chat-lab module..." -ForegroundColor Yellow
    & .\mvnw.cmd package -DskipTests -pl chat-lab -am
}

Write-Host "Starting java -jar $JarPath --role=all ..." -ForegroundColor Green
Start-Process "java" -ArgumentList @("-jar", $JarPath, "--role=all")

Write-Host "Waiting for http://127.0.0.1:8090 to answer..." -ForegroundColor Yellow
$ready = $false
for ($i = 0; $i -lt 45; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8090/api/info" -UseBasicParsing -TimeoutSec 1
        if ($resp.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

if ($ready) {
    Write-Host "Chat Lab Hub is UP and READY! Opening browser at http://127.0.0.1:8090 ..." -ForegroundColor Green
    Start-Process "http://127.0.0.1:8090"
} else {
    Write-Host "Warning: Timed out waiting for http://127.0.0.1:8090/api/info" -ForegroundColor Red
}
