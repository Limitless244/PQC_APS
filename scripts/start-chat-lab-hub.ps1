<#
.SYNOPSIS
    Starts the PQC-APS Chat Lab Hub (All-in-One) web application on port 8090.
.DESCRIPTION
    Builds the jar if missing or older than sources, starts --role=all with cmd /k,
    polls port 8090, prints any startup error, and pauses on failure.
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

$needBuild = $false
$resolvedJar = Join-Path $projectRoot $JarPath
if (-not (Test-Path $resolvedJar)) {
    $needBuild = $true
} else {
    $jarTime = (Get-Item $resolvedJar).LastWriteTime
    $srcFiles = Get-ChildItem -Path (Join-Path $projectRoot "chat-lab\src") -Recurse -File
    $latestSrc = ($srcFiles | Measure-Object -Property LastWriteTime -Maximum).Maximum
    if ($latestSrc -and $latestSrc -gt $jarTime) {
        $needBuild = $true
    }
}

if ($needBuild) {
    Write-Host "[INFO] chat-lab.jar is missing or older than sources. Packaging chat-lab module..." -ForegroundColor Yellow
    try {
        & .\mvnw.cmd package -DskipTests -pl chat-lab -am
        if ($LASTEXITCODE -ne 0) {
            throw "Maven build failed with exit code $LASTEXITCODE"
        }
    } catch {
        Write-Host "[ERROR] Build failed: $_" -ForegroundColor Red
        Read-Host "Press Enter to exit..."
        exit 1
    }
}

if (-not (Test-Path $resolvedJar)) {
    Write-Host "[ERROR] JAR file $resolvedJar not found after build!" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    exit 1
}

Write-Host "Starting Chat Lab Hub (--role=all)..." -ForegroundColor Green
$proc = Start-Process "cmd.exe" -ArgumentList @("/k", "java -jar `"$resolvedJar`" --role=all") -PassThru

Write-Host "Waiting for http://127.0.0.1:8090 to answer..." -ForegroundColor Yellow
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
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
    Write-Host "[ERROR] Timed out waiting for http://127.0.0.1:8090/api/info." -ForegroundColor Red
    Write-Host "Please check the 'PQC-APS Chat Lab Hub' console window for startup exceptions." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    exit 1
}
