# scripts/generate-all.ps1
# PQC-APS :: Automated artifact generation script for Phase 6
# Runs the 15-cell attack matrix, scans 3 targets, and generates benchmark results.

param(
    [string]$DataDir = "data"
)

$ErrorActionPreference = "Stop"

Write-Host "=========================================================================="
Write-Host "  PQC-APS :: Generating All System Artifacts"
Write-Host "=========================================================================="

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path "$DataDir/sample" | Out-Null

$mvn = "C:\Users\BAHRATHRAJ M\.m2\wrapper\dists\apache-maven-3.9.9-bin\apache-maven-3.9.9\bin\mvn.cmd"
if (-not (Test-Path $mvn)) {
    $mvn = "mvn.cmd"
}

# 1. Run 15-cell Attack Matrix
Write-Host "`n>>> [1/3] Running 15-Cell Attack Matrix..."
& $mvn test -pl attack-lab -Dtest=HardenedAttackMatrixTest "-Dpqcaps.dataDir=$DataDir"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$DataDir/attack-results.json")) {
    Write-Error "CRITICAL: Attack matrix execution failed with exit code $LASTEXITCODE."
    exit 1
}

Copy-Item "$DataDir/attack-results.json" "$DataDir/sample/attack-results.json" -Force
if (Test-Path "$DataDir/detection-events.jsonl") {
    Copy-Item "$DataDir/detection-events.jsonl" "$DataDir/sample/detection-events.jsonl" -Force
}

# 2. Run Crypto Scans on 3 targets
Write-Host "`n>>> [2/3] Scanning targets (vulnerable-app, migrated-app, self)..."
$scannerJar = "crypto-scanner/target/crypto-scanner-1.0.0-SNAPSHOT-shaded.jar"
if (-not (Test-Path $scannerJar)) {
    Write-Host "Building crypto-scanner shaded jar..."
    & $mvn package -pl crypto-scanner -DskipTests
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $scannerJar)) {
        Write-Error "CRITICAL: Failed to build crypto-scanner shaded jar."
        exit 1
    }
}

function Invoke-CryptoScan([string]$targetPath, [string]$outFile, [string[]]$extraArgs = @()) {
    Write-Host "  -> Scanning '$targetPath' -> '$outFile'..."
    if ($extraArgs.Count -gt 0) {
        java -jar $scannerJar scan --path "$targetPath" --out "$outFile" @extraArgs
    } else {
        java -jar $scannerJar scan --path "$targetPath" --out "$outFile"
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CRITICAL: Crypto scanner failed for target '$targetPath' with exit code $LASTEXITCODE."
        exit 1
    }
    if (-not (Test-Path $outFile)) {
        Write-Error "CRITICAL: Crypto scanner exited with 0 but output file '$outFile' was not generated."
        exit 1
    }
    $fileItem = Get-Item $outFile
    if ($fileItem.Length -eq 0) {
        Write-Error "CRITICAL: Generated scan report '$outFile' is empty."
        exit 1
    }
}

Invoke-CryptoScan "samples/vulnerable-app" "$DataDir/scan-report-vulnerable.json"
Invoke-CryptoScan "samples/migrated-app" "$DataDir/scan-report-migrated.json"
Invoke-CryptoScan "." "$DataDir/scan-report-self.json"
Invoke-CryptoScan "." "$DataDir/scan-report-self-production.json" @("--exclude-modules", "attack-lab,classical")
Invoke-CryptoScan "." "$DataDir/scan-report-self-tests.json" @("--include-tests")

Copy-Item "$DataDir/scan-report-vulnerable.json" "$DataDir/sample/scan-report-vulnerable.json" -Force
Copy-Item "$DataDir/scan-report-migrated.json" "$DataDir/sample/scan-report-migrated.json" -Force
Copy-Item "$DataDir/scan-report-self.json" "$DataDir/sample/scan-report-self.json" -Force
Copy-Item "$DataDir/scan-report-self-production.json" "$DataDir/sample/scan-report-self-production.json" -Force
Copy-Item "$DataDir/scan-report-self-tests.json" "$DataDir/sample/scan-report-self-tests.json" -Force

# 3. Run Benchmark (Quick mode)
Write-Host "`n>>> [3/3] Running Cryptographic Benchmarks..."
$benchCp = "benchmark-dashboard/target/classes;attack-engine/target/classes;attack-lab/target/classes;crypto-scanner/target/classes;crypto-agility/target/classes;secure-channel/target/classes;pq-auth/target/classes;hybrid-kex/target/classes;classical/target/classes;common/target/classes;C:\Users\BAHRATHRAJ M\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.80\bcprov-jdk18on-1.80.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.80\bcpkix-jdk18on-1.80.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-databind\2.18.3\jackson-databind-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-core\2.18.3\jackson-core-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-annotations\2.18.3\jackson-annotations-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\datatype\jackson-datatype-jsr310\2.18.3\jackson-datatype-jsr310-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\openjdk\jmh\jmh-core\1.37\jmh-core-1.37.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\yaml\snakeyaml\2.3\snakeyaml-2.3.jar"

java "-Dpqcaps.dataDir=$DataDir" -cp $benchCp com.pqcaps.dashboard.benchmark.BenchmarkCli quick
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$DataDir/benchmark-results.json")) {
    Write-Error "CRITICAL: Benchmark runner failed with exit code $LASTEXITCODE."
    exit 1
}

Copy-Item "$DataDir/benchmark-results.json" "$DataDir/sample/benchmark-results.json" -Force

# 4. Generate Test Summary from Surefire Reports
Write-Host "`n>>> [4/4] Aggregating Surefire Test Reports..."
$testSummaryFile = "$DataDir/test-summary.json"
$totalTests = 0
$failures = 0
$errors = 0
$skipped = 0

Get-ChildItem -Path . -Filter "TEST-*.xml" -Recurse | Where-Object { $_.FullName -notmatch "samples" } | ForEach-Object {
    try {
        [xml]$xml = Get-Content $_.FullName
        $totalTests += [int]$xml.testsuite.tests
        $failures += [int]$xml.testsuite.failures
        $errors += [int]$xml.testsuite.errors
        $skipped += [int]$xml.testsuite.skipped
    } catch {}
}

if ($totalTests -gt 0) {
    $passed = $totalTests - $failures - $errors - $skipped
    $summaryObj = [PSCustomObject]@{
        available = $true
        totalTests = $totalTests
        passed = $passed
        failures = $failures
        errors = $errors
        skipped = $skipped
        moduleCount = 10
        caption = "Across 10 modules"
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    $summaryObj | ConvertTo-Json -Depth 4 | Set-Content $testSummaryFile -Encoding UTF8
    Copy-Item $testSummaryFile "$DataDir/sample/test-summary.json" -Force
    Write-Host "Test summary generated: $totalTests tests ($passed passed, $failures failed) across 10 modules."
} else {
    Write-Host "Notice: No surefire reports found; test-summary.json not generated."
}

Write-Host "`n=========================================================================="
Write-Host "  PQC-APS :: All Artifacts Successfully Generated in $DataDir"
Write-Host "=========================================================================="
