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

# 1. Run 15-cell Attack Matrix
Write-Host "`n>>> [1/3] Running 15-Cell Attack Matrix..."
& $mvn test -pl attack-lab -Dtest=HardenedAttackMatrixTest "-Dpqcaps.dataDir=$DataDir"

Copy-Item "$DataDir/attack-results.json" "$DataDir/sample/attack-results.json" -Force
if (Test-Path "$DataDir/detection-events.jsonl") {
    Copy-Item "$DataDir/detection-events.jsonl" "$DataDir/sample/detection-events.jsonl" -Force
}

# 2. Run Crypto Scans on 3 targets
Write-Host "`n>>> [2/3] Scanning targets (vulnerable-app, migrated-app, self)..."
$scannerCp = "crypto-scanner/target/classes;crypto-agility/target/classes;common/target/classes;C:\Users\BAHRATHRAJ M\.m2\repository\org\yaml\snakeyaml\2.3\snakeyaml-2.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-databind\2.18.3\jackson-databind-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-core\2.18.3\jackson-core-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-annotations\2.18.3\jackson-annotations-2.18.3.jar"

java -cp $scannerCp com.pqcaps.scanner.CryptoScannerMain scan --path samples/vulnerable-app --out "$DataDir/scan-report-vulnerable.json"
java -cp $scannerCp com.pqcaps.scanner.CryptoScannerMain scan --path samples/migrated-app --out "$DataDir/scan-report-migrated.json"
java -cp $scannerCp com.pqcaps.scanner.CryptoScannerMain scan --path . --out "$DataDir/scan-report-self.json"

Copy-Item "$DataDir/scan-report-vulnerable.json" "$DataDir/sample/scan-report-vulnerable.json" -Force
Copy-Item "$DataDir/scan-report-migrated.json" "$DataDir/sample/scan-report-migrated.json" -Force
Copy-Item "$DataDir/scan-report-self.json" "$DataDir/sample/scan-report-self.json" -Force

# 3. Run Benchmark (Quick mode)
Write-Host "`n>>> [3/3] Running Cryptographic Benchmarks..."
$benchCp = "benchmark-dashboard/target/classes;attack-engine/target/classes;attack-lab/target/classes;crypto-scanner/target/classes;crypto-agility/target/classes;secure-channel/target/classes;pq-auth/target/classes;hybrid-kex/target/classes;classical/target/classes;common/target/classes;C:\Users\BAHRATHRAJ M\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.80\bcprov-jdk18on-1.80.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.80\bcpkix-jdk18on-1.80.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-databind\2.18.3\jackson-databind-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-core\2.18.3\jackson-core-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\com\fasterxml\jackson\core\jackson-annotations\2.18.3\jackson-annotations-2.18.3.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\openjdk\jmh\jmh-core\1.37\jmh-core-1.37.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\yaml\snakeyaml\2.3\snakeyaml-2.3.jar"

java "-Dpqcaps.dataDir=$DataDir" -cp $benchCp com.pqcaps.dashboard.benchmark.BenchmarkCli quick

Copy-Item "$DataDir/benchmark-results.json" "$DataDir/sample/benchmark-results.json" -Force

Write-Host "`nAll artifacts successfully generated in $DataDir and $DataDir/sample!"
