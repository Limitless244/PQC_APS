$projRoot = "c:\Users\BAHRATHRAJ M\OneDrive\Documents\Crypto_projects\PQC_APS"
$mvn = 'C:\Users\BAHRATHRAJ M\.m2\maven\apache-maven-3.9.9\bin\mvn.cmd'

$serverJob = Start-Job -ScriptBlock {
    param($m, $root)
    Set-Location $root
    & $m -pl secure-channel exec:java "-Dexec.mainClass=com.pqcaps.channel.demo.HybridServer" "-Dexec.args=--suite HYBRID --port 9005"
} -ArgumentList $mvn, $projRoot

Start-Sleep -Seconds 7

Set-Location $projRoot
$clientOut = & $mvn -pl secure-channel exec:java "-Dexec.mainClass=com.pqcaps.channel.demo.HybridClient" "-Dexec.args=--suite HYBRID --port 9005"

Start-Sleep -Seconds 2
$serverOut = Receive-Job $serverJob
Stop-Job $serverJob -ErrorAction SilentlyContinue
Remove-Job $serverJob -Force -ErrorAction SilentlyContinue

Write-Host "=== SERVER OUTPUT ==="
$serverOut | Out-String | Write-Host
Write-Host "=== CLIENT OUTPUT ==="
$clientOut | Out-String | Write-Host
