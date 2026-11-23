param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$MavenArgs
)
$mvnPath = "C:\Users\BAHRATHRAJ M\.m2\wrapper\dists\apache-maven-3.9.9-bin\apache-maven-3.9.9\bin\mvn.cmd"
& $mvnPath $MavenArgs
