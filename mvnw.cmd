@echo off
set "MVN_BIN=C:\Users\BAHRATHRAJ M\.m2\wrapper\dists\apache-maven-3.9.9-bin\apache-maven-3.9.9\bin\mvn.cmd"
"%MVN_BIN%" %*
exit /b %ERRORLEVEL%
