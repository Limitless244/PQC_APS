@echo off
set CP=C:\Users\BAHRATHRAJ M\.m2\repository\org\bouncycastle\bcprov-jdk18on\1.80\bcprov-jdk18on-1.80.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\bouncycastle\bcpkix-jdk18on\1.80\bcpkix-jdk18on-1.80.jar;C:\Users\BAHRATHRAJ M\.m2\repository\org\bouncycastle\bcutil-jdk18on\1.80.2\bcutil-jdk18on-1.80.2.jar
javac -cp "%CP%" scratch\TestPqcJca.java
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
java -cp "scratch;%CP%" TestPqcJca
