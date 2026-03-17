@echo off
REM ─────────────────────────────────────────────────────────
REM  Local HTTPS Proxy — Run (Windows)
REM ─────────────────────────────────────────────────────────
set JAR=%~dp0local-https-proxy.jar
if not exist "%JAR%" (
    echo local-https-proxy.jar not found!
    echo Build with: mvn package -DskipTests
    pause & exit /b 1
)
java -jar "%JAR%"
pause
