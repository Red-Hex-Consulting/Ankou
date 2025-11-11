@echo off
REM Build script for Anomaly agent (Windows)
REM This script packages the Node.js agent into an asar archive

echo Building Anomaly Agent (asar)...

REM Check if asar is installed globally
where asar >nul 2>&1
if %errorlevel% neq 0 (
    echo asar is not installed. Installing globally...
    call npm install -g @electron/asar
)

REM Create build directory
if not exist build mkdir build

REM Copy main.js to build directory
echo Copying files...
copy main.js build\main.js >nul

REM Copy package.json to build directory
copy package.json build\package.json >nul

REM Package into asar
echo Packaging into asar...
asar pack build app.asar

REM Clean up build directory
rmdir /s /q build

if exist app.asar (
    echo.
    echo ================================
    echo Build successful!
    echo Output: app.asar
    echo ================================
    echo.
    echo To run: node --no-warnings app.asar
) else (
    echo Build failed!
    exit /b 1
)


