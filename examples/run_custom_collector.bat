@echo off
REM Run Custom Collector Example for Enterprise SIEM Platform
setlocal enabledelayedexpansion

echo ===============================================
echo Enterprise SIEM Platform - Custom Collector Demo
echo ===============================================

REM Check if Python is available
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    exit /b 1
)

echo [INFO] Python found on system

REM Change to the project root directory
cd %~dp0\..

REM Check if virtual environment exists, create if not
if not exist venv (
    echo [INFO] Creating virtual environment...
    python -m venv venv
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to create virtual environment
        exit /b 1
    )
)

REM Activate the virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if requirements are installed
pip show pyyaml >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing dependencies...
    pip install -r requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install dependencies
        exit /b 1
    )
)

REM Set Demo Mode environment variable (already true by default in the script)
set DEMO_MODE=true

REM Ensure directories exist
if not exist data mkdir data
if not exist examples mkdir examples

echo [INFO] Running Custom Collector Example...
echo This will demonstrate how to create a custom collector that integrates with external APIs.
echo.

python examples/custom_collector_example.py
set COLLECTOR_RESULT=%ERRORLEVEL%
echo.

REM Deactivate virtual environment
call venv\Scripts\deactivate.bat

if %COLLECTOR_RESULT% EQU 0 (
    echo [SUCCESS] Custom Collector example completed successfully
) else (
    echo [ERROR] Custom Collector example failed with code %COLLECTOR_RESULT%
)

echo.
echo To integrate this collector into the SIEM platform, you would:
echo 1. Move the ThreatIntelCollector class to the src/collectors directory
echo 2. Update the configuration to enable the collector
echo 3. Register the collector in the run_siem.py file
echo.
echo See the docs/DEVELOPER_GUIDE.md for more information on extending the platform.
echo ===============================================
exit /b %COLLECTOR_RESULT% 