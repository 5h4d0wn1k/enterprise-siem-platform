@echo off
REM Run API Example Script for Enterprise SIEM Platform
setlocal enabledelayedexpansion

echo ===============================================
echo Enterprise SIEM Platform - API Example Runner
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

REM Ensure directories exist
if not exist data mkdir data
if not exist examples mkdir examples

echo [INFO] Running API example...
echo.
python examples/api_example.py
set EXAMPLE_RESULT=%ERRORLEVEL%
echo.

REM Deactivate virtual environment
call venv\Scripts\deactivate.bat

if %EXAMPLE_RESULT% EQU 0 (
    echo [SUCCESS] API example completed successfully
) else (
    echo [ERROR] API example failed with code %EXAMPLE_RESULT%
)

echo ===============================================
exit /b %EXAMPLE_RESULT% 