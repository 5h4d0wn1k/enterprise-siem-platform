@echo off
echo Enterprise SIEM Platform - Test Mode
echo ----------------------------------

REM Check if Python is installed
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Python is not installed or not in PATH. Please install Python 3.8 or higher.
    exit /b 1
)

REM Create virtual environment if it doesn't exist
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo Failed to create virtual environment.
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip to latest version
echo Upgrading pip...
python -m pip install --upgrade pip

REM Check if dependencies are installed (check for yaml module)
python -c "import yaml" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Installing dependencies...
    pip install --prefer-binary -r requirements.txt
    
    REM Check if installation was successful
    if %ERRORLEVEL% neq 0 (
        echo Failed to install dependencies using preferred binaries.
        echo Trying alternative installation method...
        pip install wheel
        pip install --no-build-isolation -r requirements.txt
        
        if %ERRORLEVEL% neq 0 (
            echo Failed to install dependencies.
            exit /b 1
        )
    )
    echo Dependencies installed successfully.
)

REM Create data directories if they don't exist
if not exist "data\" mkdir data
if not exist "data\logs\" mkdir data\logs
if not exist "data\configs\" mkdir data\configs
if not exist "temp\" mkdir temp

REM Parse command-line arguments
set TEST_ARGS=

:parse
if "%~1"=="" goto :endparse
set TEST_ARGS=%TEST_ARGS% %1
shift
goto :parse
:endparse

REM If no args provided, use defaults
if "%TEST_ARGS%"=="" (
    set TEST_ARGS=--test-mode both --rate 0.5 --duration 300
)

REM Run the SIEM platform in test mode
echo Starting Enterprise SIEM Platform in test mode...
echo.
echo Press Ctrl+C to stop the test
echo.
python test_siem.py %TEST_ARGS%

REM Deactivate virtual environment when done
call venv\Scripts\deactivate.bat
echo SIEM Platform test has been stopped. 