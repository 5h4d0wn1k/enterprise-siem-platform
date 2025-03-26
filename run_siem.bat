@echo off
echo Enterprise SIEM Platform
echo ========================

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

REM Parse command line arguments
set ARGS=
:parse_args
if "%~1"=="" goto run
set ARGS=%ARGS% %1
shift
goto parse_args

:run
REM Run the SIEM platform
echo Starting Enterprise SIEM Platform...
python -m src.run_siem %ARGS%

REM Deactivate virtual environment when done
call venv\Scripts\deactivate.bat
echo SIEM Platform has stopped. 