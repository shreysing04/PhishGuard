@echo off
echo ==================================================
echo   Phishing Detector - Automatic Setup ^& Run
echo ==================================================

echo.
echo [1/4] Creating Python virtual environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create virtual environment. Ensure Python is installed.
    pause
    exit /b
)

echo.
echo [2/4] Installing dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b
)

echo.
echo [3/4] Initializing MySQL Database...
python init_db.py

if %errorlevel% neq 0 (
    echo [ERROR] Failed to initialize database. Ensure MySQL is running and accessible in your PATH.
    pause
    exit /b
)

echo.
echo [4/4] Starting Flask Server...
python app.py

pause
