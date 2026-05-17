@echo off

echo ========================================
echo   NFSU Forensic Acquisition Dashboard
echo ========================================
echo.

cd /d "%~dp0"

call venv\Scripts\activate

echo Starting Flask dashboard server...
echo.

start http://127.0.0.1:5000

python dashboard.py

pause