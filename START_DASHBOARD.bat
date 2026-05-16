@echo off
title NFSU Forensic Dashboard
echo.
echo ========================================
echo   NFSU Forensic Acquisition Dashboard
echo ========================================
echo.
echo Starting server...
cd /d "%~dp0"
start "" http://localhost:5000
python dashboard.py
pause
