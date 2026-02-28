@echo off
title iStrip - iPhone Tracking Stripper
cd /d "%~dp0"
python run.py
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Python failed to start. Make sure Python is installed.
    echo Download from: https://www.python.org/downloads/
    pause
)
