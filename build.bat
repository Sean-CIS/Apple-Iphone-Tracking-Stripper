@echo off
title Building iStrip.exe...
cd /d "%~dp0"

echo Installing PyInstaller...
pip install pyinstaller >nul 2>&1

echo Building iStrip.exe — this may take a minute...
pyinstaller --onefile --name istrip --console --clean --noconfirm run.py

echo.
if exist "dist\istrip.exe" (
    echo SUCCESS: istrip.exe is ready in the dist\ folder.
    echo You can move dist\istrip.exe anywhere and double-click it.
) else (
    echo BUILD FAILED. Make sure Python and pip are installed.
)
pause
