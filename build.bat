@echo off
title Building iStrip.exe...

echo Installing PyInstaller...
pip install pyinstaller >nul 2>&1

:: PyInstaller refuses to run from System32, so copy to a temp folder and build there
set "SRC=%~dp0"
set "BUILD=%TEMP%\istrip_build"

echo Preparing build folder...
if exist "%BUILD%" rmdir /s /q "%BUILD%"
xcopy "%SRC%istrip" "%BUILD%\istrip\" /E /I /Q >nul
copy "%SRC%run.py" "%BUILD%\run.py" >nul
copy "%SRC%setup.py" "%BUILD%\setup.py" >nul

echo Building iStrip.exe -- this may take a minute...
cd /d "%BUILD%"
pyinstaller --onefile --name istrip --console --clean --noconfirm run.py

echo.
if exist "%BUILD%\dist\istrip.exe" (
    copy /Y "%BUILD%\dist\istrip.exe" "%SRC%istrip.exe" >nul
    echo ============================================
    echo  SUCCESS
    echo ============================================
    echo.
    echo  istrip.exe is in: %SRC%
    echo.
) else (
    echo BUILD FAILED. Make sure Python and pip are installed.
)

:: Clean up
cd /d "%USERPROFILE%"
rmdir /s /q "%BUILD%" >nul 2>&1

pause
