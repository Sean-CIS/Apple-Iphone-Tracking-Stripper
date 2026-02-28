@echo off
title Building iStrip.exe...

echo Installing PyInstaller...
pip install pyinstaller >nul 2>&1

:: PyInstaller refuses to run from System32, so copy to a temp folder and build there
set "SRC=%~dp0"
set "BUILD=%TEMP%\istrip_build"
set "OUTPUT=%USERPROFILE%\istrip"

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
    :: Put it in C:\Users\USERNAME\istrip\ which always exists and is writable
    if not exist "%OUTPUT%" mkdir "%OUTPUT%"
    copy /Y "%BUILD%\dist\istrip.exe" "%OUTPUT%\istrip.exe" >nul

    :: Also try to copy to Desktop (regular and OneDrive locations)
    if exist "%USERPROFILE%\Desktop" copy /Y "%BUILD%\dist\istrip.exe" "%USERPROFILE%\Desktop\istrip.exe" >nul 2>&1
    if exist "%USERPROFILE%\OneDrive\Desktop" copy /Y "%BUILD%\dist\istrip.exe" "%USERPROFILE%\OneDrive\Desktop\istrip.exe" >nul 2>&1

    echo ============================================
    echo  SUCCESS - istrip.exe has been built
    echo ============================================
    echo.
    echo  Location: %OUTPUT%\istrip.exe
    echo.
    echo  Also copied to your Desktop if possible.
    echo  Double-click istrip.exe to run the program.
    echo.

    :: Open the folder so the user can see the exe
    explorer "%OUTPUT%"
) else (
    echo BUILD FAILED. Make sure Python and pip are installed.
)

:: Clean up
cd /d "%USERPROFILE%"
rmdir /s /q "%BUILD%" >nul 2>&1

pause
