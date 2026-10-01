@echo off
title LifeVault - Smart Personal Document & Emergency Management System
setlocal

echo.
echo ============================================================
echo                 LIFEVault
echo     Smart Personal Document ^& Emergency Management System
echo ============================================================
echo.

REM Check Python
where py >nul 2>nul
if %errorlevel%==0 (
    set "PY=py"
    goto :python_found
)

where python >nul 2>nul
if %errorlevel%==0 (
    set "PY=python"
    goto :python_found
)

echo [ERROR] Python is not installed or is not available in PATH.
echo.
echo Please install Python 3.11+ from:
echo https://www.python.org/downloads/windows/
echo.
echo IMPORTANT: During installation, tick:
echo "Add python.exe to PATH"
echo.
pause
exit /b 1

:python_found
echo [OK] Python found.
%PY% --version
echo.

REM Install dependencies
if exist requirements.txt (
    echo Installing/checking required packages...
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Could not install required packages.
        echo Check your internet connection and try again.
        pause
        exit /b 1
    )
)

echo.
echo Starting LifeVault...
echo.
%PY% main.py

if errorlevel 1 (
    echo.
    echo ============================================================
    echo LifeVault stopped because an error occurred.
    echo ============================================================
    echo.
    echo If you see an error, take a screenshot of this window
    echo and send it to me.
    echo.
    pause
)

endlocal
