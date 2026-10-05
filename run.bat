@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo  PersistMap - Windows Persistence Inventory
echo ============================================
echo.

REM Prefer a local virtual environment when present.
if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python not found on PATH.
        echo Install Python 3.11+ and try again.
        pause
        exit /b 1
    )
    set "PY=python"
)

%PY% -c "import PySide6" >nul 2>nul
if errorlevel 1 (
    echo [INFO] Installing dependencies...
    %PY% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
)

echo [STARTING] PersistMap...
%PY% app.py %*
echo.
pause
endlocal