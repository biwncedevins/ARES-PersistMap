@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo  PersistMap - Building EXE with PyInstaller
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found on PATH.
    pause
    exit /b 1
)

echo [INFO] Installing PyInstaller...
python -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [ERROR] Could not install PyInstaller.
    pause
    exit /b 1
)

echo [INFO] Installing dependencies...
python -m pip install -r requirements.txt

echo [INFO] Building EXE...
python -m PyInstaller --noconfirm --clean PersistMap.spec

if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo [OK] Build complete. EXE at:
echo      dist\PersistMap\PersistMap.exe
echo.
pause
endlocal