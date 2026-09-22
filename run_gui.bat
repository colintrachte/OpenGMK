@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ========================================================
echo   OpenGMK Decompiler Studio Launcher
echo ========================================================

:: Check if release binary exists, build if not
if not exist "target\release\gm8decompiler.exe" (
    echo [OpenGMK] Release decompiler not found. Building now...
    cargo build --release --bin gm8decompiler
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to compile gm8decompiler in release mode.
        pause
        exit /b 1
    )
    echo [OpenGMK] Build completed successfully.
)

:: Launch the WPF GUI via PowerShell in STA mode
start "" powershell.exe -STA -NoProfile -ExecutionPolicy Bypass -File "%~dp0gui.ps1" %*
