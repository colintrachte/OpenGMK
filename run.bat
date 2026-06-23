@echo off
:: run.bat -- Launch gm8emulator on Windows (cmd.exe)
:: Usage: run.bat <path-to-game.exe> [options]

setlocal

set EMU=%~dp0target\release\gm8emulator.exe

if not exist "%EMU%" (
    echo ERROR: gm8emulator.exe not found. Run setup.bat first to build the project.
    exit /b 1
)

if "%~1"=="" (
    "%EMU%" --help
    exit /b 0
)

"%EMU%" %*
endlocal
