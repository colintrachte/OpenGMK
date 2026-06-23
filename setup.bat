@echo off
:: setup.bat -- OpenGMK setup for Windows (cmd.exe)
:: Requires rustup to already be installed (https://rustup.rs).
:: Installs the pinned Rust toolchain and builds all workspace crates in release mode.

setlocal

where rustup >nul 2>&1
if errorlevel 1 (
    echo ERROR: rustup not found.
    echo Please install Rust from https://rustup.rs and re-run this script.
    exit /b 1
)

echo Installing Rust toolchain 1.77...
rustup toolchain install 1.77
if errorlevel 1 ( echo ERROR: Failed to install toolchain. & exit /b 1 )

echo.
echo Building OpenGMK (release)...
cargo build --release
if errorlevel 1 ( echo ERROR: Build failed. & exit /b 1 )

echo.
echo Build complete. Binaries are in: %~dp0target\release\
echo   gm8emulator.exe   -- run a GameMaker 8 game
echo   gm8decompiler.exe -- decompile a GameMaker 8 .exe to .gmk / .gm81
endlocal
