# setup.ps1 — OpenGMK setup for Windows (PowerShell)
# Installs the Rust toolchain (if missing) and builds all workspace crates in release mode.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RUST_VERSION = "1.77"

function Fail($msg) {
    Write-Error $msg
    exit 1
}

# Check for rustup
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    Write-Host "rustup not found. Downloading installer..."
    $installer = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $installer
    & $installer --default-toolchain $RUST_VERSION --no-modify-path -y
    if ($LASTEXITCODE -ne 0) { Fail "rustup installation failed." }
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
} else {
    Write-Host "rustup found."
}

# Ensure the correct toolchain is installed
rustup toolchain install $RUST_VERSION
if ($LASTEXITCODE -ne 0) { Fail "Failed to install Rust $RUST_VERSION." }

# Build the workspace in release mode
Write-Host "`nBuilding OpenGMK (release)..."
cargo build --release
if ($LASTEXITCODE -ne 0) { Fail "Build failed." }

Write-Host "`nBuild complete. Binaries are in: $PSScriptRoot\target\release\"
Write-Host "  gm8emulator.exe  — run a GameMaker 8 game"
Write-Host "  gm8decompiler.exe — decompile a GameMaker 8 .exe to .gmk / .gm81"
