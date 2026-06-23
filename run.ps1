# run.ps1 — Launch gm8emulator on Windows (PowerShell)
# Usage: .\run.ps1 <path-to-game.exe> [options]
# Run .\run.ps1 --help for all options.

param(
    [Parameter(Position=0, Mandatory=$false)]
    [string]$Game,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Rest
)

$emulator = Join-Path $PSScriptRoot "target\release\gm8emulator.exe"

if (-not (Test-Path $emulator)) {
    Write-Error "gm8emulator.exe not found. Run .\setup.ps1 first to build the project."
    exit 1
}

if (-not $Game) {
    & $emulator --help
    exit 0
}

& $emulator $Game @Rest
exit $LASTEXITCODE
