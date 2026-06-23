#!/usr/bin/env sh
# run.sh -- Launch gm8emulator on Linux / macOS
# Usage: ./run.sh <path-to-game.exe> [options]

set -e

DIR="$(dirname "$0")"
EMU="$DIR/target/release/gm8emulator"

if [ ! -f "$EMU" ]; then
    echo "ERROR: gm8emulator not found. Run ./setup.sh first to build the project."
    exit 1
fi

if [ $# -eq 0 ]; then
    "$EMU" --help
    exit 0
fi

exec "$EMU" "$@"
