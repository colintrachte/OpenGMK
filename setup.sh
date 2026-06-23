#!/usr/bin/env sh
# setup.sh -- OpenGMK setup for Linux / macOS
# Installs the pinned Rust toolchain via rustup (if needed) and builds in release mode.

set -e

RUST_VERSION="1.77"

if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain "$RUST_VERSION" -y
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
else
    echo "rustup found."
fi

rustup toolchain install "$RUST_VERSION"

echo ""
echo "Building OpenGMK (release)..."
cargo build --release

echo ""
echo "Build complete. Binaries are in: $(dirname "$0")/target/release/"
echo "  gm8emulator   -- run a GameMaker 8 game"
echo "  gm8decompiler -- decompile a GameMaker 8 .exe to .gmk / .gm81"
