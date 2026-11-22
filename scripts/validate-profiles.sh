#!/usr/bin/env bash
# Validate every upstream JSON profile and its recorded checksum.
# Permitted locally: cargo check, cargo clippy, cargo test and this script.
# Release binaries are built only by GitHub Actions.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "${CARGO_TARGET_DIR:-}" = "" ] && [ -d "/mnt/c/php2shell-rs" ]; then
  export CARGO_TARGET_DIR="/mnt/c/php2shell-rs/target"
fi

cargo run --quiet -- profile validate
