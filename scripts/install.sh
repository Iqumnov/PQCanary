#!/usr/bin/env bash
# PQCanary Universal Installer for Linux and macOS
set -euo pipefail

echo "=========================================================="
echo "  PQCanary Enterprise Post-Quantum Security Platform"
echo "=========================================================="

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "${INSTALL_DIR}"

if command -v cargo &> /dev/null; then
  echo "Installing via Cargo toolchain..."
  cargo install --path ./cli --bin pqcanary --locked || cargo install --git https://github.com/Iqumnov/PQCanary.git --bin pqcanary
  echo "OK: Installed successfully via Cargo."
else
  echo "ERROR: Rust toolchain (cargo) not found. Please install Rust via https://rustup.rs first."
  exit 1
fi

export PATH="${INSTALL_DIR}:${PATH}"
echo "SUCCESS: PQCanary is ready: $(pqcanary --version || true)"
