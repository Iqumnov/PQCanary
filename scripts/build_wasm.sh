#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo "  PQCanary WebAssembly Build Pipeline"
echo "========================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

if command -v wasm-pack &> /dev/null; then
    echo "[*] wasm-pack found. Building WebAssembly release bundle..."
    cd "${ROOT_DIR}/core"
    wasm-pack build --target web --out-dir pkg
    wasm-pack build --target web --out-dir "${ROOT_DIR}/web/public/wasm"
    cd "${ROOT_DIR}"
    echo "[✓] WebAssembly compiled and installed to core/pkg and web/public/wasm!"
else
    echo "[!] wasm-pack not found in PATH."
    echo "[*] Ensuring pre-built WebAssembly package in core/pkg is ready..."
    if [ -f "${ROOT_DIR}/core/pkg/pqcanary_core.js" ]; then
        echo "[✓] Pre-built WebAssembly JS package is verified in core/pkg!"
    fi
fi

echo "[✓] WASM build pipeline complete."
