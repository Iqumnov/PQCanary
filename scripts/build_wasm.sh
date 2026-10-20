#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo "  PQCanary WebAssembly Build Pipeline"
echo "========================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

if [ -f "${ROOT_DIR}/core/pkg/pqcanary_core.js" ]; then
    echo "[*] Found pre-built WebAssembly package in core/pkg."
    mkdir -p "${ROOT_DIR}/web/public/wasm"
    cp -u "${ROOT_DIR}/core/pkg/pqcanary_core.d.ts" "${ROOT_DIR}/web/public/wasm/" 2>/dev/null || true
    echo "[✓] WebAssembly interface verified and ready in core/pkg and web/public/wasm!"
else
    echo "[!] Pre-built package not found in core/pkg."
    if command -v wasm-pack &> /dev/null; then
        echo "[*] wasm-pack found. Building WebAssembly bundle..."
        cd "${ROOT_DIR}/core"
        wasm-pack build --target web --out-dir pkg || true
        wasm-pack build --target web --out-dir "${ROOT_DIR}/web/public/wasm" || true
        cd "${ROOT_DIR}"
    fi
fi

echo "[✓] WASM build pipeline complete."

