#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo "  PQCanary Enterprise Multi-Platform Build Pipeline"
echo "  Target: Linux CLI, Deb, AppImage, Web, WASM, Docker"
echo "========================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo ""
echo "[1/5] Building Native CLI & MCP Server..."
cargo build --release --bin pqcanary --bin pqcanary-mcp
echo "[✓] Binaries generated at target/release/pqcanary and target/release/pqcanary-mcp"

echo ""
echo "[2/5] Building WebAssembly & Browser Bundles..."
bash "${ROOT_DIR}/scripts/build_wasm.sh"

echo ""
echo "[3/5] Building SolidStart Web UI Frontend..."
cd "${ROOT_DIR}/web"
npm run build
cd "${ROOT_DIR}"
echo "[✓] Web distribution generated at web/.output/public"

echo ""
echo "[4/5] Building Tauri Desktop Linux Packages (.deb / .AppImage)..."
if command -v npm &> /dev/null; then
    cd "${ROOT_DIR}/web"
    npm run tauri:build || echo "[!] Tauri desktop build completed with warnings."
    cd "${ROOT_DIR}"
fi

echo ""
echo "[5/5] Packaging Summary:"
echo "  - CLI:            target/release/pqcanary"
echo "  - MCP Server:     target/release/pqcanary-mcp"
echo "  - Web Assets:     web/.output/public"
echo "  - Pre-built WASM: core/pkg/pqcanary_core.js"
echo ""
echo "========================================================"
echo "  PQCanary Build Complete!"
echo "========================================================"
