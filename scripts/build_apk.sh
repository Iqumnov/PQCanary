#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo "  PQCanary Mobile APK Build Pipeline (Android)"
echo "========================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}/web"

if [ -n "${ANDROID_HOME:-}" ] && [ -n "${NDK_HOME:-}" ]; then
    echo "[*] Android SDK & NDK detected on host."
    echo "[*] Running Tauri Android APK build..."
    npx @tauri-apps/cli android init --ci || true
    npx @tauri-apps/cli android build --apk --target aarch64
    echo "[✓] Android APK generated in web/src-tauri/gen/android/app/build/outputs/apk/release/"
else
    echo "[!] ANDROID_HOME or NDK_HOME not set in local environment."
    echo "[*] Falling back to automated Dockerized Android build container..."
    echo "[*] You can build the release APK via Docker with:"
    echo "    docker run --rm -v \"${ROOT_DIR}:/workspace\" -w /workspace mobile-android-builder ./scripts/build_apk_docker.sh"
    echo ""
    echo "[*] Alternatively, push to GitHub to trigger the automated Release APK workflow (.github/workflows/release-all-platforms.yml)."
fi
