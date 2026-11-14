#!/usr/bin/env bash
# ==============================================================================
# PQCanary Universal Standalone Binary Installer
# Usage: curl -sSf https://raw.githubusercontent.com/Iqumnov/PQCanary/main/scripts/install-bin.sh | sh
# ==============================================================================
set -euo pipefail

GITHUB_REPO="Iqumnov/PQCanary"
BINARY_NAME="pqcanary"

# Text Formatting
BOLD="$(tput bold 2>/dev/null || printf '')"
GREEN="$(tput setaf 2 2>/dev/null || printf '')"
YELLOW="$(tput setaf 3 2>/dev/null || printf '')"
RED="$(tput setaf 1 2>/dev/null || printf '')"
BLUE="$(tput setaf 4 2>/dev/null || printf '')"
RESET="$(tput sgr0 2>/dev/null || printf '')"

info() {
    printf "%s==>%s %s%s%s\n" "${BLUE}" "${RESET}" "${BOLD}" "$*" "${RESET}"
}

success() {
    printf "%s==>%s %s%s%s\n" "${GREEN}" "${RESET}" "${BOLD}" "$*" "${RESET}"
}

warn() {
    printf "%sWARN:%s %s\n" "${YELLOW}" "${RESET}" "$*" >&2
}

error() {
    printf "%sERROR:%s %s\n" "${RED}" "${RESET}" "$*" >&2
    exit 1
}

# 1. Detect Operating System
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM="linux" ;;
    Darwin*)    PLATFORM="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *)          error "Unsupported operating system: ${OS}" ;;
esac

# 2. Detect CPU Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)   ARCH="x86_64" ;;
    aarch64|arm64)  ARCH="aarch64" ;;
    *)              error "Unsupported architecture: ${ARCH}. Supported architectures: x86_64, aarch64." ;;
esac

# 3. Detect C Standard Library (musl vs glibc on Linux)
LIBC_SUFFIX=""
if [ "${PLATFORM}" = "linux" ]; then
    IS_MUSL=false
    if ldd --version 2>&1 | grep -iq "musl"; then
        IS_MUSL=true
    elif ls -d /lib/ld-musl* 1>/dev/null 2>&1; then
        IS_MUSL=true
    elif [ -f /etc/os-release ] && grep -iqE "void|alpine" /etc/os-release; then
        if ! command -v getconf >/dev/null 2>&1 || ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
            IS_MUSL=true
        fi
    fi

    if [ "${IS_MUSL}" = true ]; then
        LIBC_SUFFIX="-musl"
        info "Detected musl-based Linux environment (Void Linux musl / Alpine)."
    else
        info "Detected glibc-based Linux environment."
    fi
fi

# 4. Construct Target Triple / Release Asset Name
if [ "${PLATFORM}" = "darwin" ]; then
    if [ "${ARCH}" = "aarch64" ]; then
        ASSET_FILE="pqcanary-darwin-arm64.tar.gz"
    else
        ASSET_FILE="pqcanary-darwin-x86_64.tar.gz"
    fi
elif [ "${PLATFORM}" = "windows" ]; then
    ASSET_FILE="pqcanary-windows-x86_64.zip"
else
    # Linux
    if [ "${ARCH}" = "x86_64" ]; then
        if [ -n "${LIBC_SUFFIX}" ]; then
            ASSET_FILE="pqcanary-linux-x86_64-musl.tar.gz"
        else
            ASSET_FILE="pqcanary-linux-x86_64.tar.gz"
        fi
    else
        ASSET_FILE="pqcanary-linux-aarch64.tar.gz"
    fi
fi

# 5. Resolve Version & Download URL
info "Resolving latest release of PQCanary from ${GITHUB_REPO}..."

DOWNLOAD_BASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download"
FALLBACK_DIRECT_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/pqcanary-linux-x64-cli"

TEMP_DIR="$(mktemp -d -t pqcanary-install.XXXXXX)"
cleanup() {
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT INT TERM

DOWNLOAD_FILE="${TEMP_DIR}/${ASSET_FILE}"

# Download Helper
download() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 3 --progress-bar "${url}" -o "${dest}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "${dest}" "${url}"
    else
        error "Neither curl nor wget is available. Please install one of them."
    fi
}

info "Downloading ${ASSET_FILE}..."
if ! download "${DOWNLOAD_BASE_URL}/${ASSET_FILE}" "${DOWNLOAD_FILE}" 2>/dev/null; then
    warn "Primary archive ${ASSET_FILE} not found on release. Attempting fallback Linux CLI binary..."
    if [ "${PLATFORM}" = "linux" ] && download "${FALLBACK_DIRECT_URL}" "${TEMP_DIR}/${BINARY_NAME}"; then
        chmod +x "${TEMP_DIR}/${BINARY_NAME}"
    else
        error "Failed to download release asset from https://github.com/${GITHUB_REPO}/releases."
    fi
fi

# Unpack Archive if downloaded
if [ -f "${DOWNLOAD_FILE}" ]; then
    info "Extracting binary..."
    if [[ "${ASSET_FILE}" == *.tar.gz ]]; then
        tar -xzf "${DOWNLOAD_FILE}" -C "${TEMP_DIR}"
    elif [[ "${ASSET_FILE}" == *.zip ]]; then
        unzip -q "${DOWNLOAD_FILE}" -d "${TEMP_DIR}"
    fi
fi

# Locate the binary inside temporary directory
EXTRACTED_BIN="$(find "${TEMP_DIR}" -type f -name "${BINARY_NAME}" -o -name "${BINARY_NAME}.exe" | head -n 1)"
if [ -z "${EXTRACTED_BIN}" ] || [ ! -f "${EXTRACTED_BIN}" ]; then
    error "Could not find '${BINARY_NAME}' binary in downloaded archive."
fi

# 6. Determine Install Destination
INSTALL_DIR="/usr/local/bin"
USE_SUDO=false

if [ -w "${INSTALL_DIR}" ]; then
    TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
elif [ "$(id -u)" -eq 0 ]; then
    mkdir -p "${INSTALL_DIR}"
    TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    USE_SUDO=true
    TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
else
    # Fallback to user home directory
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
    TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
fi

info "Installing ${BINARY_NAME} to ${TARGET_PATH}..."
if [ "${USE_SUDO}" = true ]; then
    sudo mkdir -p "${INSTALL_DIR}"
    sudo install -m 755 "${EXTRACTED_BIN}" "${TARGET_PATH}"
else
    install -m 755 "${EXTRACTED_BIN}" "${TARGET_PATH}"
fi

# 7. Verification & Path Advice
if command -v "${BINARY_NAME}" >/dev/null 2>&1; then
    INSTALLED_VER="$("${BINARY_NAME}" --version 2>/dev/null || echo "0.1.0")"
    success "PQCanary installed successfully: ${INSTALLED_VER}"
else
    success "PQCanary binary installed at ${TARGET_PATH}"
    warn "${INSTALL_DIR} is not currently in your system PATH."
    printf "\nAdd the following line to your shell profile (~/.bashrc, ~/.zshrc, etc.):\n"
    printf "  export PATH=\"%s:\$PATH\"\n\n" "${INSTALL_DIR}"
fi

printf "\n%sGet started with:%s\n" "${BOLD}" "${RESET}"
printf "  pqcanary scan .\n"
printf "  pqcanary probe cloudflare.com:443\n"
printf "  pqcanary --help\n\n"

