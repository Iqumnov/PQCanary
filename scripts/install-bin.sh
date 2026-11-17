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

# 4. Construct Target Triple / Release Asset Name Candidates
CANDIDATE_FILES=()
if [ "${PLATFORM}" = "darwin" ]; then
    if [ "${ARCH}" = "aarch64" ]; then
        CANDIDATE_FILES+=("pqcanary-darwin-arm64.tar.gz" "pqcanary-v0.1.0-aarch64-apple-darwin.tar.gz" "pqcanary-darwin-aarch64.tar.gz")
    else
        CANDIDATE_FILES+=("pqcanary-darwin-x86_64.tar.gz" "pqcanary-v0.1.0-x86_64-apple-darwin.tar.gz")
    fi
elif [ "${PLATFORM}" = "windows" ]; then
    CANDIDATE_FILES+=("pqcanary-windows-x86_64.zip" "pqcanary-v0.1.0-x86_64-pc-windows-msvc.zip")
else
    # Linux
    if [ "${ARCH}" = "x86_64" ]; then
        if [ -n "${LIBC_SUFFIX}" ]; then
            CANDIDATE_FILES+=("pqcanary-linux-x86_64-musl.tar.gz" "pqcanary-v0.1.0-x86_64-unknown-linux-musl.tar.gz" "pqcanary-linux-x86_64.tar.gz")
        else
            CANDIDATE_FILES+=("pqcanary-linux-x86_64.tar.gz" "pqcanary-v0.1.0-x86_64-unknown-linux-gnu.tar.gz" "pqcanary-linux-x86_64-musl.tar.gz")
        fi
    else
        CANDIDATE_FILES+=("pqcanary-linux-aarch64.tar.gz" "pqcanary-v0.1.0-aarch64-unknown-linux-musl.tar.gz")
    fi
fi
ASSET_FILE="${CANDIDATE_FILES[0]}"

# 5. Resolve Version & Download URL
VERSION="${PQCANARY_VERSION:-latest}"
if [ "${VERSION}" = "latest" ]; then
    info "Resolving latest release of PQCanary from ${GITHUB_REPO}..."
    DOWNLOAD_BASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download"
    FALLBACK_DIRECT_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/pqcanary-linux-x64-cli"
else
    info "Resolving release ${VERSION} of PQCanary from ${GITHUB_REPO}..."
    DOWNLOAD_BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    FALLBACK_DIRECT_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/pqcanary-linux-x64-cli"
fi

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

# Download Candidate Archive
DOWNLOAD_SUCCESS=false
for CANDIDATE in "${CANDIDATE_FILES[@]}"; do
    CANDIDATE_PATH="${TEMP_DIR}/${CANDIDATE}"
    info "Attempting download of ${CANDIDATE}..."
    if download "${DOWNLOAD_BASE_URL}/${CANDIDATE}" "${CANDIDATE_PATH}" 2>/dev/null; then
        DOWNLOAD_FILE="${CANDIDATE_PATH}"
        ASSET_FILE="${CANDIDATE}"
        DOWNLOAD_SUCCESS=true
        break
    fi
done

if [ "${DOWNLOAD_SUCCESS}" = false ]; then
    warn "Primary archives not found on release. Attempting fallback Linux CLI binary..."
    if [ "${PLATFORM}" = "linux" ] && download "${FALLBACK_DIRECT_URL}" "${TEMP_DIR}/${BINARY_NAME}"; then
        chmod +x "${TEMP_DIR}/${BINARY_NAME}"
    else
        error "Failed to download release asset from https://github.com/${GITHUB_REPO}/releases."
    fi
fi

# Unpack Archive if downloaded
if [ -f "${DOWNLOAD_FILE}" ]; then
    info "Extracting binaries..."
    if [[ "${ASSET_FILE}" == *.tar.gz ]]; then
        tar -xzf "${DOWNLOAD_FILE}" -C "${TEMP_DIR}"
    elif [[ "${ASSET_FILE}" == *.zip ]]; then
        unzip -q "${DOWNLOAD_FILE}" -d "${TEMP_DIR}"
    fi
fi

# Locate the primary binary inside temporary directory
EXTRACTED_BIN="$(find "${TEMP_DIR}" -type f \( -name "${BINARY_NAME}" -o -name "${BINARY_NAME}.exe" \) 2>/dev/null | head -n 1 || true)"
if [ -z "${EXTRACTED_BIN}" ] || [ ! -f "${EXTRACTED_BIN}" ]; then
    error "Could not find '${BINARY_NAME}' binary in downloaded archive."
fi

# 6. Determine Install Destination
USE_SUDO=false

if [ -n "${PQCANARY_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="${PQCANARY_INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}"
elif [ "${PQCANARY_NO_SUDO:-0}" = "1" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
elif [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    mkdir -p "${INSTALL_DIR}"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=true
else
    # Fallback to user home directory
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
fi

TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
info "Installing ${BINARY_NAME} to ${TARGET_PATH}..."
if [ "${USE_SUDO}" = true ]; then
    sudo mkdir -p "${INSTALL_DIR}"
    sudo install -m 755 "${EXTRACTED_BIN}" "${TARGET_PATH}"
else
    mkdir -p "${INSTALL_DIR}"
    install -m 755 "${EXTRACTED_BIN}" "${TARGET_PATH}"
fi

# Locate and install companion MCP server if present in archive
EXTRACTED_MCP="$(find "${TEMP_DIR}" -type f \( -name "pqcanary-mcp" -o -name "pqcanary-mcp.exe" \) 2>/dev/null | head -n 1 || true)"
if [ -n "${EXTRACTED_MCP}" ] && [ -f "${EXTRACTED_MCP}" ]; then
    MCP_TARGET_PATH="${INSTALL_DIR}/pqcanary-mcp"
    info "Installing Model Context Protocol daemon to ${MCP_TARGET_PATH}..."
    if [ "${USE_SUDO}" = true ]; then
        sudo install -m 755 "${EXTRACTED_MCP}" "${MCP_TARGET_PATH}"
    else
        install -m 755 "${EXTRACTED_MCP}" "${MCP_TARGET_PATH}"
    fi
    success "Installed Model Context Protocol daemon: ${MCP_TARGET_PATH}"
fi

# 7. Verification & Path Advice
if ! echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
    warn "${INSTALL_DIR} is not currently in your system PATH."
    CURRENT_SHELL="$(basename "${SHELL:-bash}")"
    case "${CURRENT_SHELL}" in
        zsh)  PROFILE_FILE="${HOME}/.zshrc" ;;
        fish) PROFILE_FILE="${HOME}/.config/fish/config.fish" ;;
        *)    PROFILE_FILE="${HOME}/.bashrc" ;;
    esac
    printf "\nAdd the following line to your %s:\n" "${PROFILE_FILE}"
    if [ "${CURRENT_SHELL}" = "fish" ]; then
        printf "  fish_add_path %s\n\n" "${INSTALL_DIR}"
    else
        printf "  export PATH=\"%s:\$PATH\"\n\n" "${INSTALL_DIR}"
    fi
fi

if command -v "${BINARY_NAME}" >/dev/null 2>&1; then
    INSTALLED_VER="$("${BINARY_NAME}" --version 2>/dev/null || echo "v0.1.0")"
    success "PQCanary core CLI installed successfully: ${INSTALLED_VER}"
else
    success "PQCanary binary installed at ${TARGET_PATH}"
fi

if command -v "pqcanary-mcp" >/dev/null 2>&1 || [ -f "${INSTALL_DIR}/pqcanary-mcp" ]; then
    success "PQCanary MCP server installed (ready for Claude Desktop & Cursor)"
fi

printf "\n%sQuick Start Commands:%s\n" "${BOLD}" "${RESET}"
printf "  pqcanary scan .                    # Audit current repository\n"
printf "  pqcanary cbom . -o cbom.json       # Generate CycloneDX 1.6 CBOM\n"
printf "  pqcanary probe-tls target:443      # Probe live endpoint for ML-KEM\n"
printf "  pqcanary serve --port 8080         # Launch background REST daemon\n"
printf "  pqcanary-mcp                       # Launch MCP server for AI IDEs\n"
printf "  pqcanary --help                    # Explore all 42 security tools\n\n"

