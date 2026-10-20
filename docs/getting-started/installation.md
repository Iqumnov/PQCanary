# Installation and Setup Guide

This document describes how to install, build, and deploy PQCanary across supported operating systems and environments.

---

## 1. System Requirements

### Supported Operating Systems
- Linux (x86_64, AArch64) - Ubuntu 20.04+, Debian 11+, RHEL 8+, Alpine 3.18+
- macOS (Apple Silicon M1/M2/M3/M4, Intel x86_64) - macOS 12 Monterey or newer
- Windows (x86_64, ARM64) - Windows 10, Windows 11, Windows Server 2019+

### Build Prerequisites
To compile PQCanary from source, the following tools must be installed:
- Rust toolchain: 1.77.0 or newer (managed via `rustup`)
- C compiler: `gcc` / `clang` (Linux/macOS) or MSVC C++ Build Tools (Windows)
- Node.js: 18.0.0 or newer (optional, required only for Web dashboard and VS Code extension)
- pnpm or npm: package manager for web dependencies
- Z3 Theorem Prover: version 4.12+ (optional runtime dependency for concolic execution)

---

## 2. Building from Source

### Standard Cargo Build
Clone the repository and build the workspace binaries using Cargo:

```bash
git clone https://github.com/Iqumnov/PQCanary.git
cd PQCanary

# Compile all binaries in release mode
cargo build --release --workspace

# The compiled artifacts are located in target/release:
# - target/release/pqcanary       (CLI binary)
# - target/release/pqcanary-mcp   (MCP server binary)
# - target/release/pqcanary-app   (Tauri desktop application binary)
```

To install the CLI binary into your user PATH:

```bash
cargo install --path cli
```

Verify the installation:

```bash
pqcanary --version
```

---

## 3. WebAssembly (WASM) Compilation

PQCanary core is designed to compile to WebAssembly using `wasm-pack`, enabling execution directly in client-side web browsers without backend server calls:

```bash
# Ensure wasm32-unknown-unknown target is installed
rustup target add wasm32-unknown-unknown

# Install wasm-pack
cargo install wasm-pack

# Build the WebAssembly package
cd core
wasm-pack build --target web --out-dir ../web/public/wasm
```

The resulting bundle (`pqcanary_core.js` and `pqcanary_core_bg.wasm`) exposes the `WasmScanner` interface for browser-based scanning.

---

## 4. Container Deployment (Docker)

PQCanary provides an official multi-stage Dockerfile optimized for minimal attack surface and small image footprint:

### Building the Docker Image

```bash
docker build -t pqcanary:latest .
```

### Running the Container as a CLI Tool

```bash
docker run --rm -v "$(pwd):/scan:ro" pqcanary:latest scan /scan --format text
```

### Running the Container as a Daemon Service

```bash
docker run -d \
  --name pqcanary-daemon \
  -p 8080:8080 \
  -p 9090:9090 \
  -e PQCANARY_STRICT_NETWORK=1 \
  pqcanary:latest serve --port 8080
```

### Docker Compose Stack
To run the full enterprise stack including the PQCanary daemon, an Nginx reverse proxy with TLS termination, and a Redis job queue:

```bash
docker compose up -d
```

Verify service status:

```bash
curl -s http://localhost:8080/health
```

---

## 5. Kubernetes Cluster Deployment

Deploy PQCanary into a Kubernetes cluster as a Deployment or DaemonSet:

```bash
# Apply standard Kubernetes manifests
kubectl apply -f k8s/pqcanary-k8s.yaml

# Apply the security DaemonSet for continuous node monitoring
kubectl apply -f k8s/pqcanary-daemonset.yaml
```

Verify deployment status:

```bash
kubectl get pods -l app=pqcanary
```

---

## 6. Desktop Application (Tauri)

The desktop application provides a standalone graphical user interface for security teams.

### Running in Development Mode
```bash
cd web
pnpm install
pnpm tauri dev
```

### Building Release Installers
```bash
cd web
pnpm tauri build
```

This generates native installers:
- Windows: `.msi` and `.exe` in `web/src-tauri/target/release/bundle/msi/`
- macOS: `.dmg` and `.app` in `web/src-tauri/target/release/bundle/dmg/`
- Linux: `.deb` and `.AppImage` in `web/src-tauri/target/release/bundle/appimage/`

---

## 7. IDE and Editor Extensions

### VS Code Extension
To install the VS Code extension from source:

```bash
cd extensions/vscode
npm install
npm run package
# Generates pqcanary-vscode-1.0.0.vsix

code --install-extension pqcanary-vscode-1.0.0.vsix
```

### Neovim / Vim Plugin
Add PQCanary to your plugin manager:

Using `lazy.nvim`:
```lua
{
  "Iqumnov/PQCanary",
  config = function()
    require("pqcanary").setup({
      enable_realtime = true,
      min_severity = "LOW",
    })
  end
}
```

Using `vim-plug`:
```vim
Plug 'Iqumnov/PQCanary', { 'rtp': 'extensions/neovim' }
```

### Web Browser Extension
The browser extension audits live websites for TLS 1.3 hybrid key exchange and classical cipher suites:
1. Open Chrome/Brave/Edge and navigate to `chrome://extensions/`.
2. Enable "Developer mode".
3. Click "Load unpacked" and select the `extensions/browser/` directory.

---

## 8. Verifying the Installation

Run the automated test suite across the workspace to confirm complete functionality:

```bash
cargo test --workspace
```

Expected result: 132 tests passed across core, cli, mcp, and integration test suites.
