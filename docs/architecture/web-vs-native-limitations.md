# Web Application vs. Native CLI: Architecture, Execution Models & Limitations

This document provides a technical specification and comparative analysis of PQCanary's operational mediums, specifically detailing the architectural boundaries, security models, and capability deltas between the **Web Client (WebAssembly / Cloudflare Pages)** and the **Native Platform CLI / Containerized Daemon**.

---

## 1. Architectural Overview & Boundary Matrix

PQCanary is designed to operate seamlessly across both sandboxed web environments and bare-metal native operating systems. However, the browser execution sandbox imposes strict architectural isolation that alters how cryptographic analysis is performed.

```
+------------------------------------+      +------------------------------------+
|       Web Client (Browser/WASM)    |      |         Native CLI / Daemon        |
+------------------------------------+      +------------------------------------+
| • 100% Client-Side In-Memory Execution|   | • Bare-Metal OS Kernel Access      |
| • W3C WebAssembly Sandbox          |      | • Direct Filesystem & Socket Access|
| • File System Access API (Picker)  |      | • Rayon Multi-Core Thread Pools    |
| • Zero Egress / Air-Gapped         |      | • Persistent Z3 IPC Daemon Pipe    |
| • Single Tab Linear Memory Bound   |      | • Full Hardware & Kernel Telemetry |
+------------------------------------+      +------------------------------------+
```

### Comprehensive Capability Comparison Matrix

| Architectural Capability | Web Application (Cloudflare Pages / WASM) | Native CLI / Daemon (`pqcanary`) |
| :--- | :--- | :--- |
| **Execution Medium** | Client-side Browser (`wasm32-unknown-unknown` + Web Workers) | Native machine code (`x86_64`, `aarch64`, musl, glibc) |
| **Hosting Model** | Static CDN / Cloudflare Pages Edge (zero server compute) | Workstation, CI/CD Runner, Docker container, K8s Pod |
| **Input Data Ingestion** | In-memory snippet, file upload, or `showDirectoryPicker()` | Recursive directory paths, remote Git URLs, stdin pipes |
| **AST & Pattern Engine** | **Full**: 193+ regex patterns & in-memory rule engine | **Full**: Tree-sitter CST parsing + 193+ pattern rules |
| **Standards Export** | **Full**: CycloneDX 1.6 CBOM & OASIS SARIF 2.1.0 JSON | **Full**: SARIF, CBOM, CSV, Markdown, and HTML dashboards |
| **Active Network Probing** | **Unsupported** (Browser cannot craft raw TCP SYN / TLS frames) | **Full**: Live TLS 1.3 ML-KEM-768 & SSH 2.0 KEX probing |
| **Concolic SMT Solving** | Bounded (SMT script generation & client-side constraints) | **Full**: Spawns interactive Microsoft Z3 process pipe |
| **Host Cryptographic Audit** | **Unsupported** (Browser cannot inspect host OS packages) | **Full**: `/etc/crypto-policies`, OpenSSL 3 providers |
| **Hardware Security Modules** | **Unsupported** (No PKCS#11 `.so` dynamic loading) | **Full**: PKCS#11 Oasis Cryptoki v3.0 & KMIP 2.1 interrogator |
| **Kernel eBPF Telemetry** | **Unsupported** (No Linux socket filter access) | **Full**: Traffic Control (TC) zero-overhead socket filter |
| **Compiled Binary Audit** | Inspects in-memory buffers (disassembly of dropped files) | Direct file scanning across ELF, PE64, and Mach-O |
| **Max Memory Capacity** | ~2 GB – 4 GB (Browser 32-bit WASM memory ceiling) | Full physical workstation / server RAM |
| **Multi-Threading Model** | Web Workers (requires COOP/COEP headers for SharedArrayBuffer) | POSIX threads via `rayon` work-stealing scheduler |

---

## 2. In-Depth Web Application Limitations

### A. Network Isolation & Raw Socket Constraints
Modern browsers enforce a strict security perimeter (W3C Fetch and WebSocket specifications). The browser sandbox strictly forbids raw TCP or UDP socket creation:
- **Impact**: Commands like `pqcanary probe <host>:443` (which transmits custom TLS 1.3 `ClientHello` frames containing Post-Quantum KEM extension `0x11ec`) cannot be executed by client-side browser JavaScript.
- **Remediation in Web UI**: The web application allows users to either test code snippets statically or connect to a locally running PQCanary REST API daemon (`http://localhost:8080`) when active network probing or host inspection is required.

### B. Microsoft Z3 Process Execution
The native concolic execution engine (`core/src/scanner/concolic/z3_bridge.rs`) manages an interactive IPC pipe via `std::process::Command::new("z3")`.
- **Impact**: In a browser environment, OS process execution does not exist.
- **Remediation in Web UI**: The WebAssembly bridge evaluates syntactic and algebraic constraints directly in-memory, generates valid SMT-LIB2 constraint models that can be exported, and provides deterministic safety classifications.

### C. Host Filesystem & Hardware Security Module Boundaries
The browser cannot access arbitrary local directories or system shared libraries:
- **Impact**: Dynamic interrogations of `/usr/lib/libsofthsm2.so`, `/etc/krb5.conf`, and `/sys/kernel/debug/tracing` (eBPF) are physically impossible in pure WebAssembly.
- **Intended Use Case for Web**: Instant, zero-installation cryptographic code auditing, snippet verification, CBOM inspection, and educational demonstrations of post-quantum algorithm migration.

---

## 3. Cloudflare Pages Deployment Architecture

The web application is packaged for high-performance deployment on Cloudflare Pages:

1. **Static Edge Distribution**: Built using SolidStart with prerendering, the web application generates optimized static HTML, CSS, JavaScript, and WebAssembly chunks in `.output/public`.
2. **Security Headers**: Served with strict `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` headers to permit high-resolution timers and `SharedArrayBuffer` for Web Workers.
3. **Zero Data Retention**: The client-side scanner processes all submitted files locally inside the user's browser memory. No source code or cryptographic assets are ever transmitted to Cloudflare edge nodes or external servers.

---

## 4. Operating System Compatibility: Void Linux & Musl

### The Void Linux Architecture
Void Linux features two distinct system C library flavors:
1. **Void Linux (glibc)**: Standard GNU C library.
2. **Void Linux (musl)**: Ultra-lightweight musl C library.

### Compatibility Guarantees
- **Pure Rust Networking**: The core network and HTTP engines use `rustls` (pure Rust) rather than dynamically linking against OpenSSL (`libssl.so`).
- **POSIX Serial HAL**: The hardware abstraction layer uses POSIX standard `termios` APIs, eliminating hard dependencies on system `libudev`.
- **Musl Static Builds**: For Void Linux musl and Alpine Linux, PQCanary provides pre-compiled `x86_64-unknown-linux-musl` static binaries. These binaries contain zero dynamic linker dependencies and run out of the box on any Linux distribution.

