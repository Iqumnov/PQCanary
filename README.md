# PQCanary

Enterprise Post-Quantum Cryptographic Security, Formal Verification, and Audit Platform.

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24527917.svg)](https://doi.org/10.5281/zenodo.24527917)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-green.svg)](https://cyclonedx.org/)
[![OASIS SARIF](https://img.shields.io/badge/OASIS%20SARIF-2.1.0-darkgreen.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Native%20Server-purple.svg)](https://modelcontextprotocol.io/)
[![Author: Matvei Igumnov](https://img.shields.io/badge/Author-Matvei%20Igumnov-blue.svg)](https://github.com/Iqumnov/PQCanary)

---

## Overview

PQCanary is an enterprise post-quantum cryptographic discovery, verification, and automated remediation platform. It identifies classical cryptographic algorithms vulnerable to quantum cryptanalysis (Shor's and Grover's algorithms), validates implementation safety using formal mathematical methods, generates compliance bills of materials (CBOM), and executes semantic code modernization across enterprise repositories.

The core engine is implemented in memory-safe Rust with strict safety guarantees (`#![forbid(unsafe_code)]`), compiling to native platform binaries, containerized daemons, and client-side WebAssembly targets.

```
+-----------------------------------------------------------------------------------+
|                                  PQCanary Platform                                |
+-----------------------------------------------------------------------------------+
        |                         |                         |                 |
        v                         v                         v                 v
+---------------+         +---------------+         +---------------+   +-----------+
| Multi-Engine  |         | Formal Proofs |         |    Active     |   | Standards |
| Core Audit    |         | & Simulation  |         | Network Probe |   | & Export  |
| - 193+ Rules  |         | - HoTT Lean 4 |         | - TLS 1.3 KEM |   | - SARIF   |
| - Tree-sitter |         | - Z3 SMT SSA  |         | - SSH 2.0 KEX |   | - CBOM    |
| - 8 Languages |         | - Landauer    |         | - Relativistic|   | - Patch   |
+---------------+         +---------------+         +---------------+   +-----------+
```

---

## Key Capabilities

- **Multi-Language Concrete Syntax Tree Analysis**: Analyzes Rust, TypeScript, JavaScript, Python, Go, Java, C, and C++ source code using Tree-sitter parsers alongside 193+ detection patterns spanning 22 security domains.
- **Concolic Symbolic Execution**: Lifts cryptographic operations to Static Single Assignment (SSA) form and solves branch reachability and buffer bounds constraints using Microsoft Z3.
- **Formal Verification via Homotopy Type Theory (HoTT)**: Synthesizes rigorous Lean 4 mathematical proofs verifying round-trip invertibility, injectivity, and IND-CPA semantic security.
- **Thermodynamic Side-Channel Diagnostics**: Calculates Landauer energy dissipation ($k_B T \ln 2$) and detects thermal side-channel attack (SCA) vectors exceeding sensor thresholds.
- **Relativistic Light-Cone & Pulsar Synchronization**: Evaluates network round-trip times against WGS-84 Vincenty geodesic light propagation bounds and anchors validation against ATNF radio pulsar timing arrays.
- **Active Post-Quantum Network Probing**: Performs binary handshake negotiations against live TLS 1.3 (ML-KEM-768 / Kyber) and SSH 2.0 servers without deploying invasive agents.
- **CycloneDX 1.6 CBOM Semantic Drift & Regression Gatekeeper**: Compares consecutive CBOM snapshots to detect asset additions, retirements, and quantum downgrade regressions in CI/CD pipelines.
- **PQC Network MTU & Packet Fragmentation Risk Analyzer**: Models wire overhead against network Path MTU, calculating MSS fragmentation, middlebox drop probabilities, and latency overhead for ML-KEM, ML-DSA, and SLH-DSA.
- **NIST SP 800-227 Cryptographic Agility Score (CAS)**: Audits architectural decoupling, decoupled crypto factories, and configuration-driven cipher selection (0–100 CAS).
- **Topological DAG Migration Sequencer**: Computes 5-phase CNSA 2.0 and OMB M-23-02 migration sequences respecting strict cryptographic prerequisite ordering from Root PKI to storage.
- **Zero-Downtime Data-at-Rest Re-encryption Playbooks**: Generates 3-phase automated Terraform dual-key infrastructure, Python streaming batch workers, and cutover procedures for AWS KMS, Azure Key Vault, and GCP KMS.
- **Shift-Left Git Pre-Commit Hook**: Sub-15ms incremental pre-commit gatekeeper scanning staged changes (`git diff --cached`) locally before code reaches remotes.
- **Passive eBPF Linux Kernel Handshake Sniffer**: Zero-overhead Traffic Control (TC) socket filter decoding wire TLS 1.3 `ClientHello` / `ServerHello` packets to verify X25519MLKEM768 without terminating TLS.
- **Kubernetes Service Mesh & Ingress Auto-Remediation**: Generates Istio `EnvoyFilter`, Traefik `TLSOption`, NGINX Ingress annotations, and Gateway API v1 resources to enforce hybrid post-quantum cipher suites.
- **Hardware Security Module (HSM) PKCS#11 & KMIP Audit**: Audits physical hardware security modules (Thales Luna 7, Entrust nShield, AWS CloudHSM, YubiKey 5) for FIPS 203/204 mechanisms (`CKM_ML_KEM_KEY_GEN`, `CKM_ML_DSA_KEY_GEN`).
- **Dynamic Runtime Cryptographic Interceptor**: Intercepts OpenSSL and Win32 CryptoAPI calls via `LD_PRELOAD` or Microsoft Detours to monitor or override cipher negotiation in closed-source legacy binaries.
- **Continuous Autonomous DevSecOps Bot & NIST OSCAL Exporter**: Synthesizes ready-to-merge Pull Requests with Lean 4 proofs, and exports Open Security Controls Assessment Language (OSCAL) JSON for NIST SP 800-53 Rev 5, EU DORA, and PCI DSS 4.0.1.
- **Active Post-Quantum Downgrade Attack & Middlebox Tamper Simulator**: Actively tests TLS 1.3 endpoints against MitM extension stripping (`0x11ec`), key share corruption, and version rollback to verify CNSA 2.0 fail-closed semantics.
- **NIST CAVP / ACVP Known-Answer-Test (KAT) Harness**: Mathematical verification harness testing FIPS 203/204/205 implementations against official NIST Known-Answer-Test vectors (NTT reduction, Montgomery constants).
- **Hybrid & Dual-Key Composite Certificate Validator**: Validates RFC 9758 dual-signature specifications and ITU-T X.509 catalyst extensions (`altSignatureAlgorithm`, `altSignatureValue`, dual trust anchors).
- **OpenTelemetry (OTel) Cryptographic Semantic Telemetry**: Exports runtime telemetry conforming to OpenTelemetry Cryptography Semantic Conventions directly into enterprise SIEM / SOC collectors.
- **Empirical Constant-Time & Cache-Timing Verifier**: Dudect Welch two-sample t-test ($|t| > 4.5$) for detecting microarchitectural timing leakage and KyberSlash decapsulation timing leakage.
- **Cryptographic Supply Chain Provenance & Sigstore Attestation**: Wraps CycloneDX 1.6 CBOMs in in-toto SLSA Provenance v1.0 DSSE envelopes with Sigstore keyless Cosign verification.
- **Stateful Hash-Based Signatures (HBS) State-Tracking & Snapshot-Safety Auditor**: Tracks RFC 8554 LMS/HSS and RFC 8391 XMSS key-tree state ($2^h$), OTS remaining signatures, CRIU/snapshot state duplication risks, and monotonic counter hardware bindings (TPM2 NVRAM).
- **Post-Quantum VPN & Secure Tunnel Configuration Auditor**: Audits WireGuard (`wg0.conf`), strongSwan/IPsec (`ipsec.conf`), and OpenVPN configurations for post-quantum readiness, 256-bit PSK entropy, Rosenpass daemon active posture, and RFC 9370 hybrid IKEv2 proposals.
- **Database Column-Level Envelope Encryption & Field-Level Migration Planner**: Audits Spring Data JPA `@Convert`, Prisma `@encrypted`, SQLAlchemy, and MongoDB CSFLE field annotations, generating executable Python and SQL cursor-based dual-key migration scripts.
- **Continuous Filesystem Watcher & Sub-Millisecond Incremental AST Daemon**: Monitors workspace directories recursively with debounced change detection, executing sub-millisecond incremental AST audits on modified files and tracking regression deltas.
- **Enterprise Identity, Kerberos PKINIT & Windows Credential Guard Auditor**: Audits MIT/Heimdal `krb5.conf` configurations, assessing legacy enctypes, RFC 4556 PKINIT ticket-granting-ticket exposure to HNDL cryptanalysis, and synthesizing quantum-hardened Kerberos profiles.
- **Direct Binary IAT/GOT/Mach-O Import Table Post-Quantum Patcher**: Direct zero-source-recompilation binary patcher for PE64, ELF64, and Apple Mach-O 64-bit executables, safely rewriting classical symbols in Import Directory Tables, recalculating official PE checksums, and generating companion C export forwarders.
- **Live PKCS#11 / KMIP Physical HSM Interrogator**: Interrogates physical HSM shared libraries (`.so`, `.dll`), evaluating Oasis Cryptoki v3.0 PQC mechanisms, hardware silicon boundaries (`CKF_HW`), and detecting software emulation fallback.
- **Fleet-Wide Central CBOM Data Lake & Distributed Analytics Engine**: Generates PostgreSQL / TimescaleDB and ClickHouse MergeTree DDL schemas, batch SQL insertion statements, and fleet-wide Cryptographic Agility Score (CAS) aggregation queries.
- **In-Flight PQC Network Latency & Packet Fragmentation Profiler**: Actively models wire overhead, TCP segmentation boundaries (MTU 1500 / 1420 / 1280), latency distribution (p50, p95, p99), and middlebox drop penalties for FIPS 203/204 handshakes.
- **Formally Verified Binary Translation Equivalence Engine**: Synthesizes Z3 SMT-LIB2 constraint models and Lean 4 bisimulation theorems proving control-flow graph (CFG) and opcode invariance for direct binary modifications.
- **Dynamic Symbol Resolution AST Taint & Interceptor Scanner**: Audits runtime dynamic loader invocations (`dlopen`, `dlsym`, `LoadLibrary`, `GetProcAddress`, Python `ctypes`, Java JNI) bypassing static import tables, generating targeted `LD_PRELOAD` and Win32 Detours C interceptor shims.
- **Automated Post-Quantum ACME (RFC 8555) & EST (RFC 7030) PKI Enrollment**: Synthesizes automated PKI enrollment workflows with FIPS 204 ML-DSA-65/87 and RFC 9758 composite dual-key certificates, emitting Kubernetes `cert-manager` CRDs and HashiCorp Vault role policies.
- **NIST SP 800-90B Physical Noise Source Entropy Evaluator**: Computes statistical min-entropy ($H_\infty$) across MCV, collision, Markov, and universal compression estimators to ensure hardware QRNGs provide sufficient min-entropy to seed FIPS 203 ML-KEM lattice key generation.
- **NIST CMVP FIPS 140-3 Cryptographic Module Database & Firmware Attestation**: Attests physical HSMs, firmware versions, and crypto boundaries against official NIST CMVP validation certificates and NIST SP 800-131A Rev 2 transition sunset schedules.
- **OASIS KMIP 2.1 / 3.0 Post-Quantum Wire Protocol Engine**: Formats and parses binary TTLV frames with big-endian tags and 8-byte alignment padding for enterprise KMS lifecycle management with NIST FIPS 203 ML-KEM and FIPS 204 ML-DSA attributes.
- **Turnkey CI/CD Ecosystem Packaging**: Official GitHub Composite Action (`.github/actions/pqcanary-action/action.yml`) and GitLab CI component template with automated SARIF upload to GitHub Code Scanning.
- **Automated Semantic Code Remediation**: Replaces deprecated and classical algorithms (MD5, SHA-1, DES, RC4, ECB mode, insecure PRNG) with post-quantum compliant alternatives and generates unified diffs.
- **Standardized Enterprise Reporting**: Natively exports CycloneDX 1.6 Cryptographic Bill of Materials (CBOM), OASIS SARIF 2.1.0 for GitHub Code Scanning, standalone HTML dashboards, RFC 4180 CSV, and Markdown.
- **Model Context Protocol (MCP)**: Native stdio JSON-RPC 2.0 server exposing 57 tools enabling autonomous AI coding agents (Claude, Cursor, Gemini) to invoke all security engines directly.

---

## Documentation Architecture

PQCanary maintains technical documentation structured according to the Diataxis information architecture framework:

```
docs/
|-- README.md                         # Documentation Portal & Navigation Index
|-- getting-started/
|   |-- installation.md               # Toolchain setup, native build, Docker, WASM
|   `-- quickstart.md                 # 5-minute initial audit and report generation
|-- architecture/
|   |-- system-architecture.md        # Concurrency model, memory isolation, pipeline
|   |-- pqmesh-protocol.md            # Cross-medium fleet synchronization bus
|   `-- security-and-threat-model.md  # Air-gap guarantees, SSRF defense, memory safety
|-- engines/
|   |-- ast-and-pattern-matching.md   # Tree-sitter CST parsing, 193+ rules, suppression
|   |-- concolic-symbolic-execution.md# SSA lifting, memory model, Z3 SMT solver
|   |-- formal-verification-hott.md   # Homotopy Type Theory and Lean 4 proof synthesis
|   |-- thermodynamics-and-hardware.md# Landauer dissipation, DFA, Boolean masking
|   |-- physics-and-astrophysics.md   # Relativistic causality, ATNF pulsar clock sync
|   `-- cryptographic-standards.md    # NIST FIPS 203/204/205/206, CNSA 2.0, QRAMM
|-- reference/
|   |-- cli-reference.md              # Complete CLI commands, options, exit codes
|   |-- configuration-schema.md       # .pqcanary.yaml and pqcanary.toml specification
|   |-- rest-api-and-metrics.md       # Daemon endpoints, request models, Prometheus
|   |-- mcp-specification.md          # Model Context Protocol tools and schemas
|   `-- cbom-and-sarif.md             # CycloneDX 1.6 CBOM and OASIS SARIF 2.1.0 schemas
`-- guides/
    |-- ci-cd-pipelines.md            # GitHub Actions, GitLab, Azure, pre-commit
    |-- cloud-kms-auditing.md         # AWS KMS, Azure Key Vault, GCP KMS, Terraform
    |-- remediation-and-patching.md   # Automated code modernizer and PR generator
    `-- active-network-probing.md     # TLS 1.3 ClientHello and SSH 2.0 KEX probes
```

Access the documentation directly at [docs/README.md](docs/README.md).

---

## Quickstart

### 1. Universal Quick Install (Linux, macOS, Void Linux, Alpine)

Install the pre-compiled standalone binary with zero dependencies:

```bash
curl -sSf https://raw.githubusercontent.com/Iqumnov/PQCanary/main/scripts/install-bin.sh | sh
```

### 2. Build from Source

```bash
# Clone the repository
git clone https://github.com/Iqumnov/PQCanary.git
cd PQCanary

# Build release binaries
cargo build --release

# Install CLI binary
cargo install --path ./cli --bin pqcanary
```

### 3. Audit a Repository

```bash
# Run basic audit against local directory
pqcanary scan .

# Generate an OASIS SARIF 2.1.0 report for GitHub Code Scanning
pqcanary scan . --format sarif --output pqcanary.sarif

# Generate a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
pqcanary cbom . --output cbom.json

# Audit against a baseline to fail only on new regressions
pqcanary scan . --baseline baseline.json --fail-on-new
```

### 3. Active Network Probe

```bash
# Probe a remote endpoint for Post-Quantum TLS 1.3 (ML-KEM-768)
pqcanary probe cloudflare.com:443

# Probe a remote server for Post-Quantum SSH key exchange
pqcanary probe-ssh github.com:22
```

### 4. Automated Code Patching

```bash
# Preview semantic remediation diff
pqcanary patch ./src/crypto.js --dry-run

# Apply patches in place
pqcanary patch ./src/crypto.js
```

### 5. Semantic CBOM Drift & Downgrade Prevention

```bash
# Compare consecutive CBOM releases and block CI on quantum downgrades
pqcanary diff baseline-cbom.json current-cbom.json --fail-on-downgrade
```

### 6. PQC Network MTU & Packet Fragmentation Analysis

```bash
# Analyze wire overhead, middlebox drops, and packet segmentation
pqcanary mtu --algorithm ML-DSA-87 --mtu 1500
```

### 7. Cryptographic Agility & Migration Roadmap

```bash
# Audit NIST SP 800-227 cryptographic agility score
pqcanary agility ./src

# Generate topological 5-phase CNSA 2.0 / OMB M-23-02 roadmap
pqcanary roadmap ./src
```

### 8. Shift-Left Git Pre-Commit Hook

```bash
# Install sub-15ms incremental pre-commit hook into active git repository
pqcanary hooks install

# Manually execute hook against staged files
pqcanary hooks run
```

---

## Operational Mediums

PQCanary is designed to operate seamlessly across ten distinct form factors:

| # | Medium | Purpose | Primary Protocol / Artifact |
| :--- | :--- | :--- | :--- |
| **1** | **Native CLI** | Workstation audits and script automation | Terminal UI, SARIF, CBOM, CSV, HTML |
| **2** | **REST API Daemon** | Headless microservice backend | HTTP/JSON on port 8080, Prometheus on `/metrics` |
| **3** | **Stdio MCP Server** | AI coding assistant integration | JSON-RPC 2.0 over `stdio` (`pqcanary-mcp`) |
| **4** | **Tauri Desktop GUI** | Standalone desktop application | Native window for Windows, macOS, Linux |
| **5** | **Web Client (WASM)** | 100% client-side browser execution | In-memory scan, zero network data egress |
| **6** | **Docker Container** | Reproducible containerized execution | OCI-compliant multi-stage image |
| **7** | **Docker Compose** | Clustered daemon stack | Orchestrated API, Redis queue, and Web UI |
| **8** | **Kubernetes** | In-cluster infrastructure auditing | DaemonSet volume auditor, HPA scaling |
| **9** | **GitHub Action** | CI/CD automated quality gate | Direct upload to GitHub Security Code Scanning |
| **10**| **IDE Extensions** | Real-time developer workspace diagnostics | VS Code Extension and Neovim Lua plugin |

---

## Cryptographic Standards Compliance

PQCanary evaluates systems against modern cryptographic and regulatory specifications:

- **NIST Post-Quantum Cryptography Standards**:
  - **FIPS 203**: ML-KEM (Module-Lattice Key Encapsulation Mechanism)
  - **FIPS 204**: ML-DSA (Module-Lattice Digital Signature Algorithm)
  - **FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
  - **FIPS 206**: FN-DSA (Falcon Fast-Fourier Lattice Signatures)
- **National Security Agency (NSA)**: Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)
- **Executive Office of the President**: OMB Memorandum M-23-02 (Post-Quantum Transition)
- **Data Exchange Formats**: CycloneDX 1.6 CBOM, OASIS SARIF 2.1.0, RFC 4180 CSV

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for coding conventions, test execution requirements, and architectural standards.

---

## Security

For security advisories and responsible vulnerability disclosure, please refer to [SECURITY.md](SECURITY.md) or contact [matvei@iqumnov.com](mailto:matvei@iqumnov.com).

---

## License

Copyright (c) 2024-2026 Matvei Igumnov.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
