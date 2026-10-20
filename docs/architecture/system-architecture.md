# PQCanary System Architecture

This document specifies the internal software architecture, execution lifecycle, memory management model, and multi-engine processing pipeline of the PQCanary platform.

---

## 1. High-Level Architectural Overview

PQCanary is designed as a unified cryptographic audit, formal verification, and remediation engine written in Rust. It compiles to native machine binaries (x86_64, aarch64) as well as WebAssembly (`wasm32-unknown-unknown`) for in-browser client-side execution.

The architecture separates static inspection, dynamic network probing, symbolic execution, formal theorem proving, and distributed fleet synchronization into decoupled modules coordinated by the `MasterOrchestrator`.

```
+-----------------------------------------------------------------------------------+
|                                  Entry Points                                     |
|  CLI (clap)  |  REST API (axum)  |  MCP Server (stdio)  |  WASM (web/ext)  |  UI  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                               MasterOrchestrator                                  |
|   - Work stealing path walker (rayon)      - File categorization & language route |
|   - Suppression grammar engine             - Finding deduplication & fingerprint  |
+-----------------------------------------------------------------------------------+
       |                  |                  |                  |               |
       v                  v                  v                  v               v
+--------------+   +--------------+   +--------------+   +--------------+  +--------+
|  Tree-Sitter |   |   Concolic   |   |     HoTT     |   |    Active    |  | Cloud  |
|  AST & Regex |   |   SSA / Z3   |   | Lean 4 Proof |   |   Network    |  |  KMS   |
| (193+ Rules) |   |  Constraint  |   |  Synthesis   |   | (TLS / SSH)  |  | Audits |
+--------------+   +--------------+   +--------------+   +--------------+  +--------+
       |                  |                  |                  |               |
       +------------------+------------------+------------------+---------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                             Synthesis & Export Hub                                |
|  - OASIS SARIF 2.1.0 (GitHub Code Scanning)                                       |
|  - CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)                           |
|  - Autonomous Semantic Patcher (Unified Diff & PR generation)                     |
|  - PQMesh Distributed Cross-Medium Fleet Bus                                      |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Execution Lifecycle

When an audit target (a filesystem path, Git repository URL, or network endpoint) is submitted, the execution flow proceeds across four distinct phases:

### Phase 1: Ingestion and Validation
1. **Target Normalization**: Resolves paths, URLs, or network endpoints.
2. **Security Controls**: Executes path traversal validation against `PQCANARY_SCAN_ROOT` and Server-Side Request Forgery (SSRF) checks against cloud metadata IPs (e.g., `169.254.169.254`).
3. **Repository Fetching**: If a remote Git URL is supplied, PQCanary clones or fetches the shallow archive into an isolated, temporary directory with automatic zero-leakage cleanup on drop.

### Phase 2: Parallel Discovery and Routing
1. **Parallel Walker**: Traverses the directory tree using Rayon thread pools, adhering to `.gitignore`, `.pqcanaryignore`, and `.pqcanary.yaml` exclusion rules.
2. **Language and Target Dispatching**:
   - Source code files (`.ts`, `.js`, `.py`, `.rs`, `.go`, `.java`, `.c`, `.cpp`) route to the Tree-sitter concrete syntax tree parser and pattern matcher.
   - Manifest files (`package.json`, `Cargo.toml`, `requirements.txt`, `go.mod`, `pom.xml`) route to the Dependency Scanner.
   - Certificate files (`.pem`, `.crt`, `.der`, `.key`, `.p12`) route to the Certificate Scanner.
   - Compiled binaries (`.exe`, `.dll`, `.so`, `.dylib`, `.wasm`) route to the Binary Disassembly Engine.
   - Infrastructure-as-Code (`.tf`, `.json`) route to the Cloud KMS Inspector.

### Phase 3: Deep Engine Analysis
1. **AST and Pattern Engine**: Runs concrete syntax queries and 193+ regex-based detection vectors.
2. **Concolic Symbolic Engine**: Lifts identified cryptographic code fragments to Static Single Assignment (SSA) form and solves branch reachability constraints using Z3.
3. **HoTT Proof Engine**: Synthesizes formal proofs of cryptographic safety and category-theoretic equivalence using Lean 4.
4. **Thermodynamics Analyzer**: Computes irreversible logic gate counts and compares energy dissipation against the Landauer thermodynamic limit ($k_B T \ln 2$).
5. **QRAMM Scoring**: Aggregates vulnerability severities and calculates the Quantum Risk Assessment and Migration Model readiness index.
6. **CBOM Semantic Drift Gatekeeper**: Evaluates semantic diffs between CycloneDX 1.6 releases to catch cryptographic downgrade regressions.
7. **Network MTU & Packet Fragmentation Analyzer**: Models wire overhead against network Path MTU, calculating TCP segment counts, middlebox drops, and latency overhead.
8. **Cryptographic Agility Auditor**: Evaluates compliance with NIST SP 800-227, measuring factory decoupling and configuration-driven cipher selection (0–100 CAS).
9. **Topological Migration DAG Sequencer**: Generates dependency-ordered 5-phase migration roadmaps aligned with CNSA 2.0 and OMB M-23-02.
10. **Zero-Downtime Data-at-Rest Re-encryption Generator**: Synthesizes 3-phase dual-key Terraform infrastructure and streaming re-wrapping scripts for Cloud KMS.
11. **Shift-Left Pre-Commit Gatekeeper**: Executes sub-15ms incremental AST scanning of staged Git files (`git diff --cached`) before commits are recorded.
12. **Passive eBPF Kernel Wire Sniffer**: Zero-overhead Traffic Control socket filter decoding live TLS 1.3 `ClientHello` packets on the wire.
13. **Cloud-Native Service Mesh Injector**: Generates Istio `EnvoyFilter` and Traefik `TLSOption` PQC manifests.
14. **Hardware Security Module Auditor**: Evaluates physical PKCS#11 v3.0 and KMIP tokens for FIPS 203/204 readiness.
15. **Dynamic Runtime Cryptographic Interceptor**: Intercepts OpenSSL and Win32 CryptoAPI via `LD_PRELOAD` or Detours for legacy binaries.
16. **Continuous Autonomous Bot & OSCAL Exporter**: Synthesizes ready-to-merge PRs with Lean 4 proofs and exports NIST SP 800-53 OSCAL assessment JSON.
17. **Active Quantum Downgrade & Middlebox Tamper Simulator**: Verifies TLS 1.3 handshake fail-closed semantics when `0x11ec` (X25519MLKEM768) is stripped or corrupted.
18. **NIST CAVP / ACVP KAT Conformance Harness**: Mathematically evaluates FIPS 203/204/205 implementations against official NIST Known-Answer-Test vectors.
19. **Hybrid & Dual-Key Composite Certificate Validator**: Validates RFC 9758 dual-signature specifications and ITU-T X.509 catalyst extensions (`altSignatureAlgorithm`, `altSignatureValue`).
20. **OpenTelemetry Cryptographic Semantic Telemetry Exporter**: Emits structured OTLP/HTTP logs conforming to OpenTelemetry Cryptography Semantic Conventions.
21. **Empirical Constant-Time & Cache-Timing Verifier**: Executes Dudect Welch two-sample t-test ($|t| > 4.5$) to verify constant-time execution and prevent KyberSlash timing leakage.
22. **Cryptographic Supply Chain Provenance & Sigstore Attestor**: Wraps CBOMs in in-toto SLSA Provenance v1.0 DSSE envelopes with Sigstore keyless Cosign verification.
23. **Stateful Hash-Based Signatures (HBS) State-Tracking & Snapshot-Safety Auditor**: Tracks RFC 8554 LMS/HSS and RFC 8391 XMSS tree exhaustion, OTS remaining signatures, and flags catastrophic multi-use vulnerabilities caused by hypervisor snapshots or container checkpoint/restore (CRIU).
24. **Post-Quantum VPN & Secure Tunnel Configuration Auditor**: Parses WireGuard (`wg0.conf`), strongSwan/IPsec (`ipsec.conf`), and OpenVPN configurations, evaluating pre-shared key (PSK) 256-bit entropy, Rosenpass daemon active posture, and RFC 9370 hybrid IKEv2 proposals.
25. **Database Column-Level Envelope Encryption & Field-Level Migration Planner**: Scans JPA `@Convert`, Prisma `@encrypted`, SQLAlchemy TypeDecorator, and MongoDB CSFLE annotations, synthesizing dual-key rotation schemas and cursor-based batch migration scripts.
26. **Continuous Filesystem Watcher & Sub-Millisecond Incremental AST Daemon**: Manages recursive directory watches with debounced event buffering, tracking mtime/size deltas to selectively audit modified files without full codebase rescanning.
27. **Enterprise Identity, Kerberos PKINIT & Windows Credential Guard Auditor**: Analyzes MIT and Heimdal `krb5.conf` configurations, evaluating classical RFC 4556 PKINIT DH/ECDH ticket-granting-ticket exposure to Harvest-Now-Decrypt-Later (HNDL) attacks and outputting quantum-hardened configurations.
28. **Direct Binary IAT/GOT/Mach-O Import Table Post-Quantum Patcher**: Safely rewrites Windows PE64 Import Address Table (IAT), Linux ELF64 `.dynstr`, and macOS Mach-O 64-bit symbol tables with zero source code recompilation, recalculating Microsoft PE checksums and generating C forwarder shims.
29. **Physical HSM & Token PKCS#11 / KMIP Dynamic Interrogator**: Probes PKCS#11 v2.40/v3.0 cryptoki interfaces, verifying hardware Oasis PQC mechanisms (`CKM_ML_KEM_KEY_GEN`, `CKM_ML_DSA_KEY_GEN`, `CKM_SLH_DSA_KEY_GEN`) and alerting on unaccelerated host software-emulation fallbacks (`CKF_HW`).
30. **Enterprise Fleet-Wide CBOM Data Lake & Columnar Analytics Engine**: Emits high-performance DDL schemas, partitioned batch ingestion SQL, and multi-tenant Cryptographic Agility Score (CAS) aggregation queries for PostgreSQL / TimescaleDB and ClickHouse MergeTree data lakes.
31. **In-Flight PQC TLS 1.3 & SSH 2.0 Latency, Jitter, and Fragmentation Profiler**: Models protocol wire overhead across MTU 1500, 1420, and 1280, calculating MSS segmentation boundaries, round-trip time latency inflation, and middlebox packet drop risk factors.
32. **Formally Verified Translation Validation & Control-Flow Equivalence Proof Engine**: Verifies binary mutation boundaries via automated SMT-LIB2 Z3 equivalence formulas and Lean 4 bisimulation proofs, proving that binary patch instrumentation preserves opcode semantics and control flow outside designated import table slots.
33. **Dynamic Symbol Resolution AST Taint & Interceptor Scanner**: Audits runtime dynamic loader invocations (`dlopen`, `dlsym`, `LoadLibrary`, `GetProcAddress`, Python `ctypes`, Java JNI) that bypass static PE/ELF/Mach-O import tables, generating targeted `LD_PRELOAD` shared library and Win32 Detours C interceptor shims.
34. **Automated Post-Quantum ACME (RFC 8555) & EST (RFC 7030) PKI Enrollment Engine**: Synthesizes automated PKI enrollment workflows with FIPS 204 ML-DSA-65/87 and RFC 9758 composite dual-key certificates, emitting Kubernetes `cert-manager` CRDs and HashiCorp Vault role policies.
35. **NIST SP 800-90B & AIS 31 Physical Noise Source Entropy Evaluator**: Computes statistical min-entropy ($H_\infty$) across MCV, collision, Markov, and universal compression estimators to ensure hardware QRNGs provide sufficient min-entropy to seed FIPS 203 ML-KEM lattice key generation.
36. **NIST CMVP FIPS 140-3 Cryptographic Module Database & Firmware Attestation Engine**: Attests physical HSMs, firmware versions, and crypto boundaries against official NIST CMVP validation certificates and NIST SP 800-131A Rev 2 transition sunset schedules.
37. **OASIS KMIP 2.1 / 3.0 Post-Quantum Wire Protocol Frame Encoder/Decoder**: Formats and parses binary TTLV frames with big-endian tags and 8-byte alignment padding for enterprise KMS lifecycle management with NIST FIPS 203 ML-KEM and FIPS 204 ML-DSA attributes.

### Phase 4: Output Synthesis and Mesh Propagation
1. **Deduplication**: Findings are deduplicated using SHA-256 fingerprints computed over file path, rule ID, and line number.
2. **Export Generation**: Formats findings into the requested output: SARIF 2.1.0, CycloneDX 1.6 CBOM, RFC 4180 CSV, standalone interactive HTML, or plain text.
3. **PQMesh Fleet Sync**: If the `--sync` flag is enabled, findings and telemetry events broadcast across the cross-medium bus.

---

## 3. Concurrency and Memory Architecture

### Strict Memory Safety Guarantees
- The `pqcanary-core` library enforces `#![forbid(unsafe_code)]` at the root level.
- All extracted cryptographic keys, certificates, and private credentials are encapsulated inside `SecureMaterial` structs implementing `zeroize::ZeroizeOnDrop`. Memory containing sensitive material is explicitly scrubbed upon dropping.

### Linear Memory Sandboxing
PQCanary incorporates a formal WebAssembly linear memory model to evaluate memory-safety risks in untrusted code snippets. The sandbox enforces:
- Explicit 64-KB memory page boundaries.
- Bounds-checked pointer dereferences preventing out-of-bounds reads and writes.
- Segregated allocation tracking to identify use-after-free conditions before native execution.

### Multi-Threading and Concurrency
- **CPU-Bound Workloads**: Directory traversal, AST parsing, and pattern evaluation utilize Rayon work-stealing thread pools scaled dynamically to available physical cores (`num_cpus::get()`).
- **I/O-Bound Workloads**: The daemon REST API, remote Git cloning, and network probing utilize the asynchronous Tokio runtime with non-blocking TCP socket polling.

---

## 4. Multi-Platform Delivery Model

PQCanary's codebase is designed for multi-target compilation without functional divergence:

| Target Component | Crate / Directory | Primary Technologies | Purpose |
| :--- | :--- | :--- | :--- |
| **Core Engine** | `core/` | Rust (stable), Tree-sitter, Z3 | Core scanning algorithms, HoTT, thermodynamics |
| **CLI Binary** | `cli/` | Rust, Clap, Indicatif | Standalone CLI for local terminals and CI/CD pipelines |
| **MCP Server** | `mcp/` | Rust, Serde JSON-RPC | Stdio JSON-RPC 2.0 interface for AI coding agents |
| **WebAssembly** | `core/` (`wasm32`) | `wasm-bindgen`, `wasm-pack` | In-browser client-side scanning with zero server egress |
| **Desktop App** | `web/src-tauri/` | Tauri v2, Rust | Native desktop application for Windows, macOS, Linux |
| **Web Dashboard** | `web/` | SolidStart, TypeScript | Interactive compliance and visualization interface |
| **IDE Extensions** | `extensions/` | TypeScript, Lua | Real-time diagnostics in VS Code and Neovim |
| **Kubernetes Node** | `pqmesh/` | Rust, Docker DaemonSet | In-cluster cryptographic pod auditing daemon |
