# CLI Reference Manual

This document provides a comprehensive command-line reference for the `pqcanary` binary, including subcommands, argument flags, exit status codes, and environment variables.

---

## 1. Global Syntax and Usage

```bash
pqcanary [COMMAND] [OPTIONS]
```

### Exit Codes

| Code | Status | Description |
| :--- | :--- | :--- |
| **0** | `SUCCESS` | Scan completed successfully with no threshold-breaching findings. |
| **1** | `FAILURE` | Cryptographic vulnerabilities detected that triggered active quality gates (`--fail-on`, `--fail-on-new`, `--fail-on-findings`). |
| **2** | `CONFIG_ERROR` | Command syntax error, invalid configuration file, or unresolvable target path. |

---

## 2. Subcommands Catalog

### 2.1. `scan`
Scans a local directory, remote Git repository, or web URL for post-quantum and classical cryptographic vulnerabilities.

```bash
pqcanary scan [PATH] [OPTIONS]
```

**Arguments:**
- `PATH`: Directory path, remote Git URL (`https://github.com/...`), or website URL (default: current directory `.`).

**Options:**
- `-o, --output <FILE>`: Write scan report to the specified file rather than stdout.
- `-f, --format <FORMAT>`: Output format: `text` (default), `json`, `sarif`, `cbom`, `html`, `markdown`, or `csv`.
- `-s, --severity <LEVEL>`: Minimum severity threshold: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `-b, --baseline <FILE>`: Path to a baseline JSON or SARIF report for regression tracking.
- `--fail-on-new`: Exit with code 1 only if newly introduced vulnerabilities are found compared to the baseline.
- `--fail-on <SEVERITY>`: Exit condition: `critical`, `high`, `medium`, `low`, `new`, `findings`, or `none`.
- `--fail-on-findings`: Legacy CI gate: exit with code 1 if any vulnerability is detected.
- `--ignore <RULES>`: Comma-separated rule IDs to skip (e.g., `PQC-ASYM-RSA-001,PQC-HASH-MD5-001`).
- `--ignore_category <CATEGORIES>`: Comma-separated rule categories to skip (e.g., `Certificates,Dependency Manifests`).
- `-c, --config <FILE>`: Path to configuration file (default: `.pqcanary.yaml` or `pqcanary.toml`).
- `-p, --progress`: Display real-time streaming progress indicator.
- `--sync`: Automatically stream and synchronize findings to the local/remote PQMesh fleet.

---

### 2.2. `sarif`
Generates an OASIS SARIF 2.1.0 report for native GitHub Code Scanning integration.

```bash
pqcanary sarif [PATH] [--output <FILE>]
```

---

### 2.3. `patch`
Applies automated semantic remediation patches to modernize vulnerable cryptographic calls.

```bash
pqcanary patch <FILE_PATH> [--dry-run]
```

**Options:**
- `-d, --dry-run`: Display the unified diff without modifying the source file on disk.

---

### 2.4. `classify`
Classifies a cryptographic algorithm against NIST Post-Quantum Cryptography standards.

```bash
pqcanary classify <ALGORITHM>
```

**Example:**
```bash
pqcanary classify ML-KEM-768
pqcanary classify RSA-2048
```

---

### 2.5. `prove`
Exports a formal mathematical proof in Lean 4 verifying algorithmic security properties.

```bash
pqcanary prove <ALGORITHM> [--output <FILE>]
```

---

### 2.6. `thermo`
Simulates thermodynamic heat dissipation against the Landauer limit ($k_B T \ln 2$) and evaluates thermal side-channel risks.

```bash
pqcanary thermo [--gates <COUNT>] [--erased <COUNT>]
```

**Options:**
- `--gates <COUNT>`: Total logic gates in circuit (default: 10,000).
- `--erased <COUNT>`: Number of irreversible gate erasures per clock cycle (default: 4,000).

---

### 2.7. `sandbox`
Executes the WebAssembly formal linear memory safety sandbox test to verify bounds protection.

```bash
pqcanary sandbox
```

---

### 2.8. `cbom`
Generates a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) specification.

```bash
pqcanary cbom <PATH> [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `-f, --format <FORMAT>`: Output format: `json` (default) or `markdown`.
- `-o, --output <FILE>`: Target file destination (default: stdout).

---

### 2.9. `diff`
Performs differential cryptographic regression analysis between two codebase snapshots, SARIF files, or CycloneDX 1.6 CBOM releases.

```bash
pqcanary diff <BASE> <TARGET> [--fail-on-downgrade] [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `--fail-on-downgrade`: Exits with code 1 if any post-quantum asset was replaced by a classical or deprecated algorithm.
- `-f, --format <FORMAT>`: Output format (`text` or `json`).
- `-o, --output <FILE>`: Destination file (default: stdout).

---

### 2.10. `qpu`
Simulates Quantum Processing Unit states and generates OpenQASM circuits.

```bash
pqcanary qpu simulate --qubits <N> --target <BITSTRING>
pqcanary qpu grover --qubits <N> --target <BITSTRING>
```

---

### 2.11. `worker`
Launches a distributed cluster worker node connecting to a Redis broker.

```bash
pqcanary worker [--redis-url <URL>] [--worker-id <ID>]
```

---

### 2.12. `serve`
Starts the background REST API daemon and Prometheus metrics exporter.

```bash
pqcanary serve [-p <PORT>]
```

**Options:**
- `-p, --port <PORT>`: TCP port to bind (default: 8080).

---

### 2.13. `probe` (alias `probe-tls`)
Probes a live remote network endpoint over TLS 1.3 for post-quantum hybrid key exchange (ML-KEM / Kyber).

```bash
pqcanary probe <TARGET> [-f <FORMAT>]
```

---

### 2.14. `probe-ssh` (alias `ssh-probe`)
Probes a remote SSH server for post-quantum hybrid key exchange (`sntrup761`, `mlkem768`).

```bash
pqcanary probe-ssh <TARGET> [-f <FORMAT>]
```

---

### 2.15. `qramm`
Calculates the Quantum Risk Assessment and Migration Model (QRAMM) scorecard for a repository.

```bash
pqcanary qramm [PATH] [-f <FORMAT>]
```

---

### 2.16. `audit-host` (alias `audit`)
Audits the host operating system's installed cryptographic dynamic libraries and trust roots.

```bash
pqcanary audit-host [-f <FORMAT>]
```

---

### 2.17. `rules`
Lists, inspects, and filters the built-in catalog of 193+ cryptographic detection patterns.

```bash
pqcanary rules [-c <CATEGORY>] [-s <SEVERITY>] [-q <QUANTUM_RISK>] [-f <FORMAT>]
```

---

### 2.18. `binary` (alias `disassemble`)
Disassembles a compiled native binary (PE, ELF, Mach-O, WASM) and inspects imported crypto APIs and constant tables.

```bash
pqcanary binary <FILE_PATH> [-f <FORMAT>]
```

---

### 2.19. `runtime` (alias `process-audit`)
Audits active OS processes and dynamically loaded cryptographic libraries in memory.

```bash
pqcanary runtime [-f <FORMAT>]
```

---

### 2.20. `hndl` (alias `mosca`)
Calculates the Harvest-Now-Decrypt-Later risk window using Mosca's Theorem ($X + Y > Z$).

```bash
pqcanary hndl [-x <YEARS>] [-y <YEARS>] [-z <YEARS>] [-f <FORMAT>]
```

---

### 2.21. `mesh`
Inspects online nodes or broadcasts events across the distributed PQMesh fleet bus.

```bash
pqcanary mesh status
pqcanary mesh broadcast --title <TITLE> --details <DETAILS> [--severity <SEVERITY>]
```

---

### 2.22. `cloud-kms` (alias `kms`)
Audits Cloud KMS configurations (AWS, Azure, GCP) and Terraform scripts.

```bash
pqcanary cloud-kms [PATH] [-f <FORMAT>]
```

---

### 2.23. `mtu`
Analyzes transport-layer network Path MTU constraints, TCP packet fragmentation, middlebox drop probabilities, and latency overhead penalties for post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA, and composite hybrids).

```bash
pqcanary mtu [--algorithm <ALGORITHM>] [--mtu <BYTES>] [-f <FORMAT>]
```

**Options:**
- `-a, --algorithm <ALGORITHM>`: Post-quantum algorithm to model (default: `ML-KEM-768`). Supported: `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, `X25519-MLKEM768`, `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, `SLH-DSA-128s`, `RSA-2048`, `X25519`.
- `-m, --mtu <BYTES>`: Network Path Maximum Transmission Unit in bytes (default: `1500`).
- `-f, --format <FORMAT>`: Output format (`text` or `json`).

---

### 2.24. `agility`
Evaluates the codebase against NIST SP 800-227 Cryptographic Agility guidelines, computing a 0 to 100 Agility Score (CAS) based on decoupled provider factories, config-driven cipher suites, and absence of hardcoded primitive invocations.

```bash
pqcanary agility [PATH] [-f <FORMAT>]
```

**Options:**
- `PATH`: Directory or source file path (default: `.`).
- `-f, --format <FORMAT>`: Output format (`text` or `json`).

---

### 2.25. `roadmap`
Synthesizes a topologically sequenced 5-phase migration roadmap conforming to US CNSA 2.0 and OMB Memorandum M-23-02 directives. Computes dependency ordering across Root PKI, Intermediate CAs, Ingress, Microservices, and Storage-at-Rest.

```bash
pqcanary roadmap [PATH] [--framework <FRAMEWORK>] [-f <FORMAT>]
```

**Options:**
- `PATH`: Project repository path (default: `.`).
- `--framework <FRAMEWORK>`: Target compliance standard: `cnsa2` (default) or `omb-m2302`.
- `-f, --format <FORMAT>`: Output format (`text` or `json`).

---

### 2.26. `reencrypt`
Generates a complete 3-phase automated zero-downtime data-at-rest re-encryption playbook for enterprise cloud KMS infrastructures (AWS KMS, Azure Key Vault, Google Cloud KMS).

```bash
pqcanary reencrypt --provider <AWS|AZURE|GCP> --key-arn <KEY_IDENTIFIER> [--target-algorithm <ALG>] [-o <OUTPUT_DIR>]
```

**Options:**
- `-p, --provider <PROVIDER>`: Cloud key management provider: `AWS`, `Azure`, or `GCP`.
- `-k, --key-arn <ARN>`: Target KMS Key ARN, Key Vault URI, or Cloud KMS CryptoKey ID.
- `-t, --target-algorithm <ALG>`: Modernization algorithm target (default: `ML-DSA-65`).
- `-o, --output <DIR>`: Output directory to write Terraform HCL and Python worker scripts.

---

### 2.27. `hooks`
Installs, uninstalls, or executes a sub-15ms incremental shift-left pre-commit hook that audits staged Git files (`git diff --cached`) for quantum vulnerabilities before code reaches remotes.

```bash
pqcanary hooks <install|uninstall|run>
```

**Commands:**
- `install`: Creates executable `.git/hooks/pre-commit` in the active repository.
- `uninstall`: Removes the pre-commit hook.
- `run`: Executes the staged file scanner directly (invoked automatically by Git).

---

### 2.28. `ebpf`
Passive Linux kernel Traffic Control (TC) socket filter generator and raw wire handshake decoder. Inspects TLS 1.3 `ClientHello` and `ServerHello` packets for post-quantum group negotiation (0x11ec / X25519MLKEM768) without terminating TLS or adding proxy overhead.

```bash
pqcanary ebpf [--generate-probe] [--payload-hex <HEX>] [--src <IP:PORT>] [--dst <IP:PORT>] [-f <FORMAT>]
```

**Options:**
- `--generate-probe`: Emits C source code for an eBPF TC classifier kernel program.
- `--payload-hex <HEX>`: Decodes and analyzes raw TLS 1.3 handshake packet hex string.
- `-f, --format <FORMAT>`: Output format (`text`, `json`, or `markdown`).

---

### 2.29. `k8s-mesh`
Generates cloud-native Kubernetes service mesh and ingress PQC auto-remediation manifests (Istio EnvoyFilter, Traefik TLSOption, NGINX Ingress annotations, Kubernetes Gateway API v1) enforcing hybrid `X25519MLKEM768` ciphers with zero downtime.

```bash
pqcanary k8s-mesh [--platform <istio|traefik|nginx|gateway>] [--name <NAME>] [--namespace <NS>] [--hybrid-group <GROUP>] [-o <FILE>]
```

**Options:**
- `-p, --platform <PLATFORM>`: Target ingress controller (`istio`, `traefik`, `nginx`, `gateway`).
- `--hybrid-group <GROUP>`: Named curve preference (default: `X25519MLKEM768`).
- `-o, --output <FILE>`: File path to save generated manifest.

---

### 2.30. `hsm`
Audits physical and cloud Hardware Security Modules (Thales Luna 7, Entrust nShield, AWS CloudHSM, YubiKey 5) via PKCS#11 v3.0 and OASIS KMIP for NIST FIPS 203/204 mechanism support (`CKM_ML_KEM_KEY_GEN`, `CKM_ML_DSA_KEY_GEN`).

```bash
pqcanary hsm [--provider <luna|nshield|cloudhsm|yubikey|kmip>] [--label <LABEL>] [--firmware <VER>] [--keys <N>] [--ml-kem] [--ml-dsa] [-f <FORMAT>]
```

**Options:**
- `-p, --provider <PROVIDER>`: Hardware provider type.
- `--ml-kem`: Checks if token has FIPS 203 key encapsulation capability.
- `--ml-dsa`: Checks if token has FIPS 204 signature capability.
- `-f, --format <FORMAT>`: Output format (`markdown` or `json`).

---

### 2.31. `runtime-shim`
Generates dynamic runtime cryptographic interception C shared library (`libpqcanary_shim.so` via `LD_PRELOAD` or Microsoft Detours on Windows) to monitor or override cipher negotiation in closed-source legacy binaries where source code is unavailable.

```bash
pqcanary runtime-shim [--mode <audit|enforce>] [--log-path <PATH>] [--force-hybrid <GROUPS>] [-o <FILE>]
```

**Options:**
- `-m, --mode <MODE>`: Interception mode (`audit` for logging, `enforce` for live PQC override).
- `--force-hybrid <GROUPS>`: Curve preferences list to enforce (default: `X25519MLKEM768:X25519`).
- `-o, --output <FILE>`: Destination C source file path.

---

### 2.32. `autonomous-pr`
Continuous DevSecOps webhook engine that ingests Git push events, runs concolic SMT and AST analysis, synthesizes NIST PQC unified diff patches, attaches machine-checked Lean 4 formal proofs, and outputs RFC 8259 Pull Request payloads for GitHub/GitLab.

```bash
pqcanary autonomous-pr [PATH] [--repo <ORG/REPO>] [--branch <BRANCH>] [--commit <SHA>] [-f <FORMAT>]
```

**Options:**
- `--repo <REPO>`: Repository identifier.
- `--branch <BRANCH>`: Default target branch (default: `main`).
- `-f, --format <FORMAT>`: Output format (`markdown` or `json`).

---

### 2.33. `oscal`
Evaluates and exports Open Security Controls Assessment Language (OSCAL) JSON conforming to NIST SP 800-53 Rev 5 (`SC-8`, `SC-12`, `SC-13`), European Union DORA Article 9, and PCI DSS 4.0.1 Requirement 3.4.

```bash
pqcanary oscal [PATH] [--project <NAME>] [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `--project <NAME>`: Target system identifier.
- `-f, --format <FORMAT>`: Output format (`markdown`, `json` conforming to OSCAL 1.0.4, or `text`).
- `-o, --output <FILE>`: Output destination file.

---

### 2.34. `downgrade`
Actively simulates Man-in-the-Middle (MitM) adversary and middlebox tamper attacks against TLS 1.3 handshakes. Validates that servers enforce CNSA 2.0 fail-closed semantics when post-quantum extensions (`0x11ec`) are stripped or key shares corrupted.

```bash
pqcanary downgrade <TARGET:PORT> [--strict-cnsa] [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `<TARGET:PORT>`: Target remote hostname and port (e.g. `gateway.corp.internal:443`).
- `--strict-cnsa`: Enforce strict CNSA 2.0 fail-closed policy evaluation.
- `-f, --format <FORMAT>`: Output format (`markdown`, `json`, or `text`).
- `-o, --output <FILE>`: Destination output file path.

---

### 2.35. `acvp`
NIST CAVP / ACVP Known-Answer-Test (KAT) conformance testing harness for FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). Evaluates NTT polynomial reductions, Montgomery constants, and rejection sampling bounds.

```bash
pqcanary acvp [--library <NAME>] [--algorithm <ALG>] [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `--library <NAME>`: Target cryptographic implementation library identifier (default: `liboqs-sys / RustCrypto-PQC`).
- `--algorithm <ALG>`: Target algorithm (`ml-kem-768`, `ml-dsa-65`, `slh-dsa-128s`, or `all`).
- `-f, --format <FORMAT>`: Output format (`markdown`, `json`, or `text`).
- `-o, --output <FILE>`: Destination output file path.

---

### 2.36. `composite-cert`
Evaluates and validates hybrid & dual-key composite certificate chains against RFC 9758 dual-signature specifications and ITU-T X.509 v3 catalyst extensions (`altSignatureAlgorithm`, `altSignatureValue`).

```bash
pqcanary composite-cert <PATH_OR_PEM> [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `<PATH_OR_PEM>`: Certificate file path or raw PEM content string.
- `-f, --format <FORMAT>`: Output format (`markdown`, `json`, or `text`).
- `-o, --output <FILE>`: Destination output file path.

---

### 2.37. `otel`
Exports structured cryptographic runtime telemetry conforming to OpenTelemetry Cryptography Semantic Conventions (`crypto.operation`, `crypto.algorithm`, `crypto.pqc.hybrid`, `crypto.quantum_risk`) directly into enterprise SIEM / SOC collectors.

```bash
pqcanary otel [PATH] [--collector <URL>] [--service <NAME>] [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `[PATH]`: Target codebase path to scan for cryptographic telemetry generation.
- `--collector <URL>`: OpenTelemetry OTLP/HTTP collector endpoint (default: `http://localhost:4318/v1/logs`).
- `--service <NAME>`: OpenTelemetry service name (default: `pqcanary-scanner-agent`).
- `-f, --format <FORMAT>`: Output format (`markdown`, `json`, or `text`).
- `-o, --output <FILE>`: Destination output file path.

---

### 2.38. `constant-time`
Empirical microarchitectural side-channel analyzer executing Dudect Welch's two-sample t-test ($|t| > 4.5$ threshold) across fixed-vs-random input classes to detect cache-timing vulnerabilities and KyberSlash decapsulation timing leakage.

```bash
pqcanary constant-time [--routine <NAME>] [--samples <N>] [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `--routine <NAME>`: Target cryptographic inner routine (default: `mlkem768_decaps_inner`).
- `--samples <N>`: Trace sample execution count (default: `10000`).
- `-f, --format <FORMAT>`: Output format (`markdown`, `json`, or `text`).
- `-o, --output <FILE>`: Destination output file path.

---

### 2.39. `cbom-attest`
Wraps CycloneDX 1.6 Cryptographic Bills of Materials in Dead Simple Signing Envelopes (DSSE) and in-toto SLSA Provenance v1.0 predicates. Computes cryptographic SHA-256 and SHA-512 artifact digests and generates Sigstore Cosign verification commands.

```bash
pqcanary cbom-attest <CBOM_PATH> [--project <NAME>] [--signer <EMAIL>] [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `<CBOM_PATH>`: Path to input CycloneDX 1.6 CBOM JSON file.
- `--project <NAME>`: Project or artifact name (default: `pqcanary-inspected-project`).
- `--signer <EMAIL>`: Fulcio identity or signer email (default: `security@enterprise.internal`).
- `-f, --format <FORMAT>`: Output format (`markdown`, `json`, or `text`).
- `-o, --output <FILE>`: Destination output file path.

---

### 2.40. `hbs-audit`
Audits Stateful Hash-Based Signature (HBS) implementations adhering to RFC 8554 (LMS/HSS) and RFC 8391 (XMSS). Evaluates total key-tree capacity ($2^h$), OTS remaining signatures, hypervisor snapshot/CRIU cloning risks, and monotonic counter hardware isolation.

```bash
pqcanary hbs-audit <PATH> [-f <FORMAT>]
```

**Options:**
- `<PATH>`: Target stateful signature configuration, state store file, or key descriptor.
- `-f, --format <FORMAT>`: Output format (`markdown` [default] or `json`).

---

### 2.41. `vpn-audit`
Audits Post-Quantum Virtual Private Network and secure tunnel configurations, including WireGuard (`wg0.conf`), strongSwan/IPsec (`ipsec.conf`), and OpenVPN. Validates 256-bit PSK entropy, Rosenpass post-quantum daemon integration, and RFC 9370 hybrid IKEv2 proposals.

```bash
pqcanary vpn-audit <PATH> [-f <FORMAT>]
```

**Options:**
- `<PATH>`: Path to VPN configuration file (e.g. `wg0.conf`, `ipsec.conf`, `client.ovpn`).
- `-f, --format <FORMAT>`: Output format (`markdown` [default] or `json`).

---

### 2.42. `db-envelope`
Audits column-level database envelope encryption annotations across Spring Data JPA (`@Convert`), Prisma (`@encrypted`), SQLAlchemy (`TypeDecorator`), and MongoDB CSFLE. Synthesizes migration schemas and executable cursor-based batch rotation scripts.

```bash
pqcanary db-envelope <PATH> [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `<PATH>`: Path to entity source code, schema DDL, or data model directory.
- `-f, --format <FORMAT>`: Output format (`markdown` [default], `json`, `sql`, or `python`).
- `-o, --output <FILE>`: Destination output file for generated migration scripts.

---

### 2.43. `watch`
Launches a continuous background filesystem watcher daemon with debounced change detection. Executes sub-millisecond incremental AST scans over modified files and reports regression deltas.

```bash
pqcanary watch [PATH] [--debounce-ms <MS>] [--once]
```

**Options:**
- `[PATH]`: Target directory path to watch (default: `.`).
- `--debounce-ms <MS>`: Watch cycle debounce window in milliseconds (default: `1000`).
- `--once`: Performs a single delta evaluation cycle and exits immediately.

---

### 2.44. `kerberos-audit`
Audits Enterprise Identity and Kerberos configurations (`krb5.conf`), assessing weak encryption types (DES, 3DES, RC4), Active Directory PKINIT (RFC 4556) ticket-granting-ticket exposure to Harvest-Now-Decrypt-Later (HNDL) attacks, and Windows Credential Guard isolation.

```bash
pqcanary kerberos-audit <PATH> [-f <FORMAT>] [-o <FILE>]
```

**Options:**
- `<PATH>`: Path to `krb5.conf` or Kerberos realm configuration file.
- `-f, --format <FORMAT>`: Output format (`markdown` [default], `json`, or `conf`).
- `-o, --output <FILE>`: Destination output file for quantum-hardened `krb5.conf`.

---

### 2.45. `binary-patch`
Applies direct native binary modifications to Windows PE64 and Linux ELF64 executables without requiring source code access or recompilation. Rewrites classical cryptographic import symbols, recalculates official PE header checksums, and synthesizes companion C forwarder shims.

```bash
pqcanary binary-patch <BINARY_PATH> [-o <OUTPUT>] [--target-symbol <SYM>] [--replacement-symbol <SYM>] [--shim-output <FILE>]
```

**Options:**
- `<BINARY_PATH>`: Target compiled binary file path (`.exe`, `.dll`, `.so`).
- `-o, --output <FILE>`: Destination path for patched binary executable.
- `--target-symbol <SYM>`: Classical algorithm symbol to replace (default: `RSA_generate_key_ex`).
- `--replacement-symbol <SYM>`: Post-quantum replacement symbol (default: `PQ_MLKEM768_keygen`).
- `--shim-output <FILE>`: Companion C export forwarder shim file destination.

---

### 2.46. `pkcs11-interrogate`
Interrogates physical Hardware Security Module (HSM) PKCS#11 shared libraries (`.so`, `.dll`) and KMIP appliances. Discovers supported mechanisms, verifies hardware silicon execution flags (`CKF_HW`), and evaluates NIST FIPS 203/204 capabilities.

```bash
pqcanary pkcs11-interrogate <PATH> [-f <FORMAT>]
```

**Options:**
- `<PATH>`: Path to PKCS#11 driver module shared library or token description file.
- `-f, --format <FORMAT>`: Output format (`markdown` [default] or `json`).

---

### 2.47. `datalake`
Generates enterprise PostgreSQL/TimescaleDB and ClickHouse MergeTree DDL schemas, batch SQL insert statements, and fleet-wide Cryptographic Agility Score (CAS) queries for global CBOM management.

```bash
pqcanary datalake <CBOM_PATH> [--repo <NAME>] [-f <FORMAT>]
```

**Options:**
- `<CBOM_PATH>`: Path to input CycloneDX 1.6 CBOM JSON file.
- `--repo <NAME>`: Repository identifier (default: `enterprise-repo`).
- `-f, --format <FORMAT>`: Output format (`markdown` [default], `json`, `postgres`, `clickhouse`, or `inserts`).

---

### 2.48. `profile-pqc`
Profiles active network TLS 1.3 / SSH handshake latency inflation (p50, p95, p99), TCP segmentation boundaries across MTUs (1500 / 1420 / 1280), and middlebox drop penalties for post-quantum cipher suites.

```bash
pqcanary profile-pqc <TARGET> [--samples <N>] [--rtt <MS>] [-f <FORMAT>]
```

**Options:**
- `<TARGET>`: Target network endpoint (e.g. `api.enterprise.internal:443`).
- `--samples <N>`: Probe sample count (default: `10`).
- `--rtt <MS>`: Base network round-trip time in milliseconds.
- `-f, --format <FORMAT>`: Output format (`markdown` [default] or `json`).

---

### 2.49. `verify-patch`
Formally verifies binary translation equivalence between an original executable and a patched post-quantum binary. Synthesizes Z3 SMT-LIB2 constraint models and Lean 4 bisimulation theorems proving code opcode and control-flow graph (CFG) invariance.

```bash
pqcanary verify-patch <ORIG_BIN> <PATCHED_BIN> [-f <FORMAT>] [--smt-output <FILE>] [--lean-output <FILE>]
```

**Options:**
- `<ORIG_BIN>`: Path to original unpatched binary executable.
- `<PATCHED_BIN>`: Path to patched post-quantum binary executable.
- `-f, --format <FORMAT>`: Output format (`markdown` [default] or `json`).
- `--smt-output <FILE>`: File destination for synthesized Z3 SMT-LIB2 constraint formula.
- `--lean-output <FILE>`: File destination for synthesized Lean 4 equivalence theorem.

---

### 2.50. `dynamic-symbols`
Audits source code or disassembled binary text for dynamic loader invocations (`dlsym`, `LoadLibrary`, `GetProcAddress`, Python `ctypes`, Java JNI) that bypass static import tables. Synthesizes `LD_PRELOAD` shared library C interceptors and Win32 Detours hooks.

```bash
pqcanary dynamic-symbols <TARGET_PATH> [-f <FORMAT>] [--output-hook <FILE>]
```

**Options:**
- `<TARGET_PATH>`: Path to source code file or disassembled text.
- `-f, --format <FORMAT>`: Output format (`markdown` [default], `json`, `c-preload`, or `c-detours`).
- `--output-hook <FILE>`: Destination file for synthesized C interceptor hook code.

---

### 2.51. `pqc-acme`
Synthesizes automated PKI enrollment workflows conforming to ACME (RFC 8555) and EST (RFC 7030) with NIST FIPS 204 ML-DSA-65 / ML-DSA-87 and composite dual-key certificates (RFC 9758). Generates Kubernetes `cert-manager` CRDs and HashiCorp Vault role policies.

```bash
pqcanary pqc-acme <DOMAIN> [--algo <ALGO>] [--directory <URL>] [--challenge <TYPE>] [-f <FORMAT>]
```

**Options:**
- `<DOMAIN>`: Fully qualified domain name to enroll.
- `--algo <ALGO>`: Post-quantum algorithm (`ML-DSA-65` [default] or `ML-DSA-87`).
- `--directory <URL>`: ACME directory endpoint URL.
- `--challenge <TYPE>`: Challenge verification type (`dns-01` [default], `http-01`, or `tls-alpn-01`).
- `-f, --format <FORMAT>`: Output format (`markdown` [default], `json`, `k8s`, `vault`, or `csr`).

---

### 2.52. `qrng-entropy`
Evaluates physical noise source entropy samples conforming to NIST SP 800-90B Section 6 statistical estimators (Most Common Value, Collision Test, Markov Matrix, Universal Compression). Validates whether min-entropy $H_\infty \ge 0.999$ to safely seed NIST FIPS 203 ML-KEM lattice key generation.

```bash
pqcanary qrng-entropy <SAMPLE_FILE> [--source-name <NAME>] [-f <FORMAT>]
```

**Options:**
- `<SAMPLE_FILE>`: Path to raw binary or hexadecimal entropy dump file.
- `--source-name <NAME>`: Descriptive noise source identifier (default: `QRNG-Device`).
- `-f, --format <FORMAT>`: Output format (`markdown` [default] or `json`).

---

### 2.53. `cmvp-attest`
Attests hardware cryptographic tokens, firmware builds, and crypto boundaries against official NIST Cryptographic Module Validation Program (CMVP) certificates. Cross-references FIPS 140-3 Security Levels (1–4), approved FIPS 203/204 algorithms, and NIST SP 800-131A Rev 2 classical sunset dates.

```bash
pqcanary cmvp-attest <MODULE_QUERY> [--firmware <VERSION>] [-f <FORMAT>]
```

**Options:**
- `<MODULE_QUERY>`: CMVP certificate number or hardware module name substring.
- `--firmware <VERSION>`: Queried firmware version string (e.g., `7.8.4`).
- `-f, --format <FORMAT>`: Output format (`markdown` [default] or `json`).

---

### 2.54. `kmip-wire`
Encodes and decodes OASIS KMIP 2.1 / 3.0 binary TTLV (Tag-Type-Length-Value) wire protocol frames for enterprise key management with post-quantum attributes (FIPS 203 ML-KEM, FIPS 204 ML-DSA).

```bash
pqcanary kmip-wire [--algo <ALGO>] [--length <BITS>] [--decode-hex <HEX>] [-f <FORMAT>]
```

**Options:**
- `--algo <ALGO>`: Post-quantum algorithm (`ML-KEM-768` [default], `ML-KEM-1024`, `ML-DSA-65`, `ML-DSA-87`).
- `--length <BITS>`: Cryptographic key length in bits (default: `768`).
- `--decode-hex <HEX>`: Hexadecimal wire representation of response TTLV frame to decode.
- `-f, --format <FORMAT>`: Output format (`markdown` [default], `hex`, or `json`).

---

## 3. Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `PQCANARY_SCAN_ROOT` | Path | Unset | Restricts all filesystem scans to paths within this canonical root directory. |
| `PQCANARY_STRICT_NETWORK` | Boolean | `0` | When set to `1` or `true`, blocks network probing to RFC 1918 private subnets and localhost. |
| `PQCANARY_API_TOKEN` | String | Unset | Configures a required Bearer token for authenticating REST API requests. |
| `PQCANARY_CONFIG` | Path | Unset | Explicitly sets the configuration file path. |
| `RUST_LOG` | String | `info` | Controls logging verbosity (`error`, `warn`, `info`, `debug`, `trace`). |
