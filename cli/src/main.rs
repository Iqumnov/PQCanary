//! PQCanary CLI
//!
//! Enterprise Post-quantum Cryptographic Security Platform & Scanner for CI/CD Pipelines.
//!
//! Usage:
//!   pqcanary scan ./my-project
//!   pqcanary scan ./my-project --format sarif --output results.sarif
//!   pqcanary scan ./my-project --baseline baseline.json --fail-on-new
//!   pqcanary patch ./my-project/src/crypto.js
//!   pqcanary classify RSA-2048
//!   pqcanary prove AES256
//!   pqcanary qpu simulate --qubits 4 --target 1010
//!   pqcanary worker --redis-url redis://127.0.0.1:6379

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::Path;
use std::process;
use std::sync::Arc;

use pqcanary_core::scanner::orchestrator::MasterOrchestrator;
use pqcanary_core::scanner::sarif::SarifGenerator;
use pqcanary_core::scanner::baseline::BaselineEngine;
use pqcanary_core::scanner::config::PqCanaryConfig;
use pqcanary_core::scanner::cbom::CbomGenerator;
use pqcanary_core::scanner::git_cloner::GitRepositoryFetcher;
use pqcanary_core::omega::hott_prover::HottProver;
use pqcanary_core::omega::thermodynamics::ThermodynamicsAnalyzer;
use pqcanary_core::omega::qpu_offload::QpuOffloadEngine;
use pqcanary_core::scanner::reporters::{HtmlReporter, MarkdownReporter, CsvReporter};
use pqcanary_core::scanner::network_tls::NetworkTlsProbe;
use pqcanary_core::scanner::network_ssh::NetworkSshProbe;
use pqcanary_core::refactor::autonomous_pr::SemanticPatcher;
use pqcanary_core::scanner::cbom_diff::CbomDiffEngine;
use pqcanary_core::scanner::pqc_mtu::PqcMtuAnalyzer;
use pqcanary_core::scanner::agility_scanner::AgilityScanner;
use pqcanary_core::scanner::migration_sequencer::MigrationSequencer;
use pqcanary_core::scanner::reencrypt_playbook::ReencryptPlaybookGenerator;
use pqcanary_core::scanner::git_hook::GitHookManager;
use pqcanary_core::scanner::ebpf_sniffer::EbpfSniffer;
use pqcanary_core::scanner::k8s_mesh::{K8sMeshEngine, K8sMeshConfig, K8sIngressPlatform};
use pqcanary_core::scanner::hsm_audit::{HsmAuditor, HsmProviderType};
use pqcanary_core::scanner::runtime_shim::{RuntimeShimGenerator, RuntimeShimConfig, ShimInterceptionMode};
use pqcanary_core::scanner::autonomous_bot::{AutonomousBotEngine, GitWebhookPushEvent, GitPlatformProvider};
use pqcanary_core::scanner::oscal_exporter::OscalExporter;
use pqcanary_core::scanner::downgrade_sim::DowngradeSimulator;
use pqcanary_core::scanner::acvp_kat::AcvpKatHarness;
use pqcanary_core::scanner::composite_cert::CompositeCertValidator;
use pqcanary_core::scanner::otel_exporter::OtelCryptoExporter;
use pqcanary_core::scanner::constant_time::ConstantTimeVerifier;
use pqcanary_core::scanner::cbom_attest::CbomAttestor;
use pqcanary_core::scanner::hbs_state_auditor::HbsStateAuditor;
use pqcanary_core::scanner::vpn_scanner::VpnScanner;
use pqcanary_core::scanner::db_envelope_scanner::DbEnvelopeScanner;
use pqcanary_core::scanner::watcher::WorkspaceWatcher;
use pqcanary_core::scanner::kerberos_pkinit::KerberosPkinitAuditor;
use pqcanary_core::scanner::binary_patcher::BinaryPatcher;
use pqcanary_core::scanner::pkcs11_interrogator::Pkcs11Interrogator;
use pqcanary_core::scanner::cbom_datalake::CbomDatalakeEngine;
use pqcanary_core::scanner::pqc_latency_profiler::PqcLatencyProfiler;
use pqcanary_core::scanner::binary_translation_validator::BinaryTranslationValidator;
use pqcanary_core::scanner::dynamic_symbol_interceptor::DynamicSymbolInterceptor;
use pqcanary_core::scanner::pqc_acme_enrollment::PqcAcmeEnrollmentEngine;
use pqcanary_core::scanner::qrng_entropy_evaluator::QrngEntropyEvaluator;
use pqcanary_core::scanner::cmvp_firmware_registry::CmvpFirmwareRegistry;
use pqcanary_core::scanner::kmip_wire_protocol::KmipWireProtocol;

#[derive(Parser, Debug)]
#[command(
    name = "pqcanary",
    about = "PQCanary — Enterprise Post-Quantum Cryptographic Security Platform",
    long_about = "PQCanary scans codebases for post-quantum unsafe cryptographic patterns,\n\
                  generates OASIS SARIF 2.1.0 for GitHub Code Scanning, performs baseline regression tracking,\n\
                  concolic symbolic execution with Z3, Lean 4 formal proofs, Landauer thermodynamic modeling,\n\
                  QPU circuit simulation, and automated remediation patches.",
    version = "0.1.0",
    author = "Matvei Igumnov <iqumnov@proton.me>",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a directory, remote Git repository, or web URL for cryptographic vulnerabilities.
    Scan {
        /// Path to directory, remote Git URL, or website URL (default: current directory ".").
        #[arg(default_value = ".")]
        path: String,

        /// Output findings to this file path.
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,

        /// Output format: text (default), json, sarif, cbom, html, markdown, or csv.
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Minimum severity threshold: CRITICAL, HIGH, MEDIUM, LOW, INFO.
        #[arg(short, long)]
        severity: Option<String>,

        /// Path to baseline JSON or SARIF file for tracking new regressions only.
        #[arg(short, long, value_name = "FILE")]
        baseline: Option<String>,

        /// Exit with code 1 ONLY if new findings exist compared to baseline.
        #[arg(long, default_value_t = false)]
        fail_on_new: bool,

        /// Exit condition: "critical", "high", "medium", "low", "new", "findings", or "none".
        #[arg(long)]
        fail_on: Option<String>,

        /// Exit with code 1 if any findings are found (legacy CI gate).
        #[arg(long, default_value_t = false)]
        fail_on_findings: bool,

        /// Specific pattern IDs to ignore (comma-separated, e.g. "RSA-001,CERT-*").
        #[arg(long)]
        ignore: Option<String>,

        /// Entire pattern categories to ignore (e.g. "Certificates,Dependency Manifests").
        #[arg(long)]
        ignore_category: Option<String>,

        /// Explicit path to YAML/TOML configuration file (.pqcanary.yaml).
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,

        /// Display animated streaming progress bar.
        #[arg(short, long, default_value_t = false)]
        progress: bool,

        /// Automatically stream and synchronize findings into the local/remote PQMesh fleet network.
        #[arg(long, default_value_t = false)]
        sync: bool,
    },

    /// Generate an OASIS SARIF 2.1.0 report for GitHub Code Scanning.
    Sarif {
        /// Target directory or repository to scan.
        #[arg(default_value = ".")]
        path: String,

        /// Output SARIF file path (default: stdout).
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Apply automated cryptographic remediation patches to a source file.
    Patch {
        /// Path to the source file to patch.
        file_path: String,

        /// Preview the diff without modifying the file.
        #[arg(short, long, default_value_t = false)]
        dry_run: bool,
    },

    /// Classify a cryptographic algorithm against NIST post-quantum standards.
    Classify {
        /// Algorithm name to classify (e.g., ML-KEM-768, RSA-2048, Dilithium3).
        algorithm: String,
    },

    /// Export a Lean 4 formal proof for a cryptographic algorithm.
    Prove {
        /// Algorithm name, e.g. AES128, AES256, Kyber512, ChaCha20.
        algorithm: String,

        /// Save the proof to this file instead of printing to stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Analyze thermodynamic side-channel risk using Landauer's limit.
    Thermo {
        /// Total number of logic gates in the circuit (default: 10000 for AES-128).
        #[arg(long, default_value_t = 10_000)]
        gates: usize,

        /// Number of irreversible gate operations per clock cycle (default: 4000).
        #[arg(long, default_value_t = 4_000)]
        erased: usize,
    },

    /// Run the formal WebAssembly linear memory sandbox test.
    Sandbox,

    /// Generate a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) document.
    #[command(alias = "generate-manifest")]
    Cbom {
        /// Target path or website URL to scan for CBOM generation.
        path: String,

        /// Output format: json (default) or markdown (Markdown table).
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Save CBOM output to this file (default: stdout).
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Compare two codebases, directories, or baselines for cryptographic differential analysis.
    Diff {
        /// Path to base directory, repository, or baseline file (Snapshot A).
        base: String,

        /// Path to comparison directory, repository, or scan findings (Snapshot B).
        target: String,

        /// Return exit code 1 if quantum downgrade regressions are detected.
        #[arg(long, default_value_t = false)]
        fail_on_downgrade: bool,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Save differential report to this file (default: stdout).
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Quantum Processing Unit (QPU) operations: statevector simulation and OpenQASM generation.
    Qpu {
        #[command(subcommand)]
        action: QpuAction,
    },

    /// Launch a distributed cluster worker node connecting to a Redis broker.
    Worker {
        /// Redis cluster connection URL (default: redis://127.0.0.1:6379).
        #[arg(long, default_value = "redis://127.0.0.1:6379")]
        redis_url: String,

        /// Unique worker identifier.
        #[arg(long)]
        worker_id: Option<String>,
    },

    /// Start the REST API daemon on port 8080 (serves REST API and Web UI).
    Serve {
        /// Port to listen on (default: 8080).
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },

    /// Probe a live network endpoint over TCP/TLS 1.3 for Post-Quantum key exchange (ML-KEM / Kyber).
    #[command(alias = "probe-tls")]
    Probe {
        /// Target host or host:port to probe (e.g. "cloudflare.com", "google.com:443").
        target: String,

        /// Output format: text (default) or json.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Probe a live SSH server over TCP for Post-Quantum hybrid key exchange (sntrup761 / mlkem768).
    #[command(alias = "ssh-probe")]
    ProbeSsh {
        /// Target host or host:port to probe (e.g. "github.com", "ssh.example.com:22").
        target: String,

        /// Output format: text (default) or json.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Calculate Quantum Risk Assessment & Migration Model (QRAMM) Scorecard for a repository.
    Qramm {
        /// Target path or repository to assess (default: ".").
        #[arg(default_value = ".")]
        path: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Audit the host operating system's installed cryptographic libraries and runtimes.
    #[command(name = "audit-host", alias = "audit")]
    AuditHost {
        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// List, inspect, and filter the built-in catalog of 193+ cryptographic detection rules.
    Rules {
        /// Filter by pattern category (e.g. "Real-World Cryptographic CVEs", "Post-Quantum Cryptography").
        #[arg(short, long)]
        category: Option<String>,

        /// Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO.
        #[arg(short, long)]
        severity: Option<String>,

        /// Filter by quantum risk: SAFE, PARTIAL, HYBRID, VULNERABLE, UNKNOWN.
        #[arg(short, long)]
        quantum_risk: Option<String>,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Disassemble compiled native binary (PE, ELF, Mach-O, WASM) and inspect imported cryptography and constant tables.
    #[command(alias = "disassemble")]
    Binary {
        /// Path to the compiled binary file (.exe, .dll, .so, .dylib, .wasm).
        file_path: String,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Audit live OS processes and dynamically loaded cryptographic modules in memory.
    #[command(name = "runtime", alias = "process-audit")]
    Runtime {
        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Compute Mosca's Theorem (X + Y > Z) HNDL risk window and output migration playbooks.
    #[command(alias = "mosca")]
    Hndl {
        /// Time required to migrate infrastructure in years (X, default: 3.0).
        #[arg(short = 'x', long, default_value_t = 3.0)]
        migration: f32,

        /// Shelf-life of sensitive data in years (Y, default: 10.0).
        #[arg(short = 'y', long, default_value_t = 10.0)]
        shelf_life: f32,

        /// Time until Cryptographically Relevant Quantum Computer in years (Z, default: 6.0).
        #[arg(short = 'z', long, default_value_t = 6.0)]
        threat: f32,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Inspect or broadcast across the PQMesh distributed cross-medium fleet network.
    Mesh {
        #[command(subcommand)]
        action: Option<MeshAction>,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Audit Cloud KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS) configurations and Terraform files.
    #[command(name = "cloud-kms", alias = "kms")]
    CloudKms {
        /// Path to JSON export, policy document, or Terraform configuration file (or '-' for stdin).
        #[arg(default_value = ".")]
        path: String,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Manage Git pre-commit hooks for shift-left incremental cryptographic security.
    #[command(alias = "hook")]
    Hooks {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Analyze network MTU and TCP packet fragmentation risk for Post-Quantum algorithms.
    #[command(alias = "fragmentation")]
    Mtu {
        /// Algorithm name (e.g. ML-KEM-768, ML-DSA-65, SLH-DSA-128f, RSA-2048).
        #[arg(default_value = "ML-KEM-768")]
        algorithm: String,

        /// Target network MTU in bytes (default: 1500).
        #[arg(short, long, default_value_t = 1500)]
        mtu: usize,

        /// Evaluate over IPv6 (default: IPv4).
        #[arg(long, default_value_t = false)]
        ipv6: bool,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Audit cryptographic agility (NIST SP 800-227) for hardcoded vs decoupled algorithms.
    Agility {
        /// Path to source file or directory to audit (default: ".").
        #[arg(default_value = ".")]
        path: String,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Generate an asset-dependency topological migration roadmap aligned with CNSA 2.0 / OMB M-23-02.
    Roadmap {
        /// Target path or repository to scan for migration sequencing (default: ".").
        #[arg(default_value = ".")]
        path: String,

        /// Project name for report header.
        #[arg(long, default_value = "Workspace")]
        name: String,

        /// Output format: markdown (default), json, or text.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output file path (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Generate zero-downtime envelope re-encryption Terraform and batch workers for Cloud KMS.
    #[command(name = "reencrypt-playbook", alias = "reencrypt")]
    Reencrypt {
        /// Cloud provider: aws (default), azure, or gcp.
        #[arg(short, long, default_value = "aws")]
        provider: String,

        /// Target dataset or key alias name (default: "production-vault").
        #[arg(short, long, default_value = "production-vault")]
        resource: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output file path (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Passive eBPF Linux kernel wire telemetry: generate C probe or analyze handshake packet.
    #[command(alias = "sniff")]
    Ebpf {
        /// Generate eBPF C TC classifier kernel probe source code.
        #[arg(long, default_value_t = false)]
        generate_probe: bool,

        /// Raw TLS handshake payload in hex representation.
        #[arg(long)]
        payload_hex: Option<String>,

        /// Source endpoint (default: "192.168.1.100:44320").
        #[arg(long, default_value = "192.168.1.100:44320")]
        src: String,

        /// Destination endpoint (default: "10.0.0.1:443").
        #[arg(long, default_value = "10.0.0.1:443")]
        dst: String,

        /// Output format: text (default), json, or markdown.
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Generate Kubernetes service mesh & ingress PQC auto-remediation manifests (Istio, Traefik, NGINX).
    #[command(name = "k8s-mesh", alias = "mesh-inject")]
    K8sMesh {
        /// Ingress platform: istio (default), traefik, nginx, or gateway.
        #[arg(short, long, default_value = "istio")]
        platform: String,

        /// Resource name (default: "pqc-hybrid-tls-enforce").
        #[arg(short, long, default_value = "pqc-hybrid-tls-enforce")]
        name: String,

        /// Kubernetes namespace (default: "istio-system").
        #[arg(long, default_value = "istio-system")]
        namespace: String,

        /// Hybrid post-quantum curve (default: "X25519MLKEM768").
        #[arg(long, default_value = "X25519MLKEM768")]
        hybrid_group: String,

        /// Output file path (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Audit Hardware Security Module (HSM) PKCS#11 v3.0 / OASIS KMIP tokens and firmware.
    #[command(name = "hsm", alias = "hsm-audit")]
    Hsm {
        /// HSM provider: luna (default), nshield, cloudhsm, yubikey, kmip, or pkcs11.
        #[arg(short, long, default_value = "luna")]
        provider: String,

        /// Token label name (default: "Production-Root-CA").
        #[arg(short, long, default_value = "Production-Root-CA")]
        label: String,

        /// Firmware version string (default: "7.8.1").
        #[arg(long, default_value = "7.8.1")]
        firmware: String,

        /// Total cryptographic keys stored in token (default: 50).
        #[arg(long, default_value_t = 50)]
        keys: usize,

        /// Assert token has NIST FIPS 203 (ML-KEM) key generation capability.
        #[arg(long, default_value_t = false)]
        ml_kem: bool,

        /// Assert token has NIST FIPS 204 (ML-DSA) signature capability.
        #[arg(long, default_value_t = false)]
        ml_dsa: bool,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Generate dynamic runtime cryptographic interception C shim (LD_PRELOAD / Detours) for legacy binaries.
    #[command(name = "runtime-shim", alias = "shim")]
    Shim {
        /// Mode: audit (log only) or enforce (override curves with hybrid PQC).
        #[arg(short, long, default_value = "audit")]
        mode: String,

        /// Target log file path (default: "/var/log/pqcanary_runtime.log").
        #[arg(long, default_value = "/var/log/pqcanary_runtime.log")]
        log_path: String,

        /// Enforced hybrid groups list (default: "X25519MLKEM768:X25519").
        #[arg(long, default_value = "X25519MLKEM768:X25519")]
        force_hybrid: String,

        /// Output C file path (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Synthesize autonomous Pull Request with unified diff patches and Lean 4 formal proofs.
    #[command(name = "autonomous-pr", alias = "bot")]
    Bot {
        /// Path to directory to scan (default: ".").
        #[arg(default_value = ".")]
        path: String,

        /// Repository name (e.g. "org/repo").
        #[arg(short, long, default_value = "workspace/repo")]
        repo: String,

        /// Default target branch (default: "main").
        #[arg(short, long, default_value = "main")]
        branch: String,

        /// Commit SHA triggering remediation.
        #[arg(long, default_value = "head-commit")]
        commit: String,

        /// Author name for trigger.
        #[arg(long, default_value = "CI/CD")]
        author: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Export NIST SP 800-53 OSCAL assessment JSON & EU DORA compliance matrix.
    #[command(alias = "compliance")]
    Oscal {
        /// Target path to scan (default: ".").
        #[arg(default_value = ".")]
        path: String,

        /// Project name for assessment report.
        #[arg(long, default_value = "Production System")]
        project: String,

        /// Output format: markdown (default), json (OSCAL schema), or text.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output file path (default: stdout).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Active Post-Quantum Downgrade Attack & Middlebox Tamper Simulator (RFC 8446 / CNSA 2.0).
    #[command(name = "downgrade", alias = "downgrade-test")]
    Downgrade {
        /// Target host or host:port to simulate downgrade against (e.g. "api.example.com:443").
        target: String,

        /// Assert strict fail-closed policy (CNSA 2.0 mandate).
        #[arg(long, default_value_t = false)]
        strict: bool,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Validate cryptographic library against NIST CAVP / ACVP Known-Answer-Test vectors (FIPS 203/204/205).
    #[command(name = "acvp", alias = "kat-verify")]
    Acvp {
        /// Target implementation name or shared object path.
        #[arg(default_value = "Default-Implementation")]
        library: String,

        /// Target algorithm filter: kem, dsa, slh, or all.
        #[arg(short, long)]
        algo: Option<String>,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Validate Hybrid & Dual-Key X.509 Composite Certificate chains (RFC 9758).
    #[command(name = "composite-cert", alias = "cert-dual")]
    CompositeCert {
        /// Target certificate file path or hostname.
        path: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Export OpenTelemetry Cryptographic Semantic telemetry batch for SIEM / SOC streaming.
    #[command(name = "otel", alias = "stream-otel")]
    Otel {
        /// Path to codebase or directory to scan.
        #[arg(default_value = ".")]
        path: String,

        /// Microservice or workload name.
        #[arg(short, long, default_value = "crypto-service")]
        service: String,

        /// OTLP HTTP/gRPC collector endpoint URL.
        #[arg(short, long, default_value = "http://localhost:4318/v1/logs")]
        endpoint: String,

        /// Output OTLP JSON to file instead of stdout.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Empirically verify constant-time execution and detect KyberSlash timing leaks (Welch's t-test).
    #[command(name = "constant-time", alias = "timing")]
    ConstantTime {
        /// Target routine or primitive name.
        #[arg(default_value = "ML-KEM-768: NTT Polynomial Multiplication")]
        routine: String,

        /// Sample measurement count.
        #[arg(short, long, default_value_t = 10000)]
        samples: usize,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Generate in-toto SLSA Provenance v1.0 and Sigstore Cosign DSSE attestation for CBOM.
    #[command(name = "cbom-attest", alias = "attest")]
    Attest {
        /// Path to CycloneDX 1.6 CBOM JSON file.
        cbom_file: String,

        /// Project name for attestation subject.
        #[arg(short, long, default_value = "enterprise-service")]
        project: String,

        /// Signer OIDC identity email.
        #[arg(short, long, default_value = "iqumnov@proton.me")]
        signer: String,

        /// Output DSSE envelope file path.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Audit Stateful Hash-Based Signatures (LMS/HSS RFC 8554, XMSS RFC 8391) state tracking and snapshot safety.
    #[command(name = "hbs-audit", alias = "hbs")]
    HbsAudit {
        /// Target configuration or state file path.
        path: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Audit Post-Quantum VPN & Secure Tunnel configurations (WireGuard, strongSwan IPSec, OpenVPN).
    #[command(name = "vpn-audit", alias = "vpn")]
    VpnAudit {
        /// Path to VPN configuration file (e.g., wg0.conf, ipsec.conf, client.ovpn).
        path: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Audit database column-level envelope encryption & generate migration script.
    #[command(name = "db-envelope", alias = "envelope")]
    DbEnvelope {
        /// Path to entity code, schema DDL, or model directory.
        path: String,

        /// Output format: markdown (default), json, sql, or python.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output migration script to file path.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Continuous filesystem watcher daemon for sub-millisecond incremental cryptographic delta auditing.
    Watch {
        /// Target directory to watch (default: ".").
        #[arg(default_value = ".")]
        path: String,

        /// Watch cycle debounce interval in milliseconds.
        #[arg(long, default_value_t = 1000)]
        debounce_ms: u64,

        /// Run a single cycle comparison and exit (useful for CI/hooks).
        #[arg(long, default_value_t = false)]
        once: bool,
    },

    /// Audit Enterprise Identity, Kerberos PKINIT (RFC 4556) & Windows Credential Guard.
    #[command(name = "kerberos-audit", alias = "pkinit")]
    KerberosAudit {
        /// Path to krb5.conf or realm configuration file.
        path: String,

        /// Output format: markdown (default), json, or conf.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output hardened krb5.conf to this file.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Direct Binary IAT/GOT Import Table Post-Quantum Patcher without source recompilation.
    #[command(name = "binary-patch", alias = "patch-binary")]
    BinaryPatch {
        /// Target compiled PE64 or ELF64 binary file path.
        binary_path: String,

        /// Output patched binary file path.
        #[arg(short, long)]
        output: Option<String>,

        /// Classical algorithm symbol to replace (e.g. RSA_generate_key_ex, EVP_PKEY_CTX_new_id).
        #[arg(long, default_value = "RSA_generate_key_ex")]
        target_symbol: String,

        /// Post-quantum replacement symbol (e.g. PQ_MLKEM768_keygen, OQS_KEM_mlkem_768_keypair).
        #[arg(long, default_value = "PQ_MLKEM768_keygen")]
        replacement_symbol: String,

        /// Generate companion C shim forwarder code file path.
        #[arg(long)]
        shim_output: Option<String>,
    },

    /// Interrogate physical HSM PKCS#11 module mechanisms and evaluate hardware enforcement.
    #[command(name = "pkcs11-interrogate", alias = "pkcs11")]
    Pkcs11Interrogate {
        /// Target PKCS#11 shared library (.so/.dll) or descriptor file path.
        path: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Enterprise fleet CBOM data lake schema and batch SQL ingestion generator (Postgres/ClickHouse).
    #[command(name = "datalake", alias = "cbom-datalake")]
    CbomDatalake {
        /// Path to CycloneDX 1.6 CBOM JSON file.
        cbom_path: String,

        /// Repository identifier (default: "enterprise-repo").
        #[arg(short, long, default_value = "enterprise-repo")]
        repo: String,

        /// Output format: markdown (default), json, postgres, clickhouse, or inserts.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Profile post-quantum TLS 1.3 / SSH handshake latency inflation and wire overhead.
    #[command(name = "profile-pqc", alias = "pqc-profile")]
    PqcLatencyProfile {
        /// Target endpoint (e.g. "api.enterprise.internal:443").
        target: String,

        /// Probe sample count (default: 10).
        #[arg(short, long, default_value_t = 10)]
        samples: usize,

        /// Base network round-trip time in milliseconds (optional).
        #[arg(long)]
        rtt: Option<f64>,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Formally verify binary translation equivalence using SMT-LIB2 and Lean 4.
    #[command(name = "verify-patch", alias = "patch-verify")]
    VerifyPatch {
        /// Original unpatched binary file path.
        original_binary: String,

        /// Patched post-quantum binary file path.
        patched_binary: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Save generated Z3 SMT-LIB2 proof formula to this file path.
        #[arg(long)]
        smt_output: Option<String>,

        /// Save generated Lean 4 equivalence theorem to this file path.
        #[arg(long)]
        lean_output: Option<String>,
    },

    /// Audit dynamic symbol loader calls (dlsym / GetProcAddress) and generate runtime interceptors.
    #[command(name = "dynamic-symbols", alias = "dlsym-audit")]
    DynamicSymbols {
        /// Target source code file, directory, or disassembly output.
        path: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output generated LD_PRELOAD C hook to file path.
        #[arg(long)]
        hook_output: Option<String>,
    },

    /// Automated Post-Quantum ACME (RFC 8555) & EST (RFC 7030) certificate enrollment planner.
    #[command(name = "acme-pqc", alias = "acme-enroll")]
    PqcAcme {
        /// Target domain name (e.g. "api.enterprise.internal").
        domain: String,

        /// Primary post-quantum signature algorithm (default: "ML-DSA-65").
        #[arg(short, long, default_value = "ML-DSA-65")]
        algo: String,

        /// ACME directory URL.
        #[arg(long, default_value = "https://acme.enterprise.internal/directory")]
        directory: String,

        /// Challenge type: dns-01 (default), http-01, or tls-alpn-01.
        #[arg(short, long, default_value = "dns-01")]
        challenge: String,

        /// Output format: markdown (default), json, k8s, or vault.
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output manifest to file path.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Evaluate physical noise source min-entropy conforming to NIST SP 800-90B & AIS 31.
    #[command(name = "qrng-eval", alias = "entropy-test")]
    QrngEntropy {
        /// Source identifier or hardware descriptor name.
        source: String,

        /// Path to raw entropy sample binary file.
        sample_file: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Attest cryptographic hardware token against NIST CMVP FIPS 140-3 certificate database.
    #[command(name = "cmvp-attest", alias = "fips140-audit")]
    CmvpAttest {
        /// Module query (e.g. Luna, nShield, CloudHSM, YubiKey, or CMVP Cert #).
        module: String,

        /// Firmware version string (default: "7.8.1").
        #[arg(short, long, default_value = "7.8.1")]
        firmware: String,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// OASIS KMIP 2.1 / 3.0 Post-Quantum TTLV binary wire protocol frame encoder and decoder.
    #[command(name = "kmip-wire", alias = "kmip-test")]
    KmipWire {
        /// Post-quantum algorithm: ML-KEM (default) or ML-DSA.
        #[arg(short, long, default_value = "ML-KEM")]
        algo: String,

        /// Key length in bits (default: 768).
        #[arg(short, long, default_value_t = 768)]
        length: u32,

        /// Output format: markdown (default) or json.
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },
}

#[derive(Subcommand, Debug)]
enum HookAction {
    /// Install pre-commit hook into .git/hooks/pre-commit.
    Install,

    /// Uninstall pre-commit hook from .git/hooks/pre-commit.
    Uninstall,

    /// Execute incremental scan on staged files (invoked automatically by git commit).
    Run,
}

#[derive(Subcommand, Debug)]
enum MeshAction {
    /// View active operational mediums and connected fleet nodes.
    Status,

    /// Broadcast a custom security event or policy message across all connected mediums.
    Broadcast {
        #[arg(short, long)]
        title: String,
        #[arg(short, long)]
        details: String,
        #[arg(short, long, default_value = "INFO")]
        severity: String,
    },
}

#[derive(Subcommand, Debug)]
enum QpuAction {
    /// Generate OpenQASM 2.0 Grover search circuit.
    Generate {
        #[arg(long, default_value_t = 4)]
        qubits: u32,
        #[arg(long, default_value = "1010")]
        target: String,
    },
    /// Run exact unitary statevector quantum simulation on Grover circuit.
    Simulate {
        #[arg(long, default_value_t = 4)]
        qubits: u32,
        #[arg(long, default_value = "1010")]
        target: String,
        #[arg(long, default_value_t = 1024)]
        shots: u32,
    },
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn severity_rank(s: &str) -> u8 {
    match s.to_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn print_banner() {
    eprintln!("╔════════════════════════════════════════════════════════════╗");
    eprintln!("║    PQCanary Post-Quantum Cryptographic Platform v0.1.0     ║");
    eprintln!("║    github.com/Iqumnov/PQCanary                             ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
}

fn severity_icon(severity: &str) -> &'static str {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => "CRITICAL",
        "HIGH"     => "HIGH",
        "MEDIUM"   => "MEDIUM",
        "LOW"      => "LOW",
        _          => "INFO",
    }
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            output,
            format,
            severity,
            baseline,
            fail_on_new,
            fail_on,
            fail_on_findings,
            ignore,
            ignore_category,
            config,
            progress,
            sync,
        } => {
            print_banner();

            // 1. Configuration Resolution (Config File + CLI Flags)
            let target_path = Path::new(&path);
            let file_config = if let Some(cfg_path) = config.as_deref() {
                PqCanaryConfig::load_from_file(Path::new(cfg_path)).ok()
            } else {
                PqCanaryConfig::discover(target_path).map(|(c, _)| c)
            };

            let effective_severity = severity
                .or_else(|| file_config.as_ref().and_then(|c| c.severity.clone()))
                .unwrap_or_else(|| "LOW".to_string());

            let effective_format = format.to_lowercase();
            let effective_baseline = baseline
                .or_else(|| file_config.as_ref().and_then(|c| c.baseline.clone()));

            let effective_fail_on = fail_on
                .or_else(|| file_config.as_ref().and_then(|c| c.fail_on.clone()));

            eprintln!("Target: {}", path);
            eprintln!("Min Severity: {}", effective_severity);
            if let Some(ref b) = effective_baseline {
                eprintln!("Baseline: {}", b);
            }
            eprintln!();

            // 2. Scan Execution
            let target = path.trim();
            let is_remote_domain = pqcanary_core::api::is_likely_web_url_or_domain(target);
            let mut all_findings = if GitRepositoryFetcher::is_git_repository_url(target) {
                eprintln!("Cloning remote Git repository for AST analysis...");
                let fetcher = GitRepositoryFetcher::new();
                match fetcher.fetch_repository(target).await {
                    Ok(temp_dir) => {
                        let temp_str = temp_dir.to_string_lossy().to_string();
                        let orchestrator = MasterOrchestrator::new(&temp_str);
                        let mut findings = orchestrator.execute_full_scan();
                        for f in &mut findings {
                            if let Ok(rel) = std::path::Path::new(&f.file_path).strip_prefix(&temp_dir) {
                                f.file_path = rel.to_string_lossy().to_string();
                            }
                        }
                        GitRepositoryFetcher::cleanup_temp_dir(&temp_dir);
                        findings
                    }
                    Err(e) => {
                        eprintln!("FAIL: Git fetch error: {}", e);
                        vec![]
                    }
                }
            } else if is_remote_domain {
                eprintln!("Auditing remote web endpoint TLS & headers...");
                pqcanary_core::api::audit_remote_url(target).await
            } else {
                let safe_target = match pqcanary_core::api::validate_local_path(target) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Target path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                };
                let orchestrator = MasterOrchestrator::new(&safe_target);
                if progress {
                    let pb = Arc::new(ProgressBar::new_spinner());
                    pb.set_style(ProgressStyle::default_spinner()
                        .template("{spinner:.green} [{elapsed_precise}] {msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_spinner()));
                    pb.enable_steady_tick(std::time::Duration::from_millis(80));

                    let pb_clone = pb.clone();
                    let cb = move |curr: usize, total: usize, file: &str| {
                        pb_clone.set_message(format!("Scanning ({}/{}) {}", curr, total, file));
                    };
                    let findings = orchestrator.execute_full_scan_with_progress(Some(&cb));
                    pb.finish_with_message("Scan complete.");
                    findings
                } else {
                    orchestrator.execute_full_scan()
                }
            };

            // 2.5 Evaluate custom rules from configuration if present
            if let Some(ref cfg) = file_config {
                if !cfg.custom_rules.is_empty() && Path::new(target).is_dir() {
                    let walker = pqcanary_core::scanner::walker::MonorepoWalker::new(target);
                    let files = walker.collect_files();
                    for file_p in files {
                        if let Ok(content) = fs::read_to_string(&file_p) {
                            let path_str = file_p.to_string_lossy().to_string();
                            for rule in &cfg.custom_rules {
                                if let Ok(re) = regex::Regex::new(&rule.regex) {
                                    for (line_idx, line) in content.lines().enumerate() {
                                        if re.is_match(line) {
                                            let desc = rule.description.clone().unwrap_or_else(|| rule.name.clone());
                                            let sev = rule.severity.as_deref().unwrap_or("MEDIUM");
                                            let rem = rule.remediation.clone().unwrap_or_else(|| format!("Audit custom rule match: {}", rule.name));
                                            let cat = rule.category.clone().unwrap_or_else(|| "Custom Enterprise Policy".to_string());
                                            let fp = pqcanary_core::scanner::patterns::compute_finding_fingerprint(&path_str, &rule.id, &desc);
                                            all_findings.push(pqcanary_core::scanner::orchestrator::ComprehensiveFinding {
                                                file_path: path_str.clone(),
                                                vulnerability_class: cat,
                                                description: desc,
                                                severity: sev.to_string(),
                                                line_number: (line_idx + 1) as u32,
                                                remediation: rem,
                                                rule_id: Some(rule.id.clone()),
                                                quantum_risk: Some("UNKNOWN".to_string()),
                                                confidence: Some("HIGH".to_string()),
                                                snippet: Some(line.trim().to_string()),
                                                column_number: Some(1),
                                                fingerprint: Some(fp),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 3. Filter by severity and ignores (CLI flags + Config file)
            let min_rank = severity_rank(&effective_severity);
            let mut ignored_ids: Vec<String> = ignore.unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if let Some(ref cfg) = file_config {
                ignored_ids.extend(cfg.ignore.patterns.clone());
            }

            let mut ignored_cats: Vec<String> = ignore_category.unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            if let Some(ref cfg) = file_config {
                ignored_cats.extend(cfg.ignore.categories.iter().map(|c| c.to_lowercase()));
            }

            let ignored_files: Vec<String> = file_config.as_ref()
                .map(|c| c.ignore.files.clone())
                .unwrap_or_default();

            let filtered: Vec<_> = all_findings.into_iter()
                .filter(|f| severity_rank(&f.severity) >= min_rank)
                .filter(|f| {
                    if let Some(ref rid) = f.rule_id {
                        if ignored_ids.iter().any(|ig| rid.starts_with(ig.trim_end_matches('*'))) {
                            return false;
                        }
                    }
                    if ignored_cats.iter().any(|cat| f.vulnerability_class.to_lowercase().contains(cat)) {
                        return false;
                    }
                    if !ignored_files.is_empty() && ignored_files.iter().any(|pat| {
                        let clean = pat.trim_end_matches('*');
                        f.file_path.contains(clean)
                    }) {
                        return false;
                    }
                    true
                })
                .collect();

            // 4. Baseline Comparison
            let baseline_report = if let Some(ref base_path) = effective_baseline {
                let safe_base_path = match pqcanary_core::api::validate_local_path(base_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Baseline path rejected: {}", e.description);
                        process::exit(1);
                    }
                };
                match BaselineEngine::load_baseline(&safe_base_path) {
                    Ok(base_findings) => {
                        let rep = BaselineEngine::compare(&filtered, &base_findings);
                        eprintln!("{}", BaselineEngine::format_terminal_summary(&rep));
                        Some(rep)
                    }
                    Err(e) => {
                        eprintln!("WARN: Could not load baseline '{}': {}. Evaluating all findings.", safe_base_path, e);
                        None
                    }
                }
            } else {
                None
            };

            let output = if let Some(ref out_path) = output {
                match pqcanary_core::api::validate_local_path(out_path) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("FAIL: Output path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            // 5. Output Formatting
            match effective_format.as_str() {
                "sarif" => {
                    let sarif = SarifGenerator::generate_sarif(&filtered, Some(target));
                    let json = SarifGenerator::to_json(&sarif);
                    if let Some(ref out_path) = output {
                        if let Err(e) = fs::write(out_path, &json) {
                            eprintln!("FAIL: Error writing SARIF to '{}': {}", out_path, e);
                            process::exit(1);
                        }
                        eprintln!("SARIF 2.1.0 written to {}", out_path);
                    } else {
                        println!("{}", json);
                    }
                }
                "json" => {
                    let json = serde_json::to_string_pretty(&filtered).unwrap_or_else(|_| "[]".to_string());
                    if let Some(ref out_path) = output {
                        if let Err(e) = fs::write(out_path, &json) {
                            eprintln!("FAIL: Error writing JSON to '{}': {}", out_path, e);
                            process::exit(1);
                        }
                        eprintln!("JSON findings written to {}", out_path);
                    } else {
                        println!("{}", json);
                    }
                }
                "cbom" => {
                    let cbom = CbomGenerator::generate_cbom(&filtered, target);
                    let json = CbomGenerator::to_json(&cbom);
                    if let Some(ref out_path) = output {
                        if let Err(e) = fs::write(out_path, &json) {
                            eprintln!("FAIL: Error writing CBOM to '{}': {}", out_path, e);
                            process::exit(1);
                        }
                        eprintln!("CycloneDX 1.6 CBOM written to {}", out_path);
                    } else {
                        println!("{}", json);
                    }
                }
                "html" => {
                    let html = HtmlReporter::generate(&filtered, target);
                    if let Some(ref out_path) = output {
                        if let Err(e) = fs::write(out_path, &html) {
                            eprintln!("FAIL: Error writing HTML to '{}': {}", out_path, e);
                            process::exit(1);
                        }
                        eprintln!("Interactive HTML report written to {}", out_path);
                    } else {
                        println!("{}", html);
                    }
                }
                "markdown" | "md" => {
                    let md = MarkdownReporter::generate(&filtered, target);
                    if let Some(ref out_path) = output {
                        if let Err(e) = fs::write(out_path, &md) {
                            eprintln!("FAIL: Error writing Markdown to '{}': {}", out_path, e);
                            process::exit(1);
                        }
                        eprintln!("Note: Markdown report written to {}", out_path);
                    } else {
                        println!("{}", md);
                    }
                }
                "csv" => {
                    let csv = CsvReporter::generate(&filtered);
                    if let Some(ref out_path) = output {
                        if let Err(e) = fs::write(out_path, &csv) {
                            eprintln!("FAIL: Error writing CSV to '{}': {}", out_path, e);
                            process::exit(1);
                        }
                        eprintln!("CSV export written to {}", out_path);
                    } else {
                        println!("{}", csv);
                    }
                }
                _ => {
                    // Terminal Text Mode
                    if filtered.is_empty() {
                        println!("OK: No findings above severity {} detected.", effective_severity);
                    } else {
                        println!("WARN: {} finding(s) detected:\n", filtered.len());
                        for (i, finding) in filtered.iter().enumerate() {
                            let rule_str = finding.rule_id.as_deref().unwrap_or("PQC-FINDING");
                            println!("{:>3}. {} ({}) {}",
                                i + 1,
                                severity_icon(&finding.severity),
                                rule_str,
                                finding.vulnerability_class
                            );
                            println!("      File: {}:{}", finding.file_path, finding.line_number);
                            println!("      Note: {}", finding.description);
                            if let Some(ref snip) = finding.snippet {
                                println!("      Context:\n{}", snip);
                            }
                            println!("      INFO: Remediation: {}", finding.remediation);
                            println!();
                        }

                        let qramm = pqcanary_core::scanner::qramm::QrammEngine::calculate_score(&filtered);
                        println!("──────────────────────────────────────────────────────────────────────");
                        println!("QRAMM Post-Quantum Migration Readiness: {:.1}% ({})", qramm.readiness_score, qramm.posture_level);
                        println!("    Safe: {} | Hybrid: {} | Partial: {} | Vulnerable: {} | Critical: {}",
                            qramm.safe_count, qramm.hybrid_count, qramm.partial_count, qramm.vulnerable_count, qramm.critical_count);
                        println!("──────────────────────────────────────────────────────────────────────\n");
                    }

                    if let Some(ref out_path) = output {
                        let json = serde_json::to_string_pretty(&filtered).unwrap_or_else(|_| "[]".to_string());
                        if let Err(e) = fs::write(out_path, &json) {
                            eprintln!("FAIL: Error writing file to '{}': {}", out_path, e);
                            process::exit(1);
                        }
                        eprintln!("Findings written to {}", out_path);
                    }
                }
            }

            // Sync findings to PQMesh if requested
            if sync {
                let client = reqwest::Client::new();
                let payload = serde_json::json!({
                    "node_id": "node-cli-terminal",
                    "medium": "cli",
                    "findings": filtered,
                });
                let sync_urls = ["http://localhost:8080/mesh/sync", "http://localhost:3000/mesh/sync"];
                let mut synced = false;
                for url in sync_urls {
                    if let Ok(res) = client.post(url).json(&payload).send().await {
                        if res.status().is_success() {
                            eprintln!("Synced {} finding(s) with active PQMesh node at {}", filtered.len(), url);
                            synced = true;
                            break;
                        }
                    }
                }
                if !synced {
                    pqcanary_core::scanner::mesh::FleetMeshBus::ingest_findings(
                        "node-cli-terminal",
                        pqcanary_core::scanner::mesh::OperationalMedium::Cli,
                        filtered.clone(),
                    ).await;
                    eprintln!("Synced {} finding(s) into local PQMesh in-process bus.", filtered.len());
                }
            }

            // 6. CI Exit Code Determination
            let fail_condition = effective_fail_on.as_deref().unwrap_or("").trim().to_lowercase();
            if fail_on_new || fail_condition == "new" {
                if let Some(ref rep) = baseline_report {
                    if rep.new_count > 0 {
                        eprintln!("ALERT: CI GATE FAILED: {} new regression finding(s) introduced.", rep.new_count);
                        process::exit(1);
                    }
                }
            }

            match fail_condition.as_str() {
                "none" => {}
                "critical" => {
                    if filtered.iter().any(|f| f.severity == "CRITICAL") {
                        eprintln!("ALERT: CI GATE FAILED: CRITICAL finding(s) detected.");
                        process::exit(1);
                    }
                }
                "high" => {
                    if filtered.iter().any(|f| severity_rank(&f.severity) >= severity_rank("HIGH")) {
                        eprintln!("ALERT: CI GATE FAILED: HIGH or CRITICAL finding(s) detected.");
                        process::exit(1);
                    }
                }
                "medium" => {
                    if filtered.iter().any(|f| severity_rank(&f.severity) >= severity_rank("MEDIUM")) {
                        eprintln!("ALERT: CI GATE FAILED: MEDIUM, HIGH, or CRITICAL finding(s) detected.");
                        process::exit(1);
                    }
                }
                "low" => {
                    if filtered.iter().any(|f| severity_rank(&f.severity) >= severity_rank("LOW")) {
                        eprintln!("ALERT: CI GATE FAILED: finding(s) with severity >= LOW detected.");
                        process::exit(1);
                    }
                }
                "findings" | "info" => {
                    if !filtered.is_empty() {
                        eprintln!("ALERT: CI GATE FAILED: findings detected with --fail-on {}.", fail_condition);
                        process::exit(1);
                    }
                }
                _ => {
                    if fail_on_findings && !filtered.is_empty() {
                        eprintln!("ALERT: CI GATE FAILED: findings detected with --fail-on-findings.");
                        process::exit(1);
                    }
                }
            }
        }

        Commands::Sarif { path, output } => {
            print_banner();
            let target = path.trim();
            let findings = if GitRepositoryFetcher::is_git_repository_url(target) {
                eprintln!("Cloning remote Git repository for SARIF analysis...");
                let fetcher = GitRepositoryFetcher::new();
                match fetcher.fetch_repository(target).await {
                    Ok(temp_dir) => {
                        let temp_str = temp_dir.to_string_lossy().to_string();
                        let mut f = MasterOrchestrator::new(&temp_str).execute_full_scan();
                        for item in &mut f {
                            if let Ok(rel) = std::path::Path::new(&item.file_path).strip_prefix(&temp_dir) {
                                item.file_path = rel.to_string_lossy().to_string();
                            }
                        }
                        GitRepositoryFetcher::cleanup_temp_dir(&temp_dir);
                        f
                    }
                    Err(e) => {
                        eprintln!("FAIL: Git fetch error: {}", e);
                        vec![]
                    }
                }
            } else if target.starts_with("http://") || target.starts_with("https://") {
                eprintln!("Auditing remote web endpoint TLS & headers...");
                pqcanary_core::api::audit_remote_url(target).await
            } else {
                let safe_path = match pqcanary_core::api::validate_local_path(target) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Target path rejected: {}", e.description);
                        process::exit(1);
                    }
                };
                MasterOrchestrator::new(&safe_path).execute_full_scan()
            };
            let sarif = SarifGenerator::generate_sarif(&findings, Some(target));
            let json = SarifGenerator::to_json(&sarif);

            let output = if let Some(ref out_path) = output {
                match pqcanary_core::api::validate_local_path(out_path) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("FAIL: Output path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            if let Some(out_path) = output {
                if let Err(e) = fs::write(&out_path, &json) {
                    eprintln!("FAIL: Error writing SARIF to '{}': {}", out_path, e);
                    process::exit(1);
                }
                eprintln!("SARIF 2.1.0 written to: {}", out_path);
            } else {
                println!("{}", json);
            }
        }

        Commands::Patch { file_path, dry_run } => {
            print_banner();
            let safe_file = match pqcanary_core::api::validate_local_path(&file_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: File path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            let source = fs::read_to_string(&safe_file)
                .unwrap_or_else(|e| { eprintln!("Error reading file: {}", e); process::exit(2); });

            let patcher = SemanticPatcher::new();
            let result = patcher.patch_file(&safe_file, &source);

            if !result.is_changed() {
                println!("OK: No vulnerable patterns found in {}. Already compliant.", file_path);
                return;
            }

            println!("Vulnerabilities detected and fixed:");
            for rule in &result.rules_applied {
                println!("  ▶ {}", rule);
            }
            println!();
            println!("{}", result.unified_diff);

            if !dry_run {
                fs::write(&safe_file, &result.patched_source)
                    .unwrap_or_else(|e| { eprintln!("Error writing file: {}", e); process::exit(2); });
                println!("OK: File patched: {}", safe_file);
            } else {
                println!("(Dry run — file not modified. Remove --dry-run to apply patch.)");
            }
        }

        Commands::Classify { algorithm } => {
            print_banner();
            let prover = HottProver::new();
            let classification = prover.classify_algorithm(&algorithm);
            println!("{}", classification.severity_message());
        }

        Commands::Prove { algorithm, output } => {
            print_banner();
            eprintln!("Generating Lean 4 formal proof for: {}", algorithm);
            let prover = HottProver::new();
            let proof = prover.export_lean_proof(&algorithm);
            let classification = prover.classify_algorithm(&algorithm);
            eprintln!("Classification: {}", classification.severity_message());
            eprintln!();

            if let Some(out_path) = output {
                let safe_out = match pqcanary_core::api::validate_local_path(&out_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Output path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                };
                fs::write(&safe_out, &proof)
                    .unwrap_or_else(|e| { eprintln!("Error writing proof: {}", e); process::exit(2); });
                eprintln!("OK: Lean 4 proof written to: {}", safe_out);
            } else {
                println!("{}", proof);
            }
        }

        Commands::Thermo { gates, erased } => {
            print_banner();
            let analyzer = ThermodynamicsAnalyzer::at_room_temperature();
            let report = analyzer.simulate_landauer_limit(gates, erased);

            println!("Thermodynamic Security Profile (Landauer's Limit)");
            println!("═══════════════════════════════════════════════════════════");
            println!("Temperature:             {:>10.1} K ({:.1} °C)", 
                report.temperature_kelvin, report.temperature_kelvin - 273.15);
            println!("Landauer limit / bit:    {:>10.3e} J/bit", report.landauer_limit_joules);
            println!("Total gates:             {:>10}", gates);
            println!("Irreversible ops:        {:>10} ({:.1}%)", erased, report.irreversible_fraction * 100.0);
            println!("Total heat dissipation:  {:>10.3e} J  ({:.4} fJ)", 
                report.total_dissipation_joules, report.total_dissipation_femtojoules);
            println!();
            if report.thermal_side_channel_risk {
                println!("CRITICAL: THERMAL SCA RISK: Heat exceeds 1 fJ threshold.");
            } else {
                println!("OK: No thermal side-channel risk: dissipation below 1 fJ threshold.");
            }
        }

        Commands::Sandbox => {
            print_banner();
            eprintln!("Running formal WebAssembly linear memory sandbox...");
            let orchestrator = MasterOrchestrator::new(".");
            println!("{}", orchestrator.run_memory_sandbox_test());
        }

        Commands::Cbom { path, format, output } => {
            print_banner();
            let target = path.trim();
            let is_remote_url = target.starts_with("http://") || target.starts_with("https://")
                || (!std::path::Path::new(target).exists() && target.contains('.') && !target.contains('/') && !target.contains('\\'));
            let safe_path = if GitRepositoryFetcher::is_git_repository_url(target) || is_remote_url {
                target.to_string()
            } else {
                match pqcanary_core::api::validate_local_path(target) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Target path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                }
            };
            eprintln!("Generating CycloneDX 1.6 CBOM for: {}", safe_path);
            let findings = if GitRepositoryFetcher::is_git_repository_url(&safe_path) {
                let fetcher = GitRepositoryFetcher::new();
                match fetcher.fetch_repository(&safe_path).await {
                    Ok(temp_dir) => {
                        let temp_str = temp_dir.to_string_lossy().to_string();
                        let f = MasterOrchestrator::new(&temp_str).execute_full_scan();
                        GitRepositoryFetcher::cleanup_temp_dir(&temp_dir);
                        f
                    }
                    Err(e) => {
                        eprintln!("FAIL: Git fetch error: {}", e);
                        vec![]
                    }
                }
            } else if is_remote_url {
                pqcanary_core::api::audit_remote_url(&safe_path).await
            } else {
                MasterOrchestrator::new(&safe_path).execute_full_scan()
            };
            let cbom_doc = CbomGenerator::generate_cbom(&findings, &safe_path);
            let cbom_output = if format.to_lowercase() == "markdown" || format.to_lowercase() == "md" {
                CbomGenerator::to_markdown_table(&cbom_doc)
            } else {
                CbomGenerator::to_json(&cbom_doc)
            };

            if let Some(out_file) = output {
                let safe_out = match pqcanary_core::api::validate_local_path(&out_file) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Output path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                };
                fs::write(&safe_out, &cbom_output)
                    .unwrap_or_else(|e| { eprintln!("Error: {}", e); process::exit(2); });
                eprintln!("OK: CBOM saved to: {}", safe_out);
            } else {
                println!("{}", cbom_output);
            }
        }

        Commands::Diff { base, target, fail_on_downgrade, format, output } => {
            print_banner();
            let safe_base = match pqcanary_core::api::validate_local_path(&base) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Base path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            let safe_target = match pqcanary_core::api::validate_local_path(&target) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Target path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            eprintln!("Cryptographic Differential Analysis");
            eprintln!("   Base:   {}", safe_base);
            eprintln!("   Target: {}", safe_target);
            eprintln!();

            // Check if both files are CycloneDX 1.6 CBOM files
            if Path::new(&safe_base).is_file() && Path::new(&safe_target).is_file() {
                if let (Ok(base_str), Ok(target_str)) = (fs::read_to_string(&safe_base), fs::read_to_string(&safe_target)) {
                    if base_str.contains("\"bomFormat\"") && target_str.contains("\"bomFormat\"") {
                        match CbomDiffEngine::diff_json_strings(&base_str, &target_str) {
                            Ok(cbom_report) => {
                                let out_str = match format.to_lowercase().as_str() {
                                    "json" => serde_json::to_string_pretty(&cbom_report).unwrap_or_default(),
                                    _ => CbomDiffEngine::format_markdown(&cbom_report),
                                };
                                if let Some(out_path) = output {
                                    fs::write(&out_path, &out_str).ok();
                                    println!("CBOM semantic drift report saved to '{}'.", out_path);
                                } else {
                                    println!("{}", out_str);
                                }
                                if (fail_on_downgrade || cbom_report.status == "REGRESSION_CRITICAL") && cbom_report.downgraded_count > 0 {
                                    eprintln!("FAIL: Quality gate tripped: {} quantum downgrade regression(s) detected.", cbom_report.downgraded_count);
                                    process::exit(1);
                                }
                                return;
                            }
                            Err(e) => eprintln!("WARN: Failed to parse as CBOM, falling back to AST diff: {}", e),
                        }
                    }
                }
            }

            // 1. Load or scan base findings
            let base_findings = if Path::new(&safe_base).is_file() {
                BaselineEngine::load_baseline(&safe_base)
                    .unwrap_or_else(|_| MasterOrchestrator::new(&safe_base).execute_full_scan())
            } else {
                MasterOrchestrator::new(&safe_base).execute_full_scan()
            };

            // 2. Load or scan target findings
            let target_findings = if Path::new(&safe_target).is_file() {
                BaselineEngine::load_baseline(&safe_target)
                    .unwrap_or_else(|_| MasterOrchestrator::new(&safe_target).execute_full_scan())
            } else {
                MasterOrchestrator::new(&safe_target).execute_full_scan()
            };

            // 3. Compute baseline comparison
            let report = BaselineEngine::compare(&target_findings, &base_findings);

            let out_str = match format.to_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&report).unwrap_or_default(),
                "markdown" | "md" => {
                    let mut md = String::new();
                    md.push_str("# Cryptographic Differential Security Report\n\n");
                    md.push_str(&format!("- **Base Snapshot (A)**: `{}` ({} findings)\n", safe_base, report.total_baseline));
                    md.push_str(&format!("- **Target Snapshot (B)**: `{}` ({} findings)\n\n", safe_target, report.total_current));
                    md.push_str("| Metric | Count | Status |\n");
                    md.push_str("|---|---|---|\n");
                    md.push_str(&format!("| CRITICAL: New Regressions Introduced | **{}** | {} |\n",
                        report.new_count, if report.new_count > 0 { "FAIL (Gate Blocked)" } else { "PASS" }));
                    md.push_str(&format!("| SAFE: Existing Vulnerabilities Resolved | **{}** | Remediated |\n", report.resolved_count));
                    md.push_str(&format!("| INFO: Unchanged Existing Vulnerabilities | **{}** | Tech-Debt |\n\n", report.existing_count));
                    if !report.new_findings.is_empty() {
                        md.push_str("### CRITICAL: Newly Introduced Regressions\n\n");
                        md.push_str("| Severity | Rule ID | File | Line | Description |\n");
                        md.push_str("|---|---|---|---|---|\n");
                        for f in &report.new_findings {
                            md.push_str(&format!("| {} | `{}` | `{}` | {} | {} |\n",
                                f.severity, f.rule_id.as_deref().unwrap_or("-"), f.file_path, f.line_number, f.description));
                        }
                        md.push('\n');
                    }
                    if !report.resolved_findings.is_empty() {
                        md.push_str("### SAFE: Successfully Resolved Vulnerabilities\n\n");
                        md.push_str("| Severity | Rule ID | File | Line | Description |\n");
                        md.push_str("|---|---|---|---|---|\n");
                        for f in &report.resolved_findings {
                            md.push_str(&format!("| {} | `{}` | `{}` | {} | {} |\n",
                                f.severity, f.rule_id.as_deref().unwrap_or("-"), f.file_path, f.line_number, f.description));
                        }
                    }
                    md
                }
                _ => {
                    let mut text = String::new();
                    text.push_str("╔══════════════════════════════════════════════════════════════════════╗\n");
                    text.push_str("║             PQCanary Cryptographic Differential Analysis             ║\n");
                    text.push_str("╚══════════════════════════════════════════════════════════════════════╝\n\n");
                    text.push_str(&format!("  Base (A):     {} ({} findings)\n", safe_base, report.total_baseline));
                    text.push_str(&format!("  Target (B):   {} ({} findings)\n\n", safe_target, report.total_current));
                    text.push_str(&format!("  CRITICAL: New Regressions:          {}\n", report.new_count));
                    text.push_str(&format!("  SAFE: Resolved Vulnerabilities:   {}\n", report.resolved_count));
                    text.push_str(&format!("  INFO: Existing Unchanged:        {}\n", report.existing_count));
                    text.push_str("  ----------------------------------------------------------------------\n");
                    if report.new_count > 0 {
                        text.push_str("  FAIL: POSTURE DEGRADED: New cryptographic vulnerabilities introduced!\n\n");
                        for f in &report.new_findings {
                            text.push_str(&format!("    CRITICAL: [{}] {}:{} — {}\n", f.severity, f.file_path, f.line_number, f.description));
                        }
                    } else if report.resolved_count > 0 {
                        text.push_str("  OK: POSTURE IMPROVED: Cryptographic debt remediated with zero regressions!\n");
                    } else {
                        text.push_str("  POSTURE NEUTRAL: No change in cryptographic vulnerability state.\n");
                    }
                    text.push_str("══════════════════════════════════════════════════════════════════════\n");
                    text
                }
            };

            if let Some(ref file) = output {
                let safe_out = match pqcanary_core::api::validate_local_path(file) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Output path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                };
                if let Err(e) = fs::write(&safe_out, &out_str) {
                    eprintln!("FAIL: Failed to write diff report to '{}': {}", safe_out, e);
                    process::exit(1);
                }
                eprintln!("OK: Differential analysis saved to: {}", safe_out);
            } else {
                println!("{}", out_str);
            }

            if report.new_count > 0 {
                process::exit(1);
            }
        }

        Commands::Qpu { action } => {
            print_banner();
            let engine = QpuOffloadEngine::new(None);
            match action {
                QpuAction::Generate { qubits, target } => {
                    println!("{}", QpuOffloadEngine::generate_grover_oracle_qasm(qubits, &target));
                }
                QpuAction::Simulate { qubits, target, shots } => {
                    let report = engine.simulate_statevector(qubits, &target, shots);
                    println!("Quantum Statevector Simulation Report");
                    println!("═══════════════════════════════════════════════════════════");
                    println!("Qubits:               {}", report.num_qubits);
                    println!("Statevector Dim:      {} complex amplitudes", report.statevector_dimension);
                    println!("Target Bitstring:     |{}⟩", report.dominant_state);
                    println!("Execution Target:     {}", report.execution_target);
                    println!("\nMeasurement Histogram (Shots = {}):", shots);
                    let mut sorted: Vec<_> = report.measurement_counts.into_iter().collect();
                    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
                    for (state, count) in sorted {
                        let bar = "█".repeat((count * 40 / shots as u64) as usize);
                        println!("  |{}⟩: {:>5} (p={:.4}) {}", state, count, report.probabilities.get(&state).unwrap_or(&0.0), bar);
                    }
                }
            }
        }

        Commands::Worker { redis_url, worker_id } => {
            print_banner();
            let id = worker_id.unwrap_or_else(|| format!("worker-{}", std::process::id()));
            eprintln!("Starting PQCanary Distributed Worker [{}]...", id);
            eprintln!("   Connected to Redis broker: {}", redis_url);

            use pqcanary_core::scanner::distributed_queue::{DistributedClusterWorker, WorkerStatus};
            let worker = match DistributedClusterWorker::new(&id, Some(&redis_url)) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("FAIL: Failed to create cluster worker: {}", e);
                    process::exit(1);
                }
            };

            worker.send_heartbeat(WorkerStatus::Idle, None).await.ok();
            eprintln!("OK: Node registered in cluster registry. Awaiting scan jobs...");

            loop {
                match worker.claim_job(5.0).await {
                    Ok(Some(job)) => {
                        eprintln!("Claimed job {} for repository: {}", job.job_id, job.repository_url);
                        match worker.execute_job(&job).await {
                            Ok(res) => eprintln!("OK: Completed job {}: {} findings ({} critical, {} high).",
                                res.job_id, res.total_findings, res.critical_count, res.high_count),
                            Err(e) => eprintln!("FAIL: Job {} execution failed: {}", job.job_id, e),
                        }
                    }
                    Ok(None) => {
                        // Send heartbeat on idle poll
                        worker.send_heartbeat(WorkerStatus::Idle, None).await.ok();
                    }
                    Err(e) => {
                        eprintln!("WARN: Broker poll error: {}. Retrying...", e);
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    }
                }
            }
        }

        Commands::Serve { port } => {
            print_banner();
            eprintln!("Starting PQCanary REST API & Web UI on port {}...", port);
            if let Err(e) = pqcanary_core::api::ApiDaemon::start_server_on_port(port).await {
                eprintln!("Server error: {}", e);
                process::exit(2);
            }
        }

        Commands::Probe { target, format } => {
            print_banner();
            if let Err(e) = pqcanary_core::api::validate_network_target(&target) {
                eprintln!("FAIL: Network probe rejected: {}", e);
                process::exit(1);
            }
            let (host, port) = NetworkTlsProbe::parse_target(&target);
            eprintln!("Initiating live TLS 1.3 Post-Quantum probe to {}:{}...", host, port);

            match NetworkTlsProbe::probe_endpoint(&host, port).await {
                Ok(res) => {
                    if format.to_lowercase() == "json" {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "host": res.host,
                            "port": res.port,
                            "tls_version": res.tls_version,
                            "cipher_suite": res.cipher_suite,
                            "selected_group": res.selected_group,
                            "is_post_quantum_safe": res.is_post_quantum_safe,
                            "is_hybrid": res.is_hybrid,
                            "rtt_ms": res.rtt_ms,
                        })).unwrap_or_default());
                    } else {
                        println!("\n╔══════════════════════════════════════════════════════════════════════╗");
                        println!("║             PQCanary TLS 1.3 Post-Quantum Handshake Probe            ║");
                        println!("╚══════════════════════════════════════════════════════════════════════╝");
                        println!("  Target:          {}:{}", res.host, res.port);
                        println!("  TLS Version:     {}", res.tls_version);
                        println!("  Cipher Suite:    {}", res.cipher_suite);
                        println!("  Key Share Group: {}", if res.selected_group.is_empty() { "None (Classical Key Exchange)" } else { &res.selected_group });
                        println!("  Handshake RTT:   {} ms", res.rtt_ms);
                        println!("  ----------------------------------------------------------------------");
                        if res.is_post_quantum_safe {
                            println!("  Status:          SAFE: QUANTUM-SAFE (FIPS 203 ML-KEM-768 Hybrid)");
                            println!("  Verdict:         Endpoint is immune to Store-Now-Decrypt-Later harvesting.");
                        } else if res.is_hybrid {
                            println!("  Status:          DRAFT: DRAFT QUANTUM-SAFE (X25519Kyber768 Draft)");
                            println!("  Verdict:         Endpoint supports draft PQC. Plan update to standardized FIPS 203.");
                        } else {
                            println!("  Status:          CRITICAL: QUANTUM-VULNERABLE (Classical Key Exchange)");
                            println!("  Verdict:         Traffic can be harvested today and decrypted by future quantum computers.");
                            println!("  Remediation:     Configure server / CDN to enable X25519MLKEM768 (0x11ec).");
                        }
                        println!("══════════════════════════════════════════════════════════════════════\n");
                    }
                }
                Err(err) => {
                    eprintln!("FAIL: Probe failed: {}", err);
                    process::exit(1);
                }
            }
        }

        Commands::ProbeSsh { target, format } => {
            print_banner();
            if let Err(e) = pqcanary_core::api::validate_network_target(&target) {
                eprintln!("FAIL: Network probe rejected: {}", e);
                process::exit(1);
            }
            let (host, port) = NetworkSshProbe::parse_target(&target);
            eprintln!("Initiating live SSH 2.0 Post-Quantum probe to {}:{}...", host, port);

            match NetworkSshProbe::probe_endpoint(&host, port).await {
                Ok(res) => {
                    if format.to_lowercase() == "json" {
                        println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
                    } else {
                        println!("\n╔══════════════════════════════════════════════════════════════════════╗");
                        println!("║             PQCanary SSH 2.0 Post-Quantum Handshake Probe            ║");
                        println!("╚══════════════════════════════════════════════════════════════════════╝");
                        println!("  Target:          {}:{}", res.host, res.port);
                        println!("  Server Banner:   {}", res.server_banner);
                        println!("  Handshake RTT:   {} ms", res.rtt_ms);
                        println!("  Offered KEX:     {}", res.kex_algorithms.iter().take(5).cloned().collect::<Vec<_>>().join(", "));
                        println!("  Host Keys:       {}", res.host_key_algorithms.iter().take(4).cloned().collect::<Vec<_>>().join(", "));
                        println!("  ----------------------------------------------------------------------");
                        if res.is_post_quantum_safe {
                            println!("  Status:          SAFE: QUANTUM-SAFE (Post-Quantum Hybrid KEX Active)");
                            println!("  PQC KEX:         {}", res.pqc_kex_supported.join(", "));
                            println!("  Verdict:         SSH server is immune to Store-Now-Decrypt-Later harvesting.");
                        } else {
                            println!("  Status:          CRITICAL: QUANTUM-VULNERABLE (Classical KEX Only)");
                            println!("  Verdict:         SSH sessions can be recorded today and decrypted by future CRQCs.");
                            println!("  Remediation:     Enable OpenSSH sntrup761x25519-sha512@openssh.com or ML-KEM in sshd_config.");
                        }
                        if !res.weak_kex_detected.is_empty() {
                            println!("  WARN: Weak KEX:     {}", res.weak_kex_detected.join(", "));
                        }
                        println!("══════════════════════════════════════════════════════════════════════\n");
                    }
                }
                Err(err) => {
                    eprintln!("FAIL: SSH probe failed: {}", err);
                    process::exit(1);
                }
            }
        }

        Commands::Qramm { path, format } => {
            print_banner();
            let target = path.trim();
            eprintln!("Evaluating QRAMM Post-Quantum Migration Framework for '{}'...\n", target);

            let is_remote_domain = pqcanary_core::api::is_likely_web_url_or_domain(target);
            let findings = if GitRepositoryFetcher::is_git_repository_url(target) {
                let fetcher = GitRepositoryFetcher::new();
                match fetcher.fetch_repository(target).await {
                    Ok(temp_dir) => {
                        let temp_str = temp_dir.to_string_lossy().to_string();
                        let f = MasterOrchestrator::new(&temp_str).execute_full_scan();
                        GitRepositoryFetcher::cleanup_temp_dir(&temp_dir);
                        f
                    }
                    Err(e) => {
                        eprintln!("FAIL: Git fetch error: {}", e);
                        vec![]
                    }
                }
            } else if is_remote_domain {
                pqcanary_core::api::audit_remote_url(target).await
            } else {
                let safe_target = match pqcanary_core::api::validate_local_path(target) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("FAIL: Target path rejected (Path Traversal defense): {}", e.description);
                        process::exit(1);
                    }
                };
                MasterOrchestrator::new(&safe_target).execute_full_scan()
            };

            let score = pqcanary_core::scanner::qramm::QrammEngine::calculate_score(&findings);
            if format.to_lowercase() == "json" {
                println!("{}", serde_json::to_string_pretty(&score).unwrap_or_default());
            } else {
                println!("{}", pqcanary_core::scanner::qramm::QrammEngine::to_markdown_summary(&score));
            }
        }

        Commands::AuditHost { format } => {
            let report = pqcanary_core::scanner::os_crypto::OsCryptoAuditor::audit_host();
            if format.to_lowercase() == "json" {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("{}", pqcanary_core::scanner::os_crypto::OsCryptoAuditor::format_markdown(&report));
            }
        }

        Commands::Rules { category, severity, quantum_risk, format } => {
            let all_rules = pqcanary_core::scanner::patterns::get_all_pattern_definitions();
            let filtered: Vec<_> = all_rules.into_iter().filter(|d| {
                if let Some(ref cat) = category {
                    if !d.category.to_lowercase().contains(&cat.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(ref sev) = severity {
                    if !d.severity.eq_ignore_ascii_case(sev) {
                        return false;
                    }
                }
                if let Some(ref qr) = quantum_risk {
                    if !d.quantum_risk.as_str().eq_ignore_ascii_case(qr) {
                        return false;
                    }
                }
                true
            }).collect();

            match format.to_lowercase().as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&filtered).unwrap_or_default());
                }
                "markdown" | "md" => {
                    println!("# PQCanary Cryptographic Rule Catalog\n");
                    println!("Total rules matched: **{}**\n", filtered.len());
                    println!("| Rule ID | Category | Severity | Quantum Risk | Name |");
                    println!("|---------|----------|----------|--------------|------|");
                    for r in &filtered {
                        println!("| `{}` | {} | {} | {} | {} |", r.id, r.category, r.severity, r.quantum_risk.as_str(), r.name);
                    }
                }
                _ => {
                    print_banner();
                    eprintln!("Cryptographic Detection Rule Catalog ({} rules matched):\n", filtered.len());
                    for (i, r) in filtered.iter().enumerate() {
                        let icon = severity_icon(r.severity);
                        println!("{:3}. {} [{}] {} ({})", i + 1, icon, r.id, r.name, r.category);
                        println!("     Risk: {} | Severity: {}", r.quantum_risk.as_str(), r.severity);
                        println!("     Description: {}", r.description);
                        println!("     Remediation: {}", r.remediation);
                        println!();
                    }
                }
            }
        }

        Commands::Binary { file_path, format } => {
            let data = match std::fs::read(&file_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("FAIL: Failed to read binary file '{}': {}", file_path, e);
                    process::exit(1);
                }
            };
            let file_name = Path::new(&file_path).file_name().and_then(|s| s.to_str()).unwrap_or("binary");
            let report = pqcanary_core::scanner::binary_scanner::BinaryScanner::scan_buffer(file_name, &data);

            match format.to_lowercase().as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
                "markdown" | "md" => {
                    println!("# PQCanary Native Binary Disassembly Audit: {}\n", report.file_name);
                    println!("- **Format**: {} ({}, {})", report.format, report.architecture, if report.is_64bit { "64-bit" } else { "32-bit" });
                    println!("- **File Size**: {} bytes", report.file_size_bytes);
                    println!("- **Quantum Risk**: **{}**", report.quantum_risk);
                    println!("- **Readiness Score**: **{}/100**\n", report.quantum_readiness_score);

                    println!("## Imported Cryptographic Libraries (IAT)");
                    if report.imported_crypto_libraries.is_empty() {
                        println!("_No explicit cryptographic library imports found._\n");
                    } else {
                        println!("| Library | Risk | Functions | Description |");
                        println!("|---------|------|-----------|-------------|");
                        for lib in &report.imported_crypto_libraries {
                            println!("| `{}` | {} | {} | {} |", lib.name, lib.quantum_risk, lib.imported_functions.join(", "), lib.description);
                        }
                        println!();
                    }

                    println!("## Embedded Cryptographic Constant Tables");
                    if report.detected_crypto_constants.is_empty() {
                        println!("_No known static cryptographic constant arrays detected._\n");
                    } else {
                        println!("| Algorithm | Type | Offset | Severity | Description |");
                        println!("|-----------|------|--------|----------|-------------|");
                        for c in &report.detected_crypto_constants {
                            println!("| `{}` | {} | `{}` | {} | {} |", c.algorithm, c.constant_type, c.offset_hex, c.severity, c.description);
                        }
                        println!();
                    }
                }
                _ => {
                    print_banner();
                    eprintln!("Compiled Binary Disassembly & IAT Inspector: {}\n", report.file_name);
                    println!("  Format:          {} (Arch: {}, {})", report.format, report.architecture, if report.is_64bit { "64-bit" } else { "32-bit" });
                    println!("  Size:            {} bytes", report.file_size_bytes);
                    println!("  Quantum Risk:    {}", report.quantum_risk);
                    println!("  Readiness Score: {} / 100", report.quantum_readiness_score);
                    println!("  Summary:         {}", report.summary);
                    println!();

                    if !report.imported_crypto_libraries.is_empty() {
                        println!("  Imported Cryptographic Libraries:");
                        for lib in &report.imported_crypto_libraries {
                            let risk_icon = if lib.quantum_risk == "SAFE" { "SAFE:" } else if lib.quantum_risk == "HYBRID" { "MEDIUM:" } else { "CRITICAL:" };
                            println!("    {} {} [{}]", risk_icon, lib.name, lib.quantum_risk);
                            println!("       Description: {}", lib.description);
                            if !lib.imported_functions.is_empty() {
                                println!("       Functions:   {}", lib.imported_functions.join(", "));
                            }
                        }
                        println!();
                    }

                    if !report.detected_crypto_constants.is_empty() {
                        println!("  Embedded Cryptographic Constants:");
                        for c in &report.detected_crypto_constants {
                            let icon = severity_icon(&c.severity);
                            println!("    {} {} ({}) at offset {}", icon, c.algorithm, c.constant_type, c.offset_hex);
                            println!("       {}", c.description);
                        }
                        println!();
                    }
                }
            }
        }

        Commands::Runtime { format } => {
            let report = pqcanary_core::scanner::runtime_tracer::RuntimeProcessAuditor::audit_system_processes();

            match format.to_lowercase().as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
                "markdown" | "md" => {
                    println!("# PQCanary Runtime Process Cryptography Audit\n");
                    println!("- **Inspected Processes**: {}", report.total_processes_inspected);
                    println!("- **Active Crypto Handles**: {}", report.crypto_active_processes_count);
                    println!("- **Quantum Vulnerable**: {}", report.quantum_vulnerable_processes_count);
                    println!("- **System Posture**: **{}**\n", report.system_runtime_posture);

                    println!("| PID | Process Name | Posture | Risk Score | Memory (RSS) | Loaded Crypto Modules | Recommendation |");
                    println!("|-----|--------------|---------|------------|--------------|-----------------------|----------------|");
                    for p in &report.processes {
                        println!("| {} | `{}` | {} | {}/100 | {:.1} MB | {} | {} |",
                            p.pid, p.name, p.runtime_posture, p.risk_score, p.memory_rss_mb, p.loaded_crypto_modules.join(", "), p.recommendation
                        );
                    }
                }
                _ => {
                    print_banner();
                    eprintln!("Live OS Runtime Process Cryptography Inspector:\n");
                    println!("  Total Processes Inspected: {}", report.total_processes_inspected);
                    println!("  Crypto-Active Processes:   {}", report.crypto_active_processes_count);
                    println!("  Quantum-Vulnerable:        {}", report.quantum_vulnerable_processes_count);
                    println!("  System Runtime Posture:    {}", report.system_runtime_posture);
                    println!();

                    for p in &report.processes {
                        let icon = if p.runtime_posture == "QUANTUM_RESILIENT" { "SAFE:" } else if p.runtime_posture == "TRANSITIONING" { "MEDIUM:" } else { "CRITICAL:" };
                        println!("  {} [{}] {} (PID: {}) — RSS: {:.1} MB", icon, p.runtime_posture, p.name, p.pid, p.memory_rss_mb);
                        println!("     Path:           {}", p.executable_path);
                        println!("     Crypto Modules: {}", p.loaded_crypto_modules.join(", "));
                        println!("     Recommendation: {}", p.recommendation);
                        println!();
                    }
                }
            }
        }

        Commands::Hndl { migration, shelf_life, threat, format } => {
            let report = pqcanary_core::scanner::hndl_advisor::HndlAdvisor::evaluate_risk(
                Some(migration),
                Some(shelf_life),
                Some(threat),
            );

            match format.to_lowercase().as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
                "markdown" | "md" => {
                    println!("# Mosca's Theorem Harvest-Now-Decrypt-Later (HNDL) Risk Report\n");
                    println!("- **Migration Horizon (X)**: {:.1} years", report.migration_time_years_x);
                    println!("- **Data Retention / Shelf-Life (Y)**: {:.1} years", report.shelf_life_years_y);
                    println!("- **Threat / CRQC Horizon (Z)**: {:.1} years", report.quantum_threat_years_z);
                    println!("- **Mosca Inequality (X + Y > Z)**: **{}** ({:.1} > {:.1})",
                        if report.mosca_theorem_satisfied { "VIOLATED — DANGER" } else { "SATISFIED — SECURE" },
                        report.migration_time_years_x + report.shelf_life_years_y,
                        report.quantum_threat_years_z
                    );
                    println!("- **HNDL Criticality Index**: **{:.1}/10.0**", report.hndl_criticality_index);
                    println!("- **Overall Posture**: **{}**", report.overall_posture);
                    println!("- **Estimated Compromise Year**: **{}**\n", report.estimated_year_of_compromise);

                    println!("## Regulatory Timelines & Deadlines");
                    println!("| Standard | Authority | Deadline | Status | Mandatory Algorithm |");
                    println!("|----------|-----------|----------|--------|---------------------|");
                    for reg in &report.regulatory_timelines {
                        println!("| {} | {} | {} | {} | {} |", reg.standard_name, reg.authority, reg.deadline_year, reg.compliance_status, reg.mandatory_algorithm);
                    }
                    println!();

                    println!("## Enterprise Migration Playbooks");
                    for pb in &report.migration_playbooks {
                        println!("### {}\n", pb.target_technology);
                        println!("_{}_ (File: `{}`)\n", pb.description, pb.file_path_hint);
                        println!("```\n{}\n```\n", pb.configuration_content);
                    }
                }
                _ => {
                    print_banner();
                    eprintln!("Mosca's Theorem HNDL Risk Engine (Parity with IBM Quantum Safe):\n");
                    println!("  Migration Time (X):    {:.1} years", report.migration_time_years_x);
                    println!("  Data Retention (Y):    {:.1} years", report.shelf_life_years_y);
                    println!("  CRQC Threat (Z):       {:.1} years", report.quantum_threat_years_z);
                    println!("  X + Y ({:.1}) vs Z ({:.1}): {}",
                        report.migration_time_years_x + report.shelf_life_years_y,
                        report.quantum_threat_years_z,
                        if report.mosca_theorem_satisfied { "CRITICAL: DANGER: X + Y > Z (Harvest Now, Decrypt Later Exposure!)" } else { "SAFE: SECURE: Infrastructure will migrate before CRQC arrival." }
                    );
                    println!("  Criticality Index:     {:.1} / 10.0", report.hndl_criticality_index);
                    println!("  Overall Posture:       {}", report.overall_posture);
                    println!("  Est. Year Compromised: {}", report.estimated_year_of_compromise);
                    println!();

                    println!("  Regulatory Timelines:");
                    for reg in &report.regulatory_timelines {
                        println!("    • [{}] {} — Deadline: {} (Mandatory: {})", reg.authority, reg.standard_name, reg.deadline_year, reg.mandatory_algorithm);
                    }
                    println!();

                    println!("  Enterprise Migration Playbooks Available: {}", report.migration_playbooks.len());
                    for pb in &report.migration_playbooks {
                        println!("    • {} -> {}", pb.target_technology, pb.file_path_hint);
                    }
                    println!("    (Use '--format markdown' or '--format json' to view full config contents)\n");
                }
            }
        }

        Commands::Mesh { action, format } => {
            match action.unwrap_or(MeshAction::Status) {
                MeshAction::Status => {
                    let summary = pqcanary_core::scanner::mesh::FleetMeshBus::get_summary().await;
                    match format.to_lowercase().as_str() {
                        "json" => {
                            println!("{}", serde_json::to_string_pretty(&summary).unwrap_or_default());
                        }
                        "markdown" | "md" => {
                            println!("# PQCanary Distributed Fleet Mesh Status\n");
                            println!("- **Active Nodes Online**: {}", summary.total_nodes_online);
                            println!("- **Fleet Health Score**: **{:.1}/100**", summary.fleet_health_score);
                            println!("- **Total Findings Aggregated**: {}\n", summary.total_fleet_findings);

                            println!("## Active Fleet Mediums");
                            println!("| Node ID | Operational Medium | Status | Context | Scans | Findings |");
                            println!("|---------|--------------------|--------|---------|-------|----------|");
                            for n in &summary.active_nodes {
                                println!("| `{}` | {} | {:?} | {} | {} | {} |",
                                    n.node_id, n.medium.as_str(), n.status, n.active_context.as_deref().unwrap_or("-"), n.scans_count, n.findings_count
                                );
                            }
                            println!();

                            println!("## Recent Cross-Medium Telemetry Events");
                            for evt in &summary.recent_events {
                                println!("- **[{}]** `{}` ({:?}): {} — _{}_", evt.severity, evt.source_node_id, evt.source_medium, evt.title, evt.details);
                            }
                        }
                        _ => {
                            print_banner();
                            eprintln!("PQMesh Cross-Medium Fleet Observability Bus:\n");
                            println!("  Nodes Online:      {}", summary.total_nodes_online);
                            println!("  Fleet Health:      {:.1} / 100", summary.fleet_health_score);
                            println!("  Aggregated Items:  {}", summary.total_fleet_findings);
                            println!();

                            println!("  Active Operational Mediums:");
                            for n in &summary.active_nodes {
                                println!("    {} [{:?}] {} (Medium: {})", n.medium.icon(), n.status, n.label, n.medium.as_str());
                                if let Some(ref ctx) = n.active_context {
                                    println!("       Context: {}", ctx);
                                }
                                println!("       Activity: {} scans | {} findings reported", n.scans_count, n.findings_count);
                            }
                            println!();

                            println!("  Recent Cross-Medium Events:");
                            for evt in summary.recent_events.iter().take(5) {
                                let sev_icon = severity_icon(&evt.severity);
                                println!("    {} [{}] {} (from {})", sev_icon, evt.severity, evt.title, evt.source_node_id);
                                println!("       {}", evt.details);
                            }
                            println!();
                        }
                    }
                }
                MeshAction::Broadcast { title, details, severity } => {
                    let evt = pqcanary_core::scanner::mesh::MeshEvent {
                        event_id: format!("evt-cli-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()),
                        timestamp_epoch: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        source_node_id: "node-cli-admin".to_string(),
                        source_medium: pqcanary_core::scanner::mesh::OperationalMedium::Cli,
                        event_type: pqcanary_core::scanner::mesh::MeshEventType::DirectCommand,
                        title: title.clone(),
                        details: details.clone(),
                        severity,
                        payload_json: None,
                    };
                    pqcanary_core::scanner::mesh::FleetMeshBus::broadcast_event(evt).await;
                    println!("Broadcast sent successfully to all active fleet mediums: '{}'", title);
                }
            }
        }

        Commands::CloudKms { path, format } => {
            let content = if path == "-" {
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).unwrap_or_default();
                buf
            } else if Path::new(&path).is_file() {
                fs::read_to_string(&path).unwrap_or_default()
            } else if Path::new(&path).is_dir() {
                let mut aggregated = String::new();
                if let Ok(entries) = fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                        if ext == "tf" || ext == "tfvars" || ext == "json" {
                            if let Ok(c) = fs::read_to_string(&p) {
                                aggregated.push_str(&c);
                                aggregated.push('\n');
                            }
                        }
                    }
                }
                aggregated
            } else {
                String::new()
            };
            let report = pqcanary_core::scanner::cloud_kms::CloudKmsAuditor::audit_raw_content(&content);
            match format.to_lowercase().as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
                }
                "markdown" | "md" => {
                    println!("# Cloud Cryptographic Asset & KMS Quantum Audit\n");
                    println!("- **Overall Posture**: `{}`", report.overall_posture);
                    println!("- **Keys Inspected**: {}", report.total_keys_inspected);
                    println!("- **Quantum Safe / Hybrid**: {}", report.quantum_safe_count);
                    println!("- **Vulnerable Keys**: {}", report.vulnerable_count);
                    println!("- **CNSA 2.0 Compliance**: **{}%**\n", report.cnsa_2_compliance_percent);
                    println!("{}\n", report.summary);

                    println!("| Key ID | Provider | Spec | Quantum Risk | CNSA 2.0 | Recommendation |");
                    println!("|--------|----------|------|--------------|----------|----------------|");
                    for k in &report.keys {
                        println!("| `{}` | {} | `{}` | **{}** | {} | {} |",
                            k.key_id, k.provider.as_str(), k.key_spec, k.quantum_risk,
                            if k.cnsa_2_compliant { "Yes" } else { "No" },
                            k.recommendation
                        );
                    }
                }
                _ => {
                    print_banner();
                    eprintln!("Cloud Cryptographic Asset & KMS Quantum Audit:\n");
                    println!("  Posture:            {}", report.overall_posture);
                    println!("  Keys Inspected:     {}", report.total_keys_inspected);
                    println!("  Quantum Safe Keys:  {}", report.quantum_safe_count);
                    println!("  Vulnerable Keys:    {}", report.vulnerable_count);
                    println!("  CNSA 2.0 Ratio:     {}%", report.cnsa_2_compliance_percent);
                    println!("  Summary:            {}\n", report.summary);

                    for (idx, k) in report.keys.iter().enumerate() {
                        println!("  [{}] {} ({})", idx + 1, k.key_id, k.provider.as_str());
                        println!("      Spec:           {} | Usage: {}", k.key_spec, k.key_usage);
                        println!("      Quantum Risk:   {}", k.quantum_risk);
                        println!("      CNSA 2.0:       {}", if k.cnsa_2_compliant { "COMPLIANT" } else { "NON_COMPLIANT" });
                        println!("      Details:        {}", k.description);
                        println!("      Recommendation: {}", k.recommendation);
                        println!("      Remediation:    {}\n", k.remediation_snippet);
                    }
                }
            }
        }

        Commands::Hooks { action } => {
            let repo_root = Path::new(".");
            match action {
                HookAction::Install => {
                    print_banner();
                    match GitHookManager::install_hook(repo_root) {
                        Ok(p) => {
                            println!("Successfully installed PQCanary pre-commit hook into:");
                            println!("         {}", p.display());
                            println!("         Every 'git commit' will now verify staged files in <15ms.");
                        }
                        Err(e) => {
                            eprintln!("FAIL:   Failed to install pre-commit hook: {}", e);
                            process::exit(1);
                        }
                    }
                }
                HookAction::Uninstall => {
                    print_banner();
                    match GitHookManager::uninstall_hook(repo_root) {
                        Ok(_) => println!("Successfully removed PQCanary pre-commit hook."),
                        Err(e) => {
                            eprintln!("FAIL:   Failed to uninstall pre-commit hook: {}", e);
                            process::exit(1);
                        }
                    }
                }
                HookAction::Run => {
                    match GitHookManager::scan_staged_files(repo_root) {
                        Ok(findings) => {
                            let actionable: Vec<_> = findings.into_iter()
                                .filter(|f| f.severity == "CRITICAL" || f.severity == "HIGH")
                                .collect();

                            if actionable.is_empty() {
                                // Sub-15ms clean exit
                                process::exit(0);
                            } else {
                                eprintln!("\n╔══════════════════════════════════════════════════════════════════════╗");
                                eprintln!("║  REJECTED: Git Commit Blocked: Quantum Cryptographic Debt Detected  ║");
                                eprintln!("╚══════════════════════════════════════════════════════════════════════╝\n");
                                for (idx, f) in actionable.iter().enumerate() {
                                    eprintln!("  [{}] {} in {}:{}", idx + 1, f.severity, f.file_path, f.line_number);
                                    eprintln!("      Rule:        {}", f.rule_id.as_deref().unwrap_or("PQC-CHECK"));
                                    eprintln!("      Issue:       {}", f.description);
                                    eprintln!("      Remediation: {}\n", f.remediation);
                                }
                                eprintln!("Commit aborted. Remediate findings or run 'pqcanary patch <file>' before committing.\n");
                                process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!("WARN: Hook check error: {}", e);
                            process::exit(0); // Do not block developer if git diff fails
                        }
                    }
                }
            }
        }

        Commands::Mtu { algorithm, mtu, ipv6, format } => {
            let res = PqcMtuAnalyzer::analyze(&algorithm, Some(mtu), ipv6);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default()),
                "markdown" | "md" => println!("{}", PqcMtuAnalyzer::format_markdown(&res)),
                _ => {
                    print_banner();
                    eprintln!("Post-Quantum Network MTU & Packet Fragmentation Risk:\n");
                    println!("  Algorithm:             {}", res.algorithm);
                    println!("  Target MTU:            {} B ({})", res.mtu_bytes, res.ip_version);
                    println!("  Max Segment Size:      {} B", res.max_segment_size_bytes);
                    println!("  Handshake Payload:     {} B", res.full_handshake_payload_bytes);
                    println!("  Packets Required:      {} ({})", res.packets_required, if res.is_fragmented { "FRAGMENTED" } else { "SINGLE PACKET" });
                    println!("  Fragmentation Risk:    {}", res.fragmentation_risk_level);
                    println!("  Middlebox Drop Prob:   {:.1}%", res.middlebox_drop_probability_percent);
                    println!("  Est. Latency Impact:   {:.2}x\n", res.latency_multiplier);
                    println!("  Mitigations:");
                    for m in &res.mitigations {
                        println!("   * {}", m);
                    }
                }
            }
        }

        Commands::Agility { path, format } => {
            let safe_path = match pqcanary_core::api::validate_local_path(&path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Target path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            let mut all_findings = Vec::new();
            if Path::new(&safe_path).is_file() {
                if let Ok(c) = fs::read_to_string(&safe_path) {
                    all_findings.extend(AgilityScanner::audit_source(&safe_path, &c));
                }
            } else {
                let walker = pqcanary_core::scanner::walker::MonorepoWalker::new(&safe_path);
                for file in walker.collect_files() {
                    let ext = file.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                    if ["js", "ts", "jsx", "tsx", "rs", "py", "java", "go", "c", "cpp", "cs"].contains(&ext.as_str()) {
                        if let Ok(c) = fs::read_to_string(&file) {
                            let file_str = file.to_string_lossy().to_string();
                            all_findings.extend(AgilityScanner::audit_source(&file_str, &c));
                        }
                    }
                }
            }
            let rep = AgilityScanner::evaluate_report(all_findings);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                "markdown" | "md" => println!("{}", AgilityScanner::format_markdown(&rep)),
                _ => {
                    print_banner();
                    eprintln!("NIST SP 800-227 Cryptographic Agility Score:\n");
                    println!("  Agility Score:         {:.1}/100 ({})", rep.agility_score, rep.agility_level);
                    println!("  Total Crypto Calls:    {}", rep.total_cryptographic_invocations);
                    println!("  Agile Abstractions:    {}", rep.agile_abstractions);
                    println!("  Hardcoded Invocations: {}\n", rep.hardcoded_calls);
                    println!("  Description:           {}\n", rep.description);
                    println!("  Recommendations:");
                    for g in &rep.migration_guidance {
                        println!("   * {}", g);
                    }
                }
            }
        }

        Commands::Roadmap { path, name, format, output } => {
            let safe_target = match pqcanary_core::api::validate_local_path(&path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Target path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            let findings = MasterOrchestrator::new(&safe_target).execute_full_scan();
            let roadmap = MigrationSequencer::sequence_from_findings(&name, &findings);
            let out_str = match format.to_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&roadmap).unwrap_or_default(),
                _ => MigrationSequencer::format_markdown(&roadmap),
            };

            if let Some(out_path) = output {
                fs::write(&out_path, &out_str).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("Migration roadmap saved to '{}'.", out_path);
            } else {
                println!("{}", out_str);
            }
        }

        Commands::Reencrypt { provider, resource, format, output } => {
            let playbook = ReencryptPlaybookGenerator::generate(&provider, &resource);
            let out_str = match format.to_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&playbook).unwrap_or_default(),
                _ => ReencryptPlaybookGenerator::format_markdown(&playbook),
            };

            if let Some(out_path) = output {
                fs::write(&out_path, &out_str).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("Playbook saved to '{}'.", out_path);
            } else {
                println!("{}", out_str);
            }
        }

        Commands::Ebpf { generate_probe, payload_hex, src, dst, format } => {
            if generate_probe {
                println!("{}", EbpfSniffer::generate_bpf_c_source());
                return;
            }
            if let Some(hex_str) = payload_hex {
                let bytes = (0..hex_str.len())
                    .step_by(2)
                    .filter_map(|i| {
                        if i + 2 <= hex_str.len() {
                            u8::from_str_radix(&hex_str[i..i + 2], 16).ok()
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<u8>>();
                match EbpfSniffer::parse_handshake_bytes(&bytes, &src, &dst) {
                    Ok(res) => {
                        match format.to_lowercase().as_str() {
                            "json" => println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default()),
                            "markdown" | "md" => println!("{}", EbpfSniffer::format_markdown(&res)),
                            _ => {
                                print_banner();
                                eprintln!("Passive Wire Telemetry Handshake Analysis:\n");
                                println!("  Direction:         {:?}", res.direction);
                                println!("  Endpoints:         {} -> {}", res.source_address, res.destination_address);
                                println!("  Post-Quantum:      {}", if res.has_post_quantum_capability { "YES" } else { "NO" });
                                println!("  Status:            {}\n", if res.is_quantum_safe { "QUANTUM_RESILIENT" } else { "CRITICAL_CLASSICAL_DEFICIT" });
                                println!("  Offered Groups:");
                                for g in &res.offered_groups {
                                    println!("   * 0x{:04x}: {} (PQC: {})", g.group_id, g.name, g.is_post_quantum);
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("FAIL: Handshake decode error: {}", e),
                }
            } else {
                eprintln!("INFO: Specify --generate-probe to output eBPF C kernel filter, or --payload-hex <hex> to analyze packet.");
            }
        }

        Commands::K8sMesh { platform, name, namespace, hybrid_group, output } => {
            let p = match platform.to_lowercase().as_str() {
                "traefik" => K8sIngressPlatform::TraefikTLSOption,
                "nginx" => K8sIngressPlatform::NginxIngress,
                "gateway" | "gatewayapi" => K8sIngressPlatform::GatewayApi,
                _ => K8sIngressPlatform::IstioEnvoyFilter,
            };
            let cfg = K8sMeshConfig {
                platform: p,
                namespace,
                name,
                workload_selector: "istio=ingressgateway".to_string(),
                hybrid_group,
                min_tls_version: "TLSv1_3".to_string(),
            };
            let rem = K8sMeshEngine::generate(&cfg);
            if let Some(out_path) = output {
                fs::write(&out_path, &rem.manifest_yaml).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("Manifest saved to '{}'.", out_path);
            } else {
                println!("{}", rem.manifest_yaml);
            }
        }

        Commands::Hsm { provider, label, firmware, keys, ml_kem, ml_dsa, format } => {
            let prov = match provider.to_lowercase().as_str() {
                "thales" | "luna" => HsmProviderType::ThalesLuna7,
                "entrust" | "nshield" => HsmProviderType::EntrustNshield,
                "aws" | "cloudhsm" => HsmProviderType::AwsCloudHsm,
                "yubikey" => HsmProviderType::YubiKeyPqc,
                "kmip" => HsmProviderType::OasisKmip3,
                _ => HsmProviderType::Pkcs11V3,
            };
            let rep = HsmAuditor::audit_hsm(prov, &label, &firmware, keys, ml_kem, ml_dsa);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", HsmAuditor::format_markdown(&rep)),
            }
        }

        Commands::Shim { mode, log_path, force_hybrid, output } => {
            let m = if mode.to_lowercase() == "enforce" {
                ShimInterceptionMode::ActiveEnforcementAndPqcUpgrade
            } else {
                ShimInterceptionMode::AuditAndLogOnly
            };
            let cfg = RuntimeShimConfig {
                mode: m,
                log_output_path: log_path,
                force_hybrid_group: force_hybrid,
                emit_udp_telemetry: true,
                udp_collector_endpoint: "127.0.0.1:9099".to_string(),
            };
            let c_code = RuntimeShimGenerator::generate_linux_c_shim(&cfg);
            if let Some(out_path) = output {
                fs::write(&out_path, &c_code).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("C interceptor saved to '{}'.", out_path);
            } else {
                println!("{}", c_code);
            }
        }

        Commands::Bot { path, repo, branch, commit, author, format } => {
            let safe_target = match pqcanary_core::api::validate_local_path(&path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Target path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            let findings = MasterOrchestrator::new(&safe_target).execute_full_scan();
            let evt = GitWebhookPushEvent {
                provider: GitPlatformProvider::GitHub,
                repository_name: repo,
                default_branch: branch,
                commit_sha: commit,
                author_name: author,
                modified_files: vec!["src/crypto.ts".to_string()],
            };
            match AutonomousBotEngine::process_event(&evt, &findings) {
                Some(pr) => {
                    match format.to_lowercase().as_str() {
                        "json" => println!("{}", serde_json::to_string_pretty(&pr).unwrap_or_default()),
                        _ => {
                            println!("# Autonomous Pull Request Preview\n");
                            println!("* **Title:**  {}", pr.title);
                            println!("* **Branch:** {} -> {}\n", pr.head_branch, pr.base_branch);
                            println!("{}\n", pr.body_markdown);
                            println!("### Patch Diff:\n```diff\n{}\n```", pr.patch_diff);
                        }
                    }
                }
                None => println!("Clean codebase: 0 critical or high quantum vulnerabilities requiring PR."),
            }
        }

        Commands::Oscal { path, project, format, output } => {
            let safe_target = match pqcanary_core::api::validate_local_path(&path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Target path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            let findings = MasterOrchestrator::new(&safe_target).execute_full_scan();
            let rep = OscalExporter::evaluate_compliance(&project, &findings);
            let out_str = match format.to_lowercase().as_str() {
                "json" => OscalExporter::export_oscal_json(&rep),
                _ => OscalExporter::format_markdown(&rep),
            };
            if let Some(out_path) = output {
                fs::write(&out_path, &out_str).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("Compliance assessment saved to '{}'.", out_path);
            } else {
                println!("{}", out_str);
            }
        }

        Commands::Downgrade { target, strict, format } => {
            let rep = DowngradeSimulator::simulate(&target, strict);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", DowngradeSimulator::format_markdown(&rep)),
            }
        }

        Commands::Acvp { library, algo, format } => {
            let rep = AcvpKatHarness::verify_vectors(&library, algo.as_deref());
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", AcvpKatHarness::format_markdown(&rep)),
            }
        }

        Commands::CompositeCert { path, format } => {
            let raw_data = fs::read_to_string(&path).unwrap_or_else(|_| path.clone());
            let rep = CompositeCertValidator::audit_certificate(&path, &raw_data);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", CompositeCertValidator::format_markdown(&rep)),
            }
        }

        Commands::Otel { path, service, endpoint, output } => {
            let safe_target = match pqcanary_core::api::validate_local_path(&path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Target path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            let findings = MasterOrchestrator::new(&safe_target).execute_full_scan();
            let payload = OtelCryptoExporter::export_from_findings(&findings, &service, &endpoint);
            if let Some(out_path) = output {
                fs::write(&out_path, &payload.otlp_json).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("OTLP telemetry batch saved to '{}'.", out_path);
            } else {
                println!("{}", OtelCryptoExporter::format_markdown(&payload));
            }
        }

        Commands::ConstantTime { routine, samples, format } => {
            let rep = ConstantTimeVerifier::audit_library(&routine, samples);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", ConstantTimeVerifier::format_markdown(&rep)),
            }
        }

        Commands::Attest { cbom_file, project, signer, output } => {
            let cbom_content = match fs::read_to_string(&cbom_file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("FAIL: Could not read CBOM file '{}': {}", cbom_file, e);
                    process::exit(1);
                }
            };
            let env = CbomAttestor::attest_cbom(&cbom_content, &project, &signer);
            if let Some(out_path) = output {
                fs::write(&out_path, &env.dsse_envelope_json).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("DSSE attestation envelope saved to '{}'.", out_path);
            } else {
                println!("{}", CbomAttestor::format_markdown(&env));
            }
        }

        Commands::HbsAudit { path, format } => {
            let raw_content = fs::read_to_string(&path).unwrap_or_else(|_| path.clone());
            let rep = HbsStateAuditor::audit_state_and_config(&path, &raw_content);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", HbsStateAuditor::format_markdown(&rep)),
            }
        }

        Commands::VpnAudit { path, format } => {
            let raw_conf = fs::read_to_string(&path).unwrap_or_else(|_| path.clone());
            let rep = VpnScanner::audit_config(&path, &raw_conf);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", VpnScanner::format_markdown(&rep)),
            }
        }

        Commands::DbEnvelope { path, format, output } => {
            let raw_code = fs::read_to_string(&path).unwrap_or_else(|_| path.clone());
            let plan = DbEnvelopeScanner::audit_schema_or_orm(&path, &raw_code);
            let out_str = match format.to_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&plan).unwrap_or_default(),
                "sql" => plan.generated_sql_cursor_migration.clone(),
                "python" => plan.generated_python_worker_script.clone(),
                _ => DbEnvelopeScanner::format_markdown(&plan),
            };
            if let Some(out_path) = output {
                fs::write(&out_path, &out_str).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("Migration plan saved to '{}'.", out_path);
            } else {
                println!("{}", out_str);
            }
        }

        Commands::Watch { path, debounce_ms, once } => {
            let safe_target = match pqcanary_core::api::validate_local_path(&path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("FAIL: Target path rejected: {}", e.description);
                    process::exit(1);
                }
            };
            println!("Initializing continuous watch on '{}' (debounce: {}ms)...", safe_target, debounce_ms);
            let mut snapshot = WorkspaceWatcher::initialize_snapshot(&safe_target);
            println!("Tracking {} files across workspace.", snapshot.files.len());

            if once {
                let findings = MasterOrchestrator::new(&safe_target).execute_full_scan();
                let delta = WorkspaceWatcher::evaluate_cycle(&mut snapshot, &findings);
                println!("{}", WorkspaceWatcher::format_markdown(&delta));
            } else {
                println!("Continuous daemon started. Press Ctrl+C to terminate.");
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(debounce_ms));
                    let findings = MasterOrchestrator::new(&safe_target).execute_full_scan();
                    let delta = WorkspaceWatcher::evaluate_cycle(&mut snapshot, &findings);
                    if !delta.dirty_files_detected.is_empty() || delta.new_vulnerabilities_count > 0 || delta.resolved_vulnerabilities_count > 0 {
                        println!("\n{}", WorkspaceWatcher::format_markdown(&delta));
                    }
                }
            }
        }

        Commands::KerberosAudit { path, format, output } => {
            let raw_conf = fs::read_to_string(&path).unwrap_or_else(|_| path.clone());
            let rep = KerberosPkinitAuditor::audit_config(&path, &raw_conf);
            let out_str = match format.to_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&rep).unwrap_or_default(),
                "conf" => rep.recommended_krb5_conf.clone(),
                _ => KerberosPkinitAuditor::format_markdown(&rep),
            };
            if let Some(out_path) = output {
                fs::write(&out_path, &out_str).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("Hardened configuration saved to '{}'.", out_path);
            } else {
                println!("{}", out_str);
            }
        }

        Commands::BinaryPatch { binary_path, output, target_symbol, replacement_symbol, shim_output } => {
            let data = match fs::read(&binary_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("FAIL: Could not read target binary '{}': {}", binary_path, e);
                    process::exit(1);
                }
            };
            let (res, patched_bytes) = BinaryPatcher::patch_binary(&binary_path, &data, Some((&target_symbol, &replacement_symbol)));
            if let Some(out_bin) = output {
                fs::write(&out_bin, &patched_bytes).unwrap_or_else(|e| eprintln!("FAIL: Failed to save patched binary: {}", e));
                println!("Patched executable written to '{}'.", out_bin);
            }
            if let Some(out_shim) = shim_output {
                fs::write(&out_shim, &res.companion_forwarder_c_source).unwrap_or_else(|e| eprintln!("FAIL: Failed to save companion shim: {}", e));
                println!("Companion C shim source written to '{}'.", out_shim);
            }
            println!("{}", BinaryPatcher::format_markdown(&res));
        }

        Commands::Pkcs11Interrogate { path, format } => {
            let data = fs::read(&path).unwrap_or_else(|_| path.as_bytes().to_vec());
            let rep = Pkcs11Interrogator::interrogate_module(&path, &data);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", Pkcs11Interrogator::format_markdown(&rep)),
            }
        }

        Commands::CbomDatalake { cbom_path, repo, format } => {
            let cbom_str = fs::read_to_string(&cbom_path).unwrap_or_else(|_| cbom_path.clone());
            let plan = CbomDatalakeEngine::plan_datalake_integration(&repo, &cbom_str);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&plan).unwrap_or_default()),
                "postgres" => println!("{}", plan.postgresql_schema_ddl),
                "clickhouse" => println!("{}", plan.clickhouse_schema_ddl),
                "inserts" => println!("{}", plan.generated_batch_inserts_sql),
                _ => println!("{}", CbomDatalakeEngine::format_markdown(&plan)),
            }
        }

        Commands::PqcLatencyProfile { target, samples, rtt, format } => {
            let rep = PqcLatencyProfiler::profile_endpoint(&target, samples, rtt);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", PqcLatencyProfiler::format_markdown(&rep)),
            }
        }

        Commands::VerifyPatch { original_binary, patched_binary, format, smt_output, lean_output } => {
            let orig_data = match fs::read(&original_binary) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: Could not read original binary '{}': {}", original_binary, e);
                    process::exit(1);
                }
            };
            let patched_data = match fs::read(&patched_binary) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: Could not read patched binary '{}': {}", patched_binary, e);
                    process::exit(1);
                }
            };

            let rep = BinaryTranslationValidator::validate_translation(&original_binary, &orig_data, &patched_binary, &patched_data);

            if let Some(out_smt) = smt_output {
                fs::write(&out_smt, &rep.z3_smt_lib2_proof).unwrap_or_else(|e| eprintln!("FAIL: Failed to save SMT proof: {}", e));
                println!("Z3 SMT-LIB2 proof formula saved to '{}'.", out_smt);
            }
            if let Some(out_lean) = lean_output {
                fs::write(&out_lean, &rep.lean4_equivalence_theorem).unwrap_or_else(|e| eprintln!("FAIL: Failed to save Lean 4 proof: {}", e));
                println!("Lean 4 equivalence theorem saved to '{}'.", out_lean);
            }

            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", BinaryTranslationValidator::format_markdown(&rep)),
            }
        }

        Commands::DynamicSymbols { path, format, hook_output } => {
            let content = fs::read_to_string(&path).unwrap_or_else(|_| path.clone());
            let rep = DynamicSymbolInterceptor::audit_source(&path, &content);
            if let Some(out_hook) = hook_output {
                fs::write(&out_hook, &rep.generated_ld_preload_c_hook).unwrap_or_else(|e| eprintln!("FAIL: Failed to save hook: {}", e));
                println!("LD_PRELOAD interceptor saved to '{}'.", out_hook);
            }
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", DynamicSymbolInterceptor::format_markdown(&rep)),
            }
        }

        Commands::PqcAcme { domain, algo, directory, challenge, format, output } => {
            let plan = PqcAcmeEnrollmentEngine::plan_enrollment(&domain, &algo, &directory, &challenge);
            let out_str = match format.to_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&plan).unwrap_or_default(),
                "k8s" => plan.generated_k8s_cert_manager_crd.clone(),
                "vault" => plan.generated_vault_acme_role_hcl.clone(),
                _ => PqcAcmeEnrollmentEngine::format_markdown(&plan),
            };
            if let Some(out_path) = output {
                fs::write(&out_path, &out_str).unwrap_or_else(|e| eprintln!("FAIL: Write failed: {}", e));
                println!("Manifest saved to '{}'.", out_path);
            } else {
                println!("{}", out_str);
            }
        }

        Commands::QrngEntropy { source, sample_file, format } => {
            let data = match fs::read(&sample_file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: Could not read sample file '{}': {}", sample_file, e);
                    process::exit(1);
                }
            };
            let rep = QrngEntropyEvaluator::evaluate_sample(&source, &data);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", QrngEntropyEvaluator::format_markdown(&rep)),
            }
        }

        Commands::CmvpAttest { module, firmware, format } => {
            let rep = CmvpFirmwareRegistry::attest_module(&module, &firmware);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", CmvpFirmwareRegistry::format_markdown(&rep)),
            }
        }

        Commands::KmipWire { algo, length, format } => {
            let wire = KmipWireProtocol::encode_create_key_pair_request(&algo, length);
            let rep = KmipWireProtocol::decode_response_frame(&wire);
            match format.to_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default()),
                _ => println!("{}", KmipWireProtocol::format_markdown(&rep)),
            }
        }
    }
}

