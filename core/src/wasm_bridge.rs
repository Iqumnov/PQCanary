use wasm_bindgen::prelude::*;
use crate::scanner::orchestrator::{MasterOrchestrator, ComprehensiveFinding};
use crate::scanner::patterns::{ALL_PATTERNS, SuppressionEngine, extract_code_snippet, compute_finding_fingerprint};
use crate::scanner::sarif::SarifGenerator;
use crate::scanner::baseline::BaselineEngine;
use crate::scanner::cbom::CbomGenerator;
use crate::refactor::cognitive_security::CognitiveSecurityAnalyzer;
use crate::omega::qpu_offload::QpuOffloadEngine;
use crate::omega::hott_prover::HottProver;
use crate::omega::thermodynamics::ThermodynamicsAnalyzer;
use crate::refactor::autonomous_pr::SemanticPatcher;
use crate::scanner::cbom_diff::CbomDiffEngine;
use crate::scanner::pqc_mtu::PqcMtuAnalyzer;
use crate::scanner::agility_scanner::AgilityScanner;
use crate::scanner::migration_sequencer::MigrationSequencer;
use crate::scanner::reencrypt_playbook::ReencryptPlaybookGenerator;
use crate::scanner::ebpf_sniffer::EbpfSniffer;
use crate::scanner::k8s_mesh::{K8sMeshEngine, K8sMeshConfig, K8sIngressPlatform};
use crate::scanner::hsm_audit::{HsmAuditor, HsmProviderType};
use crate::scanner::runtime_shim::{RuntimeShimGenerator, RuntimeShimConfig, ShimInterceptionMode};
use crate::scanner::autonomous_bot::{AutonomousBotEngine, GitWebhookPushEvent, GitPlatformProvider};
use crate::scanner::oscal_exporter::OscalExporter;
use crate::scanner::downgrade_sim::DowngradeSimulator;
use crate::scanner::acvp_kat::AcvpKatHarness;
use crate::scanner::composite_cert::CompositeCertValidator;
use crate::scanner::otel_exporter::OtelCryptoExporter;
use crate::scanner::constant_time::ConstantTimeVerifier;
use crate::scanner::cbom_attest::CbomAttestor;
use crate::scanner::hbs_state_auditor::HbsStateAuditor;
use crate::scanner::vpn_scanner::VpnScanner;
use crate::scanner::db_envelope_scanner::DbEnvelopeScanner;
use crate::scanner::watcher::WorkspaceWatcher;
use crate::scanner::kerberos_pkinit::KerberosPkinitAuditor;
use crate::scanner::binary_patcher::BinaryPatcher;
use crate::scanner::pkcs11_interrogator::Pkcs11Interrogator;
use crate::scanner::cbom_datalake::CbomDatalakeEngine;
use crate::scanner::pqc_latency_profiler::PqcLatencyProfiler;
use crate::scanner::binary_translation_validator::BinaryTranslationValidator;
use crate::scanner::dynamic_symbol_interceptor::DynamicSymbolInterceptor;
use crate::scanner::pqc_acme_enrollment::PqcAcmeEnrollmentEngine;
use crate::scanner::qrng_entropy_evaluator::QrngEntropyEvaluator;
use crate::scanner::cmvp_firmware_registry::CmvpFirmwareRegistry;
use crate::scanner::kmip_wire_protocol::KmipWireProtocol;

/// The WebAssembly bridge exposing PQCanary core engines directly to the browser.
///
/// Compiled with: `wasm-pack build --target web --out-dir ../web/public/wasm`
///
/// Each method is exported as a JavaScript-callable function.
/// Results are serialized to JSON strings for easy consumption in Solid.js.
#[wasm_bindgen]
pub struct WasmScanner {
    target_dir: String,
}

#[wasm_bindgen]
impl WasmScanner {
    #[wasm_bindgen(constructor)]
    pub fn new(target_dir: &str) -> Self {
        Self { target_dir: target_dir.to_string() }
    }

    /// Execute the full PQCanary scan on the target directory (for Node/WASI).
    /// Returns a JSON array of ComprehensiveFinding objects.
    #[wasm_bindgen]
    pub fn execute_scan(&self) -> String {
        let orchestrator = MasterOrchestrator::new(&self.target_dir);
        let results = orchestrator.execute_full_scan();
        serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string())
    }

    /// Scan an in-memory source code string directly in the browser using the 193+ pattern engine.
    /// Honors inline suppressions (// pqcanary:ignore) and calculates cryptographic fingerprints.
    #[wasm_bindgen]
    pub fn scan_source(source_code: &str, file_name: &str) -> String {
        let mut findings = Vec::new();
        let lines: Vec<&str> = source_code.lines().collect();

        for pat in ALL_PATTERNS.iter() {
            for mat in pat.regex.find_iter(source_code) {
                let line_number = (source_code[..mat.start()].bytes().filter(|&b| b == b'\n').count() + 1) as u32;

                if SuppressionEngine::is_suppressed(&lines, line_number, pat.def.id, pat.def.category) {
                    continue;
                }

                let line_start = source_code[..mat.start()].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
                let col = (mat.start() - line_start + 1) as u32;

                let snippet = extract_code_snippet(&lines, line_number, 2);
                let line_content = lines.get((line_number as usize).saturating_sub(1)).copied().unwrap_or(pat.def.description);
                let fingerprint = compute_finding_fingerprint(file_name, pat.def.id, line_content);

                findings.push(ComprehensiveFinding {
                    file_path: file_name.to_string(),
                    vulnerability_class: pat.def.category.to_string(),
                    description: pat.def.description.to_string(),
                    severity: pat.def.severity.to_string(),
                    line_number,
                    remediation: pat.def.remediation.to_string(),
                    rule_id: Some(pat.def.id.to_string()),
                    quantum_risk: Some(pat.def.quantum_risk.as_str().to_string()),
                    confidence: Some("HIGH".to_string()),
                    snippet: Some(snippet),
                    column_number: Some(col),
                    fingerprint: Some(fingerprint),
                });
            }
        }

        serde_json::to_string(&findings).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export scan findings as OASIS SARIF 2.1.0 JSON format for GitHub Code Scanning
    #[wasm_bindgen]
    pub fn export_sarif(findings_json: &str, repository_name: Option<String>) -> String {
        let findings: Vec<ComprehensiveFinding> = serde_json::from_str(findings_json).unwrap_or_default();
        let sarif = SarifGenerator::generate_sarif(&findings, repository_name.as_deref());
        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    }

    /// Compare current findings against a baseline report (JSON or SARIF 2.1.0) in WebAssembly
    #[wasm_bindgen]
    pub fn compare_baseline(current_json: &str, baseline_json: &str) -> String {
        let current: Vec<ComprehensiveFinding> = BaselineEngine::parse_baseline_content(current_json)
            .unwrap_or_else(|_| serde_json::from_str(current_json).unwrap_or_default());
        let baseline: Vec<ComprehensiveFinding> = BaselineEngine::parse_baseline_content(baseline_json)
            .unwrap_or_else(|_| serde_json::from_str(baseline_json).unwrap_or_default());
        let report = BaselineEngine::compare(&current, &baseline);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Export CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
    #[wasm_bindgen]
    pub fn export_cbom(findings_json: &str, target_path: &str) -> String {
        let findings: Vec<ComprehensiveFinding> = serde_json::from_str(findings_json).unwrap_or_default();
        let cbom = CbomGenerator::generate_cbom(&findings, target_path);
        serde_json::to_string_pretty(&cbom).unwrap_or_else(|_| "{}".to_string())
    }

    /// Analyze Control Flow Graph (CFG) and compute McCabe cyclomatic complexity: M = E - N + 2P
    #[wasm_bindgen]
    pub fn compute_cfg(source_code: &str) -> String {
        let analyzer = CognitiveSecurityAnalyzer::new();
        let cfg = analyzer.build_cfg(source_code);
        let cyclo = cfg.cyclomatic_complexity();
        serde_json::json!({
            "basic_blocks_count": cfg.blocks.len(),
            "edges_count": cfg.edges.len(),
            "connected_components": cfg.count_connected_components(),
            "cyclomatic_complexity": cyclo,
            "blocks": cfg.blocks,
            "edges": cfg.edges,
        }).to_string()
    }

    /// Run exact unitary statevector quantum circuit simulation directly in WebAssembly
    #[wasm_bindgen]
    pub fn simulate_quantum(num_qubits: u32, target_bitstring: &str, shots: u32) -> String {
        let engine = QpuOffloadEngine::new(None);
        let report = engine.simulate_statevector(num_qubits, target_bitstring, shots);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Classify a cryptographic algorithm and return its security verdict.
    #[wasm_bindgen]
    pub fn classify_algorithm(algorithm: &str) -> String {
        let prover = HottProver::new();
        let classification = prover.classify_algorithm(algorithm);
        serde_json::json!({
            "algorithm": algorithm,
            "is_safe": classification.is_safe(),
            "message": classification.severity_message(),
        }).to_string()
    }

    /// Export a Lean 4 formal proof file for the given cryptographic algorithm.
    #[wasm_bindgen]
    pub fn export_hott_proof(algorithm: &str) -> String {
        let prover = HottProver::new();
        prover.export_lean_proof(algorithm)
    }

    /// Simulate the Landauer thermodynamic limit for the given gate counts.
    #[wasm_bindgen]
    pub fn simulate_thermodynamics(total_gates: usize, erased_bits: usize) -> String {
        let analyzer = ThermodynamicsAnalyzer::at_room_temperature();
        let report = analyzer.simulate_landauer_limit(total_gates, erased_bits);
        serde_json::json!({
            "temperature_kelvin": report.temperature_kelvin,
            "landauer_limit_joules": report.landauer_limit_joules,
            "total_dissipation_joules": report.total_dissipation_joules,
            "total_dissipation_femtojoules": report.total_dissipation_femtojoules,
            "irreversible_fraction": report.irreversible_fraction,
            "thermal_side_channel_risk": report.thermal_side_channel_risk,
        }).to_string()
    }

    /// Apply automated cryptographic remediation patches to the given source code.
    #[wasm_bindgen]
    pub fn generate_patch(file_path: &str, source: &str) -> String {
        let patcher = SemanticPatcher::new();
        let result = patcher.patch_file(file_path, source);
        serde_json::json!({
            "changed": result.is_changed(),
            "rules_applied": result.rules_applied,
            "unified_diff": result.unified_diff,
            "patched_source": result.patched_source,
        }).to_string()
    }

    /// Compare two CycloneDX 1.6 CBOM documents and compute cryptographic drift
    #[wasm_bindgen]
    pub fn diff_cbom(base_json: &str, target_json: &str) -> String {
        match CbomDiffEngine::diff_json_strings(base_json, target_json) {
            Ok(report) => serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string()),
            Err(err) => serde_json::json!({ "error": err, "status": "ERROR" }).to_string(),
        }
    }

    /// Analyze network MTU and TCP packet fragmentation risk for a cryptographic algorithm
    #[wasm_bindgen]
    pub fn analyze_pqc_mtu(algorithm: &str, mtu: Option<usize>, is_ipv6: bool) -> String {
        let res = PqcMtuAnalyzer::analyze(algorithm, mtu, is_ipv6);
        serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string())
    }

    /// Audit cryptographic agility (NIST SP 800-227) on source code directly in WebAssembly
    #[wasm_bindgen]
    pub fn audit_crypto_agility(source_code: &str, file_name: &str) -> String {
        let findings = AgilityScanner::audit_source(file_name, source_code);
        let report = AgilityScanner::evaluate_report(findings);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate an asset-dependency topological migration roadmap (CNSA 2.0 / OMB M-23-02)
    #[wasm_bindgen]
    pub fn generate_migration_roadmap(project_name: &str, findings_json: &str) -> String {
        let findings: Vec<ComprehensiveFinding> = serde_json::from_str(findings_json).unwrap_or_default();
        let roadmap = MigrationSequencer::sequence_from_findings(project_name, &findings);
        serde_json::to_string(&roadmap).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate 3-phase zero-downtime envelope re-encryption playbook for Cloud KMS
    #[wasm_bindgen]
    pub fn generate_reencrypt_playbook(provider: &str, resource_name: &str) -> String {
        let playbook = ReencryptPlaybookGenerator::generate(provider, resource_name);
        serde_json::to_string(&playbook).unwrap_or_else(|_| "{}".to_string())
    }

    /// Passive eBPF wire telemetry: parse TLS handshake hex payload
    #[wasm_bindgen]
    pub fn analyze_ebpf_handshake(payload_hex: &str, src: &str, dst: &str) -> String {
        let bytes = (0..payload_hex.len())
            .step_by(2)
            .filter_map(|i| {
                if i + 2 <= payload_hex.len() {
                    u8::from_str_radix(&payload_hex[i..i + 2], 16).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<u8>>();
        match EbpfSniffer::parse_handshake_bytes(&bytes, src, dst) {
            Ok(res) => serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string()),
            Err(e) => serde_json::json!({ "error": e }).to_string(),
        }
    }

    /// Generate C source code for eBPF kernel Traffic Control (TC) socket filter
    #[wasm_bindgen]
    pub fn generate_ebpf_kernel_probe() -> String {
        EbpfSniffer::generate_bpf_c_source()
    }

    /// Generate Kubernetes service mesh & ingress PQC remediation manifest (Istio, Traefik, NGINX)
    #[wasm_bindgen]
    pub fn generate_k8s_mesh_remediation(platform: &str, name: &str, namespace: &str, hybrid_group: &str) -> String {
        let p = match platform.to_lowercase().as_str() {
            "traefik" => K8sIngressPlatform::TraefikTLSOption,
            "nginx" => K8sIngressPlatform::NginxIngress,
            "gateway" | "gatewayapi" => K8sIngressPlatform::GatewayApi,
            _ => K8sIngressPlatform::IstioEnvoyFilter,
        };
        let cfg = K8sMeshConfig {
            platform: p,
            namespace: if namespace.is_empty() { "istio-system".to_string() } else { namespace.to_string() },
            name: if name.is_empty() { "pqc-hybrid-tls-enforce".to_string() } else { name.to_string() },
            workload_selector: "istio=ingressgateway".to_string(),
            hybrid_group: if hybrid_group.is_empty() { "X25519MLKEM768".to_string() } else { hybrid_group.to_string() },
            min_tls_version: "TLSv1_3".to_string(),
        };
        let res = K8sMeshEngine::generate(&cfg);
        serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string())
    }

    /// Audit Hardware Security Module (HSM) PKCS#11 v3.0 / KMIP tokens
    #[wasm_bindgen]
    pub fn audit_hsm_device(provider: &str, label: &str, firmware: &str, keys_stored: usize, has_ml_kem: bool, has_ml_dsa: bool) -> String {
        let prov = match provider.to_lowercase().as_str() {
            "thales" | "luna" => HsmProviderType::ThalesLuna7,
            "entrust" | "nshield" => HsmProviderType::EntrustNshield,
            "aws" | "cloudhsm" => HsmProviderType::AwsCloudHsm,
            "yubikey" => HsmProviderType::YubiKeyPqc,
            "kmip" => HsmProviderType::OasisKmip3,
            _ => HsmProviderType::Pkcs11V3,
        };
        let res = HsmAuditor::audit_hsm(prov, label, firmware, keys_stored, has_ml_kem, has_ml_dsa);
        serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate dynamic runtime cryptographic interception C shim (LD_PRELOAD / Detours)
    #[wasm_bindgen]
    pub fn generate_runtime_interceptor_shim(mode: &str, log_path: &str, force_hybrid: &str) -> String {
        let m = if mode.to_lowercase() == "enforce" {
            ShimInterceptionMode::ActiveEnforcementAndPqcUpgrade
        } else {
            ShimInterceptionMode::AuditAndLogOnly
        };
        let cfg = RuntimeShimConfig {
            mode: m,
            log_output_path: if log_path.is_empty() { "/var/log/pqcanary_runtime.log".to_string() } else { log_path.to_string() },
            force_hybrid_group: if force_hybrid.is_empty() { "X25519MLKEM768:X25519".to_string() } else { force_hybrid.to_string() },
            emit_udp_telemetry: true,
            udp_collector_endpoint: "127.0.0.1:9099".to_string(),
        };
        let c_code = RuntimeShimGenerator::generate_linux_c_shim(&cfg);
        serde_json::json!({
            "c_source": c_code,
            "instructions": RuntimeShimGenerator::format_markdown(&cfg)
        }).to_string()
    }

    /// Synthesize autonomous Pull Request with unified diff patches and Lean 4 formal proofs
    #[wasm_bindgen]
    pub fn generate_autonomous_remediation_pr(repo_name: &str, branch: &str, commit_sha: &str, author: &str, findings_json: &str) -> String {
        let findings: Vec<ComprehensiveFinding> = serde_json::from_str(findings_json).unwrap_or_default();
        let evt = GitWebhookPushEvent {
            provider: GitPlatformProvider::GitHub,
            repository_name: repo_name.to_string(),
            default_branch: if branch.is_empty() { "main".to_string() } else { branch.to_string() },
            commit_sha: if commit_sha.is_empty() { "a1b2c3d4e5f6".to_string() } else { commit_sha.to_string() },
            author_name: if author.is_empty() { "Developer".to_string() } else { author.to_string() },
            modified_files: vec!["src/crypto.ts".to_string()],
        };
        match AutonomousBotEngine::process_event(&evt, &findings) {
            Some(pr) => serde_json::to_string(&pr).unwrap_or_else(|_| "{}".to_string()),
            None => serde_json::json!({ "status": "NO_ACTIONABLE_VULNERABILITIES" }).to_string(),
        }
    }

    /// Export NIST SP 800-53 OSCAL assessment JSON & EU DORA compliance matrix
    #[wasm_bindgen]
    pub fn export_oscal_compliance_report(project_name: &str, findings_json: &str) -> String {
        let findings: Vec<ComprehensiveFinding> = serde_json::from_str(findings_json).unwrap_or_default();
        let report = OscalExporter::evaluate_compliance(project_name, &findings);
        let oscal_json = OscalExporter::export_oscal_json(&report);
        let md = OscalExporter::format_markdown(&report);
        serde_json::json!({
            "report": report,
            "oscal_json": oscal_json,
            "markdown": md
        }).to_string()
    }

    /// Simulate active quantum downgrade attacks against target endpoint (RFC 8446 / CNSA 2.0)
    #[wasm_bindgen]
    pub fn simulate_quantum_downgrade(target: &str, enforce_cnsa: bool) -> String {
        let report = DowngradeSimulator::simulate(target, enforce_cnsa);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Verify implementation against NIST CAVP / ACVP Known-Answer-Test vectors (FIPS 203/204/205)
    #[wasm_bindgen]
    pub fn verify_acvp_kat_vectors(library_name: &str, target_algo: &str) -> String {
        let algo = if target_algo.is_empty() { None } else { Some(target_algo) };
        let report = AcvpKatHarness::verify_vectors(library_name, algo);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Inspect and validate Hybrid & Dual-Key X.509 Composite Certificate (RFC 9758)
    #[wasm_bindgen]
    pub fn validate_composite_certificate(target_name: &str, raw_pem: &str) -> String {
        let report = CompositeCertValidator::audit_certificate(target_name, raw_pem);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Export OpenTelemetry Cryptographic Semantic telemetry batch for SIEM / SOC streaming
    #[wasm_bindgen]
    pub fn export_otel_cryptography(findings_json: &str, service_name: &str, endpoint: &str) -> String {
        let findings: Vec<ComprehensiveFinding> = serde_json::from_str(findings_json).unwrap_or_default();
        let payload = OtelCryptoExporter::export_from_findings(&findings, service_name, endpoint);
        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
    }

    /// Empirically verify constant-time execution and detect KyberSlash timing leaks (Welch's t-test)
    #[wasm_bindgen]
    pub fn verify_constant_time_execution(target_name: &str, samples: usize) -> String {
        let report = ConstantTimeVerifier::audit_library(target_name, samples);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate in-toto SLSA Provenance v1.0 and Sigstore Cosign DSSE attestation for CBOM
    #[wasm_bindgen]
    pub fn attest_cbom_provenance(cbom_json: &str, project_name: &str, signer_id: &str) -> String {
        let envelope = CbomAttestor::attest_cbom(cbom_json, project_name, signer_id);
        serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string())
    }

    /// Audit Stateful Hash-Based Signatures (RFC 8554 LMS / RFC 8391 XMSS) and snapshot reuse hazards
    #[wasm_bindgen]
    pub fn audit_hbs_state(target_name: &str, content: &str) -> String {
        let report = HbsStateAuditor::audit_state_and_config(target_name, content);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Audit WireGuard, strongSwan / IPSec, and OpenVPN configurations for post-quantum tunnel readiness
    #[wasm_bindgen]
    pub fn audit_vpn_config(filename: &str, content: &str) -> String {
        let report = VpnScanner::audit_config(filename, content);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Audit database ORM / schema column-level envelope encryption (CSFLE) and synthesize migration plan
    #[wasm_bindgen]
    pub fn audit_db_envelope(filename: &str, content: &str) -> String {
        let plan = DbEnvelopeScanner::audit_schema_or_orm(filename, content);
        serde_json::to_string(&plan).unwrap_or_else(|_| "{}".to_string())
    }

    /// Continuous filesystem watch delta evaluation
    #[wasm_bindgen]
    pub fn evaluate_watch_delta(root: &str, findings_json: &str) -> String {
        let findings: Vec<ComprehensiveFinding> = serde_json::from_str(findings_json).unwrap_or_default();
        let mut snapshot = WorkspaceWatcher::initialize_snapshot(root);
        let delta = WorkspaceWatcher::evaluate_cycle(&mut snapshot, &findings);
        serde_json::to_string(&delta).unwrap_or_else(|_| "{}".to_string())
    }

    /// Audit MIT / Heimdal Kerberos krb5.conf and Active Directory PKINIT configurations
    #[wasm_bindgen]
    pub fn audit_kerberos_pkinit(target_name: &str, content: &str) -> String {
        let report = KerberosPkinitAuditor::audit_config(target_name, content);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Inspect and patch 64-bit PE / ELF binary import tables (IAT/GOT)
    #[wasm_bindgen]
    pub fn patch_binary_imports(filename: &str, binary_hex: &str, orig_sym: &str, repl_sym: &str) -> String {
        let bytes = (0..binary_hex.len())
            .step_by(2)
            .filter_map(|i| {
                if i + 2 <= binary_hex.len() {
                    u8::from_str_radix(&binary_hex[i..i + 2], 16).ok()
                } else {
                    None
                }
            })
            .collect::<Vec<u8>>();
        let custom_rule = if orig_sym.is_empty() { None } else { Some((orig_sym, repl_sym)) };
        let (result, patched_bytes) = BinaryPatcher::patch_binary(filename, &bytes, custom_rule);
        let patched_hex = patched_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        serde_json::json!({
            "result": result,
            "patched_binary_hex": patched_hex
        }).to_string()
    }

    /// Interrogate physical HSM PKCS#11 module mechanisms and hardware enforcement
    #[wasm_bindgen]
    pub fn interrogate_pkcs11(path_or_desc: &str, content: &str) -> String {
        let report = Pkcs11Interrogator::interrogate_module(path_or_desc, content.as_bytes());
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate enterprise fleet CBOM data lake DDL schemas and analytics queries
    #[wasm_bindgen]
    pub fn plan_cbom_datalake(repository_id: &str, cbom_json: &str) -> String {
        let plan = CbomDatalakeEngine::plan_datalake_integration(repository_id, cbom_json);
        serde_json::to_string(&plan).unwrap_or_else(|_| "{}".to_string())
    }

    /// Profile post-quantum TLS 1.3 / SSH handshake latency inflation and wire overhead
    #[wasm_bindgen]
    pub fn profile_pqc_handshake(target: &str, samples: usize, base_rtt_ms: f64) -> String {
        let report = PqcLatencyProfiler::profile_endpoint(target, samples, if base_rtt_ms > 0.0 { Some(base_rtt_ms) } else { None });
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Formally verify binary translation equivalence using SMT-LIB2 and Lean 4
    #[wasm_bindgen]
    pub fn validate_binary_translation(orig_name: &str, orig_hex: &str, patched_name: &str, patched_hex: &str) -> String {
        let decode_hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .filter_map(|i| {
                    if i + 2 <= s.len() {
                        u8::from_str_radix(&s[i..i + 2], 16).ok()
                    } else {
                        None
                    }
                })
                .collect()
        };
        let orig_bytes = decode_hex(orig_hex);
        let patched_bytes = decode_hex(patched_hex);
        let report = BinaryTranslationValidator::validate_translation(orig_name, &orig_bytes, patched_name, &patched_bytes);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Audit dynamic symbol resolution loader calls (dlsym / GetProcAddress)
    #[wasm_bindgen]
    pub fn audit_dynamic_symbols(target_name: &str, content: &str) -> String {
        let report = DynamicSymbolInterceptor::audit_source(target_name, content);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Plan automated post-quantum ACME RFC 8555 & EST RFC 7030 certificate enrollment
    #[wasm_bindgen]
    pub fn plan_pqc_acme_enrollment(domain: &str, pqc_algo: &str, acme_directory: &str, challenge_type: &str) -> String {
        let plan = PqcAcmeEnrollmentEngine::plan_enrollment(domain, pqc_algo, acme_directory, challenge_type);
        serde_json::to_string(&plan).unwrap_or_else(|_| "{}".to_string())
    }

    /// Evaluate physical noise source min-entropy conforming to NIST SP 800-90B
    #[wasm_bindgen]
    pub fn evaluate_qrng_entropy(source_name: &str, sample_hex: &str) -> String {
        let clean = sample_hex.trim().replace("0x", "").replace(' ', "");
        let bytes: Vec<u8> = (0..clean.len())
            .step_by(2)
            .filter_map(|i| {
                if i + 2 <= clean.len() {
                    u8::from_str_radix(&clean[i..i + 2], 16).ok()
                } else {
                    None
                }
            })
            .collect();
        let report = QrngEntropyEvaluator::evaluate_sample(source_name, &bytes);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Attest cryptographic hardware token against NIST CMVP FIPS 140-3 certificate database
    #[wasm_bindgen]
    pub fn attest_cmvp_firmware(module_query: &str, firmware_version: &str) -> String {
        let report = CmvpFirmwareRegistry::attest_module(module_query, firmware_version);
        serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
    }

    /// Encode and decode OASIS KMIP 2.1 / 3.0 TTLV binary wire protocol frames
    #[wasm_bindgen]
    pub fn process_kmip_wire_frame(algorithm: &str, length_bits: u32) -> String {
        let wire = KmipWireProtocol::encode_create_key_pair_request(algorithm, length_bits);
        let decoded = KmipWireProtocol::decode_response_frame(&wire);
        serde_json::to_string(&decoded).unwrap_or_else(|_| "{}".to_string())
    }
}


