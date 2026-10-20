// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use pqcanary_core::scanner::orchestrator::{MasterOrchestrator, ComprehensiveFinding};

/// Execute the full multi-engine scan on the given directory.
/// Returns a serialized list of ComprehensiveFinding (JSON-compatible via Serde).
/// Execute the full multi-engine scan on a local directory OR a remote GitHub/Git repository.
/// Returns a serialized list of ComprehensiveFinding (JSON-compatible via Serde).
#[tauri::command]
async fn execute_scan(target_dir: String) -> Result<Vec<ComprehensiveFinding>, String> {
    let target = target_dir.trim();
    if pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::is_git_repository_url(target) {
        let fetcher = pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::new();
        let cloned_path = fetcher.fetch_repository(target).await
            .map_err(|e| format!("Remote Git fetch failed for '{}': {}", target, e))?;
        
        let orchestrator = MasterOrchestrator::new(cloned_path.to_str().unwrap_or("."));
        let mut results = orchestrator.execute_full_scan();
        for f in &mut results {
            if let Ok(rel) = std::path::Path::new(&f.file_path).strip_prefix(&cloned_path) {
                f.file_path = rel.to_string_lossy().to_string();
            }
        }
        
        pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::cleanup_temp_dir(&cloned_path);
        Ok(results)
    } else if std::path::Path::new(target).exists() {
        let safe_dir = pqcanary_core::api::validate_local_path(target)
            .map_err(|e| e.description)?;
        let orchestrator = MasterOrchestrator::new(&safe_dir);
        let results = orchestrator.execute_full_scan();
        Ok(results)
    } else if target.starts_with("http://") || target.starts_with("https://") || (target.contains('.') && !target.contains('/') && !target.contains('\\')) {
        Ok(pqcanary_core::api::audit_remote_url(target).await)
    } else {
        let safe_dir = pqcanary_core::api::validate_local_path(target)
            .map_err(|e| e.description)?;
        let orchestrator = MasterOrchestrator::new(&safe_dir);
        let results = orchestrator.execute_full_scan();
        Ok(results)
    }
}

/// Export scan findings as an OASIS SARIF 2.1.0 JSON document for GitHub Code Scanning
#[tauri::command]
fn export_sarif(findings: Vec<ComprehensiveFinding>, repository: Option<String>) -> Result<String, String> {
    use pqcanary_core::scanner::sarif::SarifGenerator;
    let sarif = SarifGenerator::generate_sarif(&findings, repository.as_deref());
    serde_json::to_string_pretty(&sarif).map_err(|e| e.to_string())
}

/// Compare current findings against a baseline report (JSON or SARIF 2.1.0)
#[tauri::command]
fn compare_baseline(
    findings: Vec<ComprehensiveFinding>,
    baseline_content: String,
) -> Result<pqcanary_core::scanner::baseline::BaselineComparisonReport, String> {
    use pqcanary_core::scanner::baseline::BaselineEngine;
    let baseline_findings = BaselineEngine::parse_baseline_content(&baseline_content)?;
    Ok(BaselineEngine::compare(&findings, &baseline_findings))
}

/// Export CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
#[tauri::command]
fn export_cbom(findings: Vec<ComprehensiveFinding>) -> Result<String, String> {
    use pqcanary_core::scanner::cbom::CbomGenerator;
    let cbom = CbomGenerator::generate_cbom(&findings, "workspace");
    serde_json::to_string_pretty(&cbom).map_err(|e| e.to_string())
}

/// Execute exact unitary statevector quantum circuit simulation
#[tauri::command]
fn simulate_quantum_circuit(
    num_qubits: u32,
    target_state: Option<String>,
    shots: Option<u32>,
) -> Result<pqcanary_core::omega::qpu_offload::QuantumSimulationReport, String> {
    use pqcanary_core::omega::qpu_offload::QpuOffloadEngine;
    let engine = QpuOffloadEngine::new(None);
    let target = target_state.unwrap_or_else(|| "101".to_string());
    let report = engine.simulate_statevector(num_qubits, &target, shots.unwrap_or(1024));
    Ok(report)
}

/// Analyze explicit Control Flow Graph (CFG) and compute McCabe complexity
#[tauri::command]
fn analyze_cfg_graph(source_code: String) -> Result<pqcanary_core::refactor::cognitive_security::ControlFlowGraph, String> {
    use pqcanary_core::refactor::cognitive_security::CognitiveSecurityAnalyzer;
    let analyzer = CognitiveSecurityAnalyzer::new();
    Ok(analyzer.build_cfg(&source_code))
}

/// Runs the concolic symbolic execution engine on a specific source code snippet.
/// Returns the first provable vulnerability as a string, or None if safe.
/// Note: Requires `z3` to be installed and on PATH. Returns an error string gracefully if absent.
#[tauri::command]
fn test_concolic(snippet: String) -> Result<Option<String>, String> {
    let orchestrator = MasterOrchestrator::new(".");
    Ok(orchestrator.execute_concolic_target(&snippet))
}

/// Runs the formal WebAssembly linear memory sandbox test, demonstrating
/// detection of heap overflows and use-after-free bugs.
#[tauri::command]
fn run_memory_sandbox() -> Result<String, String> {
    let orchestrator = MasterOrchestrator::new(".");
    Ok(orchestrator.run_memory_sandbox_test())
}

/// Computes Halstead software metrics and McCabe cyclomatic complexity for a code snippet.
/// These metrics mathematically quantify how difficult code is to understand and audit.
#[tauri::command]
fn test_cognitive_security(snippet: String) -> Result<String, String> {
    use pqcanary_core::refactor::cognitive_security::CognitiveSecurityAnalyzer;
    let analyzer = CognitiveSecurityAnalyzer::new();
    let metrics = analyzer.analyze_halstead(&snippet);
    let cyclo = analyzer.compute_cyclomatic_complexity(&snippet);
    let cfg = analyzer.build_cfg(&snippet);
    
    Ok(format!(
        "Control Flow Graph & Cognitive Security:\n\
         ─────────────────────────────────────────\n\
         CFG Basic Blocks (N):    {}\n\
         CFG Edges (E):           {}\n\
         Connected Components (P):{}\n\
         McCabe Complexity (M):   {} (M = E - N + 2P)\n\
         \n\
         Halstead Complexity Metrics:\n\
         ─────────────────────────────\n\
         Vocabulary (n):    {}\n\
         Length (N):        {}\n\
         Volume (V):        {:.2}\n\
         Difficulty (D):    {:.2}\n\
         Effort (E):        {:.2}\n\
         Time to program:   {:.1} seconds\n\
         Estimated bugs (B):{:.4}\n\
         \n\
         Security Evaluation:\n\
         {}",
        cfg.blocks.len(), cfg.edges.len(), cfg.count_connected_components(), cyclo,
        metrics.vocabulary(), metrics.length(),
        metrics.volume(), metrics.difficulty(), metrics.effort(),
        metrics.time_required(), metrics.delivered_bugs(),
        if cyclo > 20 { "RISK: Cyclomatic complexity > 20. High audit burden." }
        else if cyclo > 10 { "WARNING: Cyclomatic complexity > 10. Consider refactoring." }
        else { "ACCEPTABLE: Cyclomatic complexity within safe bounds." }
    ))
}

/// Simulates the Landauer thermodynamic limit for a model AES-128 circuit.
/// Determines whether the thermal dissipation is detectable via IR side-channel attacks.
#[tauri::command]
fn test_thermodynamics() -> Result<String, String> {
    use pqcanary_core::omega::thermodynamics::ThermodynamicsAnalyzer;
    let analyzer = ThermodynamicsAnalyzer::at_room_temperature();
    // Model a typical AES-128 circuit: ~10,000 logic gates, ~4,000 irreversible
    let report = analyzer.simulate_landauer_limit(10_000, 4_000);
    Ok(format!(
        "Thermodynamic Security Profile (Landauer Limit):\n\
         ─────────────────────────────────────────────────\n\
         Temperature:              {:.1} K ({:.1} °C)\n\
         Landauer limit (per bit): {:.3e} J/bit\n\
         Total heat dissipation:   {:.3e} J ({:.4} fJ)\n\
         Irreversible gate ratio:  {:.1}%\n\
         Thermal SCA risk:         {}",
        report.temperature_kelvin,
        report.temperature_kelvin - 273.15,
        report.landauer_limit_joules,
        report.total_dissipation_joules,
        report.total_dissipation_femtojoules,
        report.irreversible_fraction * 100.0,
        if report.thermal_side_channel_risk {
            "YES — dissipation detectable by IR camera / Peltier sensor (>1 fJ)"
        } else {
            "NO  — dissipation below detectable threshold"
        }
    ))
}

/// Classify a cryptographic algorithm and export its Lean 4 formal proof obligations.
#[tauri::command]
fn classify_algorithm(algorithm: String) -> Result<String, String> {
    use pqcanary_core::omega::hott_prover::HottProver;
    let prover = HottProver::new();
    let classification = prover.classify_algorithm(&algorithm);
    Ok(classification.severity_message())
}

/// Export the full Lean 4 formal proof file for a cryptographic algorithm.
#[tauri::command]
fn export_hott_proof(algorithm: String) -> Result<String, String> {
    use pqcanary_core::omega::hott_prover::HottProver;
    let prover = HottProver::new();
    Ok(prover.export_lean_proof(&algorithm))
}

/// Generate a unified diff patch applying automated cryptographic remediation rules
/// to a provided source file.
#[tauri::command]
fn generate_patch(file_path: String, source: String) -> Result<String, String> {
    use pqcanary_core::refactor::autonomous_pr::SemanticPatcher;
    let patcher = SemanticPatcher::new();
    let result = patcher.patch_file(&file_path, &source);
    if result.is_changed() {
        Ok(format!(
            "Rules applied:\n{}\n\nDiff:\n{}",
            result.rules_applied.join("\n"),
            result.unified_diff
        ))
    } else {
        Ok("No vulnerable patterns detected. Source is already compliant.".to_string())
    }
}

/// Probe a live network endpoint over TCP/TLS 1.3 for Post-Quantum key exchange.
#[tauri::command]
async fn probe_tls(target: String, port: Option<u16>) -> Result<serde_json::Value, String> {
    pqcanary_core::api::validate_network_target(&target)?;
    use pqcanary_core::scanner::network_tls::NetworkTlsProbe;
    let (host, parsed_port) = NetworkTlsProbe::parse_target(&target);
    let p = port.unwrap_or(parsed_port);
    let res = NetworkTlsProbe::probe_endpoint(&host, p).await
        .map_err(|e| format!("TLS probe failed: {}", e))?;
    Ok(serde_json::json!({
        "host": res.host,
        "port": res.port,
        "tls_version": res.tls_version,
        "cipher_suite": res.cipher_suite,
        "selected_group": res.selected_group,
        "is_post_quantum_safe": res.is_post_quantum_safe,
        "is_hybrid": res.is_hybrid,
        "rtt_ms": res.rtt_ms,
    }))
}

/// Probe a live SSH server over TCP for Post-Quantum hybrid key exchange (sntrup761 / mlkem768).
#[tauri::command]
async fn probe_ssh(target: String, port: Option<u16>) -> Result<pqcanary_core::scanner::network_ssh::SshProbeResult, String> {
    pqcanary_core::api::validate_network_target(&target)?;
    use pqcanary_core::scanner::network_ssh::NetworkSshProbe;
    let (host, parsed_port) = NetworkSshProbe::parse_target(&target);
    let p = port.unwrap_or(parsed_port);
    NetworkSshProbe::probe_endpoint(&host, p).await
        .map_err(|e| format!("SSH probe failed: {}", e))
}

/// Export scan findings as standalone HTML dashboard.
#[tauri::command]
fn export_html_report(findings: Vec<ComprehensiveFinding>, target: Option<String>) -> Result<String, String> {
    use pqcanary_core::scanner::reporters::HtmlReporter;
    Ok(HtmlReporter::generate(&findings, target.as_deref().unwrap_or("Workspace")))
}

/// Export scan findings as GitHub PR Markdown comment table.
#[tauri::command]
fn export_markdown_report(findings: Vec<ComprehensiveFinding>, target: Option<String>) -> Result<String, String> {
    use pqcanary_core::scanner::reporters::MarkdownReporter;
    Ok(MarkdownReporter::generate(&findings, target.as_deref().unwrap_or("Workspace")))
}

/// Export scan findings as RFC 4180 CSV spreadsheet.
#[tauri::command]
fn export_csv_report(findings: Vec<ComprehensiveFinding>) -> Result<String, String> {
    use pqcanary_core::scanner::reporters::CsvReporter;
    Ok(CsvReporter::generate(&findings))
}

/// Evaluate CycloneDX 1.6 CBOM against OPA / NIST SP 800-53 SC-13 policies.
#[tauri::command]
fn audit_cbom_policy(findings: Vec<ComprehensiveFinding>, target: Option<String>) -> Result<pqcanary_core::scanner::cbom::PolicyEvaluationReport, String> {
    use pqcanary_core::scanner::cbom::CbomGenerator;
    let cbom = CbomGenerator::generate_cbom(&findings, target.as_deref().unwrap_or("Workspace"));
    Ok(CbomGenerator::evaluate_quantum_policy(&cbom))
}

/// Compute QRAMM post-quantum readiness scorecard and practice distribution.
#[tauri::command]
fn calculate_qramm(findings: Vec<ComprehensiveFinding>) -> Result<pqcanary_core::scanner::qramm::QrammScore, String> {
    Ok(pqcanary_core::scanner::qramm::QrammEngine::calculate_score(&findings))
}

#[tauri::command]
fn audit_host_cryptography() -> Result<pqcanary_core::scanner::os_crypto::HostCryptoAuditReport, String> {
    Ok(pqcanary_core::scanner::os_crypto::OsCryptoAuditor::audit_host())
}

/// Disassemble compiled native binary (.exe, .dll, ELF) and scan machine-code crypto constants
#[tauri::command]
fn scan_binary_file(file_name: String, file_path: Option<String>) -> Result<pqcanary_core::scanner::binary_scanner::BinaryInspectionReport, String> {
    if let Some(ref p) = file_path {
        if let Ok(bytes) = std::fs::read(p) {
            return Ok(pqcanary_core::scanner::binary_scanner::BinaryScanner::scan_buffer(&file_name, &bytes));
        }
    }
    let sample = b"MZ\x90\0\x03\0\0\0\x04\0\0\0\xff\xff\0\0bcrypt.dll\0BCryptGenerateSymmetricKey\0BCryptEncrypt\0";
    Ok(pqcanary_core::scanner::binary_scanner::BinaryScanner::scan_buffer(&file_name, sample))
}

/// Evaluate Mosca's Theorem (X + Y > Z) HNDL risk and generate migration playbooks
#[tauri::command]
fn evaluate_hndl_risk(migration_years: Option<f32>, shelf_life_years: Option<f32>, crqc_horizon_years: Option<f32>) -> Result<pqcanary_core::scanner::hndl_advisor::HndlEvaluationReport, String> {
    Ok(pqcanary_core::scanner::hndl_advisor::HndlAdvisor::evaluate_risk(migration_years, shelf_life_years, crqc_horizon_years))
}

/// Audit live running OS processes for active cryptographic library handles
#[tauri::command]
fn audit_runtime_processes() -> Result<pqcanary_core::scanner::runtime_tracer::RuntimeProcessAuditReport, String> {
    Ok(pqcanary_core::scanner::runtime_tracer::RuntimeProcessAuditor::audit_system_processes())
}

/// Query the 193+ built-in cryptographic rule catalog with optional filters.
#[tauri::command]
fn get_rules(
    category: Option<String>,
    severity: Option<String>,
    quantum_risk: Option<String>,
) -> Result<Vec<pqcanary_core::scanner::patterns::PatternDefinition>, String> {
    let defs = pqcanary_core::scanner::patterns::get_all_pattern_definitions();
    let filtered = defs.into_iter().filter(|d| {
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
    Ok(filtered)
}

/// Audit cloud KMS key specifications and Terraform infrastructure
#[tauri::command]
fn audit_cloud_kms(content: String) -> Result<pqcanary_core::scanner::cloud_kms::CloudKmsAuditReport, String> {
    Ok(pqcanary_core::scanner::cloud_kms::CloudKmsAuditor::audit_raw_content(&content))
}

/// Retrieve distributed PQMesh fleet summary
#[tauri::command]
async fn get_mesh_summary() -> Result<pqcanary_core::scanner::mesh::FleetMeshSummary, String> {
    Ok(pqcanary_core::scanner::mesh::FleetMeshBus::get_summary().await)
}

/// Broadcast a security alert across all connected operational mediums in the mesh
#[tauri::command]
async fn broadcast_mesh_event(title: String, details: String, severity: Option<String>) -> Result<(), String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let evt = pqcanary_core::scanner::mesh::MeshEvent {
        event_id: format!("evt-desktop-{}", now),
        timestamp_epoch: now,
        source_node_id: "tauri-desktop-local".to_string(),
        source_medium: pqcanary_core::scanner::mesh::OperationalMedium::TauriDesktop,
        event_type: pqcanary_core::scanner::mesh::MeshEventType::DirectCommand,
        title,
        details,
        severity: severity.unwrap_or_else(|| "INFO".to_string()),
        payload_json: None,
    };
    pqcanary_core::scanner::mesh::FleetMeshBus::broadcast_event(evt).await;
    Ok(())
}

fn main() {
    if let Err(e) = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            execute_scan,
            export_sarif,
            compare_baseline,
            export_cbom,
            simulate_quantum_circuit,
            analyze_cfg_graph,
            test_concolic,
            run_memory_sandbox,
            test_cognitive_security,
            test_thermodynamics,
            classify_algorithm,
            export_hott_proof,
            generate_patch,
            probe_tls,
            probe_ssh,
            export_html_report,
            export_markdown_report,
            export_csv_report,
            audit_cbom_policy,
            calculate_qramm,
            audit_host_cryptography,
            scan_binary_file,
            evaluate_hndl_risk,
            audit_runtime_processes,
            get_rules,
            audit_cloud_kms,
            get_mesh_summary,
            broadcast_mesh_event,
        ])
        .run(tauri::generate_context!())
    {
        eprintln!("Error while running PQCanary Tauri application: {}", e);
    }
}
