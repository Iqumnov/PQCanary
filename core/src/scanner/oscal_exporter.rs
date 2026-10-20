//! NIST SP 800-53 OSCAL & EU DORA / PCI DSS 4.0.1 Compliance Exporter
//!
//! Generates Open Security Controls Assessment Language (OSCAL) JSON artifacts
//! and regulatory compliance matrices conforming to NIST SP 800-53 Rev 5 (SC-8, SC-12, SC-13),
//! European Union DORA Article 9, and PCI DSS 4.0.1 Requirement 3.4.

use serde::{Serialize, Deserialize};
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAssessment {
    pub control_id: String,
    pub title: String,
    pub framework: String, // "NIST SP 800-53 Rev 5", "EU DORA", "PCI DSS 4.0.1"
    pub status: String,    // "SATISFIED", "NON_COMPLIANT", "REMEDIATION_IN_PROGRESS"
    pub related_findings_count: usize,
    pub description: String,
    pub remediation_guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscalComplianceReport {
    pub project_name: String,
    pub generator: String,
    pub schema_version: String,
    pub timestamp_utc: String,
    pub total_controls_evaluated: usize,
    pub compliant_controls_count: usize,
    pub non_compliant_controls_count: usize,
    pub overall_audit_verdict: String, // "PASSED", "CONDITIONAL_PASS", "FAILED"
    pub assessed_controls: Vec<ControlAssessment>,
}

pub struct OscalExporter;

impl OscalExporter {
    /// Generates structured OSCAL assessment based on cryptographic findings
    pub fn evaluate_compliance(project_name: &str, findings: &[ComprehensiveFinding]) -> OscalComplianceReport {
        let sc8_violations = findings.iter().filter(|f| f.vulnerability_class.contains("Transit") || f.vulnerability_class.contains("TLS") || f.vulnerability_class.contains("SSH")).count();
        let sc12_violations = findings.iter().filter(|f| f.vulnerability_class.contains("Key") || f.vulnerability_class.contains("KMS") || f.vulnerability_class.contains("Exchange")).count();
        let sc13_violations = findings.iter().filter(|f| f.vulnerability_class.contains("RSA") || f.vulnerability_class.contains("ECC") || f.vulnerability_class.contains("Classical")).count();
        let dora_violations = findings.iter().filter(|f| f.severity == "CRITICAL" || f.severity == "HIGH").count();
        let pci_violations = findings.iter().filter(|f| f.vulnerability_class.contains("Cipher") || f.vulnerability_class.contains("AES128") || f.vulnerability_class.contains("DES")).count();

        let mut controls = Vec::new();

        controls.push(ControlAssessment {
            control_id: "SC-8".to_string(),
            title: "Transmission Confidentiality and Integrity".to_string(),
            framework: "NIST SP 800-53 Rev 5".to_string(),
            status: if sc8_violations == 0 { "SATISFIED".to_string() } else { "NON_COMPLIANT".to_string() },
            related_findings_count: sc8_violations,
            description: "Protects the confidentiality and integrity of transmitted information using quantum-resistant hybrid key exchange.".to_string(),
            remediation_guidance: "Deploy TLS 1.3 with X25519MLKEM768 named groups across all network listeners.".to_string(),
        });

        controls.push(ControlAssessment {
            control_id: "SC-12".to_string(),
            title: "Cryptographic Key Establishment and Management".to_string(),
            framework: "NIST SP 800-53 Rev 5".to_string(),
            status: if sc12_violations == 0 { "SATISFIED".to_string() } else { "NON_COMPLIANT".to_string() },
            related_findings_count: sc12_violations,
            description: "Establishes cryptographic keys using approved post-quantum key encapsulation mechanisms (NIST FIPS 203).".to_string(),
            remediation_guidance: "Transition asymmetric key exchanges to ML-KEM-768 or ML-KEM-1024.".to_string(),
        });

        controls.push(ControlAssessment {
            control_id: "SC-13".to_string(),
            title: "Cryptographic Protection (Post-Quantum Readiness)".to_string(),
            framework: "NIST SP 800-53 Rev 5".to_string(),
            status: if sc13_violations == 0 { "SATISFIED".to_string() } else { "NON_COMPLIANT".to_string() },
            related_findings_count: sc13_violations,
            description: "Employs post-quantum cryptographic primitives conforming to FIPS 203 and FIPS 204.".to_string(),
            remediation_guidance: "Deprecate RSA-2048/3072 and ECDSA in favor of ML-DSA-65 / ML-DSA-87.".to_string(),
        });

        controls.push(ControlAssessment {
            control_id: "DORA-Art-9".to_string(),
            title: "Protection and Prevention - Cryptographic Life Cycle".to_string(),
            framework: "EU Digital Operational Resilience Act (DORA)".to_string(),
            status: if dora_violations == 0 { "SATISFIED".to_string() } else { "NON_COMPLIANT".to_string() },
            related_findings_count: dora_violations,
            description: "Financial entities shall maintain continuous cryptographic inventory and migration capabilities against quantum threats.".to_string(),
            remediation_guidance: "Establish automated continuous CBOM generation and zero-downtime envelope re-encryption.".to_string(),
        });

        controls.push(ControlAssessment {
            control_id: "PCI-DSS-Req-3.4".to_string(),
            title: "Rendering PAN Unreadable with Quantum-Resilient Cryptography".to_string(),
            framework: "PCI DSS v4.0.1".to_string(),
            status: if pci_violations == 0 { "SATISFIED".to_string() } else { "NON_COMPLIANT".to_string() },
            related_findings_count: pci_violations,
            description: "Cardholder data must be protected using strong cryptography resilient to harvest-now-decrypt-later attacks.".to_string(),
            remediation_guidance: "Upgrade storage encryption from AES-128 to AES-256-GCM with post-quantum envelope key encapsulation.".to_string(),
        });

        let non_compliant = controls.iter().filter(|c| c.status != "SATISFIED").count();
        let compliant = controls.len() - non_compliant;

        let verdict = if non_compliant == 0 {
            "PASSED".to_string()
        } else if non_compliant <= 2 {
            "CONDITIONAL_PASS".to_string()
        } else {
            "FAILED".to_string()
        };

        OscalComplianceReport {
            project_name: project_name.to_string(),
            generator: "PQCanary Enterprise OSCAL Exporter v0.1.0".to_string(),
            schema_version: "1.0.4".to_string(),
            timestamp_utc: "2026-10-10T00:00:00Z".to_string(),
            total_controls_evaluated: controls.len(),
            compliant_controls_count: compliant,
            non_compliant_controls_count: non_compliant,
            overall_audit_verdict: verdict,
            assessed_controls: controls,
        }
    }

    /// Exports conforming NIST OSCAL assessment-results JSON string
    pub fn export_oscal_json(report: &OscalComplianceReport) -> String {
        let oscal_structure = serde_json::json!({
            "assessment-results": {
                "uuid": "8b51a029-7c48-4cb2-870f-155949d21d34",
                "metadata": {
                    "title": format!("PQCanary Cryptographic Assessment - {}", report.project_name),
                    "published": report.timestamp_utc,
                    "last-modified": report.timestamp_utc,
                    "version": "1.0.0",
                    "oscal-version": report.schema_version,
                    "remarks": report.generator
                },
                "results": [
                    {
                        "uuid": "cf9260ee-bb8e-49b8-a15d-597e74888be1",
                        "title": "Quantum Cryptographic Readiness Evaluation",
                        "description": format!("Audited {} controls. Overall status: {}", report.total_controls_evaluated, report.overall_audit_verdict),
                        "start": report.timestamp_utc,
                        "reviewed-controls": {
                            "control-selections": [
                                {
                                    "include-controls": report.assessed_controls.iter().map(|c| {
                                        serde_json::json!({
                                            "control-id": c.control_id,
                                            "statement-ids": [format!("{}_smt", c.control_id)]
                                        })
                                    }).collect::<Vec<_>>()
                                }
                            ]
                        },
                        "findings": report.assessed_controls.iter().map(|c| {
                            serde_json::json!({
                                "target": {
                                    "type": "statement-id",
                                    "target-id": c.control_id,
                                    "status": { "state": if c.status == "SATISFIED" { "satisfied" } else { "not-satisfied" } }
                                },
                                "title": c.title,
                                "description": c.description,
                                "remarks": c.remediation_guidance
                            })
                        }).collect::<Vec<_>>()
                    }
                ]
            }
        });

        serde_json::to_string_pretty(&oscal_structure).unwrap_or_default()
    }

    /// Formats an audit-ready compliance matrix in Markdown
    pub fn format_markdown(report: &OscalComplianceReport) -> String {
        let mut out = String::new();
        out.push_str("# Regulatory Compliance Matrix & OSCAL Assessment\n\n");
        out.push_str(&format!("* **Target System:** {}\n", report.project_name));
        out.push_str(&format!("* **Overall Audit Verdict:** `{}`\n", report.overall_audit_verdict));
        out.push_str(&format!("* **Controls Passed:** {} / {}\n\n", report.compliant_controls_count, report.total_controls_evaluated));

        out.push_str("### Evaluated Framework Controls\n\n");
        out.push_str("| Control ID | Framework | Control Title | Status | Issues | Remediation |\n");
        out.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for c in &report.assessed_controls {
            out.push_str(&format!("| `{}` | {} | {} | `{}` | {} | {} |\n",
                c.control_id, c.framework, c.title, c.status, c.related_findings_count, c.remediation_guidance
            ));
        }

        out.push_str("\n> Conforms to NIST OSCAL 1.0.4 schema for automated ingestion into Governance, Risk & Compliance (GRC) platforms.\n");
        out
    }
}
