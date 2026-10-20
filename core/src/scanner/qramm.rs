//! Quantum Risk Assessment and Migration Model (QRAMM) Engine
//!
//! Implements enterprise QRAMM dimension scoring (CVI - Cryptographic Vulnerability & Inventory),
//! computes overall Quantum Migration Readiness index, and prioritizes remediation via
//! weighted risk ranking of code assets.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::scanner::orchestrator::ComprehensiveFinding;

/// Standardized QRAMM assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrammScore {
    pub readiness_score: f64,
    pub posture_level: String, // "QUANTUM_RESILIENT", "TRANSITIONING", "AT_RISK"
    pub total_findings: usize,
    pub safe_count: usize,
    pub hybrid_count: usize,
    pub partial_count: usize,
    pub vulnerable_count: usize,
    pub critical_count: usize,
    pub practice_distribution: HashMap<String, usize>,
    pub by_primitive: HashMap<String, usize>,
    pub top_risk_files: Vec<FileRiskScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRiskScore {
    pub file_path: String,
    pub risk_weight: u32,
    pub vulnerable_findings: usize,
    pub critical_findings: usize,
}

pub struct QrammEngine;

impl QrammEngine {
    /// Calculate comprehensive QRAMM score and breakdown across all findings.
    pub fn calculate_score(findings: &[ComprehensiveFinding]) -> QrammScore {
        let mut safe_count = 0;
        let mut hybrid_count = 0;
        let mut partial_count = 0;
        let mut vulnerable_count = 0;
        let mut critical_count = 0;

        let mut practice_map: HashMap<String, usize> = HashMap::new();
        let mut primitive_map: HashMap<String, usize> = HashMap::new();
        let mut file_risk_map: HashMap<String, FileRiskScore> = HashMap::new();

        for f in findings {
            let q_risk = f.quantum_risk.as_deref().unwrap_or("UNKNOWN");
            let sev = f.severity.as_str();
            let rule = f.rule_id.as_deref().unwrap_or("");

            // Primitive categorization
            let prim = if rule.contains("ASYM") || rule.contains("RSA") || rule.contains("KEM") || rule.contains("DH") {
                "Asymmetric Key Exchange / KEM"
            } else if rule.contains("DSA") || rule.contains("SIG") || rule.contains("ED25519") || rule.contains("ECDSA") {
                "Digital Signatures"
            } else if rule.contains("SYM") || rule.contains("AES") || rule.contains("DES") || rule.contains("CIPHER") || rule.contains("CHACHA") {
                "Symmetric Encryption"
            } else if rule.contains("HASH") || rule.contains("MD5") || rule.contains("SHA") {
                "Cryptographic Hash Functions"
            } else if rule.contains("KDF") || rule.contains("PBKDF") || rule.contains("ARGON") || rule.contains("BCRYPT") {
                "Key Derivation (KDF)"
            } else if rule.contains("CERT") {
                "Certificates & PKI"
            } else if rule.contains("TLS") || rule.contains("SSH") || rule.contains("CONF") {
                "TLS & Network Configuration"
            } else if rule.contains("SECRET") {
                "Hardcoded Secrets & Key Material"
            } else {
                "General Cryptographic Primitives"
            };
            *primitive_map.entry(prim.to_string()).or_insert(0) += 1;

            // Practice mapping:
            // CVI-1.1: Discovery & Inventory (Classical & PQC algorithms, secrets)
            // CVI-1.2: Vulnerability Assessment (Quantum Vulnerable / Critical)
            // CVI-1.3: Dependency & Supply Chain Mapping (Manifests)
            let practice = if f.vulnerability_class.contains("Software Supply Chain") || f.vulnerability_class.contains("Dependency") {
                "CVI-1.3 (Dependency Mapping)".to_string()
            } else if q_risk == "VULNERABLE" || sev == "CRITICAL" {
                "CVI-1.2 (Vulnerability Assessment)".to_string()
            } else {
                "CVI-1.1 (Discovery & Inventory)".to_string()
            };
            *practice_map.entry(practice).or_insert(0) += 1;

            match q_risk {
                "SAFE" => safe_count += 1,
                "HYBRID" => hybrid_count += 1,
                "PARTIAL" => partial_count += 1,
                "VULNERABLE" => {
                    if sev == "CRITICAL" {
                        critical_count += 1;
                    } else {
                        vulnerable_count += 1;
                    }
                }
                _ => {
                    if sev == "CRITICAL" {
                        critical_count += 1;
                    } else {
                        partial_count += 1;
                    }
                }
            }

            // File risk accumulation
            let entry = file_risk_map.entry(f.file_path.clone()).or_insert_with(|| FileRiskScore {
                file_path: f.file_path.clone(),
                risk_weight: 0,
                vulnerable_findings: 0,
                critical_findings: 0,
            });

            if sev == "CRITICAL" {
                entry.risk_weight += 25;
                entry.critical_findings += 1;
            } else if q_risk == "VULNERABLE" {
                entry.risk_weight += 10;
                entry.vulnerable_findings += 1;
            } else if q_risk == "PARTIAL" {
                entry.risk_weight += 3;
            }
        }

        let total = findings.len();
        let readiness_score = if total > 0 {
            let numerator = (safe_count as f64) + (hybrid_count as f64 * 0.8) + (partial_count as f64 * 0.3);
            ((numerator / total as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            100.0
        };

        let posture_level = if readiness_score >= 80.0 {
            "QUANTUM_RESILIENT".to_string()
        } else if readiness_score >= 50.0 {
            "TRANSITIONING".to_string()
        } else {
            "AT_RISK".to_string()
        };

        let mut risk_files: Vec<FileRiskScore> = file_risk_map.into_values().collect();
        risk_files.sort_by_key(|b| std::cmp::Reverse(b.risk_weight));
        risk_files.truncate(5);

        QrammScore {
            readiness_score,
            posture_level,
            total_findings: total,
            safe_count,
            hybrid_count,
            partial_count,
            vulnerable_count,
            critical_count,
            practice_distribution: practice_map,
            by_primitive: primitive_map,
            top_risk_files: risk_files,
        }
    }

    /// Formats the QRAMM assessment summary as a Markdown card.
    pub fn to_markdown_summary(score: &QrammScore) -> String {
        let mut out = String::new();
        out.push_str("### QRAMM Quantum Migration Assessment\n\n");
        out.push_str(&format!(
            "- **Post-Quantum Readiness Score:** `{:.1}%` ({})\n",
            score.readiness_score, score.posture_level
        ));
        out.push_str(&format!(
            "- **Inventory Breakdown:** {} Total | {} Safe (PQC) | {} Hybrid | {} Partial | {} Vulnerable | {} Critical Broken\n\n",
            score.total_findings, score.safe_count, score.hybrid_count, score.partial_count, score.vulnerable_count, score.critical_count
        ));

        out.push_str("#### Cryptographic Asset Distribution by Primitive\n\n");
        out.push_str("| Primitive Category | Findings Count |\n");
        out.push_str("| :--- | :---: |\n");
        let mut sorted_primitives: Vec<_> = score.by_primitive.iter().collect();
        sorted_primitives.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (primitive, count) in sorted_primitives {
            out.push_str(&format!("| `{}` | **{}** |\n", primitive, count));
        }

        out.push_str("\n#### QRAMM Practice Distribution (CVI Dimension)\n\n");
        out.push_str("| Practice | Name | Detected Assets |\n");
        out.push_str("| :--- | :--- | :--- |\n");
        let mut sorted_practices: Vec<_> = score.practice_distribution.iter().collect();
        sorted_practices.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (practice, count) in sorted_practices {
            out.push_str(&format!("| `{}` | Cryptographic Control | **{}** |\n", practice, count));
        }

        if !score.top_risk_files.is_empty() {
            out.push_str("\n#### Top 5 High-Priority Quantum Risk Files\n\n");
            out.push_str("| File Path | Risk Score | Critical | Vulnerable |\n");
            out.push_str("| :--- | :--- | :--- | :--- |\n");
            for file in &score.top_risk_files {
                out.push_str(&format!(
                    "| `{}` | **{} pts** | {} | {} |\n",
                    file.file_path, file.risk_weight, file.critical_findings, file.vulnerable_findings
                ));
            }
        }

        out.push('\n');
        out
    }
}
