//! Cryptographic Agility Score (CAS) & Abstraction Auditor
//!
//! Evaluates codebases against NIST SP 800-227 Cryptographic Agility guidelines:
//! detects tightly-coupled hardcoded algorithm strings vs decoupled factory, provider,
//! and configuration-driven cryptographic abstractions.

use serde::{Serialize, Deserialize};
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgilityFinding {
    pub file_path: String,
    pub line_number: u32,
    pub pattern_type: String, // "HardcodedPrimitive", "DirectCipherInstantiation", "AgileAbstraction"
    pub snippet: String,
    pub is_agile: bool,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgilityReport {
    pub total_cryptographic_invocations: usize,
    pub hardcoded_calls: usize,
    pub agile_abstractions: usize,
    pub agility_score: f64, // 0.0 to 100.0
    pub agility_level: String, // "LEVEL_0_RIGID", "LEVEL_1_BASIC", "LEVEL_2_INTERMEDIATE", "LEVEL_3_HIGH", "LEVEL_4_FULLY_AGILE"
    pub description: String,
    pub findings: Vec<AgilityFinding>,
    pub migration_guidance: Vec<String>,
}

static RE_HARDCODED_CIPHER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(createCipher(?:iv)?\s*\(\s*['"][a-z0-9_-]+['"]|Cipher\.getInstance\s*\(\s*['"][a-zA-Z0-9_/]+['"]|EVP_get_cipherbyname\s*\(\s*['"][^'"]+['"]|crypto\.subtle\.(?:encrypt|decrypt|sign)\s*\(\s*['"][^'"]+['"])"#).unwrap()
});

static RE_HARDCODED_ALGO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(algorithm\s*[:=]\s*['"](?:AES|RSA|ECDSA|SHA256|ML-KEM|ML-DSA)[^'"]*['"])"#).unwrap()
});

static RE_AGILE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(getInstance\s*\(\s*[a-zA-Z0-9_.]+(?:config|algorithm|provider|spec)|createCipheriv\s*\(\s*[a-zA-Z0-9_.]+(?:algorithm|config|suite)|EVP_get_cipherbyname\s*\(\s*[a-zA-Z0-9_]+|Security\.addProvider|OSSL_PROVIDER_load)"#).unwrap()
});

pub struct AgilityScanner;

impl AgilityScanner {
    /// Audits a single source file for cryptographic agility
    pub fn audit_source(file_path: &str, content: &str) -> Vec<AgilityFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let line_num = (idx + 1) as u32;

            if RE_AGILE_CALL.is_match(line) {
                findings.push(AgilityFinding {
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    pattern_type: "AgileAbstraction".to_string(),
                    snippet: line.trim().to_string(),
                    is_agile: true,
                    recommendation: "Properly decoupled or configuration-driven cryptographic invocation detected.".to_string(),
                });
            } else if RE_HARDCODED_CIPHER.is_match(line) || RE_HARDCODED_ALGO.is_match(line) {
                findings.push(AgilityFinding {
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    pattern_type: "HardcodedPrimitive".to_string(),
                    snippet: line.trim().to_string(),
                    is_agile: false,
                    recommendation: "Refactor hardcoded cryptographic identifier into a centralized provider or configuration wrapper to enable seamless PQC algorithm substitution.".to_string(),
                });
            }
        }

        findings
    }

    /// Evaluates aggregate agility report from findings
    pub fn evaluate_report(findings: Vec<AgilityFinding>) -> AgilityReport {
        let total = findings.len();
        let agile_count = findings.iter().filter(|f| f.is_agile).count();
        let hardcoded_count = findings.iter().filter(|f| !f.is_agile).count();

        let score = if total == 0 {
            100.0 // No crypto debt
        } else {
            let ratio = (agile_count as f64) / (total as f64);
            (ratio * 1000.0).round() / 10.0
        };

        let (level, desc) = match score as u32 {
            85..=100 => ("LEVEL_4_FULLY_AGILE", "Excellent agility: cryptography is abstracted behind providers or configuration layers. PQC transition can occur without modifying business logic."),
            65..=84 => ("LEVEL_3_HIGH", "High agility: majority of cryptographic calls are centralized, though isolated hardcoded algorithm instances remain."),
            40..=64 => ("LEVEL_2_INTERMEDIATE", "Moderate agility: mixed direct and abstracted cryptographic calls. Migration requires selective refactoring of caller call-sites."),
            15..=39 => ("LEVEL_1_BASIC", "Low agility: extensive hardcoded cipher strings throughout business logic. High migration friction when adopting NIST PQC algorithms."),
            _ => ("LEVEL_0_RIGID", "Critical rigidity: cryptography is tightly coupled and hardcoded directly across the codebase. Every algorithm update will require broad codebase modification."),
        };

        let mut guidance = Vec::new();
        if hardcoded_count > 0 {
            guidance.push(format!("Isolate {} hardcoded cryptographic invocation(s) into a unified internal crypto service module.", hardcoded_count));
            guidance.push("Adopt parameter-driven algorithm selection (e.g., config.crypto.key_exchange = 'ML-KEM-768').".to_string());
            guidance.push("Implement factory patterns or register standard cryptographic providers (e.g. OpenSSL 3.0 oqs-provider) to decouple cipher suites from domain logic.".to_string());
        } else {
            guidance.push("Maintain existing abstraction layers and monitor NIST FIPS 203/204 updates.".to_string());
        }

        AgilityReport {
            total_cryptographic_invocations: total,
            hardcoded_calls: hardcoded_count,
            agile_abstractions: agile_count,
            agility_score: score,
            agility_level: level.to_string(),
            description: desc.to_string(),
            findings,
            migration_guidance: guidance,
        }
    }

    /// Formats report as clean Markdown
    pub fn format_markdown(rep: &AgilityReport) -> String {
        let mut out = String::new();
        out.push_str("# NIST SP 800-227 Cryptographic Agility Audit\n\n");
        out.push_str(&format!("- **Cryptographic Agility Score (CAS)**: `{:.1}/100` ({})\n", rep.agility_score, rep.agility_level));
        out.push_str(&format!("- **Total Crypto Calls Scanned**: `{}`\n", rep.total_cryptographic_invocations));
        out.push_str(&format!("- **Agile Abstractions**: `{}` | **Hardcoded Invocations**: `{}`\n\n", rep.agile_abstractions, rep.hardcoded_calls));
        out.push_str(&format!("{}\n\n", rep.description));

        if !rep.migration_guidance.is_empty() {
            out.push_str("### Recommended Refactorings\n");
            for g in &rep.migration_guidance {
                out.push_str(&format!("- {}\n", g));
            }
            out.push('\n');
        }

        if !rep.findings.is_empty() {
            out.push_str("### Call-Site Breakdown\n\n");
            out.push_str("| File | Line | Type | Agility Status | Recommendation |\n");
            out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
            for f in rep.findings.iter().take(50) {
                out.push_str(&format!(
                    "| `{}` | {} | `{}` | {} | {} |\n",
                    f.file_path,
                    f.line_number,
                    f.pattern_type,
                    if f.is_agile { "Agile" } else { "**Hardcoded**" },
                    f.recommendation
                ));
            }
        }

        out
    }
}
