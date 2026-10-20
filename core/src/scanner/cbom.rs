//! CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Exporter
//! Compliant with OWASP CycloneDX 1.6 Specification for Cryptographic Assets.
//!
//! Includes standards mapping (NIST SP 800-53 Rev 5 SC-13, ISO/IEC 27001 A.8.24, CNSA 2.0),
//! cryptographic Object Identifiers (OIDs), and automated OPA-style policy compliance auditing.

use serde::{Serialize, Deserialize};
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxCbom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: CbomMetadata,
    pub components: Vec<CbomComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomMetadata {
    pub timestamp: String,
    pub tools: Vec<CbomTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomComponent {
    pub r#type: String, // "cryptographic-asset"
    pub name: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "cryptoProperties")]
    pub crypto_properties: CryptoProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: String, // "algorithm", "certificate", "key", "protocol"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub standards: Vec<String>,
    #[serde(rename = "algorithmProperties")]
    pub algorithm_properties: AlgorithmProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmProperties {
    pub primitive: String,
    #[serde(rename = "classicalSecurityLevel")]
    pub classical_security_level: u32,
    #[serde(rename = "nistQuantumSecurityLevel")]
    pub nist_quantum_security_level: u8,
    #[serde(rename = "quantumRefinement")]
    pub quantum_refinement: String, // "post-quantum-safe", "quantum-vulnerable", "classically-broken", "hybrid"
    #[serde(rename = "executionLocation")]
    pub execution_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationReport {
    pub total_assets: usize,
    pub compliant_assets: usize,
    pub non_compliant_assets: usize,
    pub compliance_rate_percent: f64,
    pub status: String, // "PASSED", "WARNING", "FAILED"
    pub violations: Vec<PolicyViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub bom_ref: String,
    pub asset_name: String,
    pub rule: String,
    pub reason: String,
    pub location: String,
}

pub struct CbomGenerator;

impl CbomGenerator {
    /// Convert a set of PQCanary security findings into a formal CycloneDX 1.6 CBOM document.
    pub fn generate_cbom(findings: &[ComprehensiveFinding], _target_path: &str) -> CycloneDxCbom {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Format as ISO 8601 UTC: YYYY-MM-DDTHH:MM:SSZ
        let epoch_days = secs / 86400;
        let secs_of_day = secs % 86400;
        let hh = secs_of_day / 3600;
        let mm = (secs_of_day % 3600) / 60;
        let ss = secs_of_day % 60;
        let mut y = 1970u64;
        let mut d = epoch_days;
        #[allow(clippy::manual_is_multiple_of)]
        let is_leap_year = |year: u64| -> bool { (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 };
        loop {
            let days_in_year = if is_leap_year(y) { 366 } else { 365 };
            if d < days_in_year { break; }
            d -= days_in_year;
            y += 1;
        }
        let month_days = [31u64, if is_leap_year(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut month = 1u64;
        for mdays in &month_days {
            if d < *mdays { break; }
            d -= mdays;
            month += 1;
        }
        let day = d + 1;
        let timestamp = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, month, day, hh, mm, ss);
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(secs.to_be_bytes());
        hasher.update((findings.len() as u64).to_be_bytes());
        let hash = hasher.finalize();
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&hash[0..16]);
        uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40; // Version 4
        uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80; // Variant 1
        let serial = format!(
            "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
            uuid_bytes[4], uuid_bytes[5],
            uuid_bytes[6], uuid_bytes[7],
            uuid_bytes[8], uuid_bytes[9],
            uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
        );

        let mut components = Vec::with_capacity(findings.len());

        for (idx, finding) in findings.iter().enumerate() {
            let rule_id = finding.rule_id.as_deref().unwrap_or("");
            let q_risk = finding.quantum_risk.as_deref().unwrap_or("");

            let (quantum_status, nist_level, prim, oid, standards) = match rule_id {
                r if r.contains("MLKEM") || r.contains("KYBER") => (
                    "post-quantum-safe",
                    3,
                    "kem",
                    Some("2.16.840.1.101.3.4.4.2".to_string()),
                    vec!["NIST FIPS 203".to_string(), "NIST SP 800-53 SC-13".to_string(), "CNSA 2.0".to_string()],
                ),
                r if r.contains("MLDSA") || r.contains("DILITHIUM") => (
                    "post-quantum-safe",
                    3,
                    "signature",
                    Some("2.16.840.1.101.3.4.3.18".to_string()),
                    vec!["NIST FIPS 204".to_string(), "NIST SP 800-53 SC-13".to_string(), "CNSA 2.0".to_string()],
                ),
                r if r.contains("SLHDSA") || r.contains("SPHINCS") => (
                    "post-quantum-safe",
                    5,
                    "signature",
                    Some("2.16.840.1.101.3.4.3.22".to_string()),
                    vec!["NIST FIPS 205".to_string(), "NIST SP 800-53 SC-13".to_string()],
                ),
                r if r.contains("FALCON") || r.contains("FNDSA") => (
                    "post-quantum-safe",
                    5,
                    "signature",
                    Some("1.3.9999.3.1".to_string()),
                    vec!["NIST FIPS 206".to_string(), "NIST SP 800-53 SC-13".to_string()],
                ),
                r if r.contains("LMS") || r.contains("XMSS") || r.contains("STATEFUL") => (
                    "post-quantum-safe",
                    5,
                    "signature",
                    Some("1.2.840.113549.1.9.16.3.17".to_string()),
                    vec!["NIST SP 800-208".to_string(), "RFC 8554".to_string(), "RFC 8391".to_string()],
                ),
                r if r.contains("BIKE") => (
                    "post-quantum-safe",
                    1,
                    "kem",
                    None,
                    vec!["NIST Round 4 Alternate".to_string(), "QC-MDPC".to_string()],
                ),
                r if r.contains("HQC") => (
                    "post-quantum-safe",
                    1,
                    "kem",
                    None,
                    vec!["NIST Round 4 Alternate".to_string(), "Hamming Quasi-Cyclic".to_string()],
                ),
                r if r.contains("MCELIECE") => (
                    "post-quantum-safe",
                    5,
                    "kem",
                    None,
                    vec!["NIST Round 4 Alternate".to_string(), "Classic McEliece Goppa".to_string()],
                ),
                r if r.contains("FRODO") => (
                    "post-quantum-safe",
                    3,
                    "kem",
                    None,
                    vec!["ISO/IEC 14888-4".to_string(), "BSI/ANSSI PQC Recommendation".to_string(), "Conservative Plain-LWE".to_string()],
                ),
                r if r.contains("NTRU") || r.contains("SNTRUP") => (
                    "post-quantum-safe",
                    3,
                    "kem",
                    None,
                    vec!["OpenSSH Hybrid PQC".to_string(), "Streamlined NTRU Prime sntrup761".to_string()],
                ),
                r if r.contains("RSA") => (
                    "quantum-vulnerable",
                    0,
                    "public-key",
                    Some("1.2.840.113549.1.1.1".to_string()),
                    vec!["NIST SP 800-53 SC-13 (Transition Required)".to_string(), "ISO/IEC 27001 A.8.24".to_string(), "PCI DSS v4.0.1 Req 12.3.3".to_string(), "NIST SP 800-227".to_string()],
                ),
                r if r.contains("ECC") || r.contains("ECDSA") || r.contains("ECDH") => (
                    "quantum-vulnerable",
                    0,
                    "keyagree",
                    Some("1.2.840.10045.2.1".to_string()),
                    vec!["NIST SP 800-53 SC-13 (Transition Required)".to_string(), "PCI DSS v4.0.1 Req 12.3.3".to_string(), "NIST SP 800-227".to_string()],
                ),
                r if r.contains("MD5") => (
                    "classically-broken",
                    0,
                    "hash",
                    Some("1.2.840.113549.2.5".to_string()),
                    vec!["NIST SP 800-131A (Disallowed)".to_string(), "PCI DSS v4.0.1 Req 12.3.3".to_string()],
                ),
                r if r.contains("SHA1") => (
                    "classically-broken",
                    0,
                    "hash",
                    Some("1.3.14.3.2.26".to_string()),
                    vec!["NIST SP 800-131A (Disallowed)".to_string(), "PCI DSS v4.0.1 Req 12.3.3".to_string()],
                ),
                r if r.contains("AES") => (
                    "post-quantum-safe",
                    1,
                    "symmetric-cipher",
                    Some("2.16.840.1.101.3.4.1.46".to_string()),
                    vec!["NIST FIPS 197".to_string(), "NIST SP 800-53 SC-13".to_string(), "PCI DSS v4.0.1 Req 12.3.3".to_string()],
                ),
                r if r.contains("CHACHA") => (
                    "post-quantum-safe",
                    1,
                    "symmetric-cipher",
                    Some("1.2.840.113549.1.9.16.3.18".to_string()),
                    vec!["RFC 8439".to_string(), "NIST SP 800-53 SC-13".to_string(), "PCI DSS v4.0.1 Req 12.3.3".to_string()],
                ),
                r if r.contains("DES") || r.contains("RC4") || r.contains("BLOWFISH") => (
                    "classically-broken",
                    0,
                    "symmetric-cipher",
                    Some("1.2.840.113549.3.4".to_string()),
                    vec!["NIST SP 800-131A (Disallowed)".to_string(), "CWE-327".to_string(), "PCI DSS v4.0.1 Req 12.3.3".to_string()],
                ),
                r if r.contains("SHA256") || r.contains("SHA384") || r.contains("SHA512") || r.contains("SHA3") || r.contains("SHAKE") => (
                    "post-quantum-safe",
                    1,
                    "hash",
                    Some("2.16.840.1.101.3.4.2.1".to_string()),
                    vec!["NIST FIPS 180-4".to_string(), "NIST FIPS 202".to_string()],
                ),
                r if r.contains("X25519") => (
                    "quantum-vulnerable",
                    0,
                    "keyagree",
                    Some("1.3.101.110".to_string()),
                    vec!["RFC 7748".to_string(), "NIST SP 800-53 SC-13 (Transition Required)".to_string()],
                ),
                r if r.contains("ED25519") => (
                    "quantum-vulnerable",
                    0,
                    "signature",
                    Some("1.3.101.112".to_string()),
                    vec!["RFC 8032".to_string(), "NIST SP 800-53 SC-13 (Transition Required)".to_string()],
                ),
                _ => match finding.vulnerability_class.as_str() {
                    "Hardcoded Cryptographic Secret" => (
                        "classically-broken",
                        0,
                        "secret-key",
                        None,
                        vec!["CWE-798".to_string(), "NIST SP 800-53 IA-7".to_string()],
                    ),
                    "Weak Cryptographic Hash" | "Weak Symmetric Cipher" => (
                        "classically-broken",
                        0,
                        "hash",
                        None,
                        vec!["NIST SP 800-131A".to_string()],
                    ),
                    _ => {
                        let status = match q_risk {
                            "SAFE" => "post-quantum-safe",
                            "HYBRID" => "hybrid",
                            "PARTIAL" => "partial",
                            _ => "quantum-vulnerable",
                        };
                        let nist = if status == "post-quantum-safe" { 3 } else { 0 };
                        (status, nist, "algorithm", None, vec!["NIST SP 800-53 SC-13".to_string()])
                    }
                },
            };

            components.push(CbomComponent {
                r#type: "cryptographic-asset".to_string(),
                name: finding.vulnerability_class.clone(),
                bom_ref: format!("crypto-asset-{}", idx + 1),
                crypto_properties: CryptoProperties {
                    asset_type: "algorithm".to_string(),
                    oid,
                    standards,
                    algorithm_properties: AlgorithmProperties {
                        primitive: prim.to_string(),
                        classical_security_level: if quantum_status == "classically-broken" { 0 } else { 128 },
                        nist_quantum_security_level: nist_level,
                        quantum_refinement: quantum_status.to_string(),
                        execution_location: format!("{}:L{}", finding.file_path, finding.line_number),
                    },
                },
            });
        }

        CycloneDxCbom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            serial_number: serial,
            version: 1,
            metadata: CbomMetadata {
                timestamp,
                tools: vec![CbomTool {
                    vendor: "PQCanary (Matvei Igumnov)".to_string(),
                    name: "PQCanary Post-Quantum Security Scanner".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }],
            },
            components,
        }
    }

    /// Evaluates cryptographic assets against NIST SP 800-53 SC-13 & post-quantum security policies.
    /// Emulates Open Policy Agent (OPA) / CBOMKit enterprise compliance gates.
    pub fn evaluate_quantum_policy(cbom: &CycloneDxCbom) -> PolicyEvaluationReport {
        let total_assets = cbom.components.len();
        let mut violations = Vec::new();
        let mut compliant_assets = 0;

        for comp in &cbom.components {
            let props = &comp.crypto_properties.algorithm_properties;
            let mut is_compliant = true;

            // Policy Rule 1: Asymmetric algorithms must have NIST quantum level >= 1 or be post-quantum safe
            if (props.primitive == "public-key" || props.primitive == "keyagree" || props.primitive == "kem" || props.primitive == "signature")
                && (props.quantum_refinement == "quantum-vulnerable" || props.nist_quantum_security_level == 0) {
                    violations.push(PolicyViolation {
                        bom_ref: comp.bom_ref.clone(),
                        asset_name: comp.name.clone(),
                        rule: "NIST_SP_800_53_SC13_QUANTUM_SAFE".to_string(),
                        reason: format!(
                            "Asymmetric asset '{}' is classified as '{}' with NIST quantum level {}. Must migrate to NIST FIPS 203/204/205.",
                            comp.name, props.quantum_refinement, props.nist_quantum_security_level
                        ),
                        location: props.execution_location.clone(),
                    });
                    is_compliant = false;
                }

            // Policy Rule 2: Classically broken primitives are strictly forbidden
            if props.quantum_refinement == "classically-broken" {
                violations.push(PolicyViolation {
                    bom_ref: comp.bom_ref.clone(),
                    asset_name: comp.name.clone(),
                    rule: "CLASSICAL_BROKEN_DISALLOWED".to_string(),
                    reason: format!(
                        "Asset '{}' uses a classically broken cryptographic algorithm or exposed secret key.",
                        comp.name
                    ),
                    location: props.execution_location.clone(),
                });
                is_compliant = false;
            }

            if is_compliant {
                compliant_assets += 1;
            }
        }

        let non_compliant_assets = total_assets - compliant_assets;
        let compliance_rate_percent = if total_assets == 0 {
            100.0
        } else {
            (compliant_assets as f64 / total_assets as f64) * 100.0
        };

        let status = if violations.is_empty() {
            "PASSED".to_string()
        } else if compliance_rate_percent >= 75.0 {
            "WARNING".to_string()
        } else {
            "FAILED".to_string()
        };

        PolicyEvaluationReport {
            total_assets,
            compliant_assets,
            non_compliant_assets,
            compliance_rate_percent,
            status,
            violations,
        }
    }

    /// Export CBOM document as pretty JSON string.
    pub fn to_json(cbom: &CycloneDxCbom) -> String {
        serde_json::to_string_pretty(cbom).unwrap_or_else(|_| "{}".to_string())
    }

    /// Export CBOM document as a GitHub-Flavored Markdown table report.
    pub fn to_markdown_table(cbom: &CycloneDxCbom) -> String {
        let mut md = String::new();
        md.push_str("# Cryptographic Bill of Materials (CBOM)\n\n");
        md.push_str(&format!("**Format**: OWASP CycloneDX v{} | **Serial**: `{}`\n", cbom.spec_version, cbom.serial_number));
        md.push_str(&format!("**Generated**: `{}` by PQCanary Engine v{}\n\n", cbom.metadata.timestamp, env!("CARGO_PKG_VERSION")));

        if cbom.components.is_empty() {
            md.push_str("No cryptographic vulnerabilities or insecure assets detected.\n");
            return md;
        }

        md.push_str("| # | Asset / Vulnerability Class | Execution Location | Primitive | Quantum Status | Standards | OID |\n");
        md.push_str("|---|---|---|---|---|---|---|\n");

        for (idx, comp) in cbom.components.iter().enumerate() {
            let props = &comp.crypto_properties.algorithm_properties;
            let status_badge = match props.quantum_refinement.as_str() {
                "classically-broken" => "CRITICAL: Classically Broken",
                "quantum-vulnerable" => "HIGH: Quantum Vulnerable",
                "post-quantum-safe"  => "SAFE: Post-Quantum Safe",
                "hybrid"             => "HYBRID: Hybrid (PQC + Classical)",
                _ => "INFO: Unknown",
            };

            let std_str = if comp.crypto_properties.standards.is_empty() {
                "-".to_string()
            } else {
                comp.crypto_properties.standards.join(", ")
            };
            let oid_str = comp.crypto_properties.oid.as_deref().unwrap_or("-");

            let comp_name = comp.name.replace('|', "\\|").replace('\n', " ");
            let exec_loc = props.execution_location.replace('|', "\\|").replace('\n', " ");
            let prim_str = props.primitive.replace('|', "\\|").replace('\n', " ");
            let std_clean = std_str.replace('|', "\\|").replace('\n', " ");

            md.push_str(&format!(
                "| {} | `{}` | `{}` | `{}` | {} | {} | `{}` |\n",
                idx + 1,
                comp_name,
                exec_loc,
                prim_str,
                status_badge,
                std_clean,
                oid_str,
            ));
        }

        // Include policy summary
        let policy_report = Self::evaluate_quantum_policy(cbom);
        md.push_str(&format!(
            "\n### Policy Compliance Audit: **{}** ({:.1}% Compliance — {}/{} Compliant Assets)\n\n",
            policy_report.status,
            policy_report.compliance_rate_percent,
            policy_report.compliant_assets,
            policy_report.total_assets
        ));

        if !policy_report.violations.is_empty() {
            md.push_str("| Violation Rule | Asset | Location | Reason |\n");
            md.push_str("|---|---|---|---|\n");
            for v in &policy_report.violations {
                let rule_clean = v.rule.replace('|', "\\|").replace('\n', " ");
                let asset_clean = v.asset_name.replace('|', "\\|").replace('\n', " ");
                let loc_clean = v.location.replace('|', "\\|").replace('\n', " ");
                let reason_clean = v.reason.replace('|', "\\|").replace('\n', " ");
                md.push_str(&format!("| `{}` | `{}` | `{}` | {} |\n", rule_clean, asset_clean, loc_clean, reason_clean));
            }
        }

        md.push_str("\n---\n*Report generated automatically by PQCanary Post-Quantum Security Scanner.*\n");
        md
    }
}
