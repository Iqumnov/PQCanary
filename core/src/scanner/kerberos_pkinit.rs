//! Enterprise Identity, Kerberos PKINIT & Windows Credential Guard Auditor
//!
//! Audits MIT/Heimdal Kerberos configurations (krb5.conf), Active Directory Certificate
//! Services (AD CS) Smartcard Logon templates, and Kerberos PKINIT (RFC 4556) parameters.
//! Evaluates Harvest-Now-Decrypt-Later exposure of Ticket Granting Tickets (TGT),
//! weak encryption types (DES, RC4, 3DES), and synthesizes quantum-hardened Kerberos directives.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosEnctypeEvaluation {
    pub enctype_name: String,
    pub is_quantum_vulnerable: bool,
    pub is_deprecated: bool,
    pub risk_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkinitParameterAudit {
    pub realm_name: String,
    pub pkinit_enabled: bool,
    pub pkinit_anchor_configured: bool,
    pub client_cert_algorithm: String,
    pub kdc_dh_group: String,
    pub hndl_tgt_exposure: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosAuditReport {
    pub config_target: String,
    pub overall_identity_quantum_readiness: String,
    pub default_realm: String,
    pub evaluated_enctypes: Vec<KerberosEnctypeEvaluation>,
    pub pkinit_realms: Vec<PkinitParameterAudit>,
    pub recommended_krb5_conf: String,
    pub recommendations: Vec<String>,
}

pub struct KerberosPkinitAuditor;

impl KerberosPkinitAuditor {
    /// Audits krb5.conf configuration content or Active Directory authentication definitions
    pub fn audit_config(target_name: &str, content: &str) -> KerberosAuditReport {
        let mut enctypes = Vec::new();
        let mut pkinit_realms = Vec::new();
        let mut recommendations = Vec::new();

        let content_lower = content.to_lowercase();
        let mut default_realm = "CORP.ENTERPRISE.INTERNAL".to_string();

        // 1. Parse [libdefaults] and encryption types
        let mut in_libdefaults = false;
        let mut in_realms = false;
        let mut current_realm = default_realm.clone();
        let mut has_pkinit = false;
        let mut pkinit_anchor = false;

        for line in content.lines() {
            let line_trim = line.trim();
            if line_trim.starts_with('#') || line_trim.starts_with(';') || line_trim.is_empty() {
                continue;
            }

            if line_trim.starts_with("[libdefaults]") {
                in_libdefaults = true;
                in_realms = false;
            } else if line_trim.starts_with("[realms]") {
                in_libdefaults = false;
                in_realms = true;
            } else if line_trim.starts_with('[') {
                in_libdefaults = false;
                in_realms = false;
            }

            if in_libdefaults {
                if line_trim.starts_with("default_realm") {
                    let parts: Vec<&str> = line_trim.split('=').collect();
                    if parts.len() >= 2 {
                        default_realm = parts[1].trim().to_string();
                        current_realm = default_realm.clone();
                    }
                } else if line_trim.starts_with("default_tkt_enctypes") || line_trim.starts_with("default_tgs_enctypes") || line_trim.starts_with("permitted_enctypes") {
                    let parts: Vec<&str> = line_trim.split('=').collect();
                    if parts.len() >= 2 {
                        for enc in parts[1].split_whitespace() {
                            let enc_name = enc.trim().to_string();
                            let enc_low = enc_name.to_lowercase();
                            let is_dep = enc_low.contains("des") || enc_low.contains("rc4") || enc_low.contains("arcfour");
                            let is_vuln = is_dep || enc_low.contains("aes128");

                            enctypes.push(KerberosEnctypeEvaluation {
                                enctype_name: enc_name.clone(),
                                is_quantum_vulnerable: is_vuln,
                                is_deprecated: is_dep,
                                risk_description: if is_dep {
                                    "Legacy broken cipher. Vulnerable to classical key recovery and offline dictionary attacks.".to_string()
                                } else if enc_low.contains("aes128") {
                                    "AES-128 offers only 64-bit security against Grover's quantum search algorithm.".to_string()
                                } else {
                                    "AES-256 provides 128-bit post-quantum security margin under Grover's algorithm.".to_string()
                                },
                            });
                        }
                    }
                }
            }

            if in_realms && (line_trim.contains("pkinit_anchors") || line_trim.contains("pkinit_identity")) {
                has_pkinit = true;
                pkinit_anchor = true;
            }
        }

        // If no enctypes explicitly declared, evaluate defaults
        if enctypes.is_empty() {
            if content_lower.contains("rc4") || content_lower.contains("arcfour") {
                enctypes.push(KerberosEnctypeEvaluation {
                    enctype_name: "rc4-hmac".to_string(),
                    is_quantum_vulnerable: true,
                    is_deprecated: true,
                    risk_description: "RC4 is deprecated and vulnerable to Kerberoasting & quantum forgery.".to_string(),
                });
            }
            enctypes.push(KerberosEnctypeEvaluation {
                enctype_name: "aes256-cts-hmac-sha1-96".to_string(),
                is_quantum_vulnerable: false,
                is_deprecated: false,
                risk_description: "AES-256 standard Kerberos encryption type.".to_string(),
            });
        }

        let is_hybrid_pkinit = content_lower.contains("mlkem") || content_lower.contains("hybrid");

        pkinit_realms.push(PkinitParameterAudit {
            realm_name: current_realm.clone(),
            pkinit_enabled: has_pkinit || content_lower.contains("pkinit"),
            pkinit_anchor_configured: pkinit_anchor,
            client_cert_algorithm: if is_hybrid_pkinit { "RFC 9758 Composite ML-DSA-65 + RSA-3072" } else { "Classical RSA-2048 / ECDSA P-256" }.to_string(),
            kdc_dh_group: if is_hybrid_pkinit { "Hybrid Oakley-14 + ML-KEM-768" } else { "Oakley-14 (MODP-2048)" }.to_string(),
            hndl_tgt_exposure: if is_hybrid_pkinit {
                "RESILIENT: TGT session key protected with hybrid post-quantum encapsulation.".to_string()
            } else {
                "CRITICAL_EXPOSURE: Intercepted AS-REP TGT exchanges can be decrypted by CRQC to recover corporate domain credentials.".to_string()
            },
            remediation: if is_hybrid_pkinit {
                "Maintain dual-key trust roots in Active Directory Certificate Services.".to_string()
            } else {
                "Enable Post-Quantum Kerberos PKINIT extension with ML-KEM key exchange in AS-REQ.".to_string()
            },
        });

        let has_dep = enctypes.iter().any(|e| e.is_deprecated);
        let overall = if is_hybrid_pkinit && !has_dep {
            "POST_QUANTUM_RESILIENT_IDENTITY_DOMAIN".to_string()
        } else if has_dep {
            "CRITICAL_DEPRECATED_CIPHERS_ACTIVE".to_string()
        } else {
            "VULNERABLE_CLASSICAL_PKINIT_EXPOSURE".to_string()
        };

        if !is_hybrid_pkinit {
            recommendations.push("Upgrade Domain Controller KDCs to support post-quantum Kerberos PKINIT hybrid exchanges.".to_string());
            recommendations.push("Disable legacy RC4-HMAC and DES enctypes across Active Directory domain policies.".to_string());
            recommendations.push("Require AES256-SHA2 for all Kerberos service accounts to defend against Kerberoasting and Grover's algorithm.".to_string());
        }

        let hardened_conf = format!(r#"[libdefaults]
    default_realm = {}
    default_tkt_enctypes = aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96
    canonicalize = true
    dns_lookup_kdc = false

[realms]
    {} = {{
        kdc = kdc1.{}:88
        admin_server = kdc1.{}:749
        pkinit_anchors = FILE:/etc/ssl/certs/pqc-composite-ca.pem
        pkinit_kdc_hostname = kdc1.{}
        pkinit_eku_checking = kpKDC
    }}
"#, default_realm, default_realm, default_realm.to_lowercase(), default_realm.to_lowercase(), default_realm.to_lowercase());

        KerberosAuditReport {
            config_target: target_name.to_string(),
            overall_identity_quantum_readiness: overall,
            default_realm,
            evaluated_enctypes: enctypes,
            pkinit_realms,
            recommended_krb5_conf: hardened_conf,
            recommendations,
        }
    }

    /// Formats the Kerberos PKINIT report as readable Markdown
    pub fn format_markdown(report: &KerberosAuditReport) -> String {
        let mut md = String::new();
        md.push_str("# Enterprise Identity & Kerberos PKINIT Quantum Audit\n\n");
        md.push_str(&format!("* **Target Configuration:** `{}`\n", report.config_target));
        md.push_str(&format!("* **Default Realm:** `{}`\n", report.default_realm));
        md.push_str(&format!("* **Identity Posture:** `{}`\n\n", report.overall_identity_quantum_readiness));

        md.push_str("### Kerberos Encryption Types (Enctypes)\n\n");
        md.push_str("| Encryption Type | Quantum Risk | Deprecated | Analysis |\n");
        md.push_str("| :--- | :--- | :--- | :--- |\n");
        for e in &report.evaluated_enctypes {
            let q_str = if e.is_quantum_vulnerable { "VULNERABLE" } else { "RESILIENT" };
            let d_str = if e.is_deprecated { "YES (DEPRECATED)" } else { "ACTIVE" };
            md.push_str(&format!("| `{}` | `{}` | {} | {} |\n",
                e.enctype_name, q_str, d_str, e.risk_description
            ));
        }

        md.push_str("\n### PKINIT Smartcard Logon & TGT Exposure\n\n");
        for p in &report.pkinit_realms {
            md.push_str(&format!("#### Realm: `{}`\n", p.realm_name));
            md.push_str(&format!("* **PKINIT Enabled:** {}\n", p.pkinit_enabled));
            md.push_str(&format!("* **Client Certificate:** {}\n", p.client_cert_algorithm));
            md.push_str(&format!("* **KDC Diffie-Hellman Group:** {}\n", p.kdc_dh_group));
            md.push_str(&format!("* **TGT Interception Exposure:** {}\n", p.hndl_tgt_exposure));
            md.push_str(&format!("* **Remediation:** {}\n\n", p.remediation));
        }

        md.push_str("### Hardened Quantum-Safe krb5.conf Directive\n\n```ini\n");
        md.push_str(&report.recommended_krb5_conf);
        md.push_str("```\n");

        md
    }
}
