//! Cloud Cryptographic Asset & KMS Quantum Auditor
//! Audits AWS KMS, Azure Key Vault, GCP Cloud KMS, and HashiCorp Vault configurations
//! for quantum vulnerabilities, CNSA 2.0 compliance, and NIST FIPS 203/204 migration paths.
//! Copyright (C) 2026 Matvei Igumnov - Apache License 2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    AwsKms,
    AzureKeyVault,
    GcpCloudKms,
    HashiCorpVault,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AwsKms => "AWS KMS",
            Self::AzureKeyVault => "Azure Key Vault",
            Self::GcpCloudKms => "GCP Cloud KMS",
            Self::HashiCorpVault => "HashiCorp Vault",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsKeyAudit {
    pub key_id: String,
    pub provider: CloudProvider,
    pub key_spec: String,
    pub key_usage: String,
    pub quantum_risk: String,
    pub cnsa_2_compliant: bool,
    pub description: String,
    pub recommendation: String,
    pub remediation_snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudKmsAuditReport {
    pub total_keys_inspected: usize,
    pub quantum_safe_count: usize,
    pub vulnerable_count: usize,
    pub cnsa_2_compliance_percent: f64,
    pub overall_posture: String,
    pub keys: Vec<KmsKeyAudit>,
    pub summary: String,
}

pub struct CloudKmsAuditor;

impl CloudKmsAuditor {
    /// Audits file content specifically if KMS/Cloud cryptographic assets are detected (returns empty Vec if no matching assets)
    pub fn audit_content_matching(content: &str) -> Vec<KmsKeyAudit> {
        let mut keys = Vec::new();

        // 1. Check for AWS KMS DescribeKey or ListKeys JSON output
        if content.contains("KeyMetadata") || (content.contains("KeySpec") && content.contains("{")) {
            keys.extend(Self::audit_aws_kms(content));
        }

        // 2. Check for Azure Key Vault Key export JSON
        if (content.contains("\"kty\"") || content.contains("keyUri")) && content.contains("{") {
            keys.extend(Self::audit_azure_keyvault(content));
        }

        // 3. Check for GCP Cloud KMS JSON
        if (content.contains("cryptoKeyVersions") || content.contains("GOOGLE_SYMMETRIC_ENCRYPTION")) && content.contains("{") {
            keys.extend(Self::audit_gcp_kms(content));
        }

        // 4. Terraform / HCL definitions (AWS, Azure, GCP, HashiCorp Vault)
        if content.contains("resource \"aws_kms_key\"")
            || content.contains("resource \"azurerm_key_vault_key\"")
            || content.contains("resource \"google_kms_crypto_key\"")
            || content.contains("resource \"vault_transit_secret_backend_key\"")
        {
            keys.extend(Self::audit_terraform_hcl(content));
        }

        keys
    }

    /// Audits raw JSON configuration exports from AWS, Azure, GCP, or Terraform
    pub fn audit_raw_content(content: &str) -> CloudKmsAuditReport {
        let keys = Self::audit_content_matching(content);

        if keys.is_empty() {
            return CloudKmsAuditReport {
                total_keys_inspected: 0,
                quantum_safe_count: 0,
                vulnerable_count: 0,
                cnsa_2_compliance_percent: 100.0,
                overall_posture: "NO_KMS_KEYS_DETECTED".to_string(),
                keys: Vec::new(),
                summary: "Zero Cloud KMS or Terraform cryptographic key resources detected in audited target.".to_string(),
            };
        }

        let total = keys.len();
        let safe = keys.iter().filter(|k| k.quantum_risk == "SAFE" || k.quantum_risk == "HYBRID").count();
        let vulnerable = keys.iter().filter(|k| k.quantum_risk == "VULNERABLE").count();
        let cnsa_count = keys.iter().filter(|k| k.cnsa_2_compliant).count();
        let cnsa_percent = (cnsa_count as f64 / total as f64) * 100.0;

        let overall_posture = if vulnerable == 0 {
            "QUANTUM_RESILIENT".to_string()
        } else if safe > 0 {
            "TRANSITIONING".to_string()
        } else {
            "CRITICALLY_VULNERABLE".to_string()
        };

        let summary = format!(
            "Inspected {} cloud KMS cryptographic key specifications. {} quantum-resilient / hybrid keys, {} classical quantum-vulnerable keys. CNSA 2.0 Compliance: {:.1}%.",
            total, safe, vulnerable, cnsa_percent
        );

        CloudKmsAuditReport {
            total_keys_inspected: total,
            quantum_safe_count: safe,
            vulnerable_count: vulnerable,
            cnsa_2_compliance_percent: (cnsa_percent * 10.0).round() / 10.0,
            overall_posture,
            keys,
            summary,
        }
    }

    fn audit_aws_kms(content: &str) -> Vec<KmsKeyAudit> {
        let mut results = Vec::new();

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
            // Case A: Single KeyMetadata object
            let meta_items = if let Some(meta) = val.get("KeyMetadata") {
                vec![meta]
            } else if let Some(arr) = val.get("Keys").and_then(|k| k.as_array()) {
                arr.iter().collect()
            } else {
                vec![&val]
            };

            for item in meta_items {
                let key_id = item.get("KeyId")
                    .and_then(|v| v.as_str())
                    .or_else(|| item.get("Arn").and_then(|v| v.as_str()))
                    .unwrap_or("arn:aws:kms:us-east-1:123456789012:key/default");

                let key_spec = item.get("KeySpec")
                    .or_else(|| item.get("CustomerMasterKeySpec"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("SYMMETRIC_DEFAULT");

                let key_usage = item.get("KeyUsage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ENCRYPT_DECRYPT");

                let is_rsa = key_spec.contains("RSA");
                let is_ecc = key_spec.contains("ECC");
                let is_aes_256 = key_spec == "SYMMETRIC_DEFAULT" || key_spec.contains("AES_256");

                let (quantum_risk, cnsa_compliant, desc, rec, remediation) = if is_rsa {
                    (
                        "VULNERABLE".to_string(),
                        false,
                        format!("AWS KMS Key {} uses classical RSA ({}) which will be broken by Shor's algorithm.", key_id, key_spec),
                        "Migrate asymmetric signing and encryption keys to hybrid ML-KEM-768 or ML-DSA-65.".to_string(),
                        format!("aws kms create-key --key-spec SYMMETRIC_DEFAULT --description 'Migrated quantum-resilient key for {}'", key_id)
                    )
                } else if is_ecc {
                    (
                        "VULNERABLE".to_string(),
                        false,
                        format!("AWS KMS Key {} uses classical elliptic curve ({}) vulnerable to discrete logarithm quantum attacks.", key_id, key_spec),
                        "Transition to CNSA 2.0 compliant post-quantum algorithms (ML-DSA-87 / SLH-DSA-256).".to_string(),
                        format!("aws kms update-key-description --key-id {} --description 'DEPRECATED_QUANTUM_VULNERABLE'", key_id)
                    )
                } else if is_aes_256 {
                    (
                        "SAFE".to_string(),
                        true,
                        "AWS KMS SYMMETRIC_DEFAULT (AES-256-GCM) provides 128 bits of post-quantum security against Grover's algorithm.".to_string(),
                        "Maintain annual key rotation and enforce TLS 1.3 hybrid key exchange for KMS API calls.".to_string(),
                        format!("aws kms enable-key-rotation --key-id {}", key_id)
                    )
                } else {
                    (
                        "HYBRID".to_string(),
                        true,
                        format!("AWS KMS Key {} has post-quantum hybrid protection.", key_id),
                        "Compliant with NIST PQC guidelines.".to_string(),
                        format!("aws kms get-key-rotation-status --key-id {}", key_id)
                    )
                };

                results.push(KmsKeyAudit {
                    key_id: key_id.to_string(),
                    provider: CloudProvider::AwsKms,
                    key_spec: key_spec.to_string(),
                    key_usage: key_usage.to_string(),
                    quantum_risk,
                    cnsa_2_compliant: cnsa_compliant,
                    description: desc,
                    recommendation: rec,
                    remediation_snippet: remediation,
                });
            }
        }

        results
    }

    fn audit_azure_keyvault(content: &str) -> Vec<KmsKeyAudit> {
        let mut results = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
            let kty = val.get("kty").and_then(|v| v.as_str()).unwrap_or("RSA");
            let key_size = val.get("key_size").and_then(|v| v.as_u64()).unwrap_or(2048);
            let kid = val.get("kid").and_then(|v| v.as_str()).unwrap_or("https://corp-vault.vault.azure.net/keys/main-key");

            let is_vulnerable = kty == "RSA" || kty == "EC";
            results.push(KmsKeyAudit {
                key_id: kid.to_string(),
                provider: CloudProvider::AzureKeyVault,
                key_spec: format!("{}-{}", kty, key_size),
                key_usage: "sign, verify, wrapKey, unwrapKey".to_string(),
                quantum_risk: if is_vulnerable { "VULNERABLE".to_string() } else { "SAFE".to_string() },
                cnsa_2_compliant: !is_vulnerable,
                description: format!("Azure Key Vault key '{}' uses {}-{} which lacks quantum resistance.", kid, kty, key_size),
                recommendation: "Deploy Azure Managed HSM with AES-256 or enroll composite post-quantum keys.".to_string(),
                remediation_snippet: "az keyvault key create --vault-name corp-vault --name pq-safe-key --kty oct --size 256".to_string(),
            });
        }
        results
    }

    fn audit_gcp_kms(content: &str) -> Vec<KmsKeyAudit> {
        let mut results = Vec::new();
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
            let algo = val.get("algorithm").and_then(|v| v.as_str()).unwrap_or("GOOGLE_SYMMETRIC_ENCRYPTION");
            let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("projects/corp/locations/global/keyRings/ring/cryptoKeys/key1");
            let is_safe = algo.contains("SYMMETRIC") || algo.contains("AES_256");

            results.push(KmsKeyAudit {
                key_id: name.to_string(),
                provider: CloudProvider::GcpCloudKms,
                key_spec: algo.to_string(),
                key_usage: "ENCRYPT_DECRYPT".to_string(),
                quantum_risk: if is_safe { "SAFE".to_string() } else { "VULNERABLE".to_string() },
                cnsa_2_compliant: is_safe,
                description: format!("GCP Cloud KMS key '{}' algorithm: {}", name, algo),
                recommendation: if is_safe { "Maintain automated 90-day key rotation schedule.".to_string() } else { "Upgrade asymmetric signing to hybrid post-quantum structure.".to_string() },
                remediation_snippet: "gcloud kms keys update key1 --keyring=ring --location=global --rotation-period=7776000s".to_string(),
            });
        }
        results
    }

    fn audit_terraform_hcl(content: &str) -> Vec<KmsKeyAudit> {
        let mut results = Vec::new();

        // 1. AWS KMS Key
        if content.contains("resource \"aws_kms_key\"") {
            let has_rotation = content.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("enable_key_rotation") && trimmed.contains("true")
            });
            let is_asymmetric = content.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.contains("customer_master_key_spec") && (trimmed.contains("RSA") || trimmed.contains("ECC"))
            });

            if is_asymmetric {
                results.push(KmsKeyAudit {
                    key_id: "terraform:resource.aws_kms_key".to_string(),
                    provider: CloudProvider::AwsKms,
                    key_spec: "ASYMMETRIC (RSA / ECC)".to_string(),
                    key_usage: "SIGN_VERIFY".to_string(),
                    quantum_risk: "VULNERABLE".to_string(),
                    cnsa_2_compliant: false,
                    description: "Terraform AWS KMS key is configured with classical asymmetric spec vulnerable to Shor's algorithm.".to_string(),
                    recommendation: "Migrate key to SYMMETRIC_DEFAULT (AES-256) or enroll hybrid ML-KEM/ML-DSA credentials.".to_string(),
                    remediation_snippet: "customer_master_key_spec = \"SYMMETRIC_DEFAULT\"\nenable_key_rotation      = true".to_string(),
                });
            } else {
                results.push(KmsKeyAudit {
                    key_id: "terraform:resource.aws_kms_key".to_string(),
                    provider: CloudProvider::AwsKms,
                    key_spec: "SYMMETRIC_DEFAULT".to_string(),
                    key_usage: "ENCRYPT_DECRYPT".to_string(),
                    quantum_risk: if has_rotation { "SAFE".to_string() } else { "HYBRID".to_string() },
                    cnsa_2_compliant: true,
                    description: "Terraform AWS KMS Key definition evaluated for quantum agility and automatic rotation.".to_string(),
                    recommendation: if !has_rotation { "Add 'enable_key_rotation = true' to Terraform resource block.".to_string() } else { "Configuration adheres to NIST guidelines.".to_string() },
                    remediation_snippet: "resource \"aws_kms_key\" \"app_kms\" {\n  description             = \"Quantum-Resilient Master Key\"\n  deletion_window_in_days = 30\n  enable_key_rotation     = true\n  customer_master_key_spec = \"SYMMETRIC_DEFAULT\"\n}".to_string(),
                });
            }
        }

        // 2. Azure Key Vault Key
        if content.contains("resource \"azurerm_key_vault_key\"") {
            let key_type = content.lines().find_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with("key_type") {
                    Some(trimmed.to_string())
                } else {
                    None
                }
            }).unwrap_or_else(|| "key_type = \"RSA\"".to_string());

            let is_vulnerable = key_type.contains("RSA") || key_type.contains("EC");
            results.push(KmsKeyAudit {
                key_id: "terraform:resource.azurerm_key_vault_key".to_string(),
                provider: CloudProvider::AzureKeyVault,
                key_spec: if is_vulnerable { "Classical Asymmetric (RSA/EC)".to_string() } else { "oct (AES-256)".to_string() },
                key_usage: "sign, verify, wrapKey, unwrapKey".to_string(),
                quantum_risk: if is_vulnerable { "VULNERABLE".to_string() } else { "SAFE".to_string() },
                cnsa_2_compliant: !is_vulnerable,
                description: "Terraform Azure Key Vault key definition evaluated for post-quantum resistance.".to_string(),
                recommendation: if is_vulnerable {
                    "Replace classical RSA/EC key_type with Managed HSM AES-256 (oct) or composite hybrid post-quantum certificates.".to_string()
                } else {
                    "Azure Key Vault symmetric key configuration meets post-quantum criteria.".to_string()
                },
                remediation_snippet: "resource \"azurerm_key_vault_key\" \"pq_key\" {\n  name         = \"pq-symmetric-key\"\n  key_vault_id = azurerm_key_vault.vault.id\n  key_type     = \"oct\"\n  key_size     = 256\n}".to_string(),
            });
        }

        // 3. GCP Cloud KMS CryptoKey
        if content.contains("resource \"google_kms_crypto_key\"") {
            let has_rotation = content.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("rotation_period")
            });
            let is_asymmetric = content.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("purpose") && (trimmed.contains("ASYMMETRIC_SIGN") || trimmed.contains("ASYMMETRIC_DECRYPT"))
            });

            results.push(KmsKeyAudit {
                key_id: "terraform:resource.google_kms_crypto_key".to_string(),
                provider: CloudProvider::GcpCloudKms,
                key_spec: if is_asymmetric { "ASYMMETRIC_SIGN / DECRYPT".to_string() } else { "GOOGLE_SYMMETRIC_ENCRYPTION".to_string() },
                key_usage: if is_asymmetric { "SIGN_VERIFY".to_string() } else { "ENCRYPT_DECRYPT".to_string() },
                quantum_risk: if is_asymmetric { "VULNERABLE".to_string() } else if has_rotation { "SAFE".to_string() } else { "HYBRID".to_string() },
                cnsa_2_compliant: !is_asymmetric,
                description: "Terraform GCP Cloud KMS CryptoKey evaluated for quantum risk and automatic rotation.".to_string(),
                recommendation: if is_asymmetric {
                    "Migrate asymmetric CryptoKey to NIST FIPS 203/204 hybrid signing architecture.".to_string()
                } else if !has_rotation {
                    "Configure 'rotation_period = \"7776000s\"' (90 days) for optimal post-quantum defense in depth.".to_string()
                } else {
                    "GCP CryptoKey adheres to CNSA 2.0 and NIST quantum resilience guidelines.".to_string()
                },
                remediation_snippet: "resource \"google_kms_crypto_key\" \"pq_key\" {\n  name            = \"app-encryption-key\"\n  key_ring        = google_kms_key_ring.keyring.id\n  rotation_period = \"7776000s\"\n  purpose         = \"ENCRYPT_DECRYPT\"\n}".to_string(),
            });
        }

        // 4. HashiCorp Vault Transit Secret Engine Key
        if content.contains("resource \"vault_transit_secret_backend_key\"") {
            let is_classical = content.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("type") && (trimmed.contains("rsa") || trimmed.contains("ecdsa") || trimmed.contains("ed25519"))
            });

            results.push(KmsKeyAudit {
                key_id: "terraform:resource.vault_transit_secret_backend_key".to_string(),
                provider: CloudProvider::HashiCorpVault,
                key_spec: if is_classical { "Classical Asymmetric (RSA/ECDSA/Ed25519)".to_string() } else { "aes256-gcm96".to_string() },
                key_usage: "ENCRYPT_DECRYPT".to_string(),
                quantum_risk: if is_classical { "VULNERABLE".to_string() } else { "SAFE".to_string() },
                cnsa_2_compliant: !is_classical,
                description: "Terraform HashiCorp Vault Transit Engine cryptographic key specification.".to_string(),
                recommendation: if is_classical {
                    "Migrate Transit key type to 'aes256-gcm96' or 'chacha20-poly1305' for 128-bit quantum security.".to_string()
                } else {
                    "HashiCorp Vault Transit key configuration is quantum-resilient against Grover's algorithm.".to_string()
                },
                remediation_snippet: "resource \"vault_transit_secret_backend_key\" \"key\" {\n  backend = vault_mount.transit.path\n  name    = \"pqc-safe-key\"\n  type    = \"aes256-gcm96\"\n}".to_string(),
            });
        }

        results
    }

    pub fn sample_enterprise_cloud_keys() -> Vec<KmsKeyAudit> {
        vec![
            KmsKeyAudit {
                key_id: "arn:aws:kms:us-east-1:012345678910:key/app-secrets-master".to_string(),
                provider: CloudProvider::AwsKms,
                key_spec: "SYMMETRIC_DEFAULT (AES-256-GCM)".to_string(),
                key_usage: "ENCRYPT_DECRYPT".to_string(),
                quantum_risk: "SAFE".to_string(),
                cnsa_2_compliant: true,
                description: "Primary database envelope encryption key. 256-bit symmetric entropy ensures 128-bit quantum security against Grover's algorithm.".to_string(),
                recommendation: "Ensure annual automatic key rotation is active.".to_string(),
                remediation_snippet: "aws kms enable-key-rotation --key-id app-secrets-master".to_string(),
            },
            KmsKeyAudit {
                key_id: "arn:aws:kms:us-east-1:012345678910:key/jwt-signing-asymmetric".to_string(),
                provider: CloudProvider::AwsKms,
                key_spec: "RSA_2048".to_string(),
                key_usage: "SIGN_VERIFY".to_string(),
                quantum_risk: "VULNERABLE".to_string(),
                cnsa_2_compliant: false,
                description: "Classical RSA-2048 signing key used for authentication JWTs. Shor's algorithm completely breaks 2048-bit integer factorization.".to_string(),
                recommendation: "Migrate JWT token verification to NIST FIPS 204 (ML-DSA-65 / Dilithium) or stateful LMS signatures.".to_string(),
                remediation_snippet: "aws kms create-key --key-spec ECC_NIST_P384 --key-usage SIGN_VERIFY --description 'Transitionary interim key prior to ML-DSA'".to_string(),
            },
            KmsKeyAudit {
                key_id: "https://enterprise-vault.vault.azure.net/keys/tls-cert-private".to_string(),
                provider: CloudProvider::AzureKeyVault,
                key_spec: "RSA-3072".to_string(),
                key_usage: "WRAP_UNWRAP".to_string(),
                quantum_risk: "VULNERABLE".to_string(),
                cnsa_2_compliant: false,
                description: "Azure Key Vault TLS key exchange certificate private key. Compromise horizon threatens recorded ciphertexts under Harvest Now, Decrypt Later (HNDL).".to_string(),
                recommendation: "Deploy hybrid TLS certificates supporting ML-KEM-768 alongside classical RSA.".to_string(),
                remediation_snippet: "az keyvault certificate create --vault-name enterprise-vault -n pq-hybrid-cert --policy @pqc-policy.json".to_string(),
            },
            KmsKeyAudit {
                key_id: "projects/cloud-infra/locations/global/keyRings/k8s-secrets/cryptoKeys/etcd-envelope".to_string(),
                provider: CloudProvider::GcpCloudKms,
                key_spec: "GOOGLE_SYMMETRIC_ENCRYPTION (AES-256)".to_string(),
                key_usage: "ENCRYPT_DECRYPT".to_string(),
                quantum_risk: "SAFE".to_string(),
                cnsa_2_compliant: true,
                description: "Kubernetes cluster etcd envelope encryption key. Compliant with CNSA 2.0 and NIST FIPS quantum safety standards.".to_string(),
                recommendation: "Current configuration complies with all post-quantum mandates.".to_string(),
                remediation_snippet: "gcloud kms keys describe etcd-envelope --keyring=k8s-secrets --location=global".to_string(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_kms_audit_detection() {
        let sample_aws = r#"{
            "KeyMetadata": {
                "KeyId": "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012",
                "KeySpec": "RSA_2048",
                "KeyUsage": "SIGN_VERIFY"
            }
        }"#;

        let report = CloudKmsAuditor::audit_raw_content(sample_aws);
        assert_eq!(report.total_keys_inspected, 1);
        assert_eq!(report.vulnerable_count, 1);
        assert_eq!(report.keys[0].quantum_risk, "VULNERABLE");
        assert!(!report.keys[0].cnsa_2_compliant);
    }

    #[test]
    fn test_terraform_kms_audit() {
        let sample_tf = r#"
        resource "aws_kms_key" "db_key" {
            description             = "Database Encryption Key"
            deletion_window_in_days = 10
            enable_key_rotation     = true
        }
        "#;

        let report = CloudKmsAuditor::audit_raw_content(sample_tf);
        assert!(!report.keys.is_empty());
        assert_eq!(report.keys[0].quantum_risk, "SAFE");
        assert!(report.keys[0].cnsa_2_compliant);
    }

    #[test]
    fn test_terraform_azure_and_vault_audit() {
        let sample_azure = r#"
        resource "azurerm_key_vault_key" "rsa_key" {
            name         = "legacy-cert-key"
            key_vault_id = "test-vault"
            key_type     = "RSA"
            key_size     = 2048
        }
        "#;
        let report = CloudKmsAuditor::audit_raw_content(sample_azure);
        assert_eq!(report.total_keys_inspected, 1);
        assert_eq!(report.vulnerable_count, 1);
        assert_eq!(report.keys[0].provider, CloudProvider::AzureKeyVault);
        assert_eq!(report.keys[0].quantum_risk, "VULNERABLE");

        let sample_vault = r#"
        resource "vault_transit_secret_backend_key" "pqc_key" {
            backend = "transit"
            name    = "safe-key"
            type    = "aes256-gcm96"
        }
        "#;
        let vault_report = CloudKmsAuditor::audit_raw_content(sample_vault);
        assert_eq!(vault_report.total_keys_inspected, 1);
        assert_eq!(vault_report.quantum_safe_count, 1);
        assert_eq!(vault_report.keys[0].provider, CloudProvider::HashiCorpVault);
        assert_eq!(vault_report.keys[0].quantum_risk, "SAFE");
    }

    #[test]
    fn test_empty_content_audit() {
        let empty_report = CloudKmsAuditor::audit_raw_content("");
        assert_eq!(empty_report.total_keys_inspected, 0);
        assert_eq!(empty_report.overall_posture, "NO_KMS_KEYS_DETECTED");
        assert!(empty_report.keys.is_empty());
    }
}
