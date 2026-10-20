//! Stateful Hash-Based Signatures (HBS) State-Tracking & Snapshot-Safety Auditor
//!
//! Evaluates implementations of RFC 8554 (LMS / HSS) and RFC 8391 (XMSS / XMSS^MT)
//! per NIST SP 800-208 and NSA CNSA 2.0 firmware signing directives.
//! Detects catastrophic One-Time Signature (OTS) key reuse hazards, uncommitted
//! volatile state counters, virtual machine snapshot restoration vulnerabilities,
//! and container replication hazards.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HbsAlgorithmFamily {
    LmsHss,
    XmssXmssMt,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CounterStorageKind {
    HardwareMonotonicTpmNvram,
    DedicatedHsmNvCounter,
    PersistentFileWithFsync,
    VolatileMemoryEphemeral,
    UnsynchronizedDatabase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ForkHazardSeverity {
    CatastrophicStateReuse,
    HighSnapshotExposure,
    MediumClusterUnsynchronized,
    CompliantHardwareGuarded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HbsKeyInstanceAudit {
    pub key_identifier: String,
    pub algorithm_type: String,
    pub tree_height: u32,
    pub total_leaf_signatures: u64,
    pub signatures_used: u64,
    pub signatures_remaining: u64,
    pub percent_exhausted: f64,
    pub counter_storage: CounterStorageKind,
    pub hazard_severity: ForkHazardSeverity,
    pub detected_hazards: Vec<String>,
    pub remediation_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HbsStateAuditReport {
    pub target_scope: String,
    pub overall_hbs_safety_status: String,
    pub keys_audited_count: usize,
    pub catastrophic_hazards_count: usize,
    pub keys: Vec<HbsKeyInstanceAudit>,
    pub environment_audit_findings: Vec<String>,
}

pub struct HbsStateAuditor;

impl HbsStateAuditor {
    /// Audits an HBS key state file or infrastructure deployment descriptor (Dockerfile, PodSpec, systemd, or raw key state)
    pub fn audit_state_and_config(target_name: &str, content: &str) -> HbsStateAuditReport {
        let mut keys = Vec::new();
        let mut env_findings = Vec::new();
        let content_lower = content.to_lowercase();

        // Check environment virtualization hazards
        let has_criu = content_lower.contains("criu") || content_lower.contains("checkpoint");
        let has_vm_snapshot = content_lower.contains("snapshot") || content_lower.contains("hypervisor") || content_lower.contains("qemu");
        let has_k8s_replicas = content_lower.contains("replicas:") && !content_lower.contains("replicas: 1");
        let has_stateless_container = content_lower.contains("docker") || content_lower.contains("podman") || content_lower.contains("containerd");
        let has_tpm_nvram = content_lower.contains("tpm2_nv") || content_lower.contains("nvram") || content_lower.contains("tpm2-tools");
        let has_pkcs11_hsm = content_lower.contains("pkcs11") || content_lower.contains("libsofthsm") || content_lower.contains("lunaclient");

        if has_criu {
            env_findings.push("CRITICAL: CRIU process checkpointing detected in signing environment. Restoring a checkpoint reuses OTS keys and leaks private state.".to_string());
        }
        if has_vm_snapshot {
            env_findings.push("HIGH: Virtual machine snapshot rollback capability detected. Reverting to prior snapshot restores obsolete OTS counter state.".to_string());
        }
        if has_k8s_replicas {
            env_findings.push("CRITICAL: Horizontal pod autoscaling (HPA) or replicas > 1 detected for stateful signing daemon. Concurrent pods cause duplicate signature generation.".to_string());
        }
        if has_stateless_container && !has_tpm_nvram && !has_pkcs11_hsm {
            env_findings.push("HIGH: Containerized signing service lacks hardware monotonic NVRAM binding. Container restart resets counter state to container image default.".to_string());
        }

        // Parse key state parameters (RFC 8554 LMS / RFC 8391 XMSS)
        // Detect tree height parameter (h=10 -> 1024, h=15 -> 32768, h=20 -> 1048576)
        let tree_height = if content_lower.contains("h20") || content_lower.contains("height: 20") || content_lower.contains("height = 20") {
            20
        } else if content_lower.contains("h15") || content_lower.contains("height: 15") || content_lower.contains("height = 15") {
            15
        } else {
            10 // Default LMS baseline (LMS_SHA256_M32_H10)
        };

        let total_leaves: u64 = 1u64 << tree_height;

        // Parse current counter value if specified (e.g. q: 512, counter = 800)
        let mut used_counter: u64 = 0;
        for line in content.lines() {
            let line_trim = line.trim();
            if line_trim.starts_with("q:") || line_trim.starts_with("q =") || line_trim.starts_with("counter:") || line_trim.starts_with("counter =") {
                let parts: Vec<&str> = line_trim.split(&[':', '='][..]).collect();
                if parts.len() >= 2 {
                    if let Ok(num) = parts[1].trim().parse::<u64>() {
                        used_counter = num;
                    }
                }
            }
        }

        let remaining = total_leaves.saturating_sub(used_counter);
        let pct_used = (used_counter as f64 / total_leaves as f64) * 100.0;

        let storage_kind = if has_tpm_nvram {
            CounterStorageKind::HardwareMonotonicTpmNvram
        } else if has_pkcs11_hsm {
            CounterStorageKind::DedicatedHsmNvCounter
        } else if content_lower.contains("fsync") || content_lower.contains("o_sync") {
            CounterStorageKind::PersistentFileWithFsync
        } else if content_lower.contains("redis") || content_lower.contains("mysql") || content_lower.contains("postgres") {
            CounterStorageKind::UnsynchronizedDatabase
        } else {
            CounterStorageKind::VolatileMemoryEphemeral
        };

        let mut key_hazards = Vec::new();
        let mut key_remediations = Vec::new();

        if used_counter >= total_leaves {
            key_hazards.push("FATAL: Key tree completely exhausted (q >= 2^h). Further signatures will catastrophically reuse OTS private keys.".to_string());
            key_remediations.push("Immediately revoke and retire this public key. Generate new LMS/XMSS tree before signing.".to_string());
        } else if pct_used >= 90.0 {
            key_hazards.push(format!("WARNING: Key is {:.1}% exhausted ({} signatures remaining).", pct_used, remaining));
            key_remediations.push("Pre-generate replacement key tree and begin root cross-signing migration.".to_string());
        }

        if storage_kind == CounterStorageKind::VolatileMemoryEphemeral {
            key_hazards.push("CRITICAL: Counter stored in volatile memory. Power loss or crash causes state rollback and private key compromise.".to_string());
            key_remediations.push("Migrate state counter to TPM 2.0 NVRAM counter (TPM2_NV_Increment) or FIPS 140-3 Level 3 HSM.".to_string());
        }

        if has_criu || has_k8s_replicas {
            key_hazards.push("CRITICAL: Deployment architecture permits concurrent or restored counter states.".to_string());
            key_remediations.push("Constrain signing service to single bare-metal host with exclusive hardware lock (flock / TPM session).".to_string());
        }

        let severity = if key_hazards.iter().any(|h| h.contains("FATAL") || h.contains("CRITICAL")) {
            ForkHazardSeverity::CatastrophicStateReuse
        } else if key_hazards.iter().any(|h| h.contains("HIGH") || h.contains("WARNING")) {
            ForkHazardSeverity::HighSnapshotExposure
        } else if storage_kind == CounterStorageKind::PersistentFileWithFsync {
            ForkHazardSeverity::MediumClusterUnsynchronized
        } else {
            ForkHazardSeverity::CompliantHardwareGuarded
        };

        let has_hbs_key = content_lower.contains("lms")
            || content_lower.contains("hss")
            || content_lower.contains("xmss")
            || content_lower.contains("hash-based")
            || content_lower.contains("8554")
            || content_lower.contains("8391")
            || content_lower.contains("sp800-208")
            || content_lower.contains("800-208")
            || content_lower.contains("ots_")
            || content_lower.contains("lm_ots");

        if has_hbs_key {
            let is_lms = content_lower.contains("lms") || content_lower.contains("hss") || !content_lower.contains("xmss");
            let algo_name = if is_lms {
                format!("RFC 8554 LMS_SHA256_M32_H{}", tree_height)
            } else {
                format!("RFC 8391 XMSS_SHA2_{}_256", tree_height)
            };

            keys.push(HbsKeyInstanceAudit {
                key_identifier: target_name.to_string(),
                algorithm_type: algo_name,
                tree_height,
                total_leaf_signatures: total_leaves,
                signatures_used: used_counter,
                signatures_remaining: remaining,
                percent_exhausted: pct_used,
                counter_storage: storage_kind,
                hazard_severity: severity,
                detected_hazards: key_hazards,
                remediation_steps: key_remediations,
            });
        }

        let cat_count = keys.iter().filter(|k| k.hazard_severity == ForkHazardSeverity::CatastrophicStateReuse).count();
        let overall = if cat_count > 0 {
            "CRITICAL_OTS_STATE_REUSE_HAZARD".to_string()
        } else if env_findings.iter().any(|f| f.contains("CRITICAL")) {
            "VULNERABLE_VIRTUALIZATION_ROLLBACK_EXPOSURE".to_string()
        } else if keys.is_empty() {
            if !env_findings.is_empty() {
                "ENVIRONMENT_CONFIGURATION_ONLY".to_string()
            } else {
                "NO_HBS_KEYS_DETECTED".to_string()
            }
        } else {
            "COMPLIANT_MONOTONIC_HARDWARE_LOCKED".to_string()
        };

        HbsStateAuditReport {
            target_scope: target_name.to_string(),
            overall_hbs_safety_status: overall,
            keys_audited_count: keys.len(),
            catastrophic_hazards_count: cat_count,
            keys,
            environment_audit_findings: env_findings,
        }
    }

    /// Formats the HBS state audit report as readable Markdown
    pub fn format_markdown(report: &HbsStateAuditReport) -> String {
        let mut md = String::new();
        md.push_str("# Stateful Hash-Based Signature (RFC 8554 LMS / RFC 8391 XMSS) State Audit\n\n");
        md.push_str(&format!("* **Target Scope:** `{}`\n", report.target_scope));
        md.push_str(&format!("* **Overall Safety Status:** `{}`\n", report.overall_hbs_safety_status));
        md.push_str(&format!("* **Keys Audited:** {} (Catastrophic Hazards: {})\n\n",
            report.keys_audited_count, report.catastrophic_hazards_count));

        if !report.environment_audit_findings.is_empty() {
            md.push_str("### Environmental & Virtualization Fork Hazards\n\n");
            for f in &report.environment_audit_findings {
                md.push_str(&format!("* {}\n", f));
            }
            md.push('\n');
        }

        if report.keys.is_empty() {
            md.push_str("> **Notice:** No stateful hash-based signature instances (RFC 8554 LMS / RFC 8391 XMSS) were detected in the target scope.\n");
            return md;
        }

        md.push_str("| Key Identifier | Algorithm | Height | Signatures Used | Remaining | Storage Subsystem | Verdict |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for k in &report.keys {
            let v_str = match k.hazard_severity {
                ForkHazardSeverity::CompliantHardwareGuarded => "COMPLIANT (TPM/HSM)",
                ForkHazardSeverity::MediumClusterUnsynchronized => "MEDIUM (FSYNC ONLY)",
                ForkHazardSeverity::HighSnapshotExposure => "HIGH (SNAPSHOT HAZARD)",
                ForkHazardSeverity::CatastrophicStateReuse => "CRITICAL (OTS REUSE)",
            };
            let stor_str = match k.counter_storage {
                CounterStorageKind::HardwareMonotonicTpmNvram => "TPM 2.0 NVRAM",
                CounterStorageKind::DedicatedHsmNvCounter => "FIPS 140-3 HSM",
                CounterStorageKind::PersistentFileWithFsync => "File + fsync()",
                CounterStorageKind::VolatileMemoryEphemeral => "Volatile RAM (UNSAFE)",
                CounterStorageKind::UnsynchronizedDatabase => "Unsync DB",
            };
            md.push_str(&format!("| `{}` | {} | {} | {} ({:.1}%) | {} | {} | `{}` |\n",
                k.key_identifier, k.algorithm_type, k.tree_height, k.signatures_used, k.percent_exhausted,
                k.signatures_remaining, stor_str, v_str
            ));
        }

        md.push_str("\n### Specific Key Hazards & Remediation\n\n");
        for k in &report.keys {
            if !k.detected_hazards.is_empty() {
                md.push_str(&format!("#### `{}` Hazards\n", k.key_identifier));
                for h in &k.detected_hazards {
                    md.push_str(&format!("* {}\n", h));
                }
                md.push_str("**Remediation Guidance:**\n");
                for r in &k.remediation_steps {
                    md.push_str(&format!("* {}\n", r));
                }
                md.push('\n');
            }
        }

        md
    }
}
