//! CycloneDX 1.6 CBOM Semantic Drift & Diff Engine
//!
//! Compares two Cryptographic Bill of Materials (CBOM) snapshots (Base vs Target),
//! detecting additions, deletions, algorithmic alterations, and critical security regressions
//! (e.g. quantum-safe to classical downgrades, key length reductions, or deprecated OIDs).

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::scanner::cbom::{CycloneDxCbom, CbomComponent};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    Downgraded,
    Unchanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentDiff {
    pub component_name: String,
    pub asset_type: String,
    pub change_type: ChangeType,
    pub old_algorithm: Option<String>,
    pub new_algorithm: Option<String>,
    pub old_quantum_refinement: Option<String>,
    pub new_quantum_refinement: Option<String>,
    pub old_key_size: Option<u32>,
    pub new_key_size: Option<u32>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomDriftReport {
    pub base_version: u32,
    pub target_version: u32,
    pub base_total_assets: usize,
    pub target_total_assets: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
    pub downgraded_count: usize,
    pub drift_score_percent: f64,
    pub status: String, // "COMPLIANT", "DRIFT_DETECTED", "REGRESSION_CRITICAL"
    pub diffs: Vec<ComponentDiff>,
    pub recommendations: Vec<String>,
}

pub struct CbomDiffEngine;

impl CbomDiffEngine {
    /// Compares two parsed CycloneDX CBOMs
    pub fn diff(base: &CycloneDxCbom, target: &CycloneDxCbom) -> CbomDriftReport {
        let mut diffs = Vec::new();
        let mut added_count = 0;
        let mut removed_count = 0;
        let mut modified_count = 0;
        let mut downgraded_count = 0;

        // Index components by bom_ref if present, else fallback to name + assetType
        let make_key = |c: &CbomComponent| -> String {
            if !c.bom_ref.is_empty() {
                c.bom_ref.clone()
            } else {
                format!("{}:{}", c.crypto_properties.asset_type, c.name)
            }
        };

        let base_map: HashMap<String, &CbomComponent> = base.components
            .iter()
            .map(|c| (make_key(c), c))
            .collect();

        let target_map: HashMap<String, &CbomComponent> = target.components
            .iter()
            .map(|c| (make_key(c), c))
            .collect();

        // 1. Inspect additions and modifications in target
        for (key, target_comp) in &target_map {
            if let Some(base_comp) = base_map.get(key) {
                // Compare properties
                let base_props = &base_comp.crypto_properties;
                let target_props = &target_comp.crypto_properties;

                let old_refine = &base_props.algorithm_properties.quantum_refinement;
                let new_refine = &target_props.algorithm_properties.quantum_refinement;
                let old_level = base_props.algorithm_properties.classical_security_level;
                let new_level = target_props.algorithm_properties.classical_security_level;

                let mut change_type = ChangeType::Unchanged;
                let mut details = Vec::new();

                // Check for security downgrades
                let is_downgrade = (old_refine == "post-quantum-safe" && new_refine != "post-quantum-safe")
                    || (old_refine == "hybrid" && (new_refine == "quantum-vulnerable" || new_refine == "classically-broken"))
                    || (new_level < old_level);

                if is_downgrade {
                    change_type = ChangeType::Downgraded;
                    downgraded_count += 1;
                    if old_refine != new_refine {
                        details.push(format!("Quantum posture downgraded from '{}' to '{}'", old_refine, new_refine));
                    }
                    if new_level < old_level {
                        details.push(format!("Classical security level reduced from {} to {} bits", old_level, new_level));
                    }
                } else if base_props.algorithm_properties.primitive != target_props.algorithm_properties.primitive
                    || old_refine != new_refine
                    || old_level != new_level
                {
                    change_type = ChangeType::Modified;
                    modified_count += 1;
                    if base_props.algorithm_properties.primitive != target_props.algorithm_properties.primitive {
                        details.push(format!("Algorithm updated from '{}' to '{}'",
                            base_props.algorithm_properties.primitive,
                            target_props.algorithm_properties.primitive));
                    }
                    if old_refine != new_refine {
                        details.push(format!("Refinement updated from '{}' to '{}'", old_refine, new_refine));
                    }
                }

                if change_type != ChangeType::Unchanged {
                    diffs.push(ComponentDiff {
                        component_name: target_comp.name.clone(),
                        asset_type: target_props.asset_type.clone(),
                        change_type,
                        old_algorithm: Some(base_props.algorithm_properties.primitive.clone()),
                        new_algorithm: Some(target_props.algorithm_properties.primitive.clone()),
                        old_quantum_refinement: Some(old_refine.clone()),
                        new_quantum_refinement: Some(new_refine.clone()),
                        old_key_size: Some(old_level),
                        new_key_size: Some(new_level),
                        details: details.join("; "),
                    });
                }
            } else {
                // Added component
                added_count += 1;
                let target_props = &target_comp.crypto_properties;
                let is_weak = target_props.algorithm_properties.quantum_refinement == "quantum-vulnerable"
                    || target_props.algorithm_properties.quantum_refinement == "classically-broken";

                diffs.push(ComponentDiff {
                    component_name: target_comp.name.clone(),
                    asset_type: target_props.asset_type.clone(),
                    change_type: if is_weak { ChangeType::Downgraded } else { ChangeType::Added },
                    old_algorithm: None,
                    new_algorithm: Some(target_props.algorithm_properties.primitive.clone()),
                    old_quantum_refinement: None,
                    new_quantum_refinement: Some(target_props.algorithm_properties.quantum_refinement.clone()),
                    old_key_size: None,
                    new_key_size: Some(target_props.algorithm_properties.classical_security_level),
                    details: if is_weak {
                        format!("New component introduced with vulnerable posture: {}", target_props.algorithm_properties.quantum_refinement)
                    } else {
                        format!("New cryptographic asset declared: {}", target_props.algorithm_properties.primitive)
                    },
                });
                if is_weak {
                    downgraded_count += 1;
                }
            }
        }

        // 2. Inspect removed components
        for (key, base_comp) in &base_map {
            if !target_map.contains_key(key) {
                removed_count += 1;
                let base_props = &base_comp.crypto_properties;
                diffs.push(ComponentDiff {
                    component_name: base_comp.name.clone(),
                    asset_type: base_props.asset_type.clone(),
                    change_type: ChangeType::Removed,
                    old_algorithm: Some(base_props.algorithm_properties.primitive.clone()),
                    new_algorithm: None,
                    old_quantum_refinement: Some(base_props.algorithm_properties.quantum_refinement.clone()),
                    new_quantum_refinement: None,
                    old_key_size: Some(base_props.algorithm_properties.classical_security_level),
                    new_key_size: None,
                    details: format!("Cryptographic asset removed: {}", base_props.algorithm_properties.primitive),
                });
            }
        }

        // Calculate drift score: (modified + added + removed + 2*downgraded) / max(total, 1)
        let total_ref = base.components.len().max(target.components.len()).max(1);
        let weighted_changes = (added_count + removed_count + modified_count + (downgraded_count * 2)) as f64;
        let drift_score = ((weighted_changes / total_ref as f64) * 100.0).min(100.0);

        let status = if downgraded_count > 0 {
            "REGRESSION_CRITICAL".to_string()
        } else if drift_score > 0.0 {
            "DRIFT_DETECTED".to_string()
        } else {
            "COMPLIANT".to_string()
        };

        let mut recommendations = Vec::new();
        if downgraded_count > 0 {
            recommendations.push(format!("Block deployment: {} cryptographic asset(s) suffered quantum security downgrades.", downgraded_count));
        }
        if added_count > 0 {
            recommendations.push(format!("Verify that the {} newly introduced cryptographic asset(s) conform to NIST FIPS 203/204.", added_count));
        }
        if drift_score == 0.0 {
            recommendations.push("CBOM snapshots are semantically identical. Zero cryptographic drift detected.".to_string());
        }

        CbomDriftReport {
            base_version: base.version,
            target_version: target.version,
            base_total_assets: base.components.len(),
            target_total_assets: target.components.len(),
            added_count,
            removed_count,
            modified_count,
            downgraded_count,
            drift_score_percent: (drift_score * 10.0).round() / 10.0,
            status,
            diffs,
            recommendations,
        }
    }

    /// Compares two CBOM JSON strings directly
    pub fn diff_json_strings(base_json: &str, target_json: &str) -> Result<CbomDriftReport, String> {
        let base: CycloneDxCbom = serde_json::from_str(base_json)
            .map_err(|e| format!("Failed to parse base CBOM JSON: {}", e))?;
        let target: CycloneDxCbom = serde_json::from_str(target_json)
            .map_err(|e| format!("Failed to parse target CBOM JSON: {}", e))?;
        Ok(Self::diff(&base, &target))
    }

    /// Generates markdown report table
    pub fn format_markdown(report: &CbomDriftReport) -> String {
        let mut out = String::new();
        out.push_str("# CycloneDX 1.6 CBOM Semantic Drift Report\n\n");
        out.push_str(&format!("- **Status**: `{}`\n", report.status));
        out.push_str(&format!("- **Cryptographic Drift Score**: `{:.1}%`\n", report.drift_score_percent));
        out.push_str(&format!("- **Base Assets**: `{}` | **Target Assets**: `{}`\n", report.base_total_assets, report.target_total_assets));
        out.push_str(&format!("- **Additions**: `{}` | **Deletions**: `{}` | **Modifications**: `{}` | **Downgrades**: `{}`\n\n",
            report.added_count, report.removed_count, report.modified_count, report.downgraded_count));

        if !report.diffs.is_empty() {
            out.push_str("| Component | Asset Type | Change | Old Posture | New Posture | Details |\n");
            out.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
            for d in &report.diffs {
                let change_tag = match d.change_type {
                    ChangeType::Downgraded => "**DOWNGRADE**",
                    ChangeType::Added => "Added",
                    ChangeType::Removed => "Removed",
                    ChangeType::Modified => "Modified",
                    ChangeType::Unchanged => "Unchanged",
                };
                out.push_str(&format!(
                    "| `{}` | `{}` | {} | `{}` | `{}` | {} |\n",
                    d.component_name,
                    d.asset_type,
                    change_tag,
                    d.old_quantum_refinement.as_deref().unwrap_or("-"),
                    d.new_quantum_refinement.as_deref().unwrap_or("-"),
                    d.details
                ));
            }
            out.push('\n');
        }

        if !report.recommendations.is_empty() {
            out.push_str("### Recommendations\n");
            for rec in &report.recommendations {
                out.push_str(&format!("- {}\n", rec));
            }
        }

        out
    }
}
