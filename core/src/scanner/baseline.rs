//! Baseline Comparison Engine for CI/CD Quality Gates
//!
//! Enables teams to record existing cryptographic tech-debt in a baseline file,
//! tracking only *new* regressions or quantum vulnerabilities introduced in pull requests.

use std::fs;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparisonReport {
    pub total_current: usize,
    pub total_baseline: usize,
    pub new_count: usize,
    pub existing_count: usize,
    pub resolved_count: usize,
    pub new_findings: Vec<ComprehensiveFinding>,
    pub existing_findings: Vec<ComprehensiveFinding>,
    pub resolved_findings: Vec<ComprehensiveFinding>,
}

pub struct BaselineEngine;

impl BaselineEngine {
    /// Loads previous findings from a baseline file (JSON or SARIF).
    pub fn load_baseline(path: &str) -> Result<Vec<ComprehensiveFinding>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read baseline file '{}': {}", path, e))?;
        Self::parse_baseline_content(&content)
    }

    /// Parses baseline findings directly from raw string content (JSON or SARIF 2.1.0).
    /// Enables in-memory baseline comparison with zero disk I/O or temporary file creation.
    pub fn parse_baseline_content(content: &str) -> Result<Vec<ComprehensiveFinding>, String> {
        // 1. Attempt parsing as standard PQCanary JSON findings list
        if let Ok(findings) = serde_json::from_str::<Vec<ComprehensiveFinding>>(content) {
            return Ok(findings);
        }

        // 2. Attempt parsing as SARIF 2.1.0 document
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
            if let Some(runs) = val.get("runs").and_then(|r| r.as_array()) {
                let mut sarif_findings = Vec::new();
                for run in runs {
                    if let Some(results) = run.get("results").and_then(|res| res.as_array()) {
                        for res in results {
                            let rule_id = res.get("ruleId").and_then(|s| s.as_str()).unwrap_or("PQC-SARIF");
                            let message = res.get("message").and_then(|m| m.get("text")).and_then(|t| t.as_str()).unwrap_or("");
                            let level = res.get("level").and_then(|l| l.as_str()).unwrap_or("warning");
                            
                            let severity = match level {
                                "error" => "HIGH",
                                "warning" => "MEDIUM",
                                _ => "LOW",
                            };

                            let (file_path, line_number) = if let Some(loc) = res.get("locations").and_then(|l| l.as_array()).and_then(|arr| arr.first()) {
                                let pl = loc.get("physicalLocation");
                                let uri = pl.and_then(|p| p.get("artifactLocation")).and_then(|a| a.get("uri")).and_then(|u| u.as_str()).unwrap_or("unknown");
                                let line = pl.and_then(|p| p.get("region")).and_then(|r| r.get("startLine")).and_then(|l| l.as_u64()).unwrap_or(1) as u32;
                                (uri.to_string(), line)
                            } else {
                                ("unknown".to_string(), 1)
                            };

                            let fingerprint = res.get("properties")
                                .and_then(|p| p.get("fingerprint"))
                                .and_then(|f| f.as_str())
                                .map(|s| s.to_string())
                                .or_else(|| {
                                    Some(crate::scanner::patterns::compute_finding_fingerprint(&file_path, rule_id, message))
                                });

                            sarif_findings.push(ComprehensiveFinding {
                                file_path,
                                vulnerability_class: rule_id.to_string(),
                                description: message.to_string(),
                                severity: severity.to_string(),
                                line_number,
                                remediation: "See SARIF remediation guidance.".to_string(),
                                rule_id: Some(rule_id.to_string()),
                                quantum_risk: None,
                                confidence: None,
                                snippet: None,
                                column_number: None,
                                fingerprint,
                            });
                        }
                    }
                }
                if !sarif_findings.is_empty() {
                    return Ok(sarif_findings);
                }
            }
        }

        Err("Baseline content is not valid PQCanary findings JSON or SARIF 2.1.0 format".to_string())
    }

    /// Compares current scan findings with baseline findings.
    /// Categorizes into New, Existing, and Resolved findings.
    pub fn compare(
        current_findings: &[ComprehensiveFinding],
        baseline_findings: &[ComprehensiveFinding],
    ) -> BaselineComparisonReport {
        let mut baseline_map: HashMap<String, Vec<&ComprehensiveFinding>> = HashMap::new();
        for bf in baseline_findings {
            let key = bf.fingerprint.clone().unwrap_or_else(|| {
                crate::scanner::patterns::compute_finding_fingerprint(
                    &bf.file_path,
                    bf.rule_id.as_deref().unwrap_or(&bf.vulnerability_class),
                    &bf.description,
                )
            });
            baseline_map.entry(key).or_default().push(bf);
        }

        let mut new_findings = Vec::new();
        let mut existing_findings = Vec::new();

        for cf in current_findings {
            let key = cf.fingerprint.clone().unwrap_or_else(|| {
                crate::scanner::patterns::compute_finding_fingerprint(
                    &cf.file_path,
                    cf.rule_id.as_deref().unwrap_or(&cf.vulnerability_class),
                    &cf.description,
                )
            });

            if let Some(queue) = baseline_map.get_mut(&key) {
                if !queue.is_empty() {
                    queue.pop();
                    existing_findings.push(cf.clone());
                } else {
                    new_findings.push(cf.clone());
                }
            } else {
                new_findings.push(cf.clone());
            }
        }

        let mut resolved_findings = Vec::new();
        for (_key, remaining) in baseline_map {
            for bf in remaining {
                resolved_findings.push(bf.clone());
            }
        }

        BaselineComparisonReport {
            total_current: current_findings.len(),
            total_baseline: baseline_findings.len(),
            new_count: new_findings.len(),
            existing_count: existing_findings.len(),
            resolved_count: resolved_findings.len(),
            new_findings,
            existing_findings,
            resolved_findings,
        }
    }

    /// Formats the baseline comparison as a terminal summary report.
    pub fn format_terminal_summary(report: &BaselineComparisonReport) -> String {
        let mut out = String::new();
        out.push_str("╔════════════════════════════════════════════════════════════╗\n");
        out.push_str("║              BASELINE COMPARISON REPORT                    ║\n");
        out.push_str("╠════════════════════════════════════════════════════════════╣\n");
        out.push_str(&format!("║ Baseline Findings:  {:>5}                                  ║\n", report.total_baseline));
        out.push_str(&format!("║ Current Findings:   {:>5}                                  ║\n", report.total_current));
        out.push_str(&format!("║ Existing (Known):   {:>5}                                  ║\n", report.existing_count));
        out.push_str(&format!("║ [NEW] Regressions:  {:>5}                                  ║\n", report.new_count));
        out.push_str(&format!("║ [RESOLVED] Fixed:   {:>5}                                  ║\n", report.resolved_count));
        out.push_str("╚════════════════════════════════════════════════════════════╝\n");
        out
    }
}
