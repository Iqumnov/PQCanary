//! OASIS SARIF 2.1.0 Output Generator
//!
//! Generates standard Static Analysis Results Interchange Format (SARIF) 2.1.0 JSON reports
//! compliant with GitHub Code Scanning, Azure DevOps, and GitLab SAST ingestion pipelines.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use crate::scanner::orchestrator::ComprehensiveFinding;
use crate::scanner::patterns::ALL_PATTERNS;

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    #[serde(rename = "semanticVersion")]
    pub semantic_version: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    pub help: SarifHelp,
    #[serde(rename = "helpUri")]
    pub help_uri: String,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifDefaultConfig,
    pub properties: SarifRuleProperties,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifHelp {
    pub text: String,
    pub markdown: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDefaultConfig {
    pub level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    pub tags: Vec<String>,
    #[serde(rename = "quantumRisk")]
    pub quantum_risk: String,
    pub category: String,
    #[serde(rename = "precision")]
    pub precision: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifResultProperties>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResultProperties {
    #[serde(rename = "quantumRisk", skip_serializing_if = "Option::is_none")]
    pub quantum_risk: Option<String>,
    #[serde(rename = "confidence", skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(rename = "remediation", skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(rename = "fingerprint", skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifSnippet>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifSnippet {
    pub text: String,
}

pub struct SarifGenerator;

impl SarifGenerator {
    /// Maps PQCanary severity to OASIS SARIF level:
    /// CRITICAL, HIGH -> "error"
    /// MEDIUM -> "warning"
    /// LOW, INFO -> "note"
    pub fn severity_to_sarif_level(severity: &str) -> &'static str {
        match severity.to_uppercase().as_str() {
            "CRITICAL" | "HIGH" => "error",
            "MEDIUM" => "warning",
            _ => "note",
        }
    }

    /// Generates a full SARIF 2.1.0 document from a set of findings.
    pub fn generate_sarif(findings: &[ComprehensiveFinding], base_dir: Option<&str>) -> SarifReport {
        let mut rules_map: HashMap<String, SarifRule> = HashMap::with_capacity(ALL_PATTERNS.len() + 16);
        let mut sarif_results = Vec::with_capacity(findings.len());

        // Preload standard rules from pattern catalog
        for pat in ALL_PATTERNS.iter() {
            let rule = SarifRule {
                id: pat.def.id.to_string(),
                name: pat.def.name.to_string(),
                short_description: SarifMessage {
                    text: pat.def.description.to_string(),
                },
                full_description: SarifMessage {
                    text: format!("{}. Classification: Quantum {}.", pat.def.description, pat.def.quantum_risk.as_str()),
                },
                help: SarifHelp {
                    text: pat.def.remediation.to_string(),
                    markdown: format!(
                        "### {}\n\n**Category**: {}\n**Quantum Risk**: `{}`\n**Severity**: `{}`\n\n#### Description\n{}\n\n#### Recommended Remediation\n{}\n",
                        pat.def.name, pat.def.category, pat.def.quantum_risk.as_str(), pat.def.severity,
                        pat.def.description, pat.def.remediation
                    ),
                },
                help_uri: format!("https://github.com/pqcanary/pqcanary/tree/main/docs/rules/{}.md", pat.def.id),
                default_configuration: SarifDefaultConfig {
                    level: Self::severity_to_sarif_level(pat.def.severity).to_string(),
                },
                properties: SarifRuleProperties {
                    tags: pat.def.tags.iter().map(|s| s.to_string()).collect(),
                    quantum_risk: pat.def.quantum_risk.as_str().to_string(),
                    category: pat.def.category.to_string(),
                    precision: "very-high".to_string(),
                },
            };
            rules_map.insert(rule.id.clone(), rule);
        }

        for finding in findings {
            let rule_id = finding.rule_id.clone().unwrap_or_else(|| {
                // Synthesize rule ID from vulnerability class if not explicitly tagged
                format!("PQC-{}", finding.vulnerability_class.to_uppercase().replace(' ', "-"))
            });

            // If rule isn't in catalog (e.g. from Concolic, DPA, Landauer, HoTT), synthesize rule metadata
            rules_map.entry(rule_id.clone()).or_insert_with(|| {
                SarifRule {
                    id: rule_id.clone(),
                    name: finding.vulnerability_class.clone(),
                    short_description: SarifMessage {
                        text: finding.description.clone(),
                    },
                    full_description: SarifMessage {
                        text: finding.description.clone(),
                    },
                    help: SarifHelp {
                        text: finding.remediation.clone(),
                        markdown: format!(
                            "### {}\n\n**Severity**: `{}`\n\n#### Description\n{}\n\n#### Remediation\n{}\n",
                            finding.vulnerability_class, finding.severity, finding.description, finding.remediation
                        ),
                    },
                    help_uri: "https://github.com/pqcanary/pqcanary".to_string(),
                    default_configuration: SarifDefaultConfig {
                        level: Self::severity_to_sarif_level(&finding.severity).to_string(),
                    },
                    properties: SarifRuleProperties {
                        tags: vec!["pqc".to_string(), "cryptography".to_string()],
                        quantum_risk: finding.quantum_risk.clone().unwrap_or_else(|| "VULNERABLE".to_string()),
                        category: finding.vulnerability_class.clone(),
                        precision: "high".to_string(),
                    },
                }
            });

            // Normalize path to relative URI for GitHub Code Scanning
            let normalized_path = finding.file_path.replace('\\', "/");
            let (relative_uri, uri_base_id) = if let Some(base) = base_dir {
                let base_path = Path::new(base);
                let find_path = Path::new(&finding.file_path);
                if let Ok(rel) = find_path.strip_prefix(base_path) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    let clean_rel = rel_str.trim_start_matches('/').to_string();
                    (clean_rel, Some("%SRCROOT%".to_string()))
                } else {
                    let is_rel = !normalized_path.starts_with('/') && !normalized_path.contains(':');
                    let base_id = if is_rel { Some("%SRCROOT%".to_string()) } else { None };
                    (normalized_path, base_id)
                }
            } else {
                let is_rel = !normalized_path.starts_with('/') && !normalized_path.contains(':');
                let base_id = if is_rel { Some("%SRCROOT%".to_string()) } else { None };
                (normalized_path, base_id)
            };

            let level = Self::severity_to_sarif_level(&finding.severity).to_string();

            let snippet_opt = finding.snippet.as_ref().map(|s| SarifSnippet {
                text: s.clone(),
            });

            sarif_results.push(SarifResult {
                rule_id: rule_id.clone(),
                level,
                message: SarifMessage {
                    text: finding.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: relative_uri,
                            uri_base_id,
                        },
                        region: SarifRegion {
                            start_line: finding.line_number.max(1),
                            start_column: finding.column_number,
                            snippet: snippet_opt,
                        },
                    },
                }],
                properties: Some(SarifResultProperties {
                    quantum_risk: finding.quantum_risk.clone(),
                    confidence: finding.confidence.clone(),
                    remediation: Some(finding.remediation.clone()),
                    fingerprint: finding.fingerprint.clone(),
                }),
            });
        }

        let mut sorted_rules: Vec<SarifRule> = rules_map.into_values().collect();
        sorted_rules.sort_by(|a, b| a.id.cmp(&b.id));

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "PQCanary".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/pqcanary/pqcanary".to_string(),
                        semantic_version: env!("CARGO_PKG_VERSION").to_string(),
                        rules: sorted_rules,
                    },
                },
                results: sarif_results,
            }],
        }
    }

    /// Serializes SARIF report to formatted JSON string.
    pub fn to_json(report: &SarifReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
    }
}
