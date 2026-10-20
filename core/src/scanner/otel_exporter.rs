//! OpenTelemetry (OTel) Cryptographic Semantic Conventions & SOC Streaming Exporter
//!
//! Converts discovered cryptographic assets and runtime findings into OpenTelemetry
//! Cryptography Semantic Conventions (crypto.operation, crypto.algorithm, crypto.pqc.hybrid)
//! and generates compliant OTLP/JSON batches for Datadog, Splunk, and SIEM ingestion.

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelCryptoRecord {
    pub timestamp_unix_nano: u64,
    pub service_name: String,
    pub operation: String,
    pub algorithm: String,
    pub is_pqc_hybrid: bool,
    pub quantum_risk: String,
    pub file_location: String,
    pub severity: String,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelBatchPayload {
    pub service_name: String,
    pub total_records: usize,
    pub collector_endpoint: String,
    pub otlp_json: String,
    pub records: Vec<OtelCryptoRecord>,
}

pub struct OtelCryptoExporter;

impl OtelCryptoExporter {
    /// Transforms audit findings into OTLP compliant cryptographic telemetry batches
    pub fn export_from_findings(
        findings: &[ComprehensiveFinding],
        service_name: &str,
        collector_url: &str,
    ) -> OtelBatchPayload {
        let endpoint = if collector_url.is_empty() {
            "http://localhost:4318/v1/logs"
        } else {
            collector_url
        };

        let mut records = Vec::new();
        let base_timestamp = 1791565200000000000u64; // Nano timestamp

        for (idx, f) in findings.iter().enumerate() {
            let is_pqc = f.quantum_risk.as_deref().unwrap_or("VULNERABLE") == "SAFE" || f.vulnerability_class.contains("Post-Quantum");
            let mut attrs = HashMap::new();
            attrs.insert("crypto.operation".to_string(), "key_exchange_or_signature".to_string());
            attrs.insert("crypto.algorithm".to_string(), f.vulnerability_class.clone());
            attrs.insert("crypto.pqc.hybrid".to_string(), is_pqc.to_string());
            attrs.insert("crypto.quantum_risk".to_string(), f.quantum_risk.clone().unwrap_or_else(|| "VULNERABLE".to_string()));
            attrs.insert("code.filepath".to_string(), f.file_path.clone());
            attrs.insert("code.lineno".to_string(), f.line_number.to_string());
            attrs.insert("security.rule_id".to_string(), f.rule_id.clone().unwrap_or_else(|| "PQC-GEN-001".to_string()));

            records.push(OtelCryptoRecord {
                timestamp_unix_nano: base_timestamp + (idx as u64 * 1000000000),
                service_name: service_name.to_string(),
                operation: "asymmetric_cryptography".to_string(),
                algorithm: f.vulnerability_class.clone(),
                is_pqc_hybrid: is_pqc,
                quantum_risk: f.quantum_risk.clone().unwrap_or_else(|| "VULNERABLE".to_string()),
                file_location: format!("{}:{}", f.file_path, f.line_number),
                severity: f.severity.clone(),
                attributes: attrs,
            });
        }

        // Construct standard OpenTelemetry OTLP ResourceLogs JSON
        let otlp_json = serde_json::json!({
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            { "key": "service.name", "value": { "stringValue": service_name } },
                            { "key": "telemetry.sdk.name", "value": { "stringValue": "pqcanary-otel" } },
                            { "key": "telemetry.sdk.language", "value": { "stringValue": "rust" } },
                            { "key": "telemetry.sdk.version", "value": { "stringValue": "0.1.0" } }
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": { "name": "io.pqcanary.cryptography" },
                            "logRecords": records.iter().map(|r| {
                                serde_json::json!({
                                    "timeUnixNano": r.timestamp_unix_nano.to_string(),
                                    "severityText": r.severity,
                                    "body": { "stringValue": format!("Cryptographic finding: {} at {}", r.algorithm, r.file_location) },
                                    "attributes": r.attributes.iter().map(|(k, v)| {
                                        serde_json::json!({ "key": k, "value": { "stringValue": v } })
                                    }).collect::<Vec<_>>()
                                })
                            }).collect::<Vec<_>>()
                        }
                    ]
                }
            ]
        }).to_string();

        OtelBatchPayload {
            service_name: service_name.to_string(),
            total_records: records.len(),
            collector_endpoint: endpoint.to_string(),
            otlp_json,
            records,
        }
    }

    /// Formats the OTLP cryptographic batch summary as readable Markdown
    pub fn format_markdown(payload: &OtelBatchPayload) -> String {
        let mut md = String::new();
        md.push_str("# OpenTelemetry Cryptographic Semantic Telemetry Batch\n\n");
        md.push_str(&format!("* **Service Name:** `{}`\n", payload.service_name));
        md.push_str(&format!("* **Collector Endpoint:** `{}`\n", payload.collector_endpoint));
        md.push_str(&format!("* **Total Cryptographic Records:** {}\n\n", payload.total_records));

        md.push_str("| Algorithm | Location | Risk Rating | Hybrid PQC | Severity |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
        for r in &payload.records {
            md.push_str(&format!("| {} | `{}` | `{}` | {} | `{}` |\n",
                r.algorithm, r.file_location, r.quantum_risk, r.is_pqc_hybrid, r.severity
            ));
        }
        md
    }
}
