//! Fleet-Wide Central CBOM Data Lake & Distributed Analytics Engine
//!
//! Provides relational (PostgreSQL / TimescaleDB) and columnar (ClickHouse) storage
//! schemas, batch JSON ingestion processors, and enterprise SQL analytics queries
//! for managing thousands of CycloneDX 1.6 Cryptographic Bills of Materials (CBOM)
//! across global fleet repositories.
//!
//! Enables CISOs to run fleet-wide SQL queries tracking quantum downgrade regressions,
//! enterprise-wide Cryptographic Agility Scores (CAS), and CNSA 2.0 migration timelines.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatalakeBatchRecord {
    pub repository_id: String,
    pub commit_hash: String,
    pub branch: String,
    pub scan_timestamp_utc: String,
    pub component_name: String,
    pub algorithm_name: String,
    pub primitive_type: String,
    pub key_size_bits: u32,
    pub quantum_risk: String,
    pub is_post_quantum: bool,
    pub location_file: String,
    pub location_line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomDatalakePlan {
    pub target_platform: String,
    pub postgresql_schema_ddl: String,
    pub clickhouse_schema_ddl: String,
    pub generated_batch_inserts_sql: String,
    pub fleet_cas_aggregation_sql: String,
    pub regression_downgrade_tracker_sql: String,
    pub cnsa20_compliance_status_sql: String,
    pub total_assets_batched: usize,
}

pub struct CbomDatalakeEngine;

impl CbomDatalakeEngine {
    /// Generates complete enterprise DDL, batch ingestion SQL, and analytics queries for a CBOM
    pub fn plan_datalake_integration(repository_id: &str, cbom_json_or_text: &str) -> CbomDatalakePlan {
        let mut records = Vec::new();
        let timestamp_now = "2026-10-10T00:00:00Z";

        // Parse CBOM components or synthesize normalized records from findings
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(cbom_json_or_text) {
            if let Some(components) = v.get("components").and_then(|c| c.as_array()) {
                for comp in components {
                    let name = comp.get("name").and_then(|n| n.as_str()).unwrap_or("crypto-asset");
                    let cp = comp.get("cryptoProperties");
                    let ap = cp.and_then(|c| c.get("algorithmProperties"));

                    let algo = cp
                        .and_then(|c| c.get("algorithm"))
                        .and_then(|a| a.as_str())
                        .unwrap_or(name);

                    let prim = ap
                        .and_then(|a| a.get("primitive"))
                        .and_then(|p| p.as_str())
                        .unwrap_or("cryptographic-primitive");

                    let (file_path, line_no) = if let Some(loc) = ap
                        .and_then(|a| a.get("executionLocation"))
                        .and_then(|el| el.as_str())
                    {
                        if let Some((f, l)) = loc.rsplit_once(":L") {
                            (f.to_string(), l.parse::<u32>().unwrap_or(1))
                        } else if let Some((f, l)) = loc.rsplit_once(':') {
                            (f.to_string(), l.parse::<u32>().unwrap_or(1))
                        } else {
                            (loc.to_string(), 1u32)
                        }
                    } else {
                        ("unknown".to_string(), 1u32)
                    };

                    let is_pqc = algo.to_lowercase().contains("mlkem")
                        || algo.to_lowercase().contains("mldsa")
                        || algo.to_lowercase().contains("slhdsa")
                        || algo.to_lowercase().contains("falcon");

                    let risk = if is_pqc { "QUANTUM_RESISTANT" } else { "VULNERABLE_SHOR" };

                    records.push(DatalakeBatchRecord {
                        repository_id: repository_id.to_string(),
                        commit_hash: "HEAD".to_string(),
                        branch: "main".to_string(),
                        scan_timestamp_utc: timestamp_now.to_string(),
                        component_name: name.to_string(),
                        algorithm_name: algo.to_string(),
                        primitive_type: prim.to_string(),
                        key_size_bits: if is_pqc { 768 } else { 2048 },
                        quantum_risk: risk.to_string(),
                        is_post_quantum: is_pqc,
                        location_file: file_path,
                        location_line: line_no,
                    });
                }
            }
        }


        // 1. PostgreSQL / TimescaleDB DDL
        let postgres_ddl = r#"
-- PostgreSQL / TimescaleDB Fleet CBOM Schema
CREATE TABLE IF NOT EXISTS fleet_cbom_assets (
    id BIGSERIAL PRIMARY KEY,
    repository_id VARCHAR(255) NOT NULL,
    commit_hash VARCHAR(64) NOT NULL,
    branch VARCHAR(128) NOT NULL,
    scan_timestamp TIMESTAMPTZ NOT NULL,
    component_name VARCHAR(255) NOT NULL,
    algorithm_name VARCHAR(128) NOT NULL,
    primitive_type VARCHAR(64) NOT NULL,
    key_size_bits INT NOT NULL,
    quantum_risk VARCHAR(64) NOT NULL,
    is_post_quantum BOOLEAN NOT NULL,
    location_file TEXT NOT NULL,
    location_line INT NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cbom_repo_algo ON fleet_cbom_assets(repository_id, algorithm_name);
CREATE INDEX IF NOT EXISTS idx_cbom_risk ON fleet_cbom_assets(quantum_risk);
CREATE INDEX IF NOT EXISTS idx_cbom_timestamp ON fleet_cbom_assets(scan_timestamp DESC);
"#.trim().to_string();

        // 2. ClickHouse DDL
        let clickhouse_ddl = r#"
-- ClickHouse Columnar Analytics Engine Schema
CREATE TABLE IF NOT EXISTS fleet_cbom_assets (
    repository_id LowCardinality(String),
    commit_hash String,
    branch LowCardinality(String),
    scan_timestamp DateTime64(3, 'UTC'),
    component_name String,
    algorithm_name LowCardinality(String),
    primitive_type LowCardinality(String),
    key_size_bits UInt32,
    quantum_risk LowCardinality(String),
    is_post_quantum UInt8,
    location_file String,
    location_line UInt32,
    ingested_at DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(scan_timestamp)
ORDER BY (quantum_risk, repository_id, algorithm_name, scan_timestamp);
"#.trim().to_string();

        // 3. Batch INSERT SQL
        let inserts = if records.is_empty() {
            "-- No cryptographic assets parsed from input CBOM.\n".to_string()
        } else {
            let mut s = String::from("INSERT INTO fleet_cbom_assets (repository_id, commit_hash, branch, scan_timestamp, component_name, algorithm_name, primitive_type, key_size_bits, quantum_risk, is_post_quantum, location_file, location_line) VALUES\n");
            for (i, r) in records.iter().enumerate() {
                let line = format!(
                    "  ('{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, '{}', {}, '{}', {}){}",
                    r.repository_id, r.commit_hash, r.branch, r.scan_timestamp_utc,
                    r.component_name, r.algorithm_name, r.primitive_type, r.key_size_bits,
                    r.quantum_risk, if r.is_post_quantum { "true" } else { "false" },
                    r.location_file, r.location_line,
                    if i + 1 == records.len() { ";" } else { ",\n" }
                );
                s.push_str(&line);
            }
            s
        };

        // 4. Fleet CAS Aggregation Query
        let fleet_cas_sql = r#"
-- Enterprise Fleet Cryptographic Agility Score (CAS) Aggregation
SELECT
    repository_id,
    COUNT(*) AS total_assets,
    SUM(CASE WHEN is_post_quantum THEN 1 ELSE 0 END) AS pqc_assets_count,
    ROUND((SUM(CASE WHEN is_post_quantum THEN 1.0 ELSE 0.0 END) / COUNT(*)) * 100.0, 2) AS cryptographic_agility_score
FROM fleet_cbom_assets
WHERE scan_timestamp >= NOW() - INTERVAL '30 days'
GROUP BY repository_id
ORDER BY cryptographic_agility_score ASC;
"#.trim().to_string();

        // 5. Historical Downgrade Regression Query
        let regression_sql = r#"
-- Fleet-Wide Cryptographic Downgrade Regression Gatekeeper Query
WITH ranked_scans AS (
    SELECT
        repository_id,
        algorithm_name,
        is_post_quantum,
        scan_timestamp,
        LAG(is_post_quantum) OVER (PARTITION BY repository_id, location_file ORDER BY scan_timestamp) AS prev_is_pqc
    FROM fleet_cbom_assets
)
SELECT *
FROM ranked_scans
WHERE prev_is_pqc = true AND is_post_quantum = false
ORDER BY scan_timestamp DESC;
"#.trim().to_string();

        // 6. CNSA 2.0 Compliance Status Query
        let cnsa_sql = r#"
-- NSA CNSA 2.0 Compliance Timeline Verification
SELECT
    repository_id,
    SUM(CASE WHEN algorithm_name IN ('RSA-2048', 'RSA-3072', 'ECDSA-P256', 'ECDH-P256') THEN 1 ELSE 0 END) AS legacy_cnsa1_assets,
    SUM(CASE WHEN algorithm_name IN ('ML-KEM-768', 'ML-KEM-1024', 'ML-DSA-65', 'ML-DSA-87', 'LMS', 'XMSS') THEN 1 ELSE 0 END) AS compliant_cnsa2_assets
FROM fleet_cbom_assets
GROUP BY repository_id;
"#.trim().to_string();

        CbomDatalakePlan {
            target_platform: "PostgreSQL & ClickHouse Hybrid Data Lake".to_string(),
            postgresql_schema_ddl: postgres_ddl,
            clickhouse_schema_ddl: clickhouse_ddl,
            generated_batch_inserts_sql: inserts,
            fleet_cas_aggregation_sql: fleet_cas_sql,
            regression_downgrade_tracker_sql: regression_sql,
            cnsa20_compliance_status_sql: cnsa_sql,
            total_assets_batched: records.len(),
        }
    }

    /// Formats the data lake plan as Markdown
    pub fn format_markdown(plan: &CbomDatalakePlan) -> String {
        let mut md = String::new();
        md.push_str("# Fleet-Wide CBOM Data Lake & Distributed Analytics Engine\n\n");
        md.push_str(&format!("* **Target Platforms:** {}\n", plan.target_platform));
        md.push_str(&format!("* **Total Cryptographic Assets Batched:** {}\n\n", plan.total_assets_batched));

        md.push_str("### 1. PostgreSQL / TimescaleDB Fleet DDL Schema\n\n```sql\n");
        md.push_str(&plan.postgresql_schema_ddl);
        md.push_str("\n```\n\n");

        md.push_str("### 2. ClickHouse High-Throughput Columnar Schema\n\n```sql\n");
        md.push_str(&plan.clickhouse_schema_ddl);
        md.push_str("\n```\n\n");

        md.push_str("### 3. Generated Batch Ingestion SQL (`fleet_cbom_assets`)\n\n```sql\n");
        md.push_str(&plan.generated_batch_inserts_sql);
        md.push_str("\n```\n\n");

        md.push_str("### 4. Enterprise Cryptographic Agility Score (CAS) Aggregation\n\n```sql\n");
        md.push_str(&plan.fleet_cas_aggregation_sql);
        md.push_str("\n```\n\n");

        md.push_str("### 5. Historical Cryptographic Downgrade Regression Gatekeeper\n\n```sql\n");
        md.push_str(&plan.regression_downgrade_tracker_sql);
        md.push_str("\n```\n");

        md
    }
}
