//! Telemetry and Metrics Engine for PQCanary.
//!
//! Exports scan statistics in the Prometheus Exposition Format (text/plain; version=0.0.4).
//! These metrics can be scraped by Prometheus and visualized in Grafana.
//!
//! Example integration:
//!   - Add a `GET /metrics` endpoint to the Axum API that calls `export_prometheus_format()`
//!   - Point Prometheus at http://localhost:8080/metrics
//!   - Import the PQCanary Grafana dashboard

use std::time::Instant;

pub struct MetricsRegistry {
    // Scanner counters
    pub ast_nodes_scanned: u64,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub concolic_paths_explored: u64,
    pub concolic_timeouts: u64,

    // Finding counters by severity
    pub findings_critical: u64,
    pub findings_high: u64,
    pub findings_medium: u64,
    pub findings_low: u64,
    pub findings_info: u64,

    // Engine-specific energy accounting
    pub heat_dissipated_joules: f64,

    // API metrics
    pub api_requests_served: u64,
    pub api_errors: u64,

    // Scan performance
    pub total_scan_duration_ms: u64,
    pub scans_completed: u64,

    // Internal: start time for duration tracking
    scan_start: Option<Instant>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            ast_nodes_scanned: 0,
            files_scanned: 0,
            files_skipped: 0,
            concolic_paths_explored: 0,
            concolic_timeouts: 0,
            findings_critical: 0,
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
            findings_info: 0,
            heat_dissipated_joules: 0.0,
            api_requests_served: 0,
            api_errors: 0,
            total_scan_duration_ms: 0,
            scans_completed: 0,
            scan_start: None,
        }
    }

    // ─── Scan Timing ──────────────────────────────────────────────────────────

    /// Record the beginning of a scan session.
    pub fn begin_scan(&mut self) {
        self.scan_start = Some(Instant::now());
    }

    /// Record the completion of a scan session and compute its duration.
    pub fn end_scan(&mut self) {
        if let Some(start) = self.scan_start.take() {
            self.total_scan_duration_ms += start.elapsed().as_millis() as u64;
            self.scans_completed += 1;
        }
    }

    // ─── File Counters ────────────────────────────────────────────────────────

    /// Record a successfully scanned file.
    pub fn inc_file_scanned(&mut self) { self.files_scanned += 1; }

    /// Record a skipped file (binary, too large, unsupported extension).
    pub fn inc_file_skipped(&mut self) { self.files_skipped += 1; }

    // ─── AST Counters ─────────────────────────────────────────────────────────

    /// Record a successfully parsed AST node across the monorepo.
    pub fn inc_ast_node(&mut self) { self.ast_nodes_scanned += 1; }

    /// Record N AST nodes at once (bulk increment).
    pub fn add_ast_nodes(&mut self, count: u64) { self.ast_nodes_scanned += count; }

    // ─── Concolic Counters ────────────────────────────────────────────────────

    /// Record branches explored by the Z3 SMT solver.
    pub fn add_concolic_paths(&mut self, paths: u64) {
        self.concolic_paths_explored += paths;
    }

    /// Record a Z3 solver timeout.
    pub fn inc_concolic_timeout(&mut self) { self.concolic_timeouts += 1; }

    // ─── Finding Counters ─────────────────────────────────────────────────────

    /// Record a finding by severity string.
    pub fn record_finding(&mut self, severity: &str) {
        match severity.to_uppercase().as_str() {
            "CRITICAL" => self.findings_critical += 1,
            "HIGH"     => self.findings_high += 1,
            "MEDIUM"   => self.findings_medium += 1,
            "LOW"      => self.findings_low += 1,
            _          => self.findings_info += 1,
        }
    }

    /// Total findings across all severity levels.
    pub fn total_findings(&self) -> u64 {
        self.findings_critical + self.findings_high + self.findings_medium
            + self.findings_low + self.findings_info
    }

    // ─── Energy Accounting ────────────────────────────────────────────────────

    /// Record theoretical physical energy expended in Landauer simulations (joules).
    pub fn add_heat(&mut self, joules: f64) { self.heat_dissipated_joules += joules; }

    // ─── API Counters ─────────────────────────────────────────────────────────

    /// Record a successfully served API request.
    pub fn inc_api_request(&mut self) { self.api_requests_served += 1; }

    /// Record an API error (4xx or 5xx response).
    pub fn inc_api_error(&mut self) { self.api_errors += 1; }

    // ─── Prometheus Export ────────────────────────────────────────────────────

    /// Export all metrics in Prometheus Exposition Format (text/plain; version=0.0.4).
    /// Compatible with Prometheus, Grafana, and any OpenMetrics-compatible scraper.
    pub fn export_prometheus_format(&self) -> String {
        let avg_scan_ms = self.total_scan_duration_ms.checked_div(self.scans_completed).unwrap_or(0);

        format!(
            "# HELP pqcanary_ast_nodes_total Total AST nodes parsed across all files.\n\
             # TYPE pqcanary_ast_nodes_total counter\n\
             pqcanary_ast_nodes_total {}\n\
             # HELP pqcanary_files_scanned_total Total source files scanned.\n\
             # TYPE pqcanary_files_scanned_total counter\n\
             pqcanary_files_scanned_total {}\n\
             # HELP pqcanary_files_skipped_total Files skipped (binary, unsupported, etc.).\n\
             # TYPE pqcanary_files_skipped_total counter\n\
             pqcanary_files_skipped_total {}\n\
             # HELP pqcanary_concolic_paths_total Symbolic execution branches explored by Z3.\n\
             # TYPE pqcanary_concolic_paths_total counter\n\
             pqcanary_concolic_paths_total {}\n\
             # HELP pqcanary_concolic_timeouts_total Z3 solver queries that exceeded time budget.\n\
             # TYPE pqcanary_concolic_timeouts_total counter\n\
             pqcanary_concolic_timeouts_total {}\n\
             # HELP pqcanary_findings_total Security findings by severity.\n\
             # TYPE pqcanary_findings_total counter\n\
             pqcanary_findings_total{{severity=\"CRITICAL\"}} {}\n\
             pqcanary_findings_total{{severity=\"HIGH\"}} {}\n\
             pqcanary_findings_total{{severity=\"MEDIUM\"}} {}\n\
             pqcanary_findings_total{{severity=\"LOW\"}} {}\n\
             pqcanary_findings_total{{severity=\"INFO\"}} {}\n\
             # HELP pqcanary_heat_dissipated_joules Cumulative Landauer-limit energy simulated.\n\
             # TYPE pqcanary_heat_dissipated_joules counter\n\
             pqcanary_heat_dissipated_joules {:.6e}\n\
             # HELP pqcanary_api_requests_total REST API requests served.\n\
             # TYPE pqcanary_api_requests_total counter\n\
             pqcanary_api_requests_total {}\n\
             # HELP pqcanary_api_errors_total REST API error responses.\n\
             # TYPE pqcanary_api_errors_total counter\n\
             pqcanary_api_errors_total {}\n\
             # HELP pqcanary_scans_completed_total Total complete scan sessions executed.\n\
             # TYPE pqcanary_scans_completed_total counter\n\
             pqcanary_scans_completed_total {}\n\
             # HELP pqcanary_scan_duration_ms_avg Average scan duration in milliseconds.\n\
             # TYPE pqcanary_scan_duration_ms_avg gauge\n\
             pqcanary_scan_duration_ms_avg {}\n",
            self.ast_nodes_scanned,
            self.files_scanned,
            self.files_skipped,
            self.concolic_paths_explored,
            self.concolic_timeouts,
            self.findings_critical,
            self.findings_high,
            self.findings_medium,
            self.findings_low,
            self.findings_info,
            self.heat_dissipated_joules,
            self.api_requests_served,
            self.api_errors,
            self.scans_completed,
            avg_scan_ms,
        )
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self { Self::new() }
}

