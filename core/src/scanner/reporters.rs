//! Multi-Format Report Generation Engine
//!
//! Provides enterprise-grade export formats:
//! 1. Standalone, interactive HTML report with dark/light themes, executive scoring, SVG charts, and search
//! 2. GitHub-flavored Markdown report optimized for PR comments and security advisories
//! 3. RFC 4180 CSV export for spreadsheets, SIEMs, and data pipelines

use crate::scanner::orchestrator::ComprehensiveFinding;
use std::collections::HashMap;

pub struct HtmlReporter;

impl HtmlReporter {
    /// Generates a self-contained, interactive single-file HTML report.
    /// Works completely offline with zero CDN dependencies.
    pub fn generate(findings: &[ComprehensiveFinding], target_path: &str) -> String {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;
        let mut safe_count = 0;
        let mut vulnerable_count = 0;
        let mut hybrid_count = 0;

        for f in findings {
            match f.severity.to_uppercase().as_str() {
                "CRITICAL" => critical_count += 1,
                "HIGH" => high_count += 1,
                "MEDIUM" => medium_count += 1,
                "LOW" => low_count += 1,
                _ => info_count += 1,
            }
            match f.quantum_risk.as_deref().unwrap_or("UNKNOWN").to_uppercase().as_str() {
                "SAFE" => safe_count += 1,
                "HYBRID" => hybrid_count += 1,
                "VULNERABLE" => vulnerable_count += 1,
                _ => {}
            }
        }

        let total = findings.len();
        let (grade, grade_color, grade_desc) = if critical_count > 0 {
            ("F", "#ef4444", "Critical Post-Quantum Vulnerabilities Detected")
        } else if high_count > 0 {
            ("C", "#f97316", "High-Risk Classical Cryptography Present")
        } else if medium_count > 0 {
            ("B", "#eab308", "Actionable Tech Debt (Short-Term Migration Needed)")
        } else if total > 0 {
            ("A", "#10b981", "Minor Issues Only — Excellent Post-Quantum Stance")
        } else {
            ("A+", "#10b981", "Post-Quantum Ready & NIST Compliant")
        };

        let readiness_score = if total == 0 {
            100
        } else {
            let penalty = (critical_count * 25) + (high_count * 15) + (medium_count * 5) + low_count;
            100usize.saturating_sub(penalty).max(5)
        };

        let target_path_html = Self::escape_html(target_path);
        let target_path_js = target_path
            .replace('\\', "\\\\")
            .replace('\'', "\\'")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('<', "\\x3c")
            .replace('>', "\\x3e");

        let findings_json = serde_json::to_string(findings)
            .unwrap_or_else(|_| "[]".to_string())
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026");

        format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PQCanary Security Audit Report — {target_path_html}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --text-bright: #f0f6fc;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #8b949e;
      --safe: #10b981;
    }}
    body.light {{
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --text: #334155;
      --text-muted: #64748b;
      --text-bright: #0f172a;
      --accent: #0284c7;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
      transition: background 0.2s, color 0.2s;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .logo-group {{ display: flex; align-items: center; gap: 12px; }}
    .logo-badge {{
      background: linear-gradient(135deg, #0284c7, #38bdf8);
      color: #fff;
      font-weight: 800;
      font-size: 1.1rem;
      padding: 6px 12px;
      border-radius: 8px;
    }}
    h1 {{ font-size: 1.4rem; color: var(--text-bright); }}
    .subtext {{ font-size: 0.85rem; color: var(--text-muted); }}
    .actions {{ display: flex; gap: 8px; }}
    button {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-bright);
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: background 0.15s, border-color 0.15s;
    }}
    button:hover {{ border-color: var(--accent); }}
    .grid-summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      position: relative;
    }}
    .grade-badge {{
      font-size: 3rem;
      font-weight: 900;
      line-height: 1;
      color: {grade_color};
    }}
    .score-bar-bg {{
      background: var(--border);
      height: 8px;
      border-radius: 4px;
      overflow: hidden;
      margin-top: 8px;
    }}
    .score-bar-fill {{
      height: 100%;
      background: linear-gradient(90deg, #ef4444, #eab308 50%, #10b981 100%);
      width: {readiness_score}%;
    }}
    .stat-val {{ font-size: 1.8rem; font-weight: 700; color: var(--text-bright); }}
    .stat-label {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; }}
    .controls-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      gap: 12px;
      flex-wrap: wrap;
    }}
    .search-box {{
      flex: 1;
      min-width: 250px;
      position: relative;
    }}
    .search-box input {{
      width: 100%;
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-bright);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 0.9rem;
    }}
    .search-box input:focus {{ outline: none; border-color: var(--accent); }}
    .filter-chips {{ display: flex; gap: 6px; flex-wrap: wrap; }}
    .chip {{
      padding: 4px 10px;
      border-radius: 14px;
      font-size: 0.8rem;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--card-bg);
      color: var(--text-muted);
    }}
    .chip.active {{ border-color: var(--accent); color: var(--accent); font-weight: 600; }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
      border-left: 4px solid var(--border);
    }}
    .finding-card.critical {{ border-left-color: var(--critical); }}
    .finding-card.high {{ border-left-color: var(--high); }}
    .finding-card.medium {{ border-left-color: var(--medium); }}
    .finding-card.low {{ border-left-color: var(--low); }}
    .finding-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 8px;
      margin-bottom: 8px;
    }}
    .rule-title {{ font-size: 1rem; font-weight: 600; color: var(--text-bright); }}
    .badges {{ display: flex; gap: 6px; align-items: center; }}
    .badge {{
      font-size: 0.72rem;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      text-transform: uppercase;
    }}
    .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); }}
    .badge.high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); }}
    .badge.medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); }}
    .badge.low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); }}
    .badge.safe {{ background: rgba(16, 185, 129, 0.2); color: var(--safe); }}
    .file-loc {{ font-family: monospace; font-size: 0.85rem; color: var(--accent); margin-bottom: 8px; }}
    .snippet-box {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 8px 12px;
      font-family: monospace;
      font-size: 0.8rem;
      color: #e2e8f0;
      overflow-x: auto;
      margin-top: 8px;
      white-space: pre-wrap;
    }}
    .remediation-box {{
      background: rgba(56, 189, 248, 0.08);
      border-left: 3px solid var(--accent);
      padding: 6px 12px;
      font-size: 0.85rem;
      margin-top: 8px;
      color: var(--text);
    }}
    footer {{
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-group">
        <span class="logo-badge">PQCANARY</span>
        <div>
          <h1>Post-Quantum Cryptographic Audit</h1>
          <div class="subtext">Target: <code>{target_path_html}</code> &bull; Engine v0.1.0</div>
        </div>
      </div>
      <div class="actions">
        <button onclick="toggleTheme()">Theme</button>
        <button onclick="downloadJson()">JSON</button>
        <button onclick="downloadSarif()">SARIF</button>
        <button onclick="window.print()">Print</button>
      </div>
    </header>

    <div class="grid-summary">
      <div class="card">
        <div class="stat-label">Post-Quantum Health Grade</div>
        <div style="display:flex; align-items:baseline; gap:12px; margin: 8px 0;">
          <div class="grade-badge">{grade}</div>
          <div style="font-size:0.9rem; font-weight:600; color:var(--text-bright);">{grade_desc}</div>
        </div>
        <div class="score-bar-bg"><div class="score-bar-fill"></div></div>
        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:4px;">Readiness Index: {readiness_score}%</div>
      </div>

      <div class="card">
        <div class="stat-label">Findings by Severity</div>
        <div style="display:flex; justify-content:space-between; margin-top:12px;">
          <div><div class="stat-val" style="color:var(--critical);">{critical_count}</div><div class="stat-label">Critical</div></div>
          <div><div class="stat-val" style="color:var(--high);">{high_count}</div><div class="stat-label">High</div></div>
          <div><div class="stat-val" style="color:var(--medium);">{medium_count}</div><div class="stat-label">Med</div></div>
          <div><div class="stat-val" style="color:var(--low);">{low_count}</div><div class="stat-label">Low</div></div>
          <div><div class="stat-val" style="color:var(--info);">{info_count}</div><div class="stat-label">Info</div></div>
        </div>
      </div>

      <div class="card">
        <div class="stat-label">Quantum Vulnerability Split</div>
        <div style="display:flex; justify-content:space-between; margin-top:12px;">
          <div><div class="stat-val" style="color:var(--critical);">{vulnerable_count}</div><div class="stat-label">Vulnerable</div></div>
          <div><div class="stat-val" style="color:var(--medium);">{hybrid_count}</div><div class="stat-label">Hybrid</div></div>
          <div><div class="stat-val" style="color:var(--safe);">{safe_count}</div><div class="stat-label">Safe / PQC</div></div>
        </div>
      </div>

      <div class="card">
        <div class="stat-label">Total Assets Audited</div>
        <div class="stat-val" style="margin-top:12px;">{total}</div>
        <div class="subtext">Across AST, CFG, Keys & Secrets</div>
      </div>
    </div>

    <div class="controls-bar">
      <div class="search-box">
        <input type="text" id="searchInput" placeholder="Search findings by file, rule ID, description..." oninput="filterFindings()">
      </div>
      <div class="filter-chips">
        <span class="chip active" data-sev="ALL" onclick="setSeverityFilter('ALL')">All ({total})</span>
        <span class="chip" data-sev="CRITICAL" onclick="setSeverityFilter('CRITICAL')">Critical ({critical_count})</span>
        <span class="chip" data-sev="HIGH" onclick="setSeverityFilter('HIGH')">High ({high_count})</span>
        <span class="chip" data-sev="MEDIUM" onclick="setSeverityFilter('MEDIUM')">Medium ({medium_count})</span>
        <span class="chip" data-sev="LOW" onclick="setSeverityFilter('LOW')">Low ({low_count})</span>
        <span class="chip" data-sev="INFO" onclick="setSeverityFilter('INFO')">Info ({info_count})</span>
      </div>
    </div>

    <div id="findingsContainer"></div>

    <footer>
      Generated by <strong>PQCanary</strong> &bull; Enterprise Post-Quantum Security Scanner &bull; NIST FIPS 203 / 204 / 205
    </footer>
  </div>

  <script>
    const FINDINGS_DATA = {findings_json};
    let currentSeverity = 'ALL';

    function renderFindings(items) {{
      const container = document.getElementById('findingsContainer');
      if (items.length === 0) {{
        container.innerHTML = '<div style="text-align:center; padding:40px; color:var(--text-muted); background:var(--card-bg); border-radius:8px;">No findings match your criteria.</div>';
        return;
      }}
      container.innerHTML = items.map(f => {{
        const sevClass = (f.severity || 'info').toLowerCase();
        const qRisk = f.quantum_risk || 'UNKNOWN';
        const qBadgeClass = qRisk === 'SAFE' ? 'safe' : (qRisk === 'HYBRID' ? 'medium' : 'critical');
        return `
          <div class="finding-card ${{sevClass}}">
            <div class="finding-header">
              <div class="rule-title">${{escapeHtml(f.vulnerability_class)}}</div>
              <div class="badges">
                <span class="badge ${{sevClass}}">${{f.severity}}</span>
                <span class="badge ${{qBadgeClass}}">${{qRisk}}</span>
                ${{f.rule_id ? `<span class="badge" style="background:var(--border); color:var(--text-muted);">${{f.rule_id}}</span>` : ''}}
              </div>
            </div>
            <div class="file-loc">${{escapeHtml(f.file_path)}}:${{f.line_number || 1}}</div>
            <div style="font-size:0.9rem; color:var(--text);">${{escapeHtml(f.description)}}</div>
            ${{f.snippet ? `<div class="snippet-box">${{escapeHtml(f.snippet)}}</div>` : ''}}
            ${{f.remediation ? `<div class="remediation-box"><strong>Remediation:</strong> ${{escapeHtml(f.remediation)}}</div>` : ''}}
          </div>
        `;
      }}).join('');
    }}

    function filterFindings() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const filtered = FINDINGS_DATA.filter(f => {{
        const matchesSev = currentSeverity === 'ALL' || (f.severity && f.severity.toUpperCase() === currentSeverity);
        const matchesQuery = !query ||
          (f.file_path && f.file_path.toLowerCase().includes(query)) ||
          (f.vulnerability_class && f.vulnerability_class.toLowerCase().includes(query)) ||
          (f.description && f.description.toLowerCase().includes(query)) ||
          (f.rule_id && f.rule_id.toLowerCase().includes(query));
        return matchesSev && matchesQuery;
      }});
      renderFindings(filtered);
    }}

    function setSeverityFilter(sev) {{
      currentSeverity = sev;
      document.querySelectorAll('.filter-chips .chip').forEach(el => {{
        el.classList.toggle('active', el.getAttribute('data-sev') === sev);
      }});
      filterFindings();
    }}

    function toggleTheme() {{
      document.body.classList.toggle('light');
    }}

    function downloadJson() {{
      const blob = new Blob([JSON.stringify(FINDINGS_DATA, null, 2)], {{ type: 'application/json' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'pqcanary_findings.json';
      a.click();
    }}

    function downloadSarif() {{
      window.location.href = '#';
      alert('To export SARIF 2.1.0 format, run: pqcanary scan {target_path_js} --format sarif -o pqcanary.sarif');
    }}

    function escapeHtml(str) {{
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }}

    renderFindings(FINDINGS_DATA);
  </script>
</body>
</html>
"##, target_path_html = target_path_html, target_path_js = target_path_js, grade = grade, grade_color = grade_color, grade_desc = grade_desc, readiness_score = readiness_score, critical_count = critical_count, high_count = high_count, medium_count = medium_count, low_count = low_count, vulnerable_count = vulnerable_count, hybrid_count = hybrid_count, safe_count = safe_count, total = total, findings_json = findings_json)
    }

    fn escape_html(val: &str) -> String {
        val.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#039;")
    }
}

pub struct MarkdownReporter;

impl MarkdownReporter {
    /// Generates a GitHub-flavored Markdown report ideal for CI summaries and PR comments.
    pub fn generate(findings: &[ComprehensiveFinding], target_path: &str) -> String {
        let total = findings.len();
        let mut md = String::with_capacity(total.saturating_mul(160) + 2048);
        use std::fmt::Write;
        let mut counts: HashMap<&str, usize> = HashMap::new();

        for f in findings {
            *counts.entry(&f.severity).or_default() += 1;
        }

        let crit = counts.get("CRITICAL").copied().unwrap_or(0);
        let high = counts.get("HIGH").copied().unwrap_or(0);
        let med = counts.get("MEDIUM").copied().unwrap_or(0);
        let low = counts.get("LOW").copied().unwrap_or(0);

        let _ = writeln!(&mut md, "# PQCanary Post-Quantum Security Report\n");
        let _ = writeln!(&mut md, "**Target:** `{}` &bull; **Total Findings:** {}\n", target_path, total);

        md.push_str("### Executive Summary\n\n");
        md.push_str("| Severity | Count | Status |\n");
        md.push_str("| :--- | :---: | :--- |\n");
        let _ = writeln!(&mut md, "| **CRITICAL** | {} | {} |", crit, if crit > 0 { "Requires immediate migration" } else { "None detected" });
        let _ = writeln!(&mut md, "| **HIGH** | {} | {} |", high, if high > 0 { "Vulnerable to Shor/Grover attacks" } else { "None detected" });
        let _ = writeln!(&mut md, "| **MEDIUM** | {} | {} |", med, if med > 0 { "Upgrade to AES-256 / SHA-384" } else { "None detected" });
        let _ = writeln!(&mut md, "| **LOW** | {} | Config / Best practices |\n", low);

        // QRAMM Quantum Migration Model Section
        let qramm = crate::scanner::qramm::QrammEngine::calculate_score(findings);
        md.push_str(&crate::scanner::qramm::QrammEngine::to_markdown_summary(&qramm));

        if findings.is_empty() {
            md.push_str("**No post-quantum cryptographic vulnerabilities detected!** Your codebase adheres to NIST post-quantum standards.\n");
            return md;
        }

        md.push_str("### Detailed Findings\n\n");
        md.push_str("| File | Line | Rule ID | Severity | Quantum Risk | Description |\n");
        md.push_str("| :--- | :---: | :--- | :---: | :---: | :--- |\n");

        for f in findings {
            let file_short = f.file_path.split(['/', '\\']).next_back().unwrap_or(&f.file_path);
            let file_clean = file_short.replace('|', "\\|").replace('\n', " ");
            let rule = f.rule_id.as_deref().unwrap_or("-").replace('|', "\\|");
            let sev_clean = f.severity.replace('|', "\\|");
            let q_risk = f.quantum_risk.as_deref().unwrap_or("UNKNOWN").replace('|', "\\|");
            let desc_clean = f.description.replace('|', "\\|").replace('\n', " ");
            let _ = writeln!(
                &mut md,
                "| `{}` | {} | `{}` | **{}** | `{}` | {} |",
                file_clean, f.line_number, rule, sev_clean, q_risk, desc_clean
            );
        }

        md.push_str("\n---\n*Report generated automatically by [PQCanary](https://github.com/pqcanary/pqcanary).*");
        md
    }
}

pub struct CsvReporter;

impl CsvReporter {
    /// Generates RFC 4180 compliant CSV format for spreadsheet analysis and SIEM ingestion.
    pub fn generate(findings: &[ComprehensiveFinding]) -> String {
        let mut csv = String::with_capacity(findings.len().saturating_mul(256) + 128);
        csv.push_str("RuleID,Severity,QuantumRisk,Confidence,Category,FilePath,LineNumber,ColumnNumber,Description,Remediation,Fingerprint\n");

        use std::fmt::Write;
        for f in findings {
            let rule = f.rule_id.as_deref().unwrap_or("");
            let q_risk = f.quantum_risk.as_deref().unwrap_or("UNKNOWN");
            let conf = f.confidence.as_deref().unwrap_or("HIGH");
            let col = f.column_number.unwrap_or(1);
            let fp = f.fingerprint.as_deref().unwrap_or("");

            let _ = writeln!(
                &mut csv,
                "{},{},{},{},{},{},{},{},{},{},{}",
                Self::escape_csv(rule),
                Self::escape_csv(&f.severity),
                Self::escape_csv(q_risk),
                Self::escape_csv(conf),
                Self::escape_csv(&f.vulnerability_class),
                Self::escape_csv(&f.file_path),
                f.line_number,
                col,
                Self::escape_csv(&f.description),
                Self::escape_csv(&f.remediation),
                Self::escape_csv(fp),
            );
        }

        csv
    }

    fn escape_csv(val: &str) -> String {
        let trimmed = val.trim_start();
        // CSV Injection Defense (CWE-1236): Neutralize formula execution triggers in Excel / LibreOffice
        let needs_prefix = trimmed.starts_with('=')
            || trimmed.starts_with('+')
            || trimmed.starts_with('-')
            || trimmed.starts_with('@')
            || trimmed.starts_with('\t')
            || trimmed.starts_with('|')
            || trimmed.starts_with('%');

        let sanitized = if needs_prefix {
            format!("'{}", val)
        } else {
            val.to_string()
        };

        if sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n') || sanitized.contains('\r') {
            format!("\"{}\"", sanitized.replace('"', "\"\""))
        } else {
            sanitized
        }
    }
}
