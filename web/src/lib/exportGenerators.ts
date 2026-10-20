import {
  type ComprehensiveFinding,
  type HostCryptoAuditReport,
  type RuntimeProcessAuditReport,
  type QrammScore,
  type HndlEvaluationReport,
  type DecoherenceReport
} from './tauri';

export interface FullAuditReportBundle {
  target?: string;
  timestamp?: string;
  securityGrade?: { grade: string; color: string; status: string; recommendations: string[] };
  findings?: ComprehensiveFinding[];
  hostAuditReport?: HostCryptoAuditReport | null;
  runtimeProcessReport?: RuntimeProcessAuditReport | null;
  qrammScore?: QrammScore | null;
  hndlReport?: HndlEvaluationReport | null;
  decoherenceReport?: DecoherenceReport | null;
  cbomJson?: string | null;
}

/** Download helper for triggering browser file downloads */
export function triggerFileDownload(content: string, filename: string, mimeType: string) {
  if (typeof window === 'undefined') return;
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Generates standardized, full metadata PQCanary Audit Report JSON */
export function generateFullAuditJson(bundle: FullAuditReportBundle): string {
  const report = {
    $schema: 'https://pqcanary.io/schema/audit-report-v1.json',
    format: 'pqcanary-audit-report',
    version: '1.0.0',
    generator: 'PQCanary Enterprise Post-Quantum Cryptographic Security Platform',
    target: bundle.target || 'Source Workspace',
    timestamp: bundle.timestamp || new Date().toUTCString(),
    security_grade: bundle.securityGrade || {
      grade: 'C',
      color: '#f59e0b',
      status: 'Cryptographic Audit Completed',
      recommendations: []
    },
    total_diagnostics: (bundle.findings || []).length,
    findings: bundle.findings || [],
    host_audit: bundle.hostAuditReport || null,
    runtime_processes: bundle.runtimeProcessReport || null,
    qramm: bundle.qrammScore || null,
    hndl: bundle.hndlReport || null,
    decoherence: bundle.decoherenceReport || null,
    cbom: bundle.cbomJson ? (typeof bundle.cbomJson === 'string' ? safeJsonParse(bundle.cbomJson) : bundle.cbomJson) : null
  };
  return JSON.stringify(report, null, 2);
}

function safeJsonParse(str: string): any {
  try {
    return JSON.parse(str);
  } catch {
    return str;
  }
}

/** RFC 4180 CSV export supporting both static code findings and runtime processes */
export function generateCsvReport(findings: ComprehensiveFinding[], bundle?: FullAuditReportBundle): string {
  const headers = ['Category', 'Index', 'Severity / Posture', 'Vulnerability / Component', 'Rule / Module', 'Quantum Risk', 'Location / Path', 'Line / PID', 'Remediation'];
  const rows: string[][] = [];

  // Static findings
  (findings || []).forEach((f, i) => {
    rows.push([
      'Static Code Diagnostic',
      (i + 1).toString(),
      escapeCsv(f.severity),
      escapeCsv(f.vulnerability_class),
      escapeCsv(f.pattern_name || f.rule_id || 'N/A'),
      escapeCsv(f.quantum_risk || f.nist_status || 'UNKNOWN'),
      escapeCsv(f.file_path),
      (f.line_number || 1).toString(),
      escapeCsv(f.remediation)
    ]);
  });

  // Host OS Cryptography
  if (bundle?.hostAuditReport) {
    const h = bundle.hostAuditReport;
    rows.push([
      'Host OS Environment',
      'OS-1',
      escapeCsv(h.quantum_readiness_posture),
      escapeCsv(`Host OS: ${h.os_name} (${h.arch})`),
      escapeCsv(h.openssl_detected ? `OpenSSL ${h.openssl_version || ''}` : 'No OpenSSL in PATH'),
      escapeCsv(h.quantum_readiness_posture),
      escapeCsv(h.trust_store_path || 'System Root Store'),
      'N/A',
      escapeCsv((h.recommendations || []).join('; '))
    ]);
  }

  // Runtime Process Memory findings
  if (bundle?.runtimeProcessReport?.processes) {
    bundle.runtimeProcessReport.processes.forEach((p, i) => {
      rows.push([
        'Runtime Process Memory',
        (i + 1).toString(),
        escapeCsv(p.runtime_posture),
        escapeCsv(p.name),
        escapeCsv((p.loaded_crypto_modules || []).join('; ')),
        escapeCsv(p.runtime_posture),
        escapeCsv(p.executable_path),
        p.pid.toString(),
        escapeCsv(p.recommendation)
      ]);
    });
  }

  if (rows.length === 0) {
    rows.push(['No Cryptographic Deficits', '1', 'CLEAN', 'Zero Vulnerabilities Detected', 'NIST-FIPS', 'QUANTUM_RESILIENT', 'N/A', '1', 'No action needed']);
  }

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
}

function escapeCsv(val: string): string {
  if (!val) return '""';
  const trimmed = val.trimStart();
  // CSV Injection Defense (CWE-1236)
  const needsPrefix = ['=', '+', '-', '@', '\t', '|', '%'].some(c => trimmed.startsWith(c));
  const sanitized = needsPrefix ? `'${val}` : val;
  const clean = sanitized.replace(/"/g, '""');
  return `"${clean}"`;
}

/** Comprehensive GitHub-flavored Markdown report */
export function generateMarkdownReport(
  findings: ComprehensiveFinding[],
  target: string,
  grade: { grade: string; color: string; status: string; recommendations: string[] },
  timestamp: string,
  bundle?: FullAuditReportBundle
): string {
  let md = `# PQCanary Post-Quantum Security Audit Report\n\n`;
  md += `- **Audit Target**: \`${target || 'Local Workspace'}\`\n`;
  md += `- **Security Health Grade**: **${grade.grade}** (${grade.status})\n`;
  md += `- **Evaluation Date**: \`${timestamp || new Date().toUTCString()}\`\n`;
  md += `- **Total Code Diagnostics**: \`${findings.length}\`\n`;
  if (bundle?.runtimeProcessReport) {
    md += `- **Runtime Processes Inspected**: \`${bundle.runtimeProcessReport.total_processes_inspected}\` (\`${bundle.runtimeProcessReport.quantum_vulnerable_processes_count}\` Vulnerable)\n`;
  }
  md += `\n`;

  md += `## Actionable Executive Recommendations\n\n`;
  if (grade.recommendations.length > 0) {
    grade.recommendations.forEach(r => { md += `- ${r}\n`; });
  } else {
    md += `- Zero post-quantum cryptographic vulnerabilities detected.\n`;
  }

  // Host OS Cryptography Environment
  if (bundle?.hostAuditReport) {
    const h = bundle.hostAuditReport;
    md += `\n## Host Operating System Cryptographic Environment\n\n`;
    md += `| Environment Property | Observed Value |\n`;
    md += `|---|---|\n`;
    md += `| **Operating System** | \`${h.os_name} (${h.arch})\` |\n`;
    md += `| **OpenSSL CLI Runtime** | \`${h.openssl_detected ? (h.openssl_version || 'Detected') : 'Not found in system PATH'}\` |\n`;
    md += `| **Quantum Readiness Posture** | **${h.quantum_readiness_posture}** |\n`;
    md += `| **System Trust Store** | \`${h.trust_store_path || 'Windows/OS Certificate Store'}\` |\n`;
  }

  // Runtime Process Memory Inspection
  if (bundle?.runtimeProcessReport) {
    const rp = bundle.runtimeProcessReport;
    md += `\n## Runtime Process Memory & Dynamic Library Auditor\n\n`;
    md += `- **Total Processes Scanned**: \`${rp.total_processes_inspected}\`\n`;
    md += `- **Crypto Active Processes**: \`${rp.crypto_active_processes_count}\`\n`;
    md += `- **Vulnerable Processes**: \`${rp.quantum_vulnerable_processes_count}\`\n`;
    md += `- **System Runtime Posture**: \`${rp.system_runtime_posture}\`\n\n`;

    if (rp.processes.length > 0) {
      md += `| PID | Process Name | Runtime Posture | Loaded Crypto Modules | Recommendation |\n`;
      md += `|---|---|---|---|---|\n`;
      rp.processes.slice(0, 30).forEach(p => {
        md += `| \`${p.pid}\` | \`${p.name}\` | **${p.runtime_posture}** | \`${p.loaded_crypto_modules.join(', ')}\` | ${p.recommendation} |\n`;
      });
      if (rp.processes.length > 30) {
        md += `| ... | *(${rp.processes.length - 30} additional processes inspected)* | ... | ... | ... |\n`;
      }
    }
  }

  // QRAMM Maturity Scorecard
  if (bundle?.qrammScore) {
    const q = bundle.qrammScore;
    md += `\n## QRAMM 5-Dimension Migration Readiness\n\n`;
    md += `- **Readiness Score**: **${q.readiness_score}%** (${q.posture_level})\n`;
    md += `- **Post-Quantum Safe Assets**: \`${q.safe_count}\`\n`;
    md += `- **Hybrid Transitional Assets**: \`${q.hybrid_count}\`\n`;
    md += `- **Vulnerable Classical Assets**: \`${q.vulnerable_count}\`\n`;
  }

  // HNDL Mosca Theorem Risk
  if (bundle?.hndlReport) {
    const hndl = bundle.hndlReport;
    md += `\n## Mosca Theorem HNDL Exposure Analysis\n\n`;
    md += `- **Mosca Theorem Satisfied**: **${hndl.mosca_theorem_satisfied ? 'YES (VULNERABLE: X + Y > Z)' : 'NO (RESILIENT)'}**\n`;
    md += `- **HNDL Criticality Index**: \`${hndl.hndl_criticality_index} / 100\`\n`;
    md += `- **Quantum Threat Horizon (Z)**: \`${hndl.quantum_threat_years_z} years\`\n`;
    md += `- **Overall Posture**: **${hndl.overall_posture}**\n`;
  }

  // Diagnostic Findings Table
  md += `\n## Diagnostic Code Findings Table\n\n`;
  md += `| # | Severity | Quantum Risk | Vulnerability Class | File & Line | Remediation Guidance |\n`;
  md += `|---|---|---|---|---|---|\n`;

  if (findings.length === 0) {
    md += `| - | **CLEAN** | SAFE | No classical or quantum-vulnerable code findings | - | Conforms to post-quantum standards |\n`;
  } else {
    findings.forEach((f, i) => {
      md += `| ${i + 1} | **${f.severity}** | ${f.quantum_risk || 'VULNERABLE'} | \`${f.vulnerability_class}\` | \`${f.file_path}:${f.line_number}\` | ${f.remediation} |\n`;
    });
  }

  md += `\n---\n*Generated by PQCanary — Enterprise Post-Quantum Cryptographic Platform (NIST FIPS 203 / FIPS 204 Ready)*\n`;
  return md;
}

/** Standalone, interactive HTML report with embedded re-importable data */
export function generateInteractiveHtmlReport(
  findings: ComprehensiveFinding[],
  target: string,
  grade: { grade: string; color: string; status: string; recommendations: string[] },
  timestamp: string,
  bundle?: FullAuditReportBundle
): string {
  const safeTarget = escapeHtml(target || 'Source Snippet / Workspace');
  const safeTimestamp = escapeHtml(timestamp || new Date().toUTCString());
  const safeGradeColor = /^[#a-zA-Z0-9(),. -]+$/.test(grade?.color || '') ? grade.color : '#f59e0b';
  const safeGrade = escapeHtml(grade?.grade || 'C');
  const criticalCount = findings.filter(f => f.severity.toUpperCase() === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity.toUpperCase() === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity.toUpperCase() === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity.toUpperCase() === 'LOW').length;

  const fullBundle: FullAuditReportBundle = {
    target,
    timestamp,
    securityGrade: grade,
    findings,
    hostAuditReport: bundle?.hostAuditReport || null,
    runtimeProcessReport: bundle?.runtimeProcessReport || null,
    qrammScore: bundle?.qrammScore || null,
    hndlReport: bundle?.hndlReport || null,
    decoherenceReport: bundle?.decoherenceReport || null,
    cbomJson: bundle?.cbomJson || null
  };
  const embeddedJson = JSON.stringify(fullBundle).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PQCanary Security Audit Report — ${safeTarget}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;600&family=Syne:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0a0a0a;
      --card-bg: rgba(255, 255, 255, 0.04);
      --card-border: rgba(255, 255, 255, 0.08);
      --text: #f5f5f4;
      --text-muted: #a8a29e;
      --amber: #f59e0b;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --safe: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      background-image: radial-gradient(circle 800px at 50% 100vh, rgba(245, 158, 11, 0.12) 0%, rgba(217, 119, 6, 0.04) 40%, transparent 80%);
      color: var(--text);
      font-family: 'Outfit', sans-serif;
      padding: 3rem 1.5rem;
      min-height: 100vh;
    }
    .container { max-width: 1080px; margin: 0 auto; }
    header { text-align: center; margin-bottom: 2.5rem; }
    header h1 { font-family: 'Syne', sans-serif; font-size: 2rem; font-weight: 600; letter-spacing: -0.02em; color: #fff; margin-bottom: 0.5rem; }
    header p { color: var(--text-muted); font-size: 0.9rem; font-weight: 300; }
    .verdict-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 2rem 2.25rem;
      margin-bottom: 2rem;
      backdrop-filter: blur(20px);
      box-shadow: 0 20px 40px -15px rgba(0,0,0,0.8);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1.5rem;
    }
    .grade-badge {
      font-family: 'Syne', sans-serif;
      font-size: 4rem;
      font-weight: 300;
      line-height: 1;
      color: ${safeGradeColor};
      margin-right: 1.25rem;
    }
    .verdict-info h2 { font-size: 1.25rem; font-weight: 500; margin-bottom: 0.35rem; color: #fff; }
    .verdict-info span { font-size: 0.85rem; color: var(--text-muted); }
    .stats-bar { display: flex; gap: 0.8rem; margin-top: 1.25rem; flex-wrap: wrap; }
    .stat-pill {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 0.4rem 0.9rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-family: 'Space Grotesk', sans-serif;
    }
    .recommendations-card {
      background: rgba(245, 158, 11, 0.04);
      border: 1px solid rgba(245, 158, 11, 0.15);
      border-radius: 18px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 2rem;
    }
    .recommendations-card h3 {
      font-family: 'Space Grotesk', sans-serif;
      font-size: 0.9rem;
      color: var(--amber);
      margin-bottom: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .recommendations-card ul { padding-left: 1.25rem; }
    .recommendations-card li { margin-bottom: 0.4rem; font-size: 0.9rem; font-weight: 300; color: #e7e5e4; line-height: 1.5; }
    .section-title { font-family: 'Space Grotesk', sans-serif; font-size: 1rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin: 2rem 0 1rem 0; }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 1rem;
    }
    .badge {
      font-size: 0.7rem;
      font-weight: 600;
      padding: 0.2rem 0.6rem;
      border-radius: 6px;
      text-transform: uppercase;
      font-family: 'Space Grotesk', sans-serif;
    }
    .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-HIGH { background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge-MEDIUM { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge-LOW { background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.4); }
    .table-container { width: 100%; overflow-x: auto; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.1); color: var(--text-muted); font-family: 'Space Grotesk', sans-serif; }
    td { padding: 0.75rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); color: #e7e5e4; }
    footer { text-align: center; margin-top: 3.5rem; color: var(--text-muted); font-size: 0.8rem; font-weight: 300; }
  </style>
</head>
<body>
  <!-- Embedded Machine-Readable PQCanary Report Data for Instant Re-Import -->
  <script id="pqcanary-audit-data" type="application/json">
${embeddedJson}
  </script>

  <div class="container">
    <header>
      <h1>PQCanary Security Audit Report</h1>
      <p>Target: <code>${safeTarget}</code> &bull; Audited on ${safeTimestamp}</p>
    </header>

    <div class="verdict-card">
      <div style="display: flex; align-items: center;">
        <div class="grade-badge">${safeGrade}</div>
        <div class="verdict-info">
          <h2>${escapeHtml(grade.status)}</h2>
          <span>NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA) Post-Quantum Compliance Verified</span>
        </div>
      </div>
      <div class="stats-bar">
        <div class="stat-pill">Diagnostics: <strong>${findings.length}</strong></div>
        ${bundle?.runtimeProcessReport ? `<div class="stat-pill">Processes: <strong>${bundle.runtimeProcessReport.total_processes_inspected}</strong></div>` : ''}
        <div class="stat-pill" style="color: #ef4444;">Critical: <strong>${criticalCount}</strong></div>
        <div class="stat-pill" style="color: #f97316;">High: <strong>${highCount}</strong></div>
        <div class="stat-pill" style="color: #f59e0b;">Medium: <strong>${mediumCount}</strong></div>
      </div>
    </div>

    <div class="recommendations-card">
      <h3>Actionable Executive Recommendations</h3>
      <ul>
        ${grade.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
      </ul>
    </div>

    ${bundle?.hostAuditReport ? `
    <h2 class="section-title">Host Operating System Cryptographic Environment</h2>
    <div class="finding-card">
      <div class="table-container">
        <table>
          <tr><th>Operating System</th><td><code>${escapeHtml(bundle.hostAuditReport.os_name)} (${escapeHtml(bundle.hostAuditReport.arch)})</code></td></tr>
          <tr><th>OpenSSL Runtime</th><td><code>${escapeHtml(bundle.hostAuditReport.openssl_detected ? (bundle.hostAuditReport.openssl_version || 'Detected') : 'Not found in system PATH')}</code></td></tr>
          <tr><th>Readiness Posture</th><td><strong>${escapeHtml(bundle.hostAuditReport.quantum_readiness_posture)}</strong></td></tr>
          <tr><th>Trust Store</th><td><code>${escapeHtml(bundle.hostAuditReport.trust_store_path || 'Windows/OS Certificate Store')}</code></td></tr>
        </table>
      </div>
    </div>
    ` : ''}

    ${bundle?.runtimeProcessReport ? `
    <h2 class="section-title">Runtime Process Memory & Dynamic Library Auditor (${bundle.runtimeProcessReport.total_processes_inspected} Inspected)</h2>
    <div class="finding-card">
      <div style="margin-bottom: 1rem; font-size: 0.85rem; color: var(--text-muted);">
        System Runtime Posture: <strong>${escapeHtml(bundle.runtimeProcessReport.system_runtime_posture)}</strong>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>PID</th><th>Process</th><th>Posture</th><th>Loaded Modules</th><th>Recommendation</th></tr>
          </thead>
          <tbody>
            ${bundle.runtimeProcessReport.processes.slice(0, 30).map(p => `
              <tr>
                <td><code>${p.pid}</code></td>
                <td><strong>${escapeHtml(p.name)}</strong></td>
                <td><span class="badge badge-${p.runtime_posture === 'VULNERABLE' ? 'CRITICAL' : 'MEDIUM'}">${escapeHtml(p.runtime_posture)}</span></td>
                <td><code>${escapeHtml(p.loaded_crypto_modules.join(', '))}</code></td>
                <td>${escapeHtml(p.recommendation)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
    ` : ''}

    <h2 class="section-title">Diagnostic Findings (${findings.length})</h2>
    <div id="findings-list">
      ${findings.length === 0 ? '<div class="finding-card" style="color: #10b981; text-align: center; padding: 2rem;">Zero post-quantum security deficits or classical cryptographic vulnerabilities detected in code input.</div>' : ''}
      ${findings.map((f, i) => `
        <div class="finding-card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span class="badge badge-${escapeHtml(f.severity.toUpperCase())}">${escapeHtml(f.severity)}</span>
            <span style="font-family: monospace; font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(f.file_path)}:${f.line_number}</span>
          </div>
          <div style="font-size: 1rem; font-weight: 500; color: #fff; margin-bottom: 0.4rem;">${escapeHtml(f.vulnerability_class)}</div>
          <div style="font-size: 0.85rem; color: #d6d3d1; font-weight: 300; margin-bottom: 0.75rem; line-height: 1.5;">${escapeHtml(f.description)}</div>
          <div style="background: rgba(16, 185, 129, 0.06); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 10px; padding: 0.6rem 0.85rem; font-size: 0.825rem; color: #34d399; font-weight: 300;"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>
        </div>
      `).join('')}
    </div>

    <footer>
      Generated by PQCanary &bull; NIST FIPS 203 / 204 Enterprise Post-Quantum Security Platform
    </footer>
  </div>
  <script id="pqcanary-audit-data" type="application/json">${embeddedJson}</script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
