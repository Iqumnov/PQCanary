import {
  type ComprehensiveFinding,
  type HostCryptoAuditReport,
  type RuntimeProcessAuditReport,
  type QrammScore,
  type HndlEvaluationReport,
  type DecoherenceReport,
  type RunningCryptoProcess
} from './tauri';

export interface ImportedReportBundle {
  format: 'pqcanary_json' | 'cbom' | 'sarif' | 'findings_json' | 'csv' | 'html';
  formatLabel: string;
  target?: string;
  timestamp?: string;
  securityGrade: {
    grade: string;
    color: string;
    status: string;
    recommendations: string[];
  };
  findings: ComprehensiveFinding[];
  hostAuditReport?: HostCryptoAuditReport | null;
  runtimeProcessReport?: RuntimeProcessAuditReport | null;
  qrammScore?: QrammScore | null;
  hndlReport?: HndlEvaluationReport | null;
  decoherenceReport?: DecoherenceReport | null;
  cbomJson?: string | null;
  rawReport?: any;
}

/**
 * Intelligent Multi-Layer Sniffer to determine if a string or file is a PQCanary / Security Audit Report
 */
export function isReportContent(content: string, filename?: string): boolean {
  if (!content || typeof content !== 'string') return false;
  const trimmed = content.trim();

  // Extension check
  if (filename) {
    const lowerName = filename.toLowerCase();
    if (lowerName.endsWith('.sarif') || lowerName.endsWith('.sarif.json')) return true;
    if (lowerName.endsWith('.cbom.json') || lowerName.endsWith('.cbom')) return true;
    if (lowerName.endsWith('.pqcanary.json')) return true;
  }

  // HTML embedded report
  if (trimmed.includes('id="pqcanary-audit-data"') || trimmed.includes('PQCanary Security Audit Report')) {
    return true;
  }

  // JSON report checks
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      // PQCanary full report
      if (parsed.$schema?.includes('pqcanary') || parsed.format === 'pqcanary-audit-report' || parsed.generator?.includes('PQCanary')) {
        return true;
      }
      if (parsed.security_grade && (parsed.findings || parsed.host_audit || parsed.runtime_processes)) {
        return true;
      }
      if (parsed.securityGrade && (parsed.findings || parsed.hostAuditReport)) {
        return true;
      }
      // CycloneDX CBOM
      if (parsed.bomFormat === 'CycloneDX' || (parsed.$schema && parsed.$schema.includes('bom'))) {
        return true;
      }
      if (Array.isArray(parsed.components) && parsed.components.some((c: any) => c.type === 'cryptographic-asset' || c['bom-ref']?.includes('crypto'))) {
        return true;
      }
      // SARIF 2.1.0
      if ((parsed.version === '2.1.0' && Array.isArray(parsed.runs)) || parsed.$schema?.includes('sarif')) {
        return true;
      }
      // Raw findings array
      if (Array.isArray(parsed) && parsed.length > 0) {
        const first = parsed[0];
        if (first && (first.vulnerability_class || first.rule_id || (first.severity && first.file_path))) {
          return true;
        }
      }
    } catch {}
  }

  // CSV check
  const firstLine = trimmed.split(/\r?\n/)[0] || '';
  if (firstLine.includes(',') && (firstLine.includes('Vulnerability Class') || (firstLine.includes('Severity') && firstLine.includes('Remediation')))) {
    return true;
  }

  return false;
}

/**
 * Universal Multi-Format Report Parser
 * Ingests PQCanary JSON, CycloneDX CBOM, SARIF, CSV, Raw Findings JSON, or HTML and reconstructs complete state.
 */
export function parseReportFile(content: string, filename?: string): ImportedReportBundle | null {
  if (!content || typeof content !== 'string') return null;
  const trimmed = content.trim();

  // 1. Interactive HTML Report with Embedded Data
  if (trimmed.includes('pqcanary-audit-data')) {
    const match = trimmed.match(/<script\b[^>]*id=["']pqcanary-audit-data["'][^>]*>([\s\S]*?)<\/script>/i);
    if (match && match[1]) {
      try {
        const bundle = parseReportFile(match[1].trim(), filename);
        if (bundle) {
          bundle.format = 'html';
          bundle.formatLabel = 'Interactive HTML Report';
          return bundle;
        }
      } catch {}
    }
  }

  // 2. JSON Reports (PQCanary Full, CBOM, SARIF, Raw Findings)
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);

      // 2A. Full PQCanary Audit Report JSON
      if (
        parsed.$schema?.includes('pqcanary') ||
        parsed.format === 'pqcanary-audit-report' ||
        parsed.generator?.includes('PQCanary') ||
        (parsed.security_grade && (parsed.findings || parsed.host_audit || parsed.runtime_processes)) ||
        (parsed.securityGrade && (parsed.findings || parsed.hostAuditReport))
      ) {
        const secGrade = parsed.security_grade || parsed.securityGrade || deriveSecurityGrade(parsed.findings || []);
        const rawFindings: ComprehensiveFinding[] = (parsed.findings || []).map(normalizeFinding);
        const hostRep: HostCryptoAuditReport | null = parsed.host_audit || parsed.hostAuditReport || null;
        const procRep: RuntimeProcessAuditReport | null = parsed.runtime_processes || parsed.runtimeProcessReport || null;
        const qramm: QrammScore | null = parsed.qramm || parsed.qrammScore || null;
        const hndl: HndlEvaluationReport | null = parsed.hndl || parsed.hndlReport || null;
        const deco: DecoherenceReport | null = parsed.decoherence || parsed.decoherenceReport || null;
        const cbom: string | null = typeof parsed.cbom === 'string' ? parsed.cbom : (parsed.cbom ? JSON.stringify(parsed.cbom, null, 2) : null);

        return {
          format: 'pqcanary_json',
          formatLabel: 'PQCanary Complete Audit Report',
          target: parsed.target || parsed.workspace || filename || 'Imported Workspace',
          timestamp: parsed.timestamp || parsed.audit_timestamp || new Date().toUTCString(),
          securityGrade: secGrade,
          findings: rawFindings,
          hostAuditReport: hostRep,
          runtimeProcessReport: procRep,
          qrammScore: qramm,
          hndlReport: hndl,
          decoherenceReport: deco,
          cbomJson: cbom,
          rawReport: parsed,
        };
      }

      // 2B. CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
      if (
        parsed.bomFormat === 'CycloneDX' ||
        (parsed.$schema && parsed.$schema.includes('bom')) ||
        (Array.isArray(parsed.components) && parsed.components.some((c: any) => c.type === 'cryptographic-asset' || c['bom-ref']?.includes('crypto')))
      ) {
        const findings = extractFindingsFromCbom(parsed);
        const secGrade = deriveSecurityGrade(findings);
        return {
          format: 'cbom',
          formatLabel: 'CycloneDX 1.6 CBOM',
          target: parsed.metadata?.component?.name || filename || 'CBOM Manifest',
          timestamp: parsed.metadata?.timestamp || new Date().toUTCString(),
          securityGrade: secGrade,
          findings,
          cbomJson: JSON.stringify(parsed, null, 2),
          rawReport: parsed,
        };
      }

      // 2C. SARIF 2.1.0 Static Analysis Report
      if ((parsed.version === '2.1.0' && Array.isArray(parsed.runs)) || parsed.$schema?.includes('sarif')) {
        const findings = extractFindingsFromSarif(parsed);
        const secGrade = deriveSecurityGrade(findings);
        const target = parsed.runs?.[0]?.tool?.driver?.name
          ? `${parsed.runs[0].tool.driver.name} SARIF Scan`
          : filename || 'SARIF Audit';

        return {
          format: 'sarif',
          formatLabel: 'SARIF 2.1.0 Audit Report',
          target,
          timestamp: new Date().toUTCString(),
          securityGrade: secGrade,
          findings,
          rawReport: parsed,
        };
      }

      // 2D. Raw Findings JSON Array
      if (Array.isArray(parsed) && parsed.length >= 0) {
        const findings = parsed.map(normalizeFinding);
        const secGrade = deriveSecurityGrade(findings);
        return {
          format: 'findings_json',
          formatLabel: 'PQCanary Findings Dataset',
          target: filename || 'Imported Findings',
          timestamp: new Date().toUTCString(),
          securityGrade: secGrade,
          findings,
          rawReport: parsed,
        };
      }
    } catch {}
  }

  // 3. RFC 4180 CSV Report
  const firstLine = trimmed.split(/\r?\n/)[0] || '';
  if (firstLine.includes(',') && (firstLine.includes('Vulnerability Class') || firstLine.includes('Severity'))) {
    const findings = parseCsvFindings(trimmed);
    if (findings.length > 0) {
      const secGrade = deriveSecurityGrade(findings);
      return {
        format: 'csv',
        formatLabel: 'PQCanary CSV Export',
        target: filename || 'Imported CSV Audit',
        timestamp: new Date().toUTCString(),
        securityGrade: secGrade,
        findings,
        rawReport: trimmed,
      };
    }
  }

  return null;
}

/**
 * Extracts ComprehensiveFindings from a CycloneDX 1.6 CBOM JSON
 */
function extractFindingsFromCbom(cbom: any): ComprehensiveFinding[] {
  const findings: ComprehensiveFinding[] = [];
  const components: any[] = cbom.components || [];

  for (let i = 0; i < components.length; i++) {
    const c = components[i];
    if (c.type === 'cryptographic-asset' || c['bom-ref']?.includes('crypto') || c.cryptoProperties) {
      const name = c.name || c.cryptoProperties?.algorithmProperties?.name || 'Cryptographic Asset';
      const isPqc =
        name.includes('ML-KEM') ||
        name.includes('ML-DSA') ||
        name.includes('SLH-DSA') ||
        name.includes('Falcon') ||
        name.includes('Kyber') ||
        name.includes('Dilithium') ||
        name.includes('SPHINCS') ||
        c.cryptoProperties?.algorithmProperties?.classicalSecurityLevel >= 256;

      const severity = isPqc ? 'LOW' : 'HIGH';
      const quantum_risk = isPqc ? 'QUANTUM_RESILIENT' : 'VULNERABLE';
      const file_path = c.evidence?.occurrences?.[0]?.location || cbom.metadata?.component?.name || 'CBOM Component';
      const line_number = c.evidence?.occurrences?.[0]?.line || 1;

      findings.push({
        file_path,
        line_number,
        rule_id: c['bom-ref'] || `CBOM-${i + 1}`,
        vulnerability_class: name,
        description: c.description || `Cryptographic asset component '${name}' specified in CycloneDX CBOM bill of materials.`,
        severity,
        quantum_risk,
        remediation: isPqc
          ? 'Asset conforms to post-quantum standards.'
          : 'Migrate classical algorithm to NIST FIPS 203 (ML-KEM) or FIPS 204 (ML-DSA).',
      });
    }
  }

  return findings;
}

/**
 * Extracts ComprehensiveFindings from a SARIF 2.1.0 JSON object
 */
function extractFindingsFromSarif(sarif: any): ComprehensiveFinding[] {
  const findings: ComprehensiveFinding[] = [];
  const runs = sarif.runs || [];

  for (const run of runs) {
    const results = run.results || [];
    for (const res of results) {
      const loc = res.locations?.[0]?.physicalLocation;
      const file_path = loc?.artifactLocation?.uri || 'unknown';
      const line_number = loc?.region?.startLine || 1;
      const rule_id = res.ruleId || 'PQC-SARIF';
      const vulnerability_class = res.message?.text || rule_id;
      const level = res.level || 'warning';
      const severity = level === 'error' ? 'CRITICAL' : level === 'warning' ? 'HIGH' : 'LOW';

      findings.push({
        file_path,
        line_number,
        rule_id,
        vulnerability_class,
        description: res.message?.text || `Static security diagnostic identified by rule ${rule_id}.`,
        severity,
        remediation: 'Migrate classical cryptography to post-quantum compliant algorithms (NIST FIPS 203/204).',
      });
    }
  }

  return findings;
}

/**
 * Parses CSV text into ComprehensiveFindings
 */
function parseCsvFindings(csvText: string): ComprehensiveFinding[] {
  const lines = csvText.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length < 2) return [];

  const headers = parseCsvRow(lines[0]);
  const severityIdx = headers.findIndex(h => /severity/i.test(h));
  const classIdx = headers.findIndex(h => /vulnerability|class|name/i.test(h));
  const ruleIdx = headers.findIndex(h => /rule/i.test(h));
  const fileIdx = headers.findIndex(h => /file|location|path/i.test(h));
  const lineIdx = headers.findIndex(h => /line/i.test(h));
  const remIdx = headers.findIndex(h => /remediation|guidance/i.test(h));

  const findings: ComprehensiveFinding[] = [];
  for (let i = 1; i < lines.length; i++) {
    const row = parseCsvRow(lines[i]);
    if (row.length === 0) continue;

    const vulnerability_class = (classIdx >= 0 && row[classIdx]) ? row[classIdx] : `Cryptographic Asset #${i}`;
    const severity = (severityIdx >= 0 && row[severityIdx]) ? row[severityIdx].toUpperCase() : 'MEDIUM';
    const file_path = (fileIdx >= 0 && row[fileIdx]) ? row[fileIdx] : 'imported_dataset';
    const line_number = (lineIdx >= 0 && parseInt(row[lineIdx], 10)) || 1;
    const rule_id = (ruleIdx >= 0 && row[ruleIdx]) ? row[ruleIdx] : `CSV-${i}`;
    const remediation = (remIdx >= 0 && row[remIdx]) ? row[remIdx] : 'Upgrade to NIST FIPS 203/204 standard.';

    findings.push({
      file_path,
      line_number,
      rule_id,
      vulnerability_class,
      description: `Imported finding: ${vulnerability_class}`,
      severity,
      remediation,
    });
  }

  return findings;
}

function parseCsvRow(rowText: string): string[] {
  const cells: string[] = [];
  let inQuotes = false;
  let curCell = '';

  for (let i = 0; i < rowText.length; i++) {
    const c = rowText[i];
    if (c === '"') {
      if (inQuotes && rowText[i + 1] === '"') {
        curCell += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (c === ',' && !inQuotes) {
      cells.push(curCell.trim());
      curCell = '';
    } else {
      curCell += c;
    }
  }
  cells.push(curCell.trim());
  return cells;
}

function normalizeFinding(f: any): ComprehensiveFinding {
  return {
    file_path: f.file_path || f.filePath || f.file || 'unknown',
    line_number: Number(f.line_number || f.lineNumber || f.line || 1),
    vulnerability_class: f.vulnerability_class || f.vulnerabilityClass || f.name || 'Cryptographic Tech Debt',
    description: f.description || '',
    severity: (f.severity || 'MEDIUM').toUpperCase(),
    remediation: f.remediation || 'Modernize to post-quantum standard',
    rule_id: f.rule_id || f.ruleId || f.rule,
    pattern_name: f.pattern_name || f.patternName,
    nist_status: f.nist_status || f.nistStatus,
    quantum_risk: f.quantum_risk || f.quantumRisk,
  };
}

/**
 * Derives a standardized security health grade from findings
 */
export function deriveSecurityGrade(findings: ComprehensiveFinding[]): {
  grade: string;
  color: string;
  status: string;
  recommendations: string[];
} {
  const critical = findings.filter(f => f.severity.toUpperCase() === 'CRITICAL').length;
  const high = findings.filter(f => f.severity.toUpperCase() === 'HIGH').length;
  const medium = findings.filter(f => f.severity.toUpperCase() === 'MEDIUM').length;

  if (critical > 0) {
    return {
      grade: 'F',
      color: '#ef4444',
      status: `Critical Quantum Vulnerabilities Detected (${critical} Critical)`,
      recommendations: [
        'Immediately deprecate classical public-key cryptography (RSA, ECDSA, DH).',
        'Initiate transition to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).',
        'Deploy post-quantum hybrid TLS termination proxies.'
      ]
    };
  }
  if (high > 0) {
    return {
      grade: 'C',
      color: '#f97316',
      status: `Quantum-Vulnerable Classical Cryptography Present (${high} High)`,
      recommendations: [
        'Replace quantum-vulnerable key exchange algorithms with ML-KEM-768.',
        'Adopt stateful hash-based or ML-DSA signatures for software signing.',
        'Prepare enterprise CBOM for cryptographic asset inventory.'
      ]
    };
  }
  const low = findings.filter(f => f.severity.toUpperCase() === 'LOW').length;

  if (medium > 0) {
    return {
      grade: 'B',
      color: '#f59e0b',
      status: 'Post-Quantum Migration Recommendations Identified',
      recommendations: [
        'Review transitional ciphers and evaluate quantum resistance horizons.',
        'Enable hybrid key agreement in transport layers.'
      ]
    };
  }
  if (low > 0) {
    return {
      grade: 'A-',
      color: '#38bdf8',
      status: `Minor Cryptographic Technical Debt Detected (${low} Low)`,
      recommendations: [
        'Remediate minor cryptographic technical debt and configuration warnings.',
        'Verify key lengths and salt parameters against NIST SP 800-131A Rev 2.'
      ]
    };
  }
  return {
    grade: 'A+',
    color: '#10b981',
    status: 'Quantum Resilient Cryptography Verified',
    recommendations: [
      'NIST FIPS 203 and FIPS 204 compliant cryptography verified across assets.',
      'Maintain continuous CI/CD cryptographic audit tracking.'
    ]
  };
}
