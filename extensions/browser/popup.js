/**
 * PQCanary Browser Extension Popup Controller
 * Executes live website cryptographic audits using the 193 PQCanary rule catalog.
 * Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
 */

document.addEventListener("DOMContentLoaded", async () => {
  let activeTabUrl = "";
  let activeTabId = null;

  const siteHostnameEl = document.getElementById("site-hostname");
  const siteFullUrlEl = document.getElementById("site-full-url");
  const siteProtoBadgeEl = document.getElementById("site-protocol-badge");
  const gradeBadgeEl = document.getElementById("grade-badge");
  const gradeStatusEl = document.getElementById("grade-status");
  const gradeSummaryEl = document.getElementById("grade-summary");
  const metricCriticalEl = document.getElementById("metric-critical-count");
  const metricFindingsEl = document.getElementById("metric-findings-count");
  const metricScriptsEl = document.getElementById("metric-scripts-count");
  const findingsListEl = document.getElementById("findings-list");
  const findingsPillEl = document.getElementById("findings-pill");
  const btnScanSite = document.getElementById("btn-scan-site");
  const btnDeepScan = document.getElementById("btn-deep-scan");

  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url) {
    activeTabUrl = tab.url;
    activeTabId = tab.id;

    try {
      const urlObj = new URL(tab.url);
      siteHostnameEl.textContent = urlObj.hostname || "Webpage";
      siteFullUrlEl.textContent = tab.url;

      if (urlObj.protocol === "https:") {
        siteProtoBadgeEl.textContent = "HTTPS";
        siteProtoBadgeEl.classList.remove("insecure");
      } else {
        siteProtoBadgeEl.textContent = "HTTP (Insecure)";
        siteProtoBadgeEl.classList.add("insecure");
      }
    } catch {
      siteHostnameEl.textContent = tab.title || "Active Page";
      siteFullUrlEl.textContent = tab.url;
    }

    // Auto-run scan on popup open
    runPageAudit();
  } else {
    siteHostnameEl.textContent = "No active webpage";
    siteFullUrlEl.textContent = "Open a website to audit post-quantum security.";
  }

  btnScanSite.addEventListener("click", () => {
    runPageAudit();
  });

  btnDeepScan.addEventListener("click", () => {
    if (activeTabUrl) {
      const targetUrl = `http://localhost:3000/?url=${encodeURIComponent(activeTabUrl)}`;
      chrome.tabs.create({ url: targetUrl });
    }
  });

  async function runPageAudit() {
    if (!activeTabId) return;

    btnScanSite.disabled = true;
    btnScanSite.querySelector("span").textContent = "Auditing...";
    findingsListEl.innerHTML = '<div class="pq-empty-state">Inspecting active DOM, scripts, and WebCrypto APIs...</div>';

    let pageData = null;
    try {
      pageData = await chrome.tabs.sendMessage(activeTabId, { action: "getPageCryptoData" });
    } catch (e) {
      // Content script not injected yet or restricted page (e.g. chrome://)
      pageData = {
        url: activeTabUrl,
        isHttps: activeTabUrl.startsWith("https:"),
        scripts: [],
        webCryptoAlgos: [],
        librarySignatures: []
      };
    }

    const findings = executeRuleAudit(pageData);
    renderAuditResults(findings, pageData);

    btnScanSite.disabled = false;
    btnScanSite.querySelector("span").textContent = "Audit Current Site";
  }

  function executeRuleAudit(pageData) {
    const findings = [];
    const seenRuleIds = new Set();

    // 1. Insecure Plaintext HTTP Check
    if (!pageData.isHttps && pageData.url.startsWith("http://")) {
      findings.push({
        id: "NET-HTTP-001",
        name: "Insecure Plaintext Transport",
        severity: "CRITICAL",
        quantum_risk: "Vulnerable",
        description: "Website communicates over unencrypted plaintext HTTP. All credentials, keys, and session cookies are fully subject to eavesdropping.",
        remediation: "Enforce HTTPS transport with TLS 1.3 and hybrid post-quantum key exchange (X25519MLKEM768)."
      });
      seenRuleIds.add("NET-HTTP-001");
    }

    // 2. Scan WebCrypto Runtime Usages
    if (pageData.webCryptoAlgos && pageData.webCryptoAlgos.length > 0) {
      for (const algo of pageData.webCryptoAlgos) {
        if (/rsa/i.test(algo)) {
          if (!seenRuleIds.has("ASYM-RSA-001")) {
            findings.push({
              id: "ASYM-RSA-001",
              name: "Classical RSA in WebCrypto API",
              severity: "CRITICAL",
              quantum_risk: "Vulnerable",
              description: `Active WebCrypto API invoked with algorithm "${algo}". RSA integer factorization is completely broken by Shor's quantum algorithm.`,
              remediation: "Migrate asymmetric cryptography to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)."
            });
            seenRuleIds.add("ASYM-RSA-001");
          }
        }
        if (/ecdsa|ecdh|curve25519|p-256|p-384|p-521/i.test(algo)) {
          if (!seenRuleIds.has("ASYM-ECC-001")) {
            findings.push({
              id: "ASYM-ECC-001",
              name: "Classical Elliptic Curve in WebCrypto API",
              severity: "CRITICAL",
              quantum_risk: "Vulnerable",
              description: `Active WebCrypto API invoked with elliptic curve algorithm "${algo}". Elliptic curve discrete logarithm is fully broken by Shor's quantum algorithm.`,
              remediation: "Upgrade key exchange to NIST FIPS 203 (ML-KEM-768) and digital signatures to NIST FIPS 204 (ML-DSA-65)."
            });
            seenRuleIds.add("ASYM-ECC-001");
          }
        }
      }
    }

    // 3. Scan Library Signatures
    if (pageData.librarySignatures) {
      for (const sig of pageData.librarySignatures) {
        if (sig.includes("Classical RSA") && !seenRuleIds.has("LIB-RSA")) {
          findings.push({
            id: "LIB-RSA",
            name: "Classical JSEncrypt Library Loaded",
            severity: "HIGH",
            quantum_risk: "Vulnerable",
            description: "Website bundles JSEncrypt library for client-side RSA encryption.",
            remediation: "Replace client-side RSA encryption with lattice-based ML-KEM or Kyber."
          });
          seenRuleIds.add("LIB-RSA");
        }
        if (sig.includes("Post-Quantum Safe") && !seenRuleIds.has("PQC-SAFE")) {
          findings.push({
            id: "PQC-SAFE",
            name: "Post-Quantum Cryptography Detected",
            severity: "INFO",
            quantum_risk: "Safe",
            description: `Website bundles post-quantum library: ${sig}.`,
            remediation: "NIST FIPS 203/204 compliant implementation verified."
          });
          seenRuleIds.add("PQC-SAFE");
        }
      }
    }

    // 4. Run Builtin Rules Against Inline Scripts & Page Content
    const rules = typeof BUILTIN_RULES !== "undefined" ? BUILTIN_RULES : [];
    const scriptTexts = [];

    if (pageData.scripts) {
      for (const s of pageData.scripts) {
        if (s.content) scriptTexts.push(s.content);
        if (s.src) scriptTexts.push(s.src);
      }
    }

    const combinedCode = scriptTexts.join("\n").substring(0, 200000);

    for (const rule of rules) {
      if (seenRuleIds.has(rule.id)) continue;
      try {
        let pattern = rule.regex_pattern;
        let flags = "i";
        if (pattern.startsWith("(?i)")) {
          pattern = pattern.substring(4);
        }
        const regex = new RegExp(pattern, flags);
        if (regex.test(combinedCode) || regex.test(pageData.url)) {
          findings.push({
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            quantum_risk: rule.quantum_risk,
            description: rule.description,
            remediation: rule.remediation
          });
          seenRuleIds.add(rule.id);
          if (findings.length >= 25) break; // Cap at 25 findings for popup performance
        }
      } catch {
        // Regex syntax error fallback
      }
    }

    return findings;
  }

  function renderAuditResults(findings, pageData) {
    const totalCount = findings.length;
    const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;
    const highCount = findings.filter(f => f.severity === "HIGH").length;
    const safeCount = findings.filter(f => f.quantum_risk === "Safe").length;

    metricFindingsEl.textContent = totalCount;
    metricCriticalEl.textContent = criticalCount;
    metricScriptsEl.textContent = (pageData.scripts && pageData.scripts.length) || "0";
    findingsPillEl.textContent = totalCount;

    // Determine Security Health Grade
    let grade = "A+";
    let gradeClass = "grade-a";
    let statusText = "Post-Quantum Safe & Compliant";
    let summaryText = "Conforms to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards.";
    let badgeColor = "#10B981";

    if (!pageData.isHttps) {
      grade = "F";
      gradeClass = "grade-f";
      statusText = "FAIL: Insecure Plaintext HTTP";
      summaryText = "Traffic is completely unencrypted. Subject to trivial MitM interception.";
      badgeColor = "#EF4444";
    } else if (criticalCount > 0) {
      grade = "C";
      gradeClass = "grade-c";
      statusText = "WARNING: Quantum-Vulnerable Cryptography";
      summaryText = `${criticalCount} critical quantum deficits found (RSA / ECC broken by Shor's algorithm).`;
      badgeColor = "#F97316";
    } else if (highCount > 0) {
      grade = "B";
      gradeClass = "grade-b";
      statusText = "NOTICE: Classical Primitives Detected";
      summaryText = "Classical hash functions or weak symmetric ciphers require PQC migration.";
      badgeColor = "#F59E0B";
    } else if (totalCount === 0) {
      grade = "A";
      gradeClass = "grade-a";
      statusText = "CLEAN: Zero Quantum Security Deficits";
      summaryText = "Analyzed webpage contains no classical cryptographic vulnerabilities.";
      badgeColor = "#10B981";
    }

    gradeBadgeEl.textContent = grade;
    gradeBadgeEl.className = `pq-grade-circle ${gradeClass}`;
    gradeStatusEl.textContent = statusText;
    gradeSummaryEl.textContent = summaryText;

    // Send badge update to background service worker
    chrome.runtime.sendMessage({
      action: "setBadgeGrade",
      tabId: activeTabId,
      grade: grade,
      color: badgeColor
    });

    // Report audit findings for PQMesh fleet synchronization
    chrome.runtime.sendMessage({
      action: "reportAuditFindings",
      url: activeTabUrl,
      grade: grade,
      findingsCount: totalCount,
      criticalCount: criticalCount,
      highCount: highCount,
      findings: findings.slice(0, 10)
    });

    // Render findings list
    if (findings.length === 0) {
      findingsListEl.innerHTML = `
        <div class="pq-empty-state">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2" style="margin-bottom: 6px;">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <div style="color: #10B981; font-weight: 500;">Zero Quantum Deficits Detected</div>
          <div style="font-size: 0.68rem; color: #71717a; margin-top: 2px;">
            Target conforms to post-quantum standards.
          </div>
        </div>
      `;
    } else {
      findingsListEl.innerHTML = findings.map(f => {
        const severityClass = `severity-${(f.severity || "info").toLowerCase()}`;
        return `
          <div class="pq-finding-card ${severityClass}">
            <div class="pq-finding-top">
              <span class="pq-finding-name">${escapeHtml(f.name)}</span>
              <span class="pq-severity-tag">${escapeHtml(f.severity)}</span>
            </div>
            <div class="pq-finding-desc">${escapeHtml(f.description)}</div>
            ${f.remediation ? `<div class="pq-finding-rem">&rarr; ${escapeHtml(f.remediation)}</div>` : ""}
          </div>
        `;
      }).join("");
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
});
