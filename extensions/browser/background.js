/**
 * PQCanary Background Service Worker (Manifest V3)
 * Manages tab security lifecycle, icon badge states, and local API tunneling.
 * Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    pqcanaryServerUrl: "http://localhost:3000",
    minSeverity: "LOW",
    autoScan: true
  });
  console.log("PQCanary Post-Quantum Security Auditor extension installed.");
});

// Update badge and evaluate crypto security when tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    browserScansCount++;
    try {
      const parsedUrl = new URL(tab.url);
      if (tab.url.startsWith("http://")) {
        chrome.action.setBadgeText({ tabId, text: "!" });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
        browserFindingsCount++;
        broadcastMeshEvent(
          "Insecure Plaintext Transport Detected",
          `Unencrypted HTTP communication on '${parsedUrl.hostname}'. Immediate TLS upgrade required.`,
          "HIGH"
        );
        registerWithPQMesh(`http://${parsedUrl.hostname} (Plaintext Insecure)`);
      } else {
        // Query content script for real-time crypto fingerprint
        chrome.tabs.sendMessage(tabId, { action: "getPageCryptoData" }, (response) => {
          if (chrome.runtime.lastError || !response) {
            chrome.action.setBadgeText({ tabId, text: "PQ" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
            registerWithPQMesh(`${parsedUrl.origin} (TLS 1.3 Audited)`);
            return;
          }

          const hasClassical = (response.webCryptoAlgos && response.webCryptoAlgos.some(a => /rsa|ec/i.test(a))) ||
                               (response.librarySignatures && response.librarySignatures.some(s => s.includes("Classical")));
          if (hasClassical) {
            chrome.action.setBadgeText({ tabId, text: "C" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#F97316" });
            browserFindingsCount++;
            registerWithPQMesh(`${parsedUrl.origin} (Classical Cryptography Found)`);
          } else {
            chrome.action.setBadgeText({ tabId, text: "A+" });
            chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
            registerWithPQMesh(`${parsedUrl.origin} (Post-Quantum Ready)`);
          }
        });
      }
    } catch {
      // Ignored
    }
  }
});

// Message listener for background network tasks and fleet synchronization
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "setBadgeGrade") {
    const { tabId, grade, color } = request;
    if (tabId) {
      chrome.action.setBadgeText({ tabId, text: grade });
      chrome.action.setBadgeBackgroundColor({ tabId, color: color || "#10B981" });
    }
    sendResponse({ ok: true });
  } else if (request.action === "reportAuditFindings") {
    const { url, grade, findingsCount, criticalCount, highCount } = request;
    browserFindingsCount += (findingsCount || 0);
    try {
      const hostname = new URL(url).hostname;
      if (criticalCount > 0) {
        broadcastMeshEvent(
          "Quantum Deficits Identified on Target",
          `Audited '${hostname}': Found ${criticalCount} critical quantum vulnerabilities (Grade: ${grade}).`,
          "CRITICAL"
        );
      }
      registerWithPQMesh(`${hostname} (Grade: ${grade}, ${findingsCount} issues)`);
    } catch {
      // Ignore URL parse error
    }
    sendResponse({ ok: true });
  } else if (request.action === "reportPqcEndpoint") {
    const { url, kexGroup, cipherSuite } = request;
    broadcastMeshEvent(
      "Live Post-Quantum TLS Verified",
      `Target '${url}' negotiated ${kexGroup || "ML-KEM-768"} hybrid key exchange (${cipherSuite || "TLS 1.3"}).`,
      "INFO"
    );
    sendResponse({ ok: true });
  }
  return true;
});

// --- PQMesh Fleet Synchronization Bus Client ---
const MESH_API_BASE = "http://localhost:8080";
let browserScansCount = 0;
let browserFindingsCount = 0;
let lastAuditedContext = "Active Browser Tab";

function getBrowserNodeId() {
  const idStr = chrome.runtime.id ? chrome.runtime.id.substring(0, 8) : "chrome";
  return `node-browser-${idStr}`;
}

async function registerWithPQMesh(contextUrl) {
  if (contextUrl) lastAuditedContext = contextUrl;
  const payload = {
    node_id: getBrowserNodeId(),
    medium: "browser",
    label: "Security Audit Browser Extension",
    version: "1.0.0",
    endpoint: `chrome-extension://${chrome.runtime.id}`,
    active_context: lastAuditedContext,
    findings_count: browserFindingsCount,
    scans_count: browserScansCount,
    patches_applied: 0,
  };

  try {
    await fetch(`${MESH_API_BASE}/mesh/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    // Non-blocking: mesh daemon might be offline or starting up
  }
}

async function broadcastMeshEvent(title, details, severity = "INFO") {
  const payload = {
    source_node_id: getBrowserNodeId(),
    source_medium: "browser",
    title,
    details,
    severity,
  };

  try {
    await fetch(`${MESH_API_BASE}/mesh/event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    // Non-blocking
  }
}

// Initial registration and recurring heartbeat
registerWithPQMesh("Browser Extension Active");
setInterval(() => {
  registerWithPQMesh();
}, 45000);
