/**
 * PQCanary Content Script
 * Extracts real-time cryptographic footprint, active scripts, and WebCrypto usages from the current webpage.
 * Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
 */

(function () {
  'use strict';

  // Track runtime WebCrypto algorithm usages
  const capturedWebCryptoAlgos = new Set();

  // Listen to custom events dispatched by the main-world interceptor
  window.addEventListener('__PQCANARY_CRYPTO_EVENT__', function (e) {
    if (e.detail && typeof e.detail === 'string') {
      capturedWebCryptoAlgos.add(e.detail);
    }
  });

  // Fallback: Also monitor subtle crypto directly if accessible in current world
  try {
    if (window.crypto && window.crypto.subtle) {
      const subtle = window.crypto.subtle;
      const record = function (algo) {
        if (!algo) return;
        if (typeof algo === 'string') {
          capturedWebCryptoAlgos.add(algo);
        } else if (algo && algo.name) {
          const mod = algo.modulusLength ? `-${algo.modulusLength}` : '';
          const curve = algo.namedCurve ? `-${algo.namedCurve}` : '';
          capturedWebCryptoAlgos.add(`${algo.name}${mod}${curve}`);
        }
      };

      const origGenKey = subtle.generateKey ? subtle.generateKey.bind(subtle) : null;
      if (origGenKey) {
        subtle.generateKey = function (algorithm, extractable, keyUsages) {
          record(algorithm);
          return origGenKey(algorithm, extractable, keyUsages);
        };
      }

      const origImpKey = subtle.importKey ? subtle.importKey.bind(subtle) : null;
      if (origImpKey) {
        subtle.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
          record(algorithm);
          return origImpKey(format, keyData, algorithm, extractable, keyUsages);
        };
      }
    }
  } catch {
    // Cross-origin restriction / sandboxed iframe guard
  }

  function collectPageCryptoData() {
    const scripts = [];
    const scriptElements = Array.from(document.querySelectorAll("script"));

    for (const el of scriptElements) {
      if (el.src) {
        scripts.push({ type: "external", src: el.src });
      } else if (el.textContent) {
        // Sample inline script content up to 100KB to prevent memory exhaustion
        const contentSample = el.textContent.substring(0, 100000);
        scripts.push({ type: "inline", content: contentSample });
      }
    }

    // Inspect dynamic script and WASM resource loads via Performance API
    try {
      if (window.performance && typeof performance.getEntriesByType === "function") {
        const resources = performance.getEntriesByType("resource");
        for (const res of resources) {
          if (res.name && (res.initiatorType === "script" || res.name.endsWith(".js") || res.name.endsWith(".wasm"))) {
            if (!scripts.some(s => s.src === res.name)) {
              scripts.push({ type: "dynamic", src: res.name });
            }
          }
        }
      }
    } catch {
      // Performance API not permitted
    }

    // Inspect meta tags for security / CSP
    const metaTags = Array.from(document.querySelectorAll("meta")).map(m => ({
      name: m.getAttribute("name") || m.getAttribute("http-equiv") || "",
      content: m.getAttribute("content") || ""
    })).filter(m => m.name.toLowerCase().includes("security") || m.name.toLowerCase().includes("csp") || m.name.toLowerCase().includes("crypto"));

    // Check DOM for security certificates / crypto library signatures
    const librarySignatures = [];
    const htmlText = document.documentElement.innerHTML.substring(0, 150000);
    if (/CryptoJS/i.test(htmlText)) librarySignatures.push("CryptoJS (Classical Crypto)");
    if (/JSEncrypt/i.test(htmlText)) librarySignatures.push("JSEncrypt (Classical RSA)");
    if (/node-forge/i.test(htmlText) || /forge\.pkcs/i.test(htmlText)) librarySignatures.push("Forge (Classical X.509/RSA)");
    if (/sjcl/i.test(htmlText)) librarySignatures.push("SJCL (Stanford JavaScript Crypto)");
    if (/elliptic/i.test(htmlText) && !/kyber/i.test(htmlText)) librarySignatures.push("Elliptic (Classical ECC)");
    if (/kyber/i.test(htmlText) || /ml-kem/i.test(htmlText)) librarySignatures.push("Kyber / ML-KEM (Post-Quantum Safe)");
    if (/dilithium/i.test(htmlText) || /ml-dsa/i.test(htmlText)) librarySignatures.push("Dilithium / ML-DSA (Post-Quantum Safe)");

    return {
      url: window.location.href,
      origin: window.location.origin,
      protocol: window.location.protocol,
      hostname: window.location.hostname,
      title: document.title,
      isHttps: window.location.protocol === "https:",
      scriptCount: scripts.length,
      scripts: scripts,
      webCryptoAlgos: Array.from(capturedWebCryptoAlgos),
      librarySignatures: librarySignatures,
      metaTags: metaTags
    };
  }

  // Handle messages from extension popup and background worker
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getPageCryptoData") {
      const data = collectPageCryptoData();
      sendResponse(data);
    }
    return true;
  });
})();
