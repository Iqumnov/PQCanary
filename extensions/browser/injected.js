/**
 * PQCanary Main World WebCrypto Interceptor
 * Injected at document_start in the MAIN world to monitor cryptographic API calls.
 * Copyright (C) 2026 Matvei Igumnov - Apache License 2.0
 */

(function () {
  'use strict';

  if (window.__PQCANARY_MAIN_INTERCEPTOR_ACTIVE__) return;
  window.__PQCANARY_MAIN_INTERCEPTOR_ACTIVE__ = true;

  const capturedAlgos = new Set();

  function formatAlgorithm(algo) {
    if (!algo) return null;
    if (typeof algo === 'string') return algo;
    if (typeof algo === 'object') {
      const name = algo.name || 'Unknown';
      const mod = algo.modulusLength ? `-${algo.modulusLength}` : '';
      const curve = algo.namedCurve ? `-${algo.namedCurve}` : '';
      let hash = '';
      if (algo.hash) {
        if (typeof algo.hash === 'string') {
          hash = `/${algo.hash}`;
        } else if (algo.hash.name) {
          hash = `/${algo.hash.name}`;
        }
      }
      return `${name}${mod}${curve}${hash}`;
    }
    return null;
  }

  function recordAlgo(algo) {
    const formatted = formatAlgorithm(algo);
    if (formatted && !capturedAlgos.has(formatted)) {
      capturedAlgos.add(formatted);
      try {
        window.dispatchEvent(
          new CustomEvent('__PQCANARY_CRYPTO_EVENT__', {
            detail: formatted,
          })
        );
      } catch {
        // Fallback for sandboxed DOM
      }
    }
  }

  // Hook WebCrypto SubtleCrypto methods
  try {
    if (window.crypto && window.crypto.subtle) {
      const subtle = window.crypto.subtle;

      // 1. generateKey
      const origGenerateKey = subtle.generateKey ? subtle.generateKey.bind(subtle) : null;
      if (origGenerateKey) {
        subtle.generateKey = function (algorithm, extractable, keyUsages) {
          recordAlgo(algorithm);
          return origGenerateKey(algorithm, extractable, keyUsages);
        };
      }

      // 2. importKey
      const origImportKey = subtle.importKey ? subtle.importKey.bind(subtle) : null;
      if (origImportKey) {
        subtle.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
          recordAlgo(algorithm);
          return origImportKey(format, keyData, algorithm, extractable, keyUsages);
        };
      }

      // 3. deriveKey
      const origDeriveKey = subtle.deriveKey ? subtle.deriveKey.bind(subtle) : null;
      if (origDeriveKey) {
        subtle.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
          recordAlgo(algorithm);
          recordAlgo(derivedKeyType);
          return origDeriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages);
        };
      }

      // 4. deriveBits
      const origDeriveBits = subtle.deriveBits ? subtle.deriveBits.bind(subtle) : null;
      if (origDeriveBits) {
        subtle.deriveBits = function (algorithm, baseKey, length) {
          recordAlgo(algorithm);
          return origDeriveBits(algorithm, baseKey, length);
        };
      }

      // 5. encrypt / decrypt
      const origEncrypt = subtle.encrypt ? subtle.encrypt.bind(subtle) : null;
      if (origEncrypt) {
        subtle.encrypt = function (algorithm, key, data) {
          recordAlgo(algorithm);
          if (key && key.algorithm) recordAlgo(key.algorithm);
          return origEncrypt(algorithm, key, data);
        };
      }

      const origDecrypt = subtle.decrypt ? subtle.decrypt.bind(subtle) : null;
      if (origDecrypt) {
        subtle.decrypt = function (algorithm, key, data) {
          recordAlgo(algorithm);
          if (key && key.algorithm) recordAlgo(key.algorithm);
          return origDecrypt(algorithm, key, data);
        };
      }

      // 6. sign / verify
      const origSign = subtle.sign ? subtle.sign.bind(subtle) : null;
      if (origSign) {
        subtle.sign = function (algorithm, key, data) {
          recordAlgo(algorithm);
          if (key && key.algorithm) recordAlgo(key.algorithm);
          return origSign(algorithm, key, data);
        };
      }

      const origVerify = subtle.verify ? subtle.verify.bind(subtle) : null;
      if (origVerify) {
        subtle.verify = function (algorithm, key, signature, data) {
          recordAlgo(algorithm);
          if (key && key.algorithm) recordAlgo(key.algorithm);
          return origVerify(algorithm, key, signature, data);
        };
      }
    }
  } catch {
    // Sandboxed or restricted execution context
  }
})();
