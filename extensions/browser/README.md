# PQCanary Browser Extension

**Post-Quantum Cryptographic Security Auditor for Web Browsers (Chrome, Brave, Edge, Firefox, Opera)**  
*Copyright (C) 2026 Matvei Igumnov — Apache License 2.0*

---

## Overview

The **PQCanary Browser Extension** audits the cryptographic security of the website you are currently visiting in real time. It detects classical algorithms vulnerable to quantum decryption (RSA, ECC, Diffie-Hellman, DSA, MD5, SHA-1) and checks compliance against **NIST FIPS 203 (ML-KEM)** and **NIST FIPS 204 (ML-DSA)** post-quantum standards.

### Features
- **Real-Time Website Scan**: Inspects active DOM, loaded JavaScript bundles, and WebCrypto API invocations (`window.crypto.subtle`).
- **Executive Security Health Grade**: Computes grades from **A+** (Post-Quantum Safe) to **F** (Insecure Plaintext Transport).
- **193+ Cryptographic Rules Engine**: Runs the full PQCanary rule catalog directly in the browser with zero external dependencies.
- **1-Click Deep Scan**: Directly links into the full PQCanary Web Dashboard for network TLS cipher suite analysis.
- **Glassmorphism Dark Theme**: Matches PQCanary's aesthetic with interactive button physics and amber status badges.

---

## Installation (Developer Mode / Load Unpacked)

1. Open your Chromium-based browser (Chrome, Brave, Edge, Opera, Vivaldi).
2. Navigate to `chrome://extensions` (or `edge://extensions`, `brave://extensions`).
3. Enable **Developer mode** toggle in the top-right corner.
4. Click **Load unpacked**.
5. Select this folder: `pqcanary/extensions/browser`.
6. The PQCanary shield icon will appear in your browser toolbar!

For Firefox:
1. Navigate to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Select `extensions/browser/manifest.json`.

---

## Architecture

- `manifest.json`: Manifest V3 specification.
- `popup.html` & `popup.css`: Extension interface.
- `popup.js`: Controller that orchestrates DOM analysis, runs rules, and calculates the health grade.
- `content.js`: Injected script that extracts loaded script sources and captures runtime WebCrypto API usages.
- `background.js`: Service worker managing tab events and toolbar badge colors.
- `rules.js`: Synchronized 193+ post-quantum cryptographic detection signatures.
