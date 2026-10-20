# PQCanary VS Code Extension

**Real-Time Post-Quantum Cryptographic Security Analysis & Remediation in VS Code**  
*Copyright (C) 2026 Matvei Igumnov — Apache License 2.0*

---

## Overview

The **PQCanary VS Code Extension** audits your source code for post-quantum cryptographic vulnerabilities in real time as you type. It highlights classical algorithms vulnerable to Shor's algorithm (RSA, ECC, Diffie-Hellman, DSA, MD5, SHA-1) and provides automated **NIST FIPS 203 (ML-KEM)** and **NIST FIPS 204 (ML-DSA)** Quick Fix migrations.

### Key Features
- **Real-Time In-Editor Diagnostics**: Squiggly lines highlight vulnerable algorithms, weak keys, and deprecated hashes instantly as you type.
- **193+ Cryptographic Detection Rules**: Full rule catalog covering Asymmetric, Symmetric, Hash, MAC, KDF, Certificates, Cloud KMS, and PRNGs.
- **1-Click Quick Fixes (Code Actions)**:
  - Migrate RSA/ECC to **NIST FIPS 203 (ML-KEM-768)**
  - Migrate Digital Signatures to **NIST FIPS 204 (ML-DSA-65)**
  - Replace MD5/SHA-1 with **NIST FIPS 202 (SHA-3 / SHAKE256)**
  - Upgrade symmetric encryption to **AES-256-GCM**
- **Live Status Bar Health Grade**: Shows current file quantum rating (`$(shield) PQ: A+ (Safe)` or `$(alert) PQ: C (3 issues)`).
- **Workspace Scan**: One command (`PQCanary: Scan Entire Workspace`) audits all files and reports security posture.
- **Web Dashboard Integration**: Direct 1-click access to the full PQCanary web platform.

---

## Usage

1. Open any source code file (`.ts`, `.js`, `.py`, `.rs`, `.go`, `.java`, `.c`, `.cpp`, `.sol`, etc.).
2. Any vulnerable cryptographic pattern is underlined with an inline diagnostic:
   ```
   [PQCanary ASYM-RSA-001] RSA Public-Key Cryptography: RSA integer factorization is broken by Shor's algorithm.
   Remediation: Migrate to NIST FIPS 203 (ML-KEM) or FIPS 204 (ML-DSA).
   ```
3. Press `Ctrl + .` (or `Cmd + .`) on the highlighted code to apply an automated Post-Quantum Quick Fix.
4. Press `Ctrl + Shift + P` and search for:
   - `PQCanary: Scan Current File`
   - `PQCanary: Scan Entire Workspace`
   - `PQCanary: Open Post-Quantum Web Dashboard`

---

## Building & Installation

To package the extension into a `.vsix` file:
```bash
cd extensions/vscode
npx vsce package
```
Then install in VS Code via:
```bash
code --install-extension pqcanary-vscode-1.0.0.vsix
```
Or debug directly by pressing `F5` inside the `extensions/vscode` directory.
