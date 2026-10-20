# Quickstart Guide

This guide walks through running your first post-quantum cryptographic audit using PQCanary, interpreting findings, generating compliance documents, and setting up an automated quality gate.

---

## 1. Running Your First Scan

By default, running `pqcanary scan` against a directory executes all enabled engines (Tree-sitter AST, regular expression patterns, dependency supply-chain scanners, certificate decoders, and linear memory sandbox checks):

```bash
# Scan the current working directory
pqcanary scan .

# Scan an explicit target path
pqcanary scan /path/to/project
```

### Example Terminal Output
```
INFO: PQCanary 0.1.0 starting multi-engine scan on: ./src
INFO: Discovered 42 source files. Executing parallel AST analysis...
WARNING: PQC-ASYM-001: Classical RSA Key Generation Detected
  File: src/auth/token.ts:45
  Severity: HIGH | Risk: VULNERABLE
  Description: Use of RSA-2048 with classical factorization security. Vulnerable to Shor's algorithm on CRQC.
  Remediation: Migrate asymmetric operations to NIST FIPS 203 (ML-KEM-768) or FIPS 204 (ML-DSA-65).

INFO: Scan completed in 48ms.
Total findings: 1 (0 Critical, 1 High, 0 Medium, 0 Low, 0 Info)
Quantum Readiness Posture: TRANSITIONING (Score: 68.0/100)
```

---

## 2. Generating Compliance Artifacts

PQCanary natively outputs structured compliance artifacts without needing third-party converters.

### Exporting OASIS SARIF 2.1.0
For integration into GitHub Code Scanning or Azure DevOps security tabs:

```bash
pqcanary scan ./src --format sarif --output results.sarif
```

### Exporting CycloneDX 1.6 CBOM
To produce a Cryptographic Bill of Materials listing all cryptographic assets, Object Identifiers (OIDs), and NIST security levels:

```bash
pqcanary generate-manifest ./src --output cbom.json
```

### Exporting Self-Contained HTML Report
For executive review and compliance documentation, generate an interactive standalone HTML report:

```bash
pqcanary scan ./src --format html --output report.html
```

### Exporting Markdown and CSV
```bash
# Markdown summary table
pqcanary scan ./src --format markdown --output audit-summary.md

# RFC 4180 compliant CSV (with formula injection protections)
pqcanary scan ./src --format csv --output inventory.csv
```

---

## 3. Classifying Specific Algorithms

You can quickly query PQCanary to classify any cryptographic algorithm against NIST standards and determine required quantum resources:

```bash
# Query an algorithm
pqcanary classify ML-KEM-768

# Output:
# Algorithm: ML-KEM-768
# Status: POST-QUANTUM SAFE
# Standard: NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism
# Security Level: NIST Category 3 (Equivalent to AES-192)
# Grover Resistance: 192 bits classical / 128 bits quantum
```

---

## 4. Establishing a Baseline (Differential Auditing)

When adopting PQCanary on an existing enterprise codebase with legacy cryptography, you can establish a baseline to track new regressions without failing builds on existing debt:

### Step 1: Create the Initial Baseline
```bash
pqcanary scan ./src --format json --output baseline.json
```

### Step 2: Enforce the Baseline in CI
```bash
pqcanary scan ./src --baseline baseline.json --fail-on-new
```
If a developer introduces a new classical RSA, MD5, or unmasked algorithm, the scan fails with exit code 1. If only existing baseline findings remain, the build passes.

---

## 5. Automated Code Remediation

PQCanary includes a semantic code patcher that automatically resolves known insecure cryptographic patterns (e.g., replacing MD5 with SHA-256, DES with AES-256-GCM, and `Math.random` with secure random):

### Preview Changes (Dry Run)
```bash
pqcanary patch src/crypto.js --dry-run
```

### Apply Changes in Place
```bash
pqcanary patch src/crypto.js
```

---

## 6. Active Network Probing

Verify whether remote network endpoints have deployed post-quantum hybrid key exchange:

### Probe a TLS Endpoint (HTTPS)
Tests whether the remote web server supports `X25519MLKEM768` (0x11ec):
```bash
pqcanary probe tls cloudflare.com:443
```

### Probe an SSH Endpoint
Tests whether the remote SSH daemon negotiates `sntrup761x25519-sha512@openssh.com` or `mlkem768x25519-sha256`:
```bash
pqcanary probe ssh github.com:22
```

---

## 7. Next Steps

- Consult the [System Architecture](../architecture/system-architecture.md) for details on the multi-engine pipeline.
- Review the [Configuration Schema](../reference/configuration-schema.md) to set up `.pqcanary.yaml`.
- Integrate PQCanary into your CI/CD pipeline using the [CI/CD Integration Guide](../guides/ci-cd-pipelines.md).
