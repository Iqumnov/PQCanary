# Security Policy

PQCanary is designed for security-critical environments where data integrity, cryptographic rigor, and offline confidentiality are paramount. This document describes the security policies, supported versions, and procedures for reporting vulnerabilities.

---

## 1. Supported Versions

Security updates and patches are provided for the following releases:

| Version | Supported | Security Patch Policy |
| :--- | :--- | :--- |
| **0.1.x** (Latest) | Yes | Active maintenance, regular CVE and pattern updates. |
| **< 0.1.0** | No | Deprecated development prototypes. Upgrade recommended. |

---

## 2. Reporting a Vulnerability

The PQCanary project practices coordinated vulnerability disclosure. If you discover a security vulnerability in PQCanary, do not open a public GitHub issue.

Please report vulnerabilities via email:

- **Security Contact**: Matvei Igumnov
- **Email**: `security@pqcanary.io`

### Information to Include
To help us triage and remediate the issue rapidly, please provide:
1. Description of the vulnerability and its potential impact.
2. Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
3. Component affected (`core`, `cli`, `mcp`, `web`, or `extensions`).
4. Operating system, architecture, and Rust compiler version used.

### Response Timeline
- **Acknowledgement**: Within 48 hours of initial report receipt.
- **Initial Assessment**: Within 7 business days with a severity rating and remediation plan.
- **Fix & Advisory**: We coordinate a mutual disclosure date with the reporter once a patch has been tested and verified.

---

## 3. Core Security Commitments

### 3.1. Air-Gap Guarantee
PQCanary guarantees that local audits (`pqcanary scan <PATH>`) do not transmit source code, findings, file hashes, or environment details to external servers or cloud services. All analysis engines execute locally on the host machine.

### 3.2. Strict Memory Safety
The `pqcanary-core` library enforces `#![forbid(unsafe_code)]`. Memory safety bugs (such as use-after-free or buffer overflows) are treated as critical security issues.

### 3.3. Deterministic Memory Scrubbing
All extracted cryptographic keys and sensitive strings are encapsulated within `SecureMaterial` and zeroized on drop (`zeroize::ZeroizeOnDrop`) to prevent memory dump exposure.

### 3.4. Server-Side Request Forgery (SSRF) Protection
All network targets submitted to `pqcanary probe` or the REST API undergo multi-stage SSRF filtering that unconditionally blocks cloud instance metadata services (e.g., `169.254.169.254`).
