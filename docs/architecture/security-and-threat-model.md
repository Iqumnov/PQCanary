# Security Architecture and Threat Model

This document outlines the security invariants, threat model, defense-in-depth mitigations, and compliance boundaries implemented across the PQCanary platform.

---

## 1. Security Invariants and Principles

PQCanary processes sensitive enterprise assets, including proprietary source code, private cryptographic keys, certificates, and infrastructure configuration files. The platform is designed around four foundational security invariants:

1. **Air-Gap Default (Zero Telemetry Egress)**: By default, PQCanary runs 100% offline. No source code, findings, file hashes, or environment details are transmitted outside the host execution environment.
2. **Deterministic Memory Scrubbing**: Sensitive extracted keys and tokens are securely overwritten in RAM immediately upon leaving scope.
3. **Strict Memory Safety**: The core scanning engine explicitly forbids unsafe Rust code (`#![forbid(unsafe_code)]`).
4. **Input Sanitization and Least Privilege**: All filesystem paths, network targets, and input files are validated before processing.

---

## 2. Threat Model and Attack Surfaces

```
+-------------------------------------------------------------------------------+
|                               Untrusted Inputs                                |
|  - Malicious source code (path traversal, zip slips, bomb files)             |
|  - Hostile web domains (SSRF targeting cloud metadata, DNS rebinding)         |
|  - Tainted API requests (timing attacks, resource exhaustion, heap attacks)   |
+-------------------------------------------------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                           Security Defense Layers                             |
|  [Path Validator]     [SSRF Validator]      [Constant-Time Auth]   [Resource] |
|   - Traversal block    - IMDS blocking       - subtle crate         - 20MB    |
|   - ADS / DOS block    - DNS check           - Timing immune        - 10k lim |
+-------------------------------------------------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                      Isolated Core Processing Pipeline                        |
|  - #![forbid(unsafe_code)]          - ZeroizeOnDrop sensitive material        |
|  - Paged linear memory sandbox      - Isolated temporary directory scrubbers  |
+-------------------------------------------------------------------------------+
```

---

## 3. Defense Mechanisms and Mitigations

### 3.1. Path Traversal and Filesystem Security

When analyzing directories or files, PQCanary enforces validation via `validate_local_path`:
- **Directory Traversal**: Rejects paths containing `..`, null bytes (`\0`), wildcard patterns (`*`), or ASCII control characters.
- **Windows Device Namespaces**: Rejects device paths such as `\\.\`, `//./`, and `\??\`.
- **Legacy DOS Reserved Device Names**: On Windows, explicitly blocks requests referencing `CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9`, and `LPT1` through `LPT9`.
- **NTFS Alternate Data Streams (ADS)**: Rejects colon descriptors (`file.txt:stream`) to prevent hidden file execution or stream extraction.
- **Boundary Containment (`PQCANARY_SCAN_ROOT`)**: If the `PQCANARY_SCAN_ROOT` environment variable is defined, canonicalized paths outside this directory root are rejected.

### 3.2. Server-Side Request Forgery (SSRF) Prevention

PQCanary's active network probing and remote URL audit capabilities feature a multi-stage SSRF firewall (`validate_network_target`):
- **Cloud Metadata Defense**: Unconditionally blocks requests to AWS, Azure, Google Cloud, and Alibaba instance metadata services:
  - `169.254.169.254` (IPv4 Link-Local IMDS)
  - `fd00:ec2::254` (IPv6 AWS IMDS)
  - `100.100.100.200` (Alibaba Cloud IMDS)
  - `metadata.google.internal` (GCP Metadata hostname)
- **Flexible Representation Decoding**: Decodes decimal integers (`http://2852039166`), hexadecimals (`http://0xa9fea9fe`), and octal IP notations according to POSIX `inet_aton` rules before inspection.
- **IPv4-Mapped IPv6 Unpacking**: Converts mapped IPv6 representations (e.g., `::ffff:169.254.169.254`) to their underlying IPv4 form.
- **Strict Network Mode (`PQCANARY_STRICT_NETWORK=1`)**: When enabled, blocks all private IP ranges (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), shared address space (`100.64.0.0/10`), documentation blocks, and unique local IPv6 (`fc00::/7`).
- **DNS Rebinding Protection**: Resolves domain names prior to issuing HTTP requests. If any resolved IP belongs to a link-local or restricted subnet, the connection terminates.

### 3.3. Memory Protection and Key Scrubbing

Cryptographic secrets extracted during AST inspection or certificate scanning are encapsulated in `SecureMaterial`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecureMaterial {
    pub raw_bytes: Vec<u8>,
    pub file_path: String,
    pub line_number: u32,
}
```

By leveraging `ZeroizeOnDrop`, the memory buffer containing `raw_bytes` is overwritten with zeros when the structure is dropped or goes out of scope, mitigating memory scraping attacks.

### 3.4. Timing Side-Channel Immunity

Authentication bearer tokens processed by the daemon REST API are verified using constant-time comparisons via the `subtle` crate:

```rust
use subtle::ConstantTimeEq;

let is_valid = token.as_bytes().ct_eq(expected_token.as_bytes()).into();
```

This prevents remote attackers from deducing API tokens character-by-character through execution timing discrepancies.

### 3.5. Denial-of-Service and Resource Limits

To prevent resource exhaustion when scanning untrusted repositories:
- In-memory batch file scans are hard-capped at 10,000 files per request.
- Individual files larger than 20 MB are skipped during batch memory inspection.
- Concolic SMT execution enforces bounded search depth and timeouts to prevent exponential path explosion in complex loops.
