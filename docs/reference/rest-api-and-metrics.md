# REST API and Prometheus Metrics Reference

This document specifies the HTTP REST endpoints, request/response payloads, authentication controls, and OpenMetrics Prometheus metrics exposed by the PQCanary daemon (`pqcanary serve`).

---

## 1. Daemon Overview and Authentication

Start the REST API daemon on port 8080 (or custom port via `-p`):

```bash
pqcanary serve --port 8080
```

### Authentication Header
If the `PQCANARY_API_TOKEN` environment variable is configured, all requests must provide a matching Bearer token in the `Authorization` header:

```http
Authorization: Bearer <TOKEN>
```

Authentication is validated using constant-time string comparison (`subtle::ConstantTimeEq`) to prevent timing side-channel attacks.

Exempt endpoints accessible without authentication:
- `GET /health`
- `GET /version`
- `GET /metrics`

---

## 2. API Endpoints Specification

### 2.1. `POST /scan`
Executes a multi-engine scan against a local directory, remote Git repository URL, or public web domain.

**Request:**
```json
{
  "path": "./src/crypto"
}
```

**Response (200 OK):**
```json
[
  {
    "file_path": "src/crypto/auth.ts",
    "vulnerability_class": "Asymmetric Public Key",
    "description": "Legacy RSA public key operation detected.",
    "severity": "HIGH",
    "line_number": 42,
    "remediation": "Migrate to NIST FIPS 204 ML-DSA.",
    "rule_id": "PQC-ASYM-RSA-001",
    "quantum_risk": "VULNERABLE",
    "confidence": "HIGH",
    "fingerprint": "a3f5..."
  }
]
```

---

### 2.2. `POST /scan/files`
Performs in-memory batch scanning on source code files without touching host storage. Capped at 10,000 files and 20 MB per file.

**Request:**
```json
{
  "files": [
    {
      "path": "crypto.ts",
      "content": "const hash = crypto.createHash('md5');"
    }
  ]
}
```

---

### 2.3. `POST /concolic`
Runs concolic symbolic execution (SSA lifting + Z3 SMT solver) on a JavaScript/TypeScript source code snippet.

**Request:**
```json
{
  "snippet": "function test(buf, len) { return buf[len + 10]; }"
}
```

**Response (200 OK):**
```json
{
  "status": "vulnerable",
  "details": "Out-of-bounds read constraint SAT: len > capacity(buf) - 10"
}
```

---

### 2.4. `GET /thermodynamics`
Calculates Landauer thermodynamic dissipation and thermal side-channel attack (SCA) risk.

**Parameters:**
- `temp` (float, optional): Temperature in Kelvin (default: `300.0`).
- `gates` (integer, optional): Total logic gates (default: `10000`).
- `erased` (integer, optional): Irreversible gate erasures (default: `4000`).

**Response (200 OK):**
```json
{
  "temperature_kelvin": 300.0,
  "min_entropy_cost_joules": 2.8718e-21,
  "total_dissipation_joules": 1.1487e-17,
  "total_dissipation_femtojoules": 0.011487,
  "irreversible_fraction": 0.4,
  "vulnerable_to_sca": false
}
```

---

### 2.5. `POST /hott/export`
Exports a Lean 4 formal verification proof file for a designated algorithm.

**Request:**
```json
{
  "algorithm": "Kyber512"
}
```

**Response (200 OK):**
```json
{
  "algorithm": "Kyber512",
  "classification": "Post-Quantum Safe (NIST FIPS 203)",
  "is_safe": true,
  "lean4_proof": "import Mathlib.Topology.Basic\n..."
}
```

---

### 2.6. `POST /patch`
Applies automated semantic remediation patches to source code.

**Request:**
```json
{
  "file_path": "src/hasher.js",
  "source": "const h = crypto.createHash('md5').update(d).digest();"
}
```

**Response (200 OK):**
```json
{
  "changed": true,
  "rules_applied": ["PQC-REMEDIATE-MD5-TO-SHA256"],
  "unified_diff": "--- src/hasher.js\n+++ src/hasher.js\n@@ -1 +1 @@\n-const h = crypto.createHash('md5').update(d).digest();\n+const h = crypto.createHash('sha256').update(d).digest();",
  "patched_source": "const h = crypto.createHash('sha256').update(d).digest();"
}
```

---

### 2.7. `POST /cbom`
Generates a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) JSON object.

**Request:**
```json
{
  "path": "."
}
```

---

### 2.8. `GET /rules`
Queries the 193+ detection rule catalog with optional filtering.

**Parameters:**
- `category` (string, optional)
- `severity` (string, optional)
- `quantum_risk` (string, optional)

---

### 2.9. `POST /cognitive`
Calculates Halstead complexity metrics and McCabe cyclomatic complexity.

**Request:**
```json
{
  "snippet": "function complexCrypto(a, b) { ... }"
}
```

**Response (200 OK):**
```json
{
  "vocabulary": 24,
  "length": 142,
  "volume": 651.06,
  "difficulty": 18.2,
  "effort": 11849.2,
  "time_seconds": 658.2,
  "estimated_bugs": 0.21,
  "cyclomatic_complexity": 8,
  "risk_level": "MEDIUM: Elevated complexity — recommend peer review of crypto logic."
}
```

---

### 2.10. `GET /health` and `GET /version`
Liveness check for Kubernetes probes and metadata.

**Health Response:**
```json
{
  "status": "ok",
  "service": "pqcanary-api",
  "version": "0.1.0"
}
```

---

## 3. Prometheus Metrics (`GET /metrics`)

The `/metrics` endpoint exports application telemetry in OpenMetrics Prometheus text format:

```prometheus
# HELP pqcanary_api_requests_total Total API requests received
# TYPE pqcanary_api_requests_total counter
pqcanary_api_requests_total 42

# HELP pqcanary_api_errors_total Total API internal errors
# TYPE pqcanary_api_errors_total counter
pqcanary_api_errors_total 0

# HELP pqcanary_findings_total Total security findings identified
# TYPE pqcanary_findings_total counter
pqcanary_findings_total{severity="CRITICAL"} 3
pqcanary_findings_total{severity="HIGH"} 12
pqcanary_findings_total{severity="MEDIUM"} 7
pqcanary_findings_total{severity="LOW"} 4
pqcanary_findings_total{severity="INFO"} 19

# HELP pqcanary_files_scanned_total Total files processed by orchestrator
# TYPE pqcanary_files_scanned_total counter
pqcanary_files_scanned_total 1248
```
