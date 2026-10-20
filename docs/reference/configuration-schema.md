# Configuration File Schema Specification

This document defines the declarative configuration schema for `.pqcanary.yaml` and `pqcanary.toml`, detailing all supported properties, default values, and custom detection rule definitions.

---

## 1. File Discovery and Precedence

When running `pqcanary`, configuration files are automatically discovered in the working directory in the following priority order:
1. File explicitly passed via `--config <FILE>` or `-c <FILE>`
2. Environment variable `PQCANARY_CONFIG`
3. `.pqcanary.yaml` / `.pqcanary.yml`
4. `pqcanary.yaml` / `pqcanary.yml`
5. `.pqcanary.toml`
6. `pqcanary.toml`

CLI argument flags override settings declared in the configuration file.

---

## 2. Complete YAML Schema

```yaml
# Target scanning path or remote URL
target: "."

# Minimum severity threshold (CRITICAL, HIGH, MEDIUM, LOW, INFO)
severity: "HIGH"

# Output format (text, json, sarif, cbom, html, markdown, csv)
format: "sarif"

# Output report destination file path
output: "results.sarif"

# Baseline report path for regression comparison
baseline: "baseline.json"

# Quality gate exit condition (critical, high, medium, low, new, findings, none)
fail_on: "high"

# Ignore rules, categories, and file paths
ignore:
  patterns:
    - "PQC-ASYM-RSA-001"
    - "PQC-HASH-MD5-*"
  categories:
    - "Certificates"
    - "Dependency Manifests"
  files:
    - "**/tests/**"
    - "**/fixtures/**"
    - "legacy_crypto.c"

# Granular engine toggles (all true by default)
engines:
  ast: true          # Tree-sitter AST & 193+ regex patterns
  concolic: true     # Z3 SSA symbolic execution
  ffi: true          # FFI memory leak traceability
  dpa: true          # Boolean masking & side-channel check
  thermo: true       # Landauer limit thermodynamic dissipation
  hott: true         # Homotopy Type Theory formal verification
  snn: true          # Neuromorphic spike-rate analysis

# Quantum Processing Unit (QPU) cloud offload credentials
qpu:
  token: "IBM_QUANTUM_API_TOKEN"
  backend: "ibm_brisbane"
  shots: 1024

# Webhook notification URL for completed scans or violations
webhook_url: "https://security-alerts.internal.corp/pqcanary-webhook"

# Custom enterprise detection patterns
custom_rules:
  - id: "CORP-CRYPTO-001"
    name: "Legacy Internal Key Derivation"
    category: "Internal Policy"
    pattern: "LegacyCorpKdf::deriveKey"
    severity: "CRITICAL"
    description: "Use of decommissioned internal KDF without salt or work factor."
    remediation: "Migrate to Argon2id or HKDF with SHA-384."
    tags:
      - "internal"
      - "kdf"
```

---

## 3. Equivalent TOML Schema

```toml
target = "."
severity = "HIGH"
format = "sarif"
output = "results.sarif"
baseline = "baseline.json"
fail_on = "high"
webhook_url = "https://security-alerts.internal.corp/pqcanary-webhook"

[ignore]
patterns = ["PQC-ASYM-RSA-001", "PQC-HASH-MD5-*"]
categories = ["Certificates", "Dependency Manifests"]
files = ["**/tests/**", "**/fixtures/**"]

[engines]
ast = true
concolic = true
ffi = true
dpa = true
thermo = true
hott = true
snn = true

[qpu]
token = "IBM_QUANTUM_API_TOKEN"
backend = "ibm_brisbane"
shots = 1024

[[custom_rules]]
id = "CORP-CRYPTO-001"
name = "Legacy Internal Key Derivation"
category = "Internal Policy"
pattern = "LegacyCorpKdf::deriveKey"
severity = "CRITICAL"
description = "Use of decommissioned internal KDF without salt or work factor."
remediation = "Migrate to Argon2id or HKDF with SHA-384."
tags = ["internal", "kdf"]
```

---

## 4. Property Specifications

### Global Options
- **`target`** (`string`, optional): Relative or absolute filesystem path, Git repository URL, or web domain. Default: `"."`.
- **`severity`** (`string`, optional): Minimum severity filter. Supported values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- **`format`** (`string`, optional): Output reporter type. Values: `text`, `json`, `sarif`, `cbom`, `html`, `markdown`, `csv`.
- **`output`** (`string`, optional): File path where the formatted report is saved.
- **`baseline`** (`string`, optional): Path to a historical JSON or SARIF report used for differential auditing.
- **`fail_on`** (`string`, optional): Exit code 1 trigger condition. Values: `critical`, `high`, `medium`, `low`, `new`, `findings`, `none`.
- **`webhook_url`** (`string`, optional): HTTPS endpoint where finding payloads are posted upon scan completion.

### `ignore` Table
- **`patterns`** (`list[string]`): Exact rule IDs or glob patterns (e.g., `PQC-SYM-*`).
- **`categories`** (`list[string]`): Pattern categories to suppress.
- **`files`** (`list[string]`): Glob patterns matching relative file paths to exclude from traversal.

### `engines` Table
Allows selectively disabling compute-intensive engines when scanning large codebases:
- `ast` (`boolean`, default: `true`)
- `concolic` (`boolean`, default: `true`)
- `ffi` (`boolean`, default: `true`)
- `dpa` (`boolean`, default: `true`)
- `thermo` (`boolean`, default: `true`)
- `hott` (`boolean`, default: `true`)
- `snn` (`boolean`, default: `true`)
