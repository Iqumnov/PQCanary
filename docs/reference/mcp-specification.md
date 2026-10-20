# Model Context Protocol (MCP) Server Specification

This document specifies the JSON-RPC 2.0 tools, parameters, and invocation schemas exposed by the PQCanary MCP Server (`pqcanary-mcp`).

---

## 1. Overview and Architecture

The Model Context Protocol (MCP) enables autonomous Large Language Model (LLM) agents (including Claude Desktop, Cursor, Gemini, and custom agents) to programmatically invoke PQCanary's cryptographic inspection and remediation engines.

- **Transport**: Standard I/O (`stdio`). Requests are read from `stdin`, and JSON-RPC responses are written to `stdout`. All diagnostic logs are redirected to `stderr`.
- **Protocol**: JSON-RPC 2.0.
- **Specification Reference**: [Model Context Protocol Specification](https://modelcontextprotocol.io/docs/concepts/architecture).

### Starting the Server

```bash
# Run standalone
pqcanary-mcp

# Or via cargo
cargo run --release -p pqcanary-mcp
```

### Configuration for Claude Desktop / Cursor (`mcpServers`)

```json
{
  "mcpServers": {
    "pqcanary": {
      "command": "pqcanary-mcp",
      "args": []
    }
  }
}
```

---

## 2. Standard MCP Tools Catalog

The server exposes 57 native tools:

| Tool Identifier | Primary Function | Input Parameters |
| :--- | :--- | :--- |
| `scan_directory` | Full multi-engine audit of a local path | `path` (string, required) |
| `scan_github_repository` | Clones and audits a remote Git repository | `url` (string, required) |
| `analyze_snippet` | Concolic SMT symbolic execution with Z3 | `snippet` (string, required) |
| `classify_algorithm` | Classifies algorithm against NIST PQC standards | `algorithm` (string, required) |
| `generate_hott_proof` | Exports Lean 4 formal verification proof | `algorithm` (string, required) |
| `analyze_thermodynamics`| Landauer dissipation and thermal SCA risk | `total_gates` (int), `erased_bits` (int) |
| `generate_patch` | Applies semantic AST code remediation | `file_path` (string), `source` (string) |
| `run_memory_sandbox` | Paged linear memory overflow detector | (none) |
| `compute_halstead_metrics`| Halstead and McCabe complexity scores | `snippet` (string, required) |
| `generate_cbom` | Generates CycloneDX 1.6 CBOM | `path` (string, required) |
| `diff_cbom` | Detects CBOM semantic drift & quantum downgrades | `old_cbom` (string), `new_cbom` (string), `fail_on_downgrade` (bool) |
| `analyze_pqc_mtu` | Models network MTU fragmentation & middlebox drops | `algorithm` (string), `mtu` (int) |
| `audit_crypto_agility` | Evaluates NIST SP 800-227 agility score (CAS) | `path` (string) |
| `generate_migration_roadmap` | Synthesizes 5-phase CNSA 2.0 / OMB M-23-02 roadmap | `path` (string), `framework` (string) |
| `generate_reencrypt_playbook`| Generates Terraform & Python KMS re-encryption scripts | `provider` (string), `key_arn` (string), `target_algorithm` (string) |
| `probe_tls_endpoint` | Probes remote host for TLS 1.3 ML-KEM | `target` (string, required) |
| `probe_ssh_endpoint` | Probes remote host for SSH 2.0 PQC KEX | `target` (string, required) |
| `generate_sarif` | Generates OASIS SARIF 2.1.0 JSON | `path` (string, required) |
| `generate_report` | Generates HTML, Markdown, or CSV report | `path` (string), `format` ("html"|"markdown"|"csv") |
| `compare_baseline` | Detects new regressions against baseline | `current_path` (string), `baseline_path` (string) |
| `diff_codebases` | Differential audit between two snapshots | `base_path` (string), `target_path` (string) |
| `audit_cbom_policy` | Evaluates CBOM against OPA / CNSA 2.0 | `path` (string, required) |
| `calculate_qramm_score` | Computes QRAMM readiness score (0-100) | `path` (string, required) |
| `audit_host_cryptography`| Inspects OS crypto runtimes and DLLs | (none) |
| `list_cryptographic_rules`| Queries 193+ detection rule definitions | `category` (string), `severity` (string), `quantum_risk` (string) |
| `scan_binary` | Disassembles PE/ELF/Mach-O/WASM binaries | `path` (string, required) |
| `audit_runtime_processes`| Audits live OS processes and crypto DLLs | (none) |
| `evaluate_hndl_risk` | Computes Mosca's Theorem ($X+Y>Z$) risk | `migration_years` (num), `shelf_life_years` (num), `crqc_horizon_years` (num) |
| `get_mesh_status` | Returns online PQMesh nodes and events | (none) |
| `broadcast_mesh_event` | Emits custom alert across PQMesh fleet | `title` (string), `details` (string), `severity` (string) |
| `audit_cloud_kms` | Audits AWS/Azure/GCP KMS and Terraform | `content` (string, required) |
| `analyze_ebpf_handshake` | Passive wire inspection of TLS 1.3 ClientHello hex | `payload_hex` (string, required) |
| `generate_k8s_mesh_remediation` | Generates Istio/Traefik PQC ingress EnvoyFilters | `platform` (string), `hybrid_group` (string) |
| `audit_hsm_token` | Audits PKCS#11 v3.0 / KMIP tokens for FIPS 203 | `provider` (string), `firmware_version` (string) |
| `generate_runtime_shim` | Generates dynamic LD_PRELOAD C interceptor | `mode` (string), `force_hybrid_group` (string) |
| `generate_autonomous_pr` | Synthesizes Pull Request with Lean 4 proofs | `path` (string, required), `repository_name` (string) |
| `export_oscal_compliance` | Exports NIST SP 800-53 OSCAL & EU DORA JSON | `path` (string, required), `project_name` (string) |
| `simulate_quantum_downgrade` | Simulates MitM downgrade and middlebox stripping | `target` (string, required), `strict_cnsa` (bool) |
| `verify_acvp_kat_vectors` | Verifies NIST CAVP / ACVP Known-Answer-Test vectors | `library` (string), `algorithm` (string) |
| `validate_composite_certificate` | Validates RFC 9758 composite certs and dual signatures | `target` (string), `raw_pem` (string, required) |
| `export_otel_cryptography` | Exports OpenTelemetry cryptographic telemetry batch | `findings_json` (string, required), `service` (string), `collector` (string) |
| `verify_constant_time_execution` | Verifies constant-time execution with Welch t-test | `routine` (string), `samples` (int) |
| `attest_cbom_provenance` | Generates SLSA Provenance v1.0 & Sigstore Cosign DSSE | `cbom_json` (string, required), `project` (string), `signer` (string) |
| `audit_hbs_state` | Audits LMS/HSS and XMSS state tracking and snapshot safety | `content` (string, required) |
| `audit_vpn_tunnel` | Audits WireGuard, strongSwan IPSec, and OpenVPN configurations | `content` (string, required) |
| `plan_db_envelope_migration` | Scans entity code and plans column envelope migration | `content` (string, required) |
| `watch_workspace_delta` | Evaluates incremental changes and regression deltas | `path` (string, required) |
| `audit_kerberos_pkinit` | Audits krb5.conf, PKINIT HNDL exposure, and Credential Guard | `content` (string, required) |
| `patch_binary_import_table` | Direct PE64 / ELF64 / Mach-O IAT/GOT import symbol patcher | `binary_hex` (string, required), `target_symbol` (string), `replacement_symbol` (string) |
| `interrogate_pkcs11_token` | Interrogates PKCS#11 v2.40/v3.0 token capabilities and hardware PQC support | `token_info_hex` (string, required) |
| `generate_cbom_datalake_schema` | Generates PostgreSQL/TimescaleDB or ClickHouse DDL and analytics for fleet-wide CBOMs | `dialect` (string), `cluster_shards` (int) |
| `profile_pqc_handshake_latency` | Profiles TLS 1.3/SSH 2.0 PQC wire size, MSS packet fragmentation, and latency | `algorithm` (string, required), `mtu` (int), `latency_ms` (num) |
| `verify_binary_patch_equivalence` | Formally validates binary patches via SMT Z3 equivalence and Lean 4 bisimulation | `original_hex` (string, required), `patched_hex` (string, required), `expected_slot` (string) |
| `audit_dynamic_symbols` | Scans AST/bytecode for `dlsym` / `GetProcAddress` calls and generates `LD_PRELOAD` & Detours hooks | `content` (string, required), `target_name` (string) |
| `plan_post_quantum_acme_enrollment` | Synthesizes ACME RFC 8555 & EST RFC 7030 certificate order, CSR PEM, and cert-manager CRDs | `domain` (string, required), `pqc_algorithm` (string), `acme_directory` (string), `challenge_type` (string) |
| `evaluate_qrng_min_entropy` | Evaluates hardware QRNG and noise source min-entropy under NIST SP 800-90B & AIS 31 | `sample_hex` (string, required), `source_name` (string) |
| `attest_cmvp_fips140_firmware` | Attests HSM token firmware against NIST CMVP FIPS 140-3 certificate registry and SP 800-131A | `module_query` (string, required), `firmware_version` (string) |
| `encode_kmip_wire_frame` | Encodes and decodes OASIS KMIP 2.1/3.0 TTLV binary wire protocol frames with FIPS 203 attributes | `algorithm` (string, required), `key_length_bits` (int) |

---

## 3. Sample JSON-RPC Interactions

### 3.1. Tool Listing Request
**Client Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

### 3.2. Invoking `classify_algorithm`
**Client Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "classify_algorithm",
    "arguments": {
      "algorithm": "ML-KEM-768"
    }
  }
}
```

**Server Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"algorithm\": \"ML-KEM-768\",\n  \"is_post_quantum_safe\": true,\n  \"standard\": \"NIST FIPS 203\",\n  \"verdict\": \"Post-Quantum Safe\"\n}"
      }
    ]
  }
}
```

### 3.3. Invoking `generate_patch`
**Client Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "generate_patch",
    "arguments": {
      "file_path": "crypto.js",
      "source": "const hash = crypto.createHash('md5');"
    }
  }
}
```

**Server Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"changed\": true,\n  \"rules_applied\": [\"PQC-REMEDIATE-MD5-TO-SHA256\"],\n  \"unified_diff\": \"--- crypto.js\\n+++ crypto.js\\n@@ -1 +1 @@\\n-const hash = crypto.createHash('md5');\\n+const hash = crypto.createHash('sha256');\"\n}"
      }
    ]
  }
}
```
