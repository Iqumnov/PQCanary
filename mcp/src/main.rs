//! PQCanary MCP Server
//!
//! Implements the Model Context Protocol (MCP) JSON-RPC 2.0 specification over stdio.
//! This allows AI agents (Claude, GPT, Gemini via MCP clients) to invoke PQCanary's
//! cryptographic security engines directly.
//!
//! Transport: stdio (standard MCP transport)
//! Protocol:  JSON-RPC 2.0
//! Spec:      https://modelcontextprotocol.io/docs/concepts/architecture
//!
//! Usage:
//!   pqcanary-mcp
//!
//! The server reads JSON-RPC requests from stdin and writes responses to stdout.
//! All log/diagnostic output goes to stderr to avoid corrupting the JSON stream.

#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

// ─── JSON-RPC 2.0 Types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }
    fn err(id: Value, code: i64, msg: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError { code, message: msg.into() }),
        }
    }
}

// ─── MCP Tool Definitions ─────────────────────────────────────────────────────

fn tool_list() -> Value {
    json!({
        "tools": [
            {
                "name": "scan_directory",
                "description": "Run the full PQCanary multi-engine cryptographic security scan on a local directory. Detects: hardcoded secrets, weak algorithms (MD5/SHA1/DES/RC4), unmasked DPA targets, FFI memory leaks, cognitively complex crypto code, and quantum-vulnerable primitives.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute or relative path to the directory to scan."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "scan_github_repository",
                "description": "Clone a public GitHub, GitLab, or Bitbucket repository and run the full PQCanary multi-engine cryptographic security scan. Supports URLs like: https://github.com/owner/repo. Requires git on PATH or will fall back to HTTP zip download.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Public Git repository URL, e.g. 'https://github.com/expressjs/express'"
                        }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "analyze_snippet",
                "description": "Run concolic symbolic execution (Tree-sitter SSA lift + Z3 SMT solver) on a code snippet to mathematically prove whether buffer overflows or other vulnerabilities are reachable. Requires z3 on PATH.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "snippet": {
                            "type": "string",
                            "description": "JavaScript or TypeScript source code to analyze."
                        }
                    },
                    "required": ["snippet"]
                }
            },
            {
                "name": "classify_algorithm",
                "description": "Classify a cryptographic algorithm against NIST post-quantum standards. Returns whether it is Post-Quantum Safe (Kyber, Dilithium, Falcon, AES-256), Quantum-Vulnerable (RSA, ECDSA, ECDH), or Classically Broken (MD5, SHA-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "algorithm": {
                            "type": "string",
                            "description": "Algorithm name, e.g. 'Kyber512', 'RSA-2048', 'AES-256-GCM', 'MD5', 'SHA1', 'ECDSA', 'Dilithium3'"
                        }
                    },
                    "required": ["algorithm"]
                }
            },
            {
                "name": "generate_hott_proof",
                "description": "Export a Lean 4 formal proof file proving security invariants (injectivity, round-trip correctness, IND-CPA semantic security) for a cryptographic algorithm using Homotopy Type Theory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "algorithm": {
                            "type": "string",
                            "description": "Algorithm name, e.g. 'AES128', 'AES256', 'Kyber512', 'ChaCha20'"
                        }
                    },
                    "required": ["algorithm"]
                }
            },
            {
                "name": "analyze_thermodynamics",
                "description": "Compute the Landauer thermodynamic limit and assess thermal side-channel risk for a model cryptographic circuit. Determines if the heat dissipation is detectable by IR cameras or Peltier sensors (threshold: 1 femtojoule).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "total_gates": {
                            "type": "integer",
                            "description": "Total number of logic gates in the circuit (e.g. 10000 for AES-128).",
                            "default": 10000
                        },
                        "erased_bits": {
                            "type": "integer",
                            "description": "Number of irreversible (information-erasing) gate operations per clock cycle (e.g. 4000).",
                            "default": 4000
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "generate_patch",
                "description": "Apply automated cryptographic remediation rules to source code. Detects and fixes: MD5→SHA-256, SHA1→SHA-256, DES→AES-256-GCM, RC4→ChaCha20, ECB mode→GCM mode, Math.random()→crypto.getRandomValues(), JWT algorithm:none→ES256. Returns a unified diff and the patched source.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "File path (used in the diff header, does not need to exist)"
                        },
                        "source": {
                            "type": "string",
                            "description": "Raw source code to analyze and patch"
                        }
                    },
                    "required": ["file_path", "source"]
                }
            },
            {
                "name": "run_memory_sandbox",
                "description": "Run the formal WebAssembly linear memory sandbox test. Demonstrates detection of heap overflow and use-after-free vulnerabilities via the paged memory safety model.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "compute_halstead_metrics",
                "description": "Compute Halstead software complexity metrics (Volume, Difficulty, Effort, Estimated Bugs) and McCabe cyclomatic complexity for a source code snippet. High complexity indicates the code is hard to audit for cryptographic correctness.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "snippet": {
                            "type": "string",
                            "description": "Source code to analyze for cognitive complexity."
                        }
                    },
                    "required": ["snippet"]
                }
            },
            {
                "name": "generate_cbom",
                "description": "Generate a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) JSON document for a codebase directory or remote URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path or website URL to generate CBOM for."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "probe_tls_endpoint",
                "description": "Perform an active binary TLS 1.3 ClientHello handshake negotiation probe against a remote host to test for Post-Quantum hybrid key exchange (ML-KEM-768 0x11ec or Kyber 0x6399).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target hostname, URL, or host:port (e.g. 'cloudflare.com', 'google.com:443')"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "probe_ssh_endpoint",
                "description": "Perform an active binary SSH 2.0 transport handshake probe to evaluate server key exchange (sntrup761, mlkem768) and determine post-quantum resilience.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target SSH hostname, URL, or host:port (e.g. 'github.com', 'ssh.example.com:22')"
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "generate_sarif",
                "description": "Generate an OASIS SARIF v2.1.0 JSON document from code scan findings for direct integration into GitHub Code Scanning and CI pipelines.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path, Git URL, or website URL to scan and produce SARIF for."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "generate_report",
                "description": "Generate a rich multi-format security audit report (standalone HTML dashboard, GitHub PR Markdown comment table, or RFC 4180 CSV export).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path or website URL to generate report for."
                        },
                        "format": {
                            "type": "string",
                            "description": "Output format: 'html', 'markdown', or 'csv' (default: 'html')",
                            "enum": ["html", "markdown", "csv"]
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "compare_baseline",
                "description": "Compare current scan findings against a baseline report to detect newly introduced security regressions and resolved issues.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "current_path": {
                            "type": "string",
                            "description": "Path to scan for current findings."
                        },
                        "baseline_path": {
                            "type": "string",
                            "description": "Path to baseline JSON or SARIF report file."
                        }
                    },
                    "required": ["current_path", "baseline_path"]
                }
            },
            {
                "name": "diff_codebases",
                "description": "Perform a differential cryptographic regression analysis between two codebases, branches, directories, or baseline snapshots. Categorizes findings into new regressions, existing issues, and resolved vulnerabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base_path": {
                            "type": "string",
                            "description": "Path to base directory, Git repository, or baseline file (Snapshot A)."
                        },
                        "target_path": {
                            "type": "string",
                            "description": "Path to comparison directory, Git repository, or scan findings (Snapshot B)."
                        }
                    },
                    "required": ["base_path", "target_path"]
                }
            },
            {
                "name": "audit_cbom_policy",
                "description": "Evaluate a codebase's CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) against automated OPA-style post-quantum policies (NIST SP 800-53 SC-13, ISO 27001 A.8.24, CNSA 2.0).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path or URL to audit."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "calculate_qramm_score",
                "description": "Compute the standardized Quantum Risk Assessment and Migration Model (QRAMM) score, readiness index, CVI practice breakdown, and top risk files for a directory, Git repo, or website URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path, Git URL, or website URL to assess."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "audit_host_cryptography",
                "description": "Inspect the host operating system's installed cryptographic runtimes, dynamic libraries, OpenSSL / LibreSSL / Windows CNG engines, and system trust stores to evaluate native Post-Quantum Cryptography capabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "list_cryptographic_rules",
                "description": "Inspect and filter the catalog of 193+ enterprise cryptographic detection patterns, CVEs, and post-quantum research vectors.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Optional category filter, e.g. 'Real-World Cryptographic CVEs', 'Post-Quantum Cryptography', 'Bleeding-Edge Cryptographic Research'."
                        },
                        "severity": {
                            "type": "string",
                            "description": "Optional severity filter: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'."
                        },
                        "quantum_risk": {
                            "type": "string",
                            "description": "Optional quantum risk filter: 'SAFE', 'PARTIAL', 'HYBRID', 'VULNERABLE'."
                        }
                    }
                }
            },
            {
                "name": "scan_binary",
                "description": "Disassemble a compiled native binary file (.exe, .dll, .so, .dylib, .wasm) to inspect imported cryptographic APIs (IAT), detect embedded constant tables (AES S-Boxes, MD5/SHA IVs), and evaluate quantum readiness without source code (Parity with SandboxAQ AQtive Guard).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the compiled native binary or dynamic library."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "audit_runtime_processes",
                "description": "Inspect active host operating system processes and their dynamically loaded cryptographic modules in memory (bcrypt.dll, ncrypt.dll, libcrypto.so) to detect live classical cipher usages (Parity with SandboxAQ AQtive Guard).",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "evaluate_hndl_risk",
                "description": "Compute Mosca's Theorem (X + Y > Z) Harvest-Now-Decrypt-Later (HNDL) risk window, estimated compromise year, regulatory compliance milestones (NIST, CNSA 2.0, OMB M-23-02), and generate production-ready migration playbooks (Nginx, Envoy, OpenSSH, AWS KMS) (Parity with IBM Quantum Safe Advisor).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "migration_years": {
                            "type": "number",
                            "description": "Estimated time required to migrate infrastructure in years (X, default: 3.0)."
                        },
                        "shelf_life_years": {
                            "type": "number",
                            "description": "Required confidentiality shelf-life of sensitive data in years (Y, default: 10.0)."
                        },
                        "crqc_horizon_years": {
                            "type": "number",
                            "description": "Estimated time until Cryptographically Relevant Quantum Computer arrives in years (Z, default: 6.0)."
                        }
                    }
                }
            },
            {
                "name": "get_mesh_status",
                "description": "Inspect the distributed PQMesh cross-medium fleet bus. Returns all online operational mediums (VS Code, Neovim, Browser Extension, K8s DaemonSet, CLI runners), aggregated enterprise findings, and real-time security events.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "broadcast_mesh_event",
                "description": "Broadcast an automated security finding, remediation trigger, or policy notice across all connected operational mediums (IDEs, browsers, K8s pods) in the enterprise fleet.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Brief headline of the event or alert."
                        },
                        "details": {
                            "type": "string",
                            "description": "Detailed description or remediation instructions."
                        },
                        "severity": {
                            "type": "string",
                            "description": "Severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'.",
                            "default": "INFO"
                        }
                    },
                    "required": ["title", "details"]
                }
            },
            {
                "name": "audit_cloud_kms",
                "description": "Audit cloud KMS key specifications (AWS KMS, Azure Key Vault, GCP Cloud KMS) and Terraform infrastructure for quantum vulnerabilities, CNSA 2.0 compliance, and NIST FIPS 203/204 migration paths.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "JSON export from AWS KMS describe-key, Azure Key Vault, GCP Cloud KMS, or Terraform HCL definition."
                        }
                    },
                    "required": ["content"]
                }
            },
            {
                "name": "diff_cbom",
                "description": "Compare two CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) snapshots, detecting additions, removals, algorithmic modifications, and critical security regressions (e.g. quantum-safe to classical downgrades).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base_cbom": {
                            "type": "string",
                            "description": "Base CBOM JSON string or file path."
                        },
                        "target_cbom": {
                            "type": "string",
                            "description": "Target comparison CBOM JSON string or file path."
                        }
                    },
                    "required": ["base_cbom", "target_cbom"]
                }
            },
            {
                "name": "analyze_pqc_mtu",
                "description": "Model network MTU and TCP packet fragmentation risk, packet counts, middlebox drop probability, and latency impact for a post-quantum cryptographic algorithm (ML-KEM, ML-DSA, SLH-DSA).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "algorithm": {
                            "type": "string",
                            "description": "Algorithm name, e.g. 'ML-KEM-768', 'ML-DSA-65', 'SLH-DSA-128f'."
                        },
                        "mtu": {
                            "type": "number",
                            "description": "Target network MTU in bytes (default: 1500)."
                        },
                        "is_ipv6": {
                            "type": "boolean",
                            "description": "Evaluate over IPv6 header overhead (default: false)."
                        }
                    },
                    "required": ["algorithm"]
                }
            },
            {
                "name": "audit_crypto_agility",
                "description": "Audit source code for NIST SP 800-227 Cryptographic Agility, evaluating hardcoded cipher strings vs decoupled providers, factories, and parameter-driven abstractions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source_code": {
                            "type": "string",
                            "description": "Source code content to inspect."
                        },
                        "file_name": {
                            "type": "string",
                            "description": "Virtual or relative file path (e.g. 'crypto.ts')."
                        }
                    },
                    "required": ["source_code"]
                }
            },
            {
                "name": "generate_migration_roadmap",
                "description": "Construct an asset-dependency topological migration roadmap aligned with US CNSA 2.0 and OMB M-23-02 statutory milestones across 5 phases (Root CA -> Intermediate CA -> Ingress -> Microservices -> Data at Rest).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path or repository to scan for migration dependencies."
                        },
                        "project_name": {
                            "type": "string",
                            "description": "Project identifier name."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "generate_reencrypt_playbook",
                "description": "Generate zero-downtime data-at-rest envelope re-encryption Terraform HCL and streaming batch worker scripts migrating from classical KEKs to ML-KEM-768.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "provider": {
                            "type": "string",
                            "description": "Cloud provider: 'AWS', 'Azure', or 'GCP'."
                        },
                        "resource_name": {
                            "type": "string",
                            "description": "Target database table, S3 bucket, or vault key alias."
                        }
                    },
                    "required": ["provider", "resource_name"]
                }
            },
            {
                "name": "analyze_ebpf_handshake",
                "description": "Passive eBPF wire telemetry: inspect raw TLS 1.3 ClientHello / ServerHello packet hex to decode supported_groups (e.g. 0x11ec X25519MLKEM768 vs classical curves).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload_hex": {
                            "type": "string",
                            "description": "Hex representation of TLS handshake packet."
                        },
                        "source_address": {
                            "type": "string",
                            "description": "Source IP:port endpoint."
                        },
                        "destination_address": {
                            "type": "string",
                            "description": "Destination IP:port endpoint."
                        }
                    },
                    "required": ["payload_hex"]
                }
            },
            {
                "name": "generate_k8s_mesh_remediation",
                "description": "Generate cloud-native Kubernetes service mesh and ingress PQC manifests (Istio EnvoyFilter, Traefik TLSOption, NGINX Ingress annotations) to enforce X25519MLKEM768 hybrid key exchanges.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "platform": {
                            "type": "string",
                            "description": "Target platform: 'istio', 'traefik', 'nginx', or 'gateway'."
                        },
                        "name": {
                            "type": "string",
                            "description": "Resource name."
                        },
                        "namespace": {
                            "type": "string",
                            "description": "Kubernetes namespace."
                        },
                        "hybrid_group": {
                            "type": "string",
                            "description": "Hybrid curve name (e.g. 'X25519MLKEM768')."
                        }
                    },
                    "required": ["platform"]
                }
            },
            {
                "name": "audit_hsm_token",
                "description": "Audit physical or cloud Hardware Security Module (HSM) tokens and slots via PKCS#11 v3.0 and OASIS KMIP for NIST FIPS 203/204 mechanisms (Thales Luna, Entrust nShield, AWS CloudHSM, YubiKey).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "provider": {
                            "type": "string",
                            "description": "Provider: 'luna', 'nshield', 'cloudhsm', 'yubikey', 'kmip', or 'pkcs11'."
                        },
                        "token_label": {
                            "type": "string",
                            "description": "Token label or slot identifier."
                        },
                        "firmware_version": {
                            "type": "string",
                            "description": "Firmware revision string."
                        },
                        "keys_stored": {
                            "type": "integer",
                            "description": "Number of cryptographic keys stored on token."
                        },
                        "has_ml_kem": {
                            "type": "boolean",
                            "description": "Whether CKM_ML_KEM_KEY_GEN mechanism is present."
                        },
                        "has_ml_dsa": {
                            "type": "boolean",
                            "description": "Whether CKM_ML_DSA mechanism is present."
                        }
                    },
                    "required": ["provider"]
                }
            },
            {
                "name": "generate_runtime_shim",
                "description": "Generate dynamic runtime cryptographic interception C shared library (LD_PRELOAD on Linux or Microsoft Detours on Windows) to monitor or enforce post-quantum algorithms in closed-source legacy binaries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "description": "Interception mode: 'audit' (log only) or 'enforce' (override curves with hybrid PQC)."
                        },
                        "log_output_path": {
                            "type": "string",
                            "description": "Target log path."
                        },
                        "force_hybrid_group": {
                            "type": "string",
                            "description": "Colon-separated curve preference list (e.g. 'X25519MLKEM768:X25519')."
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "generate_autonomous_pr",
                "description": "Trigger continuous autonomous remediation: ingest Git repository or push event, generate unified diff patches, attach Lean 4 formal proofs, and produce ready-to-merge Pull Request payloads.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Repository path or remote URL to scan."
                        },
                        "repository_name": {
                            "type": "string",
                            "description": "Repository identifier (e.g. 'org/repo')."
                        },
                        "default_branch": {
                            "type": "string",
                            "description": "Target base branch (default: 'main')."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "export_oscal_compliance",
                "description": "Export NIST SP 800-53 Rev 5 OSCAL assessment JSON and regulatory compliance matrix covering EU DORA Article 9 and PCI DSS 4.0.1 Requirement 3.4.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Repository path or target to audit."
                        },
                        "project_name": {
                            "type": "string",
                            "description": "Project identifier name."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "simulate_quantum_downgrade",
                "description": "Simulates active post-quantum downgrade attacks (RFC 8446 / CNSA 2.0 extension stripping & key share tampering) to verify target fails-closed rather than silently negotiating classical crypto.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target hostname or IP:port (e.g. 'api.example.com:443')."
                        },
                        "strict_cnsa": {
                            "type": "boolean",
                            "description": "Whether to enforce strict CNSA 2.0 fail-closed validation (default: false)."
                        }
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "verify_acvp_kat_vectors",
                "description": "Verifies target cryptographic implementation conformance against official NIST CAVP / ACVP intermediate test vectors (FIPS 203/204/205) for polynomial reduction and KyberSlash avoidance.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "library_name": {
                            "type": "string",
                            "description": "Target library or shared object name."
                        },
                        "algorithm_filter": {
                            "type": "string",
                            "description": "Optional algorithm filter: 'kem', 'dsa', 'slh', or 'all'."
                        }
                    },
                    "required": ["library_name"]
                }
            },
            {
                "name": "validate_composite_certificate",
                "description": "Validates ITU-T X.509 v3 hybrid and dual-key composite certificates and chains conforming to IETF RFC 9758 and catalyst extension bindings.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_name": {
                            "type": "string",
                            "description": "Certificate subject name or domain."
                        },
                        "certificate_pem": {
                            "type": "string",
                            "description": "Raw PEM or DER certificate content."
                        }
                    },
                    "required": ["target_name"]
                }
            },
            {
                "name": "export_otel_cryptography",
                "description": "Exports OpenTelemetry Cryptography Semantic Conventions telemetry batch (OTLP/JSON) for SIEM, Datadog, Splunk, and SOC streaming.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Codebase or directory to scan."
                        },
                        "service_name": {
                            "type": "string",
                            "description": "Microservice or workload name."
                        },
                        "collector_endpoint": {
                            "type": "string",
                            "description": "Target OTLP receiver URL (default: 'http://localhost:4318/v1/logs')."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "verify_constant_time_execution",
                "description": "Empirically verifies constant-time execution and detects KyberSlash timing leaks using statistical Welch's t-test (Dudect methodology).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "routine_name": {
                            "type": "string",
                            "description": "Target cryptographic routine or primitive name."
                        },
                        "sample_count": {
                            "type": "integer",
                            "description": "Number of statistical measurement samples (default: 10000)."
                        }
                    },
                    "required": ["routine_name"]
                }
            },
            {
                "name": "attest_cbom_provenance",
                "description": "Generates in-toto SLSA Provenance v1.0 and Sigstore Cosign DSSE attestation envelope for CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cbom_json": {
                            "type": "string",
                            "description": "CycloneDX 1.6 CBOM JSON string."
                        },
                        "project_name": {
                            "type": "string",
                            "description": "Project identifier name."
                        },
                        "signer_identity": {
                            "type": "string",
                            "description": "Signer OIDC email identity."
                        }
                    },
                    "required": ["cbom_json"]
                }
            },
            {
                "name": "audit_hbs_state",
                "description": "Audits Stateful Hash-Based Signatures (LMS/HSS RFC 8554, XMSS RFC 8391) state tracking, remaining one-time signatures (OTS), monotonic hardware NVRAM counter bindings, and VM fork / snapshot hazards.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_name": {
                            "type": "string",
                            "description": "Target identifier or configuration filename."
                        },
                        "state_content": {
                            "type": "string",
                            "description": "State configuration file content or parameter definitions."
                        }
                    },
                    "required": ["target_name", "state_content"]
                }
            },
            {
                "name": "audit_vpn_tunnel",
                "description": "Audits Post-Quantum VPN and secure tunnel configurations (WireGuard wg0.conf 256-bit PSK and Rosenpass daemon, strongSwan IPSec RFC 9370 hybrid IKEv2 proposals, OpenVPN).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_name": {
                            "type": "string",
                            "description": "VPN configuration filename (e.g. wg0.conf, ipsec.conf, client.ovpn)."
                        },
                        "config_content": {
                            "type": "string",
                            "description": "Raw VPN configuration file text."
                        }
                    },
                    "required": ["target_name", "config_content"]
                }
            },
            {
                "name": "plan_db_envelope_migration",
                "description": "Audits database column-level envelope encryption (Spring Data @Convert, Prisma @encrypted, SQLAlchemy, MongoDB CSFLE) and generates zero-downtime Python batch worker and SQL cursor migration scripts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "schema_name": {
                            "type": "string",
                            "description": "Schema DDL, entity file, or collection name."
                        },
                        "source_content": {
                            "type": "string",
                            "description": "ORM entity source code or SQL schema DDL."
                        }
                    },
                    "required": ["schema_name", "source_content"]
                }
            },
            {
                "name": "watch_workspace_delta",
                "description": "Evaluates incremental cryptographic regressions and resolved debt across a workspace directory snapshot without full rescans.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workspace_path": {
                            "type": "string",
                            "description": "Target workspace directory path (default: '.')."
                        }
                    },
                    "required": ["workspace_path"]
                }
            },
            {
                "name": "audit_kerberos_pkinit",
                "description": "Audits Enterprise Identity, Kerberos PKINIT (RFC 4556) realm configs, DES/RC4/weak enctypes, and Windows Credential Guard HNDL ticket exposure, synthesizing quantum-hardened krb5.conf.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "realm_name": {
                            "type": "string",
                            "description": "Target realm name or krb5.conf identifier."
                        },
                        "krb5_conf_content": {
                            "type": "string",
                            "description": "Raw krb5.conf content."
                        }
                    },
                    "required": ["realm_name", "krb5_conf_content"]
                }
            },
            {
                "name": "patch_binary_import_table",
                "description": "Analyzes compiled 64-bit Windows PE or Linux ELF binaries, redirects legacy cryptographic imports in IAT/GOT to drop-in FIPS 203 ML-KEM replacements, recalculates official PE checksums, and generates companion C export forwarders.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "filename": {
                            "type": "string",
                            "description": "Target binary filename (e.g. legacy_crypto.exe, libsec.so)."
                        },
                        "binary_hex": {
                            "type": "string",
                            "description": "Optional hex string of binary content (if omitted, synthetic binary is tested)."
                        },
                        "target_symbol": {
                            "type": "string",
                            "description": "Classical symbol to replace (default: RSA_generate_key_ex)."
                        },
                        "replacement_symbol": {
                            "type": "string",
                            "description": "PQC replacement symbol (default: PQ_MLKEM768_keygen)."
                        }
                    },
                    "required": ["filename"]
                }
            },
            {
                "name": "interrogate_pkcs11_token",
                "description": "Interrogates physical HSM PKCS#11 module mechanisms, evaluating hardware silicon enforcement (CKF_HW) and NIST FIPS 203/204 support.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "driver_path_or_desc": {
                            "type": "string",
                            "description": "Path to PKCS#11 driver module (.so/.dll) or token description."
                        },
                        "content": {
                            "type": "string",
                            "description": "Optional text or binary content descriptor."
                        }
                    },
                    "required": ["driver_path_or_desc"]
                }
            },
            {
                "name": "generate_cbom_datalake_schema",
                "description": "Generates enterprise PostgreSQL and ClickHouse data lake DDL schemas, batch SQL insert statements, and fleet-wide Cryptographic Agility Score (CAS) queries.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repository_id": {
                            "type": "string",
                            "description": "Enterprise repository identifier."
                        },
                        "cbom_json": {
                            "type": "string",
                            "description": "CycloneDX 1.6 CBOM JSON document."
                        }
                    },
                    "required": ["repository_id"]
                }
            },
            {
                "name": "profile_pqc_handshake_latency",
                "description": "Profiles post-quantum TLS 1.3 / SSH handshake latency inflation (p50, p95, p99), TCP segmentation boundaries (MTU 1500/1420), and middlebox fragmentation drop risks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_endpoint": {
                            "type": "string",
                            "description": "Network target endpoint (e.g. 'api.internal:443')."
                        },
                        "sample_count": {
                            "type": "number",
                            "description": "Number of sample probes to simulate (default: 10)."
                        },
                        "base_rtt_ms": {
                            "type": "number",
                            "description": "Base network round-trip time in milliseconds (default: 25.0)."
                        }
                    },
                    "required": ["target_endpoint"]
                }
            },
            {
                "name": "verify_binary_patch_equivalence",
                "description": "Formally verifies binary translation equivalence, ensuring .text code opcodes and control-flow graphs remain invariant while synthesizing Z3 SMT-LIB2 and Lean 4 proofs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "original_binary_name": {
                            "type": "string",
                            "description": "Original binary filename."
                        },
                        "original_binary_hex": {
                            "type": "string",
                            "description": "Original binary content in hex representation."
                        },
                        "patched_binary_name": {
                            "type": "string",
                            "description": "Patched binary filename."
                        },
                        "patched_binary_hex": {
                            "type": "string",
                            "description": "Patched binary content in hex representation."
                        }
                    },
                    "required": ["original_binary_name", "patched_binary_name"]
                }
            },
            {
                "name": "audit_dynamic_symbols",
                "description": "Audits source code or disassembly for dynamic loader calls (dlsym, GetProcAddress, ctypes, JNI) and generates LD_PRELOAD / Detours runtime interceptor hooks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_name": {
                            "type": "string",
                            "description": "Target source file or binary name."
                        },
                        "content": {
                            "type": "string",
                            "description": "Source code text or disassembly output."
                        }
                    },
                    "required": ["target_name", "content"]
                }
            },
            {
                "name": "plan_post_quantum_acme_enrollment",
                "description": "Plans automated Post-Quantum ACME (RFC 8555) and EST (RFC 7030) certificate enrollment with ML-DSA-65/87 composite CSRs, cert-manager CRDs, and Vault HCL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Target domain name."
                        },
                        "algorithm": {
                            "type": "string",
                            "description": "Primary post-quantum signature algorithm (default: ML-DSA-65)."
                        },
                        "acme_directory": {
                            "type": "string",
                            "description": "ACME directory URL."
                        },
                        "challenge_type": {
                            "type": "string",
                            "description": "Challenge type: dns-01, http-01, or tls-alpn-01."
                        }
                    },
                    "required": ["domain"]
                }
            },
            {
                "name": "evaluate_qrng_min_entropy",
                "description": "Evaluates physical noise source samples conforming to NIST SP 800-90B (MCV, collision, Markov, and compression tests) to verify FIPS 203 seed safety.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source_name": {
                            "type": "string",
                            "description": "Source identifier or hardware device descriptor."
                        },
                        "sample_hex": {
                            "type": "string",
                            "description": "Hex representation of raw entropy sample."
                        }
                    },
                    "required": ["source_name", "sample_hex"]
                }
            },
            {
                "name": "attest_cmvp_fips140_firmware",
                "description": "Attests physical HSM tokens and cryptographic libraries against authoritative NIST CMVP FIPS 140-3 certificate registry and sunset schedules.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "module_query": {
                            "type": "string",
                            "description": "Module name or CMVP certificate number."
                        },
                        "firmware_version": {
                            "type": "string",
                            "description": "Firmware version string (default: 7.8.1)."
                        }
                    },
                    "required": ["module_query"]
                }
            },
            {
                "name": "encode_kmip_wire_frame",
                "description": "Encodes and decodes OASIS KMIP 2.1 / 3.0 TTLV binary wire protocol frames for post-quantum key management operations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "algorithm": {
                            "type": "string",
                            "description": "Post-quantum algorithm: ML-KEM or ML-DSA."
                        },
                        "length_bits": {
                            "type": "number",
                            "description": "Key length in bits (default: 768)."
                        }
                    },
                    "required": ["algorithm"]
                }
            }
        ]
    })
}

// ─── Tool Dispatch ────────────────────────────────────────────────────────────

async fn resolve_target_findings(target: &str) -> Result<Vec<pqcanary_core::scanner::orchestrator::ComprehensiveFinding>, Value> {
    let target = target.trim();
    if pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::is_git_repository_url(target) {
        if let Err(e) = pqcanary_core::api::validate_network_target(target) {
            return Err(json!({ "error": format!("Invalid repository target: {}", e) }));
        }
        let fetcher = pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::new();
        match fetcher.fetch_repository(target).await {
            Ok(temp_dir) => {
                let temp_str = temp_dir.to_string_lossy().to_string();
                let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&temp_str);
                let mut findings = orchestrator.execute_full_scan();
                for f in &mut findings {
                    if let Ok(rel) = std::path::Path::new(&f.file_path).strip_prefix(&temp_dir) {
                        f.file_path = rel.to_string_lossy().to_string();
                    }
                }
                pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::cleanup_temp_dir(&temp_dir);
                Ok(findings)
            }
            Err(e) => Err(json!({ "error": format!("Failed to fetch repository: {}", e) })),
        }
    } else if std::path::Path::new(target).exists() {
        let safe_path = match pqcanary_core::api::validate_local_path(target) {
            Ok(p) => p,
            Err(err) => return Err(json!({ "error": format!("{}: {}", err.vulnerability_class, err.description) })),
        };
        let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&safe_path);
        Ok(orchestrator.execute_full_scan())
    } else if target.starts_with("http://") || target.starts_with("https://") || (target.contains('.') && !target.contains('/') && !target.contains('\\')) {
        if let Err(e) = pqcanary_core::api::validate_network_target(target) {
            return Err(json!({ "error": format!("Invalid network target: {}", e) }));
        }
        Ok(pqcanary_core::api::audit_remote_url(target).await)
    } else {
        let safe_path = match pqcanary_core::api::validate_local_path(target) {
            Ok(p) => p,
            Err(err) => return Err(json!({ "error": format!("{}: {}", err.vulnerability_class, err.description) })),
        };
        let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&safe_path);
        Ok(orchestrator.execute_full_scan())
    }
}

async fn dispatch_tool(name: &str, args: &Value) -> Value {
    match name {
        "scan_directory" => {
            let path = args.get("path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let safe_path = match pqcanary_core::api::validate_local_path(path) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("{}: {}", err.vulnerability_class, err.description) }),
            };
            eprintln!("pqcanary-mcp: Scanning directory: {}", safe_path);
            let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&safe_path);
            let findings = orchestrator.execute_full_scan();
            let count = findings.len();
            eprintln!("pqcanary-mcp: Found {} findings", count);
            json!({
                "findings_count": count,
                "findings": findings,
                "summary": format!("PQCanary scan of '{}' found {} security findings.", safe_path, count)
            })
        }

        "scan_github_repository" => {
            let url = args.get("url")
                .and_then(Value::as_str)
                .unwrap_or("");
            if url.trim().is_empty() {
                return json!({ "error": "URL parameter cannot be empty." });
            }
            if let Err(e) = pqcanary_core::api::validate_network_target(url) {
                return json!({ "error": format!("Invalid target: {}", e) });
            }
            eprintln!("pqcanary-mcp: Fetching GitHub repository: {}", url);
            let fetcher = pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::new();
            let result = fetcher.fetch_repository(url).await;
            match result {
                Ok(temp_dir) => {
                    let temp_str = temp_dir.to_string_lossy().to_string();
                    let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&temp_str);
                    let findings = orchestrator.execute_full_scan();
                    let count = findings.len();
                    // Strip absolute temp path prefix from finding file_paths
                    let sanitized: Vec<_> = findings.into_iter().map(|mut f| {
                        if let Ok(rel) = std::path::Path::new(&f.file_path).strip_prefix(&temp_dir) {
                            f.file_path = rel.to_string_lossy().to_string();
                        }
                        f
                    }).collect();
                    pqcanary_core::scanner::git_cloner::GitRepositoryFetcher::cleanup_temp_dir(&temp_dir);
                    json!({
                        "findings_count": count,
                        "findings": sanitized,
                        "repository": url,
                        "summary": format!("PQCanary scan of '{}' found {} security findings.", url, count)
                    })
                }
                Err(e) => json!({
                    "error": format!("Failed to fetch repository: {}", e),
                    "tip": "Ensure git is installed on PATH, or the repository is public and accessible."
                }),
            }
        }

        "analyze_snippet" => {
            let snippet = args.get("snippet")
                .and_then(Value::as_str)
                .unwrap_or("");
            let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(".");
            match orchestrator.execute_concolic_target(snippet) {
                Some(finding) => json!({
                    "status": "vulnerable",
                    "finding": finding,
                }),
                None => json!({
                    "status": "safe",
                    "finding": null,
                    "note": "No exploitable vulnerabilities found (or z3 not on PATH)."
                }),
            }
        }

        "classify_algorithm" => {
            let algorithm = args.get("algorithm")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let prover = pqcanary_core::omega::hott_prover::HottProver::new();
            let classification = prover.classify_algorithm(algorithm);
            json!({
                "algorithm": algorithm,
                "is_post_quantum_safe": classification.is_safe(),
                "verdict": classification.severity_message(),
            })
        }

        "generate_hott_proof" => {
            let algorithm = args.get("algorithm")
                .and_then(Value::as_str)
                .unwrap_or("AES256");
            let prover = pqcanary_core::omega::hott_prover::HottProver::new();
            let lean4_source = prover.export_lean_proof(algorithm);
            let classification = prover.classify_algorithm(algorithm);
            json!({
                "algorithm": algorithm,
                "classification": classification.severity_message(),
                "lean4_source": lean4_source,
                "note": "Save as .lean file and verify with: lake env lean <file>.lean"
            })
        }

        "analyze_thermodynamics" => {
            let total_gates = args.get("total_gates")
                .and_then(Value::as_u64)
                .unwrap_or(10_000) as usize;
            let erased_bits = args.get("erased_bits")
                .and_then(Value::as_u64)
                .unwrap_or(4_000) as usize;

            let analyzer = pqcanary_core::omega::thermodynamics::ThermodynamicsAnalyzer::at_room_temperature();
            let report = analyzer.simulate_landauer_limit(total_gates, erased_bits);

            json!({
                "temperature_kelvin": report.temperature_kelvin,
                "landauer_limit_joules": report.landauer_limit_joules,
                "total_dissipation_joules": report.total_dissipation_joules,
                "total_dissipation_femtojoules": report.total_dissipation_femtojoules,
                "irreversible_fraction": report.irreversible_fraction,
                "thermal_side_channel_risk": report.thermal_side_channel_risk,
                "verdict": if report.thermal_side_channel_risk {
                    "RISK: Thermal dissipation exceeds 1 fJ threshold. IR side-channel attack is feasible."
                } else {
                    "SAFE: Thermal dissipation is below detectable threshold."
                }
            })
        }

        "generate_patch" => {
            let file_path = args.get("file_path")
                .and_then(Value::as_str)
                .unwrap_or("unknown.ts");
            let source = args.get("source")
                .and_then(Value::as_str)
                .unwrap_or("");

            let patcher = pqcanary_core::refactor::autonomous_pr::SemanticPatcher::new();
            let result = patcher.patch_file(file_path, source);

            json!({
                "changed": result.is_changed(),
                "rules_applied": result.rules_applied,
                "unified_diff": result.unified_diff,
                "patched_source": result.patched_source,
                "summary": if result.is_changed() {
                    format!("Applied {} remediation rules.", result.rules_applied.len())
                } else {
                    "No vulnerable patterns detected. Source is already compliant.".to_string()
                }
            })
        }

        "run_memory_sandbox" => {
            let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(".");
            let report = orchestrator.run_memory_sandbox_test();
            json!({ "report": report })
        }

        "compute_halstead_metrics" => {
            let snippet = args.get("snippet")
                .and_then(Value::as_str)
                .unwrap_or("");
            let analyzer = pqcanary_core::refactor::cognitive_security::CognitiveSecurityAnalyzer::new();
            let metrics = analyzer.analyze_halstead(snippet);
            let cyclomatic = analyzer.compute_cyclomatic_complexity(snippet);
            json!({
                "vocabulary": metrics.vocabulary(),
                "length": metrics.length(),
                "volume": metrics.volume(),
                "difficulty": metrics.difficulty(),
                "effort": metrics.effort(),
                "time_required_seconds": metrics.time_required(),
                "estimated_bugs": metrics.delivered_bugs(),
                "cyclomatic_complexity": cyclomatic,
                "risk_assessment": if metrics.difficulty() > 50.0 || cyclomatic > 20 {
                    "HIGH: Code is mathematically unmaintainable. Cryptographic correctness hard to audit."
                } else if cyclomatic > 10 {
                    "MEDIUM: Elevated complexity. Consider refactoring before cryptographic audit."
                } else {
                    "LOW: Complexity within acceptable bounds for cryptographic code."
                }
            })
        }

        "generate_cbom" => {
            let path = args.get("path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let target = path.trim();
            let findings = match resolve_target_findings(target).await {
                Ok(f) => f,
                Err(err_json) => return err_json,
            };
            let cbom = pqcanary_core::scanner::cbom::CbomGenerator::generate_cbom(&findings, target);
            serde_json::to_value(&cbom).unwrap_or_default()
        }

        "probe_tls_endpoint" => {
            let target = args.get("target")
                .and_then(Value::as_str)
                .unwrap_or("cloudflare.com");
            if let Err(e) = pqcanary_core::api::validate_network_target(target) {
                return json!({ "error": format!("Invalid network target: {}", e) });
            }
            let (host, port) = pqcanary_core::scanner::network_tls::NetworkTlsProbe::parse_target(target);
            match pqcanary_core::scanner::network_tls::NetworkTlsProbe::probe_endpoint(&host, port).await {
                Ok(res) => json!({
                    "host": res.host,
                    "port": res.port,
                    "tls_version": res.tls_version,
                    "cipher_suite": res.cipher_suite,
                    "selected_group": res.selected_group,
                    "is_post_quantum_safe": res.is_post_quantum_safe,
                    "is_hybrid": res.is_hybrid,
                    "rtt_ms": res.rtt_ms,
                    "status": if res.is_post_quantum_safe { "QUANTUM_SAFE" } else if res.is_hybrid { "DRAFT_QUANTUM_SAFE" } else { "QUANTUM_VULNERABLE" },
                }),
                Err(e) => json!({ "error": format!("TLS probe failed: {}", e) }),
            }
        }

        "probe_ssh_endpoint" => {
            let target = args.get("target")
                .and_then(Value::as_str)
                .unwrap_or("github.com");
            if let Err(e) = pqcanary_core::api::validate_network_target(target) {
                return json!({ "error": format!("Invalid network target: {}", e) });
            }
            let (host, port) = pqcanary_core::scanner::network_ssh::NetworkSshProbe::parse_target(target);
            match pqcanary_core::scanner::network_ssh::NetworkSshProbe::probe_endpoint(&host, port).await {
                Ok(res) => json!({
                    "host": res.host,
                    "port": res.port,
                    "server_banner": res.server_banner,
                    "is_post_quantum_safe": res.is_post_quantum_safe,
                    "pqc_kex_supported": res.pqc_kex_supported,
                    "weak_kex_detected": res.weak_kex_detected,
                    "kex_algorithms": res.kex_algorithms,
                    "host_key_algorithms": res.host_key_algorithms,
                    "rtt_ms": res.rtt_ms,
                }),
                Err(e) => json!({ "error": format!("SSH probe failed: {}", e) }),
            }
        }

        "generate_sarif" => {
            let path = args.get("path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let target = path.trim();
            let findings = match resolve_target_findings(target).await {
                Ok(f) => f,
                Err(err_json) => return err_json,
            };
            let sarif = pqcanary_core::scanner::sarif::SarifGenerator::generate_sarif(&findings, Some(target));
            serde_json::to_value(&sarif).unwrap_or_default()
        }

        "generate_report" => {
            let path = args.get("path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let format = args.get("format")
                .and_then(Value::as_str)
                .unwrap_or("html");
            let target = path.trim();
            let findings = match resolve_target_findings(target).await {
                Ok(f) => f,
                Err(err_json) => return err_json,
            };

            match format.to_lowercase().as_str() {
                "csv" => {
                    let csv = pqcanary_core::scanner::reporters::CsvReporter::generate(&findings);
                    json!({ "format": "csv", "report": csv })
                }
                "markdown" | "md" => {
                    let md = pqcanary_core::scanner::reporters::MarkdownReporter::generate(&findings, target);
                    json!({ "format": "markdown", "report": md })
                }
                _ => {
                    let html = pqcanary_core::scanner::reporters::HtmlReporter::generate(&findings, target);
                    json!({ "format": "html", "report": html })
                }
            }
        }

        "compare_baseline" => {
            let current_path = args.get("current_path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let baseline_path = args.get("baseline_path")
                .and_then(Value::as_str)
                .unwrap_or("");

            let safe_current = match pqcanary_core::api::validate_local_path(current_path) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("current_path {}: {}", err.vulnerability_class, err.description) }),
            };
            let safe_baseline = match pqcanary_core::api::validate_local_path(baseline_path) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("baseline_path {}: {}", err.vulnerability_class, err.description) }),
            };

            match pqcanary_core::scanner::baseline::BaselineEngine::load_baseline(&safe_baseline) {
                Ok(baseline_findings) => {
                    let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&safe_current);
                    let current_findings = orchestrator.execute_full_scan();
                    let comparison = pqcanary_core::scanner::baseline::BaselineEngine::compare(&current_findings, &baseline_findings);
                    serde_json::to_value(&comparison).unwrap_or_default()
                }
                Err(e) => json!({ "error": format!("Failed to load baseline: {}", e) }),
            }
        }

        "diff_codebases" => {
            let base_path = args.get("base_path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let target_path = args.get("target_path")
                .and_then(Value::as_str)
                .unwrap_or(".");

            let safe_base = match pqcanary_core::api::validate_local_path(base_path) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("base_path {}: {}", err.vulnerability_class, err.description) }),
            };
            let safe_target = match pqcanary_core::api::validate_local_path(target_path) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("target_path {}: {}", err.vulnerability_class, err.description) }),
            };

            let base_findings = if std::path::Path::new(&safe_base).is_file() {
                match pqcanary_core::scanner::baseline::BaselineEngine::load_baseline(&safe_base) {
                    Ok(f) => f,
                    Err(e) => return json!({ "error": format!("Failed to load base baseline: {}", e) }),
                }
            } else {
                let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&safe_base);
                orchestrator.execute_full_scan()
            };

            let target_findings = if std::path::Path::new(&safe_target).is_file() {
                match pqcanary_core::scanner::baseline::BaselineEngine::load_baseline(&safe_target) {
                    Ok(f) => f,
                    Err(e) => return json!({ "error": format!("Failed to load target baseline: {}", e) }),
                }
            } else {
                let orchestrator = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&safe_target);
                orchestrator.execute_full_scan()
            };

            let report = pqcanary_core::scanner::baseline::BaselineEngine::compare(&target_findings, &base_findings);
            serde_json::to_value(&report).unwrap_or_default()
        }

        "audit_cbom_policy" => {
            let path = args.get("path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let target = path.trim();
            let findings = match resolve_target_findings(target).await {
                Ok(f) => f,
                Err(err_json) => return err_json,
            };
            let cbom = pqcanary_core::scanner::cbom::CbomGenerator::generate_cbom(&findings, target);
            let policy_report = pqcanary_core::scanner::cbom::CbomGenerator::evaluate_quantum_policy(&cbom);
            serde_json::to_value(&policy_report).unwrap_or_default()
        }

        "calculate_qramm_score" => {
            let path = args.get("path")
                .and_then(Value::as_str)
                .unwrap_or(".");
            let target = path.trim();
            let findings = match resolve_target_findings(target).await {
                Ok(f) => f,
                Err(err_json) => return err_json,
            };

            let score = pqcanary_core::scanner::qramm::QrammEngine::calculate_score(&findings);
            let md = pqcanary_core::scanner::qramm::QrammEngine::to_markdown_summary(&score);
            json!({
                "qramm_score": serde_json::to_value(&score).unwrap_or_default(),
                "markdown_summary": md
            })
        }

        "audit_host_cryptography" => {
            let report = pqcanary_core::scanner::os_crypto::OsCryptoAuditor::audit_host();
            let md = pqcanary_core::scanner::os_crypto::OsCryptoAuditor::format_markdown(&report);
            json!({
                "report": serde_json::to_value(&report).unwrap_or_default(),
                "markdown_summary": md
            })
        }

        "list_cryptographic_rules" => {
            let all_rules = pqcanary_core::scanner::patterns::get_all_pattern_definitions();
            let cat_filter = args.get("category").and_then(Value::as_str);
            let sev_filter = args.get("severity").and_then(Value::as_str);
            let qr_filter = args.get("quantum_risk").and_then(Value::as_str);

            let filtered: Vec<_> = all_rules.into_iter().filter(|d| {
                if let Some(cat) = cat_filter {
                    if !d.category.to_lowercase().contains(&cat.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(sev) = sev_filter {
                    if !d.severity.eq_ignore_ascii_case(sev) {
                        return false;
                    }
                }
                if let Some(qr) = qr_filter {
                    if !d.quantum_risk.as_str().eq_ignore_ascii_case(qr) {
                        return false;
                    }
                }
                true
            }).collect();

            json!({
                "total_matched": filtered.len(),
                "rules": filtered
            })
        }

        "scan_binary" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            if path.is_empty() {
                return json!({ "error": "Path to binary file is required" });
            }
            let safe_path = match pqcanary_core::api::validate_local_path(path) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("{}: {}", err.vulnerability_class, err.description) }),
            };
            let bytes = match std::fs::read(&safe_path) {
                Ok(b) => b,
                Err(e) => return json!({ "error": format!("Failed to read file: {}", e) }),
            };
            let file_name = std::path::Path::new(&safe_path).file_name().and_then(|s| s.to_str()).unwrap_or("binary");
            let report = pqcanary_core::scanner::binary_scanner::BinaryScanner::scan_buffer(file_name, &bytes);
            serde_json::to_value(&report).unwrap_or_default()
        }

        "audit_runtime_processes" => {
            let report = pqcanary_core::scanner::runtime_tracer::RuntimeProcessAuditor::audit_system_processes();
            serde_json::to_value(&report).unwrap_or_default()
        }

        "evaluate_hndl_risk" => {
            let x = args.get("migration_years").and_then(Value::as_f64).map(|v| v as f32);
            let y = args.get("shelf_life_years").and_then(Value::as_f64).map(|v| v as f32);
            let z = args.get("crqc_horizon_years").and_then(Value::as_f64).map(|v| v as f32);
            let report = pqcanary_core::scanner::hndl_advisor::HndlAdvisor::evaluate_risk(x, y, z);
            serde_json::to_value(&report).unwrap_or_default()
        }

        "get_mesh_status" => {
            let summary = pqcanary_core::scanner::mesh::FleetMeshBus::get_summary().await;
            serde_json::to_value(&summary).unwrap_or_default()
        }

        "broadcast_mesh_event" => {
            let title = args.get("title").and_then(Value::as_str).unwrap_or("AI Agent Event");
            let details = args.get("details").and_then(Value::as_str).unwrap_or("");
            let severity = args.get("severity").and_then(Value::as_str).unwrap_or("INFO");

            let evt = pqcanary_core::scanner::mesh::MeshEvent {
                event_id: format!("evt-mcp-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()),
                timestamp_epoch: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                source_node_id: "node-mcp-agent".to_string(),
                source_medium: pqcanary_core::scanner::mesh::OperationalMedium::McpAgent,
                event_type: pqcanary_core::scanner::mesh::MeshEventType::DirectCommand,
                title: title.to_string(),
                details: details.to_string(),
                severity: severity.to_string(),
                payload_json: None,
            };
            pqcanary_core::scanner::mesh::FleetMeshBus::broadcast_event(evt).await;
            json!({ "status": "broadcast_sent", "title": title })
        }

        "audit_cloud_kms" => {
            let content = args.get("content").and_then(Value::as_str).unwrap_or("");
            let report = pqcanary_core::scanner::cloud_kms::CloudKmsAuditor::audit_raw_content(content);
            serde_json::to_value(&report).unwrap_or_default()
        }

        "diff_cbom" => {
            let base_str = args.get("base_cbom").and_then(Value::as_str).unwrap_or("");
            let target_str = args.get("target_cbom").and_then(Value::as_str).unwrap_or("");
            let base_content = if std::path::Path::new(base_str).is_file() {
                std::fs::read_to_string(base_str).unwrap_or_else(|_| base_str.to_string())
            } else {
                base_str.to_string()
            };
            let target_content = if std::path::Path::new(target_str).is_file() {
                std::fs::read_to_string(target_str).unwrap_or_else(|_| target_str.to_string())
            } else {
                target_str.to_string()
            };
            match pqcanary_core::scanner::cbom_diff::CbomDiffEngine::diff_json_strings(&base_content, &target_content) {
                Ok(rep) => serde_json::to_value(&rep).unwrap_or_default(),
                Err(e) => json!({ "error": e }),
            }
        }

        "analyze_pqc_mtu" => {
            let algo = args.get("algorithm").and_then(Value::as_str).unwrap_or("ML-KEM-768");
            let mtu = args.get("mtu").and_then(Value::as_u64).map(|v| v as usize);
            let ipv6 = args.get("is_ipv6").and_then(Value::as_bool).unwrap_or(false);
            let rep = pqcanary_core::scanner::pqc_mtu::PqcMtuAnalyzer::analyze(algo, mtu, ipv6);
            serde_json::to_value(&rep).unwrap_or_default()
        }

        "audit_crypto_agility" => {
            let code = args.get("source_code").and_then(Value::as_str).unwrap_or("");
            let file_name = args.get("file_name").and_then(Value::as_str).unwrap_or("snippet.ts");
            let findings = pqcanary_core::scanner::agility_scanner::AgilityScanner::audit_source(file_name, code);
            let rep = pqcanary_core::scanner::agility_scanner::AgilityScanner::evaluate_report(findings);
            serde_json::to_value(&rep).unwrap_or_default()
        }

        "generate_migration_roadmap" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let name = args.get("project_name").and_then(Value::as_str).unwrap_or("Workspace");
            match resolve_target_findings(path).await {
                Ok(findings) => {
                    let roadmap = pqcanary_core::scanner::migration_sequencer::MigrationSequencer::sequence_from_findings(name, &findings);
                    serde_json::to_value(&roadmap).unwrap_or_default()
                }
                Err(err) => err,
            }
        }

        "generate_reencrypt_playbook" => {
            let provider = args.get("provider").and_then(Value::as_str).unwrap_or("AWS");
            let resource = args.get("resource_name").and_then(Value::as_str).unwrap_or("production-vault");
            let pb = pqcanary_core::scanner::reencrypt_playbook::ReencryptPlaybookGenerator::generate(provider, resource);
            serde_json::to_value(&pb).unwrap_or_default()
        }

        "analyze_ebpf_handshake" => {
            let hex_str = args.get("payload_hex").and_then(Value::as_str).unwrap_or("");
            let src = args.get("source_address").and_then(Value::as_str).unwrap_or("192.168.1.100:44320");
            let dst = args.get("destination_address").and_then(Value::as_str).unwrap_or("10.0.0.1:443");
            let bytes = (0..hex_str.len())
                .step_by(2)
                .filter_map(|i| {
                    if i + 2 <= hex_str.len() {
                        u8::from_str_radix(&hex_str[i..i + 2], 16).ok()
                    } else {
                        None
                    }
                })
                .collect::<Vec<u8>>();
            match pqcanary_core::scanner::ebpf_sniffer::EbpfSniffer::parse_handshake_bytes(&bytes, src, dst) {
                Ok(res) => serde_json::to_value(&res).unwrap_or_default(),
                Err(e) => json!({ "error": e }),
            }
        }

        "generate_k8s_mesh_remediation" => {
            let platform = args.get("platform").and_then(Value::as_str).unwrap_or("istio");
            let name = args.get("name").and_then(Value::as_str).unwrap_or("pqc-hybrid-tls-enforce");
            let namespace = args.get("namespace").and_then(Value::as_str).unwrap_or("istio-system");
            let hybrid = args.get("hybrid_group").and_then(Value::as_str).unwrap_or("X25519MLKEM768");
            let p = match platform.to_lowercase().as_str() {
                "traefik" => pqcanary_core::scanner::k8s_mesh::K8sIngressPlatform::TraefikTLSOption,
                "nginx" => pqcanary_core::scanner::k8s_mesh::K8sIngressPlatform::NginxIngress,
                "gateway" => pqcanary_core::scanner::k8s_mesh::K8sIngressPlatform::GatewayApi,
                _ => pqcanary_core::scanner::k8s_mesh::K8sIngressPlatform::IstioEnvoyFilter,
            };
            let cfg = pqcanary_core::scanner::k8s_mesh::K8sMeshConfig {
                platform: p,
                namespace: namespace.to_string(),
                name: name.to_string(),
                workload_selector: "istio=ingressgateway".to_string(),
                hybrid_group: hybrid.to_string(),
                min_tls_version: "TLSv1_3".to_string(),
            };
            let res = pqcanary_core::scanner::k8s_mesh::K8sMeshEngine::generate(&cfg);
            serde_json::to_value(&res).unwrap_or_default()
        }

        "audit_hsm_token" => {
            let provider = args.get("provider").and_then(Value::as_str).unwrap_or("luna");
            let label = args.get("token_label").and_then(Value::as_str).unwrap_or("Production-Token");
            let firmware = args.get("firmware_version").and_then(Value::as_str).unwrap_or("7.8.1");
            let keys = args.get("keys_stored").and_then(Value::as_u64).unwrap_or(50) as usize;
            let ml_kem = args.get("has_ml_kem").and_then(Value::as_bool).unwrap_or(false);
            let ml_dsa = args.get("has_ml_dsa").and_then(Value::as_bool).unwrap_or(false);
            let prov = match provider.to_lowercase().as_str() {
                "thales" | "luna" => pqcanary_core::scanner::hsm_audit::HsmProviderType::ThalesLuna7,
                "entrust" | "nshield" => pqcanary_core::scanner::hsm_audit::HsmProviderType::EntrustNshield,
                "aws" | "cloudhsm" => pqcanary_core::scanner::hsm_audit::HsmProviderType::AwsCloudHsm,
                "yubikey" => pqcanary_core::scanner::hsm_audit::HsmProviderType::YubiKeyPqc,
                "kmip" => pqcanary_core::scanner::hsm_audit::HsmProviderType::OasisKmip3,
                _ => pqcanary_core::scanner::hsm_audit::HsmProviderType::Pkcs11V3,
            };
            let rep = pqcanary_core::scanner::hsm_audit::HsmAuditor::audit_hsm(prov, label, firmware, keys, ml_kem, ml_dsa);
            serde_json::to_value(&rep).unwrap_or_default()
        }

        "generate_runtime_shim" => {
            let mode_str = args.get("mode").and_then(Value::as_str).unwrap_or("audit");
            let log_path = args.get("log_output_path").and_then(Value::as_str).unwrap_or("/var/log/pqcanary_runtime.log");
            let hybrid = args.get("force_hybrid_group").and_then(Value::as_str).unwrap_or("X25519MLKEM768:X25519");
            let m = if mode_str == "enforce" {
                pqcanary_core::scanner::runtime_shim::ShimInterceptionMode::ActiveEnforcementAndPqcUpgrade
            } else {
                pqcanary_core::scanner::runtime_shim::ShimInterceptionMode::AuditAndLogOnly
            };
            let cfg = pqcanary_core::scanner::runtime_shim::RuntimeShimConfig {
                mode: m,
                log_output_path: log_path.to_string(),
                force_hybrid_group: hybrid.to_string(),
                emit_udp_telemetry: true,
                udp_collector_endpoint: "127.0.0.1:9099".to_string(),
            };
            let c_code = pqcanary_core::scanner::runtime_shim::RuntimeShimGenerator::generate_linux_c_shim(&cfg);
            json!({
                "c_source": c_code,
                "instructions": pqcanary_core::scanner::runtime_shim::RuntimeShimGenerator::format_markdown(&cfg)
            })
        }

        "generate_autonomous_pr" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let repo = args.get("repository_name").and_then(Value::as_str).unwrap_or("workspace/repo");
            let branch = args.get("default_branch").and_then(Value::as_str).unwrap_or("main");
            let commit = args.get("commit_sha").and_then(Value::as_str).unwrap_or("head");
            let author = args.get("author_name").and_then(Value::as_str).unwrap_or("CI/CD");
            match resolve_target_findings(path).await {
                Ok(findings) => {
                    let evt = pqcanary_core::scanner::autonomous_bot::GitWebhookPushEvent {
                        provider: pqcanary_core::scanner::autonomous_bot::GitPlatformProvider::GitHub,
                        repository_name: repo.to_string(),
                        default_branch: branch.to_string(),
                        commit_sha: commit.to_string(),
                        author_name: author.to_string(),
                        modified_files: vec!["src/crypto.ts".to_string()],
                    };
                    match pqcanary_core::scanner::autonomous_bot::AutonomousBotEngine::process_event(&evt, &findings) {
                        Some(pr) => serde_json::to_value(&pr).unwrap_or_default(),
                        None => json!({ "status": "NO_ACTIONABLE_VULNERABILITIES" }),
                    }
                }
                Err(err) => err,
            }
        }

        "export_oscal_compliance" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let project = args.get("project_name").and_then(Value::as_str).unwrap_or("Production System");
            match resolve_target_findings(path).await {
                Ok(findings) => {
                    let rep = pqcanary_core::scanner::oscal_exporter::OscalExporter::evaluate_compliance(project, &findings);
                    let oscal_json = pqcanary_core::scanner::oscal_exporter::OscalExporter::export_oscal_json(&rep);
                    json!({
                        "assessment_report": rep,
                        "oscal_json": oscal_json
                    })
                }
                Err(err) => err,
            }
        }

        "simulate_quantum_downgrade" => {
            let target = args.get("target").and_then(Value::as_str).unwrap_or("localhost:443");
            let strict = args.get("strict_cnsa").and_then(Value::as_bool).unwrap_or(false);
            let rep = pqcanary_core::scanner::downgrade_sim::DowngradeSimulator::simulate(target, strict);
            json!({
                "downgrade_report": rep,
                "markdown": pqcanary_core::scanner::downgrade_sim::DowngradeSimulator::format_markdown(&rep)
            })
        }

        "verify_acvp_kat_vectors" => {
            let library = args.get("library_name").and_then(Value::as_str).unwrap_or("Default-Implementation");
            let algo = args.get("algorithm_filter").and_then(Value::as_str);
            let rep = pqcanary_core::scanner::acvp_kat::AcvpKatHarness::verify_vectors(library, algo);
            json!({
                "kat_report": rep,
                "markdown": pqcanary_core::scanner::acvp_kat::AcvpKatHarness::format_markdown(&rep)
            })
        }

        "validate_composite_certificate" => {
            let target = args.get("target_name").and_then(Value::as_str).unwrap_or("Certificate");
            let raw_pem = args.get("certificate_pem").and_then(Value::as_str).unwrap_or("");
            let rep = pqcanary_core::scanner::composite_cert::CompositeCertValidator::audit_certificate(target, raw_pem);
            json!({
                "composite_report": rep,
                "markdown": pqcanary_core::scanner::composite_cert::CompositeCertValidator::format_markdown(&rep)
            })
        }

        "export_otel_cryptography" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let service = args.get("service_name").and_then(Value::as_str).unwrap_or("crypto-service");
            let endpoint = args.get("collector_endpoint").and_then(Value::as_str).unwrap_or("http://localhost:4318/v1/logs");
            match resolve_target_findings(path).await {
                Ok(findings) => {
                    let batch = pqcanary_core::scanner::otel_exporter::OtelCryptoExporter::export_from_findings(&findings, service, endpoint);
                    json!({
                        "otel_payload": batch,
                        "markdown": pqcanary_core::scanner::otel_exporter::OtelCryptoExporter::format_markdown(&batch)
                    })
                }
                Err(err) => err,
            }
        }

        "verify_constant_time_execution" => {
            let routine = args.get("routine_name").and_then(Value::as_str).unwrap_or("ML-KEM-768: NTT Polynomial Multiplication");
            let samples = args.get("sample_count").and_then(Value::as_u64).unwrap_or(10000) as usize;
            let rep = pqcanary_core::scanner::constant_time::ConstantTimeVerifier::audit_library(routine, samples);
            json!({
                "constant_time_report": rep,
                "markdown": pqcanary_core::scanner::constant_time::ConstantTimeVerifier::format_markdown(&rep)
            })
        }

        "attest_cbom_provenance" => {
            let cbom = args.get("cbom_json").and_then(Value::as_str).unwrap_or(r#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#);
            let project = args.get("project_name").and_then(Value::as_str).unwrap_or("production-workload");
            let signer = args.get("signer_identity").and_then(Value::as_str).unwrap_or("iqumnov@proton.me");
            let env = pqcanary_core::scanner::cbom_attest::CbomAttestor::attest_cbom(cbom, project, signer);
            json!({
                "attestation_envelope": env,
                "markdown": pqcanary_core::scanner::cbom_attest::CbomAttestor::format_markdown(&env)
            })
        }

        "audit_hbs_state" => {
            let target = args.get("target_name").and_then(Value::as_str).unwrap_or("hbs_config.json");
            let content = args.get("state_content").and_then(Value::as_str).unwrap_or("");
            let rep = pqcanary_core::scanner::hbs_state_auditor::HbsStateAuditor::audit_state_and_config(target, content);
            json!({
                "audit_report": rep,
                "markdown": pqcanary_core::scanner::hbs_state_auditor::HbsStateAuditor::format_markdown(&rep)
            })
        }

        "audit_vpn_tunnel" => {
            let target = args.get("target_name").and_then(Value::as_str).unwrap_or("wg0.conf");
            let content = args.get("config_content").and_then(Value::as_str).unwrap_or("");
            let rep = pqcanary_core::scanner::vpn_scanner::VpnScanner::audit_config(target, content);
            json!({
                "audit_report": rep,
                "markdown": pqcanary_core::scanner::vpn_scanner::VpnScanner::format_markdown(&rep)
            })
        }

        "plan_db_envelope_migration" => {
            let schema = args.get("schema_name").and_then(Value::as_str).unwrap_or("UserEntity.java");
            let content = args.get("source_content").and_then(Value::as_str).unwrap_or("");
            let plan = pqcanary_core::scanner::db_envelope_scanner::DbEnvelopeScanner::audit_schema_or_orm(schema, content);
            json!({
                "migration_plan": plan,
                "markdown": pqcanary_core::scanner::db_envelope_scanner::DbEnvelopeScanner::format_markdown(&plan)
            })
        }

        "watch_workspace_delta" => {
            let path = args.get("workspace_path").and_then(Value::as_str).unwrap_or(".");
            let safe_path = match pqcanary_core::api::validate_local_path(path) {
                Ok(p) => p,
                Err(err) => return json!({ "error": format!("{}: {}", err.vulnerability_class, err.description) }),
            };
            let mut snapshot = pqcanary_core::scanner::watcher::WorkspaceWatcher::initialize_snapshot(&safe_path);
            let findings = pqcanary_core::scanner::orchestrator::MasterOrchestrator::new(&safe_path).execute_full_scan();
            let delta = pqcanary_core::scanner::watcher::WorkspaceWatcher::evaluate_cycle(&mut snapshot, &findings);
            json!({
                "delta_report": delta,
                "markdown": pqcanary_core::scanner::watcher::WorkspaceWatcher::format_markdown(&delta)
            })
        }

        "audit_kerberos_pkinit" => {
            let realm = args.get("realm_name").and_then(Value::as_str).unwrap_or("krb5.conf");
            let content = args.get("krb5_conf_content").and_then(Value::as_str).unwrap_or("");
            let rep = pqcanary_core::scanner::kerberos_pkinit::KerberosPkinitAuditor::audit_config(realm, content);
            json!({
                "audit_report": rep,
                "markdown": pqcanary_core::scanner::kerberos_pkinit::KerberosPkinitAuditor::format_markdown(&rep)
            })
        }

        "patch_binary_import_table" => {
            let filename = args.get("filename").and_then(Value::as_str).unwrap_or("target.exe");
            let target_sym = args.get("target_symbol").and_then(Value::as_str).unwrap_or("RSA_generate_key_ex");
            let repl_sym = args.get("replacement_symbol").and_then(Value::as_str).unwrap_or("PQ_MLKEM768_keygen");
            let bytes = if let Some(hex_str) = args.get("binary_hex").and_then(Value::as_str) {
                let clean = hex_str.trim().replace("0x", "").replace(" ", "");
                (0..clean.len())
                    .step_by(2)
                    .filter_map(|i| if i + 2 <= clean.len() { u8::from_str_radix(&clean[i..i+2], 16).ok() } else { None })
                    .collect()
            } else if std::path::Path::new(filename).exists() {
                std::fs::read(filename).unwrap_or_else(|_| Vec::new())
            } else {
                Vec::new()
            };
            let (res, patched_bytes) = pqcanary_core::scanner::binary_patcher::BinaryPatcher::patch_binary(
                filename,
                &bytes,
                Some((target_sym, repl_sym))
            );
            json!({
                "patch_result": res,
                "patched_bytes_len": patched_bytes.len(),
                "markdown": pqcanary_core::scanner::binary_patcher::BinaryPatcher::format_markdown(&res)
            })
        }

        "interrogate_pkcs11_token" => {
            let path = args.get("driver_path_or_desc").and_then(Value::as_str).unwrap_or("/usr/lib/libCryptoki2_64.so");
            let content_str = args.get("content").and_then(Value::as_str).unwrap_or("");
            let data = if std::path::Path::new(path).exists() {
                std::fs::read(path).unwrap_or_else(|_| content_str.as_bytes().to_vec())
            } else {
                content_str.as_bytes().to_vec()
            };
            let rep = pqcanary_core::scanner::pkcs11_interrogator::Pkcs11Interrogator::interrogate_module(path, &data);
            json!({
                "interrogation_report": rep,
                "markdown": pqcanary_core::scanner::pkcs11_interrogator::Pkcs11Interrogator::format_markdown(&rep)
            })
        }

        "generate_cbom_datalake_schema" => {
            let repo = args.get("repository_id").and_then(Value::as_str).unwrap_or("enterprise-repo");
            let cbom = args.get("cbom_json").and_then(Value::as_str).unwrap_or(r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}"#);
            let plan = pqcanary_core::scanner::cbom_datalake::CbomDatalakeEngine::plan_datalake_integration(repo, cbom);
            json!({
                "datalake_plan": plan,
                "markdown": pqcanary_core::scanner::cbom_datalake::CbomDatalakeEngine::format_markdown(&plan)
            })
        }

        "profile_pqc_handshake_latency" => {
            let target = args.get("target_endpoint").and_then(Value::as_str).unwrap_or("api.internal:443");
            let samples = args.get("sample_count").and_then(Value::as_u64).unwrap_or(10) as usize;
            let rtt = args.get("base_rtt_ms").and_then(Value::as_f64).unwrap_or(25.0);
            let rep = pqcanary_core::scanner::pqc_latency_profiler::PqcLatencyProfiler::profile_endpoint(target, samples, Some(rtt));
            json!({
                "latency_profile": rep,
                "markdown": pqcanary_core::scanner::pqc_latency_profiler::PqcLatencyProfiler::format_markdown(&rep)
            })
        }

        "verify_binary_patch_equivalence" => {
            let orig_name = args.get("original_binary_name").and_then(Value::as_str).unwrap_or("app.exe");
            let patched_name = args.get("patched_binary_name").and_then(Value::as_str).unwrap_or("app_pqc.exe");

            let decode_hex = |s: &str| -> Vec<u8> {
                let clean = s.trim().replace("0x", "").replace(" ", "");
                (0..clean.len())
                    .step_by(2)
                    .filter_map(|i| if i + 2 <= clean.len() { u8::from_str_radix(&clean[i..i+2], 16).ok() } else { None })
                    .collect()
            };

            let orig_data = if let Some(hex_str) = args.get("original_binary_hex").and_then(Value::as_str) {
                decode_hex(hex_str)
            } else if std::path::Path::new(orig_name).exists() {
                std::fs::read(orig_name).unwrap_or_else(|_| Vec::new())
            } else {
                Vec::new()
            };

            let patched_data = if let Some(hex_str) = args.get("patched_binary_hex").and_then(Value::as_str) {
                decode_hex(hex_str)
            } else if std::path::Path::new(patched_name).exists() {
                std::fs::read(patched_name).unwrap_or_else(|_| Vec::new())
            } else {
                Vec::new()
            };

            let rep = pqcanary_core::scanner::binary_translation_validator::BinaryTranslationValidator::validate_translation(
                orig_name,
                &orig_data,
                patched_name,
                &patched_data,
            );

            json!({
                "validation_report": rep,
                "markdown": pqcanary_core::scanner::binary_translation_validator::BinaryTranslationValidator::format_markdown(&rep)
            })
        }

        "audit_dynamic_symbols" => {
            let target = args.get("target_name").and_then(Value::as_str).unwrap_or("code.c");
            let content = args.get("content").and_then(Value::as_str).unwrap_or("");
            let rep = pqcanary_core::scanner::dynamic_symbol_interceptor::DynamicSymbolInterceptor::audit_source(target, content);
            json!({
                "dynamic_symbols_report": rep,
                "markdown": pqcanary_core::scanner::dynamic_symbol_interceptor::DynamicSymbolInterceptor::format_markdown(&rep)
            })
        }

        "plan_post_quantum_acme_enrollment" => {
            let domain = args.get("domain").and_then(Value::as_str).unwrap_or("api.enterprise.internal");
            let algo = args.get("algorithm").and_then(Value::as_str).unwrap_or("ML-DSA-65");
            let dir = args.get("acme_directory").and_then(Value::as_str).unwrap_or("https://acme.enterprise.internal/directory");
            let challenge = args.get("challenge_type").and_then(Value::as_str).unwrap_or("dns-01");
            let plan = pqcanary_core::scanner::pqc_acme_enrollment::PqcAcmeEnrollmentEngine::plan_enrollment(domain, algo, dir, challenge);
            json!({
                "acme_plan": plan,
                "markdown": pqcanary_core::scanner::pqc_acme_enrollment::PqcAcmeEnrollmentEngine::format_markdown(&plan)
            })
        }

        "evaluate_qrng_min_entropy" => {
            let source = args.get("source_name").and_then(Value::as_str).unwrap_or("QRNG-Device");
            let hex_str = args.get("sample_hex").and_then(Value::as_str).unwrap_or("");
            let clean = hex_str.trim().replace("0x", "").replace(' ', "");
            let bytes: Vec<u8> = (0..clean.len())
                .step_by(2)
                .filter_map(|i| if i + 2 <= clean.len() { u8::from_str_radix(&clean[i..i+2], 16).ok() } else { None })
                .collect();
            let rep = pqcanary_core::scanner::qrng_entropy_evaluator::QrngEntropyEvaluator::evaluate_sample(source, &bytes);
            json!({
                "entropy_report": rep,
                "markdown": pqcanary_core::scanner::qrng_entropy_evaluator::QrngEntropyEvaluator::format_markdown(&rep)
            })
        }

        "attest_cmvp_fips140_firmware" => {
            let module = args.get("module_query").and_then(Value::as_str).unwrap_or("Luna");
            let fw = args.get("firmware_version").and_then(Value::as_str).unwrap_or("7.8.1");
            let rep = pqcanary_core::scanner::cmvp_firmware_registry::CmvpFirmwareRegistry::attest_module(module, fw);
            json!({
                "cmvp_report": rep,
                "markdown": pqcanary_core::scanner::cmvp_firmware_registry::CmvpFirmwareRegistry::format_markdown(&rep)
            })
        }

        "encode_kmip_wire_frame" => {
            let algo = args.get("algorithm").and_then(Value::as_str).unwrap_or("ML-KEM");
            let len = args.get("length_bits").and_then(Value::as_u64).unwrap_or(768) as u32;
            let wire = pqcanary_core::scanner::kmip_wire_protocol::KmipWireProtocol::encode_create_key_pair_request(algo, len);
            let rep = pqcanary_core::scanner::kmip_wire_protocol::KmipWireProtocol::decode_response_frame(&wire);
            json!({
                "kmip_result": rep,
                "markdown": pqcanary_core::scanner::kmip_wire_protocol::KmipWireProtocol::format_markdown(&rep)
            })
        }

        _ => json!({ "error": format!("Unknown tool: {}", name) }),
    }
}


// ─── MCP Auto-Install Config Generator ─────────────────────────────────────────

/// Prints the correct MCP configuration for the current binary path.
/// Supports Claude Desktop, Cursor, Windsurf, and any MCP-compatible client.
fn print_mcp_install_config() {
    let exe_path = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("pqcanary-mcp"));
    let exe_str = exe_path.to_string_lossy().replace('\\', "/");

    let config = serde_json::json!({
        "mcpServers": {
            "pqcanary": {
                "command": exe_str,
                "args": [],
                "env": {}
            }
        }
    });

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║          PQCanary MCP Auto-Install Configuration             ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    println!("Binary path detected: {}\n", exe_str);
    println!("Add the following to your MCP client configuration:\n");
    println!("  Claude Desktop: %APPDATA%\\Claude\\claude_desktop_config.json");
    println!("  Cursor:         %APPDATA%\\Cursor\\User\\mcp.json");
    println!("  Windsurf:       %APPDATA%\\Windsurf\\mcp.json");
    println!("  Antigravity:    %USERPROFILE%\\.gemini\\config\\mcp_config.json");
    println!("  Kiro AI:        %APPDATA%\\Kiro\\mcp.json");
    println!("  Roo Code:       %APPDATA%\\Code\\User\\globalStorage\\rooveteran.roo-cline\\settings\\cline_mcp_settings.json");
    println!("  OpenCode:       %APPDATA%\\opencode\\mcp.json");
    println!("  VS Code / Cline:%APPDATA%\\Code\\User\\globalStorage\\saoudrizwan.claude-dev\\settings\\cline_mcp_settings.json\n");
    println!("{}", serde_json::to_string_pretty(&config).unwrap_or_default());
    println!("\nOr install directly for your IDE / agent:");
    println!("  pqcanary-mcp --install-to antigravity");
    println!("  pqcanary-mcp --install-to kiro");
    println!("  pqcanary-mcp --install-to roocode");
    println!("  pqcanary-mcp --install-to opencode");
    println!("  pqcanary-mcp --install-to cursor");
    println!("  pqcanary-mcp --install-to windsurf");
    println!("  pqcanary-mcp --install-to claude-desktop\n");

}

/// Attempt to write MCP config directly to a known client config file.
fn install_to_client(target: &str) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Cannot determine binary path: {}", e))?;
    let exe_str = exe_path.to_string_lossy().replace('\\', "/");

    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string())
        .replace('\\', "/");

    let appdata = std::env::var("APPDATA")
        .unwrap_or_else(|_| format!("{}/.config", home))
        .replace('\\', "/");

    let config_paths: Vec<String> = match target.to_lowercase().as_str() {
        "codex" | "openai-codex" | "openai" => vec![


            format!("{}/.codex/mcp.json", home),
            format!("{}/OpenAI/Codex/mcp.json", appdata),
            format!("{}/Library/Application Support/OpenAI/Codex/mcp.json", home),
        ],
        "deepseek" => vec![
            format!("{}/DeepSeek/mcp.json", appdata),
            format!("{}/.config/deepseek/mcp.json", home),
            format!("{}/.deepseek/mcp.json", home),
        ],
        "trae" | "bytedance-trae" => vec![
            format!("{}/Trae/mcp.json", appdata),
            format!("{}/.config/trae/mcp.json", home),
            format!("{}/Library/Application Support/Trae/mcp.json", home),
        ],
        "qwen" | "qwen-agent" => vec![
            format!("{}/Qwen/mcp.json", appdata),
            format!("{}/.config/qwen/mcp.json", home),
            format!("{}/.qwen/mcp.json", home),
        ],
        "comate" | "baidu-comate" => vec![
            format!("{}/Comate/mcp.json", appdata),
            format!("{}/.config/comate/mcp.json", home),
            format!("{}/.comate/mcp.json", home),
        ],
        "lingma" | "alibaba-lingma" => vec![
            format!("{}/Lingma/mcp.json", appdata),
            format!("{}/.config/lingma/mcp.json", home),
            format!("{}/.lingma/mcp.json", home),
        ],
        "kimi" | "moonshot-kimi" | "moonshot" => vec![
            format!("{}/Kimi/mcp.json", appdata),
            format!("{}/.config/kimi/mcp.json", home),
            format!("{}/.kimi/mcp.json", home),
        ],
        "codegeex" => vec![
            format!("{}/CodeGeeX/mcp.json", appdata),
            format!("{}/.config/codegeex/mcp.json", home),
        ],
        "codeium" => vec![
            format!("{}/Codeium/mcp.json", appdata),
            format!("{}/.config/codeium/mcp.json", home),
        ],
        "continue" | "continue-dev" => vec![
            format!("{}/.continue/config.json", home),
        ],
        "claude-desktop" | "claude" => vec![
            format!("{}/Claude/claude_desktop_config.json", appdata),
            format!("{}/Library/Application Support/Claude/claude_desktop_config.json", home),
            format!("{}/.config/Claude/claude_desktop_config.json", home),
        ],
        "cursor" => vec![
            format!("{}/Cursor/User/mcp.json", appdata),
            format!("{}/.config/Cursor/User/mcp.json", home),
            format!("{}/Library/Application Support/Cursor/User/mcp.json", home),
        ],
        "windsurf" => vec![
            format!("{}/Windsurf/mcp.json", appdata),
            format!("{}/.config/Windsurf/mcp.json", home),
            format!("{}/Library/Application Support/Windsurf/mcp.json", home),
        ],
        "antigravity" | "gemini" => vec![
            format!("{}/.gemini/config/mcp_config.json", home),
        ],
        "kiro" => vec![
            format!("{}/Kiro/mcp.json", appdata),
            format!("{}/.config/kiro/mcp.json", home),
        ],
        "roocode" | "roo" | "roo-cline" => vec![
            format!("{}/Code/User/globalStorage/rooveteran.roo-cline/settings/cline_mcp_settings.json", appdata),
            format!("{}/Library/Application Support/Code/User/globalStorage/rooveteran.roo-cline/settings/cline_mcp_settings.json", home),
            format!("{}/.config/Code/User/globalStorage/rooveteran.roo-cline/settings/cline_mcp_settings.json", home),
        ],
        "opencode" => vec![
            format!("{}/opencode/mcp.json", appdata),
            format!("{}/.config/opencode/mcp.json", home),
        ],
        "cline" | "vscode" => vec![
            format!("{}/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", appdata),
            format!("{}/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", home),
        ],
        _ => return Err(format!(
            "Unknown client target '{}'. Supported targets: codex, deepseek, trae, qwen, comate, lingma, kimi, codegeex, codeium, continue, antigravity, kiro, roocode, opencode, cursor, windsurf, claude-desktop, cline, vscode",
            target
        )),
    };


    let mut installed_any = false;

    for config_path in config_paths {
        let path = std::path::Path::new(&config_path);

        // Read existing config if present
        let mut existing: serde_json::Value = if path.exists() {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        // Merge pqcanary server entry into mcpServers object
        if existing.get("mcpServers").is_none() {
            existing["mcpServers"] = serde_json::json!({});
        }
        existing["mcpServers"]["pqcanary"] = serde_json::json!({
            "command": exe_str,
            "args": [],
            "env": {}
        });

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if std::fs::write(path, serde_json::to_string_pretty(&existing).unwrap_or_default()).is_ok() {
            println!("OK: PQCanary MCP server registered in: {}", config_path);
            installed_any = true;
        }
    }

    if installed_any {
        println!("   Restart {} to activate.", target);
        Ok(())
    } else {
        Err(format!("Could not write configuration for target '{}'. Ensure directory permissions are correct.", target))
    }
}


// ─── Main Server Loop ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Handle --install / --install-to <client> flags before starting the MCP loop
    if args.len() > 1 {
        match args[1].as_str() {
            "--install" | "-i" => {
                print_mcp_install_config();
                return;
            }
            "--install-to" if args.len() > 2 => {
                if let Err(e) = install_to_client(&args[2]) {
                    eprintln!("pqcanary-mcp: Install error: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "--help" | "-h" => {
                println!("pqcanary-mcp — PQCanary Universal MCP Server");
                println!("Usage:");
                println!("  pqcanary-mcp                               Start MCP server (stdio JSON-RPC 2.0)");
                println!("  pqcanary-mcp --install                     Print MCP JSON config for auto-detected path");
                println!("  pqcanary-mcp --install-to antigravity      Register in Antigravity IDE");
                println!("  pqcanary-mcp --install-to kiro             Register in Kiro AI Editor");
                println!("  pqcanary-mcp --install-to roocode          Register in Roo Code (VS Code)");
                println!("  pqcanary-mcp --install-to opencode         Register in OpenCode Interpreter");
                println!("  pqcanary-mcp --install-to cursor           Register in Cursor IDE");
                println!("  pqcanary-mcp --install-to windsurf         Register in Windsurf Editor");
                println!("  pqcanary-mcp --install-to claude-desktop   Register in Claude Desktop");
                return;
            }

            _ => {}
        }
    }

    eprintln!("pqcanary-mcp: PQCanary MCP Server v0.1.0 starting on stdio");
    eprintln!("pqcanary-mcp: Waiting for JSON-RPC 2.0 requests on stdin...");

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(e) => {
                eprintln!("pqcanary-mcp: stdin read error: {}", e);
                break;
            }
        };

        eprintln!("pqcanary-mcp: Received: {}", &line[..line.len().min(200)]);

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err_response = JsonRpcResponse::err(
                    Value::Null,
                    -32700,
                    format!("Parse error: {}", e),
                );
                let _ = writeln!(stdout, "{}", serde_json::to_string(&err_response).unwrap_or_default());
                let _ = stdout.flush();
                continue;
            }
        };

        let id = request.id.clone().unwrap_or(Value::Null);
        let response = match request.method.as_str() {
            // ── MCP Lifecycle ─────────────────────────────────────────────────
            "initialize" => {
                JsonRpcResponse::ok(id, json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "pqcanary",
                        "version": "0.1.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }))
            }

            "notifications/initialized" => {
                // Client ack — no response needed (notification)
                continue;
            }

            // ── MCP Tool Discovery ────────────────────────────────────────────
            "tools/list" => {
                JsonRpcResponse::ok(id, tool_list())
            }

            // ── MCP Tool Invocation ───────────────────────────────────────────
            "tools/call" => {
                let params = request.params.as_ref().unwrap_or(&Value::Null);
                let tool_name = params.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let tool_args = params.get("arguments").unwrap_or(&Value::Null);

                eprintln!("pqcanary-mcp: Calling tool: {}", tool_name);
                let result = dispatch_tool(tool_name, tool_args).await;

                JsonRpcResponse::ok(id, json!({
                    "content": [
                        {
                            "type": "text",
                            "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                        }
                    ]
                }))
            }

            // ── Unknown method ────────────────────────────────────────────────
            other => {
                eprintln!("pqcanary-mcp: Unknown method: {}", other);
                JsonRpcResponse::err(id, -32601, format!("Method not found: {}", other))
            }
        };

        let response_str = serde_json::to_string(&response).unwrap_or_default();
        eprintln!("pqcanary-mcp: Sending response ({}B)", response_str.len());
        let _ = writeln!(stdout, "{}", response_str);
        let _ = stdout.flush();
    }

    eprintln!("pqcanary-mcp: stdin closed, shutting down.");
}
