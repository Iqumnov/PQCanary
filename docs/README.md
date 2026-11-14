# PQCanary Documentation Portal

Welcome to the technical documentation for PQCanary, an enterprise post-quantum cryptographic security, audit, and verification platform.

PQCanary provides automated discovery, formal mathematical verification, and remediation of classical and post-quantum cryptographic assets across source code, compiled binaries, network endpoints, cloud key management systems, and runtime environments.

---

## Documentation Organization

The documentation follows the Diataxis information architecture framework, dividing material into four distinct categories based on user needs:

```
docs/
|-- README.md                         # Documentation index and navigation portal
|-- getting-started/
|   |-- installation.md               # Build instructions, dependencies, and packages
|   `-- quickstart.md                 # Initial scan, interpreting findings, and reports
|-- architecture/
|   |-- system-architecture.md        # Multi-engine pipeline and data flow
|   |-- web-vs-native-limitations.md  # Web (WASM/Cloudflare) vs Native CLI boundary
|   |-- pqmesh-protocol.md            # Distributed cross-medium synchronization bus
|   `-- security-and-threat-model.md  # Air-gap guarantees and security controls
|-- engines/
|   |-- ast-and-pattern-matching.md   # Tree-sitter parsing and rule catalog
|   |-- concolic-symbolic-execution.md# SSA lifting and Z3 SMT constraint solving
|   |-- formal-verification-hott.md   # Homotopy Type Theory and Lean 4 proofs
|   |-- thermodynamics-and-hardware.md# Landauer dissipation and side-channel analysis
|   |-- physics-and-astrophysics.md   # Relativistic causality and pulsar clock sync
|   `-- cryptographic-standards.md    # NIST FIPS 203/204/205/206 and CNSA 2.0 mapping
|-- reference/
|   |-- cli-reference.md              # Complete CLI command and flag manual
|   |-- configuration-schema.md       # .pqcanary.yaml and pqcanary.toml specification
|   |-- rest-api-and-metrics.md       # REST endpoints and Prometheus metrics
|   |-- mcp-specification.md          # Model Context Protocol tools and schemas
|   `-- cbom-and-sarif.md             # CycloneDX 1.6 and OASIS SARIF 2.1.0 schemas
`-- guides/
    |-- ci-cd-pipelines.md            # Integration with GitHub Actions, GitLab, and Azure
    |-- cloud-kms-auditing.md         # AWS KMS, Azure Key Vault, GCP KMS, and Terraform
    |-- remediation-and-patching.md   # Automated code patching and pull requests
    `-- active-network-probing.md     # TLS 1.3 and SSH 2.0 live handshake probes
```

---

## Section Summaries

### 1. Getting Started
Designed for new operators and evaluators:
- [Installation Guide](getting-started/installation.md): Prerequisites, native compilation, containerized deployments, WebAssembly targets, and IDE extensions.
- [Quickstart Guide](getting-started/quickstart.md): Running an initial local repository audit, generating compliance reports, and evaluating results in five minutes.

### 2. Architecture
In-depth technical explanations of system internals:
- [System Architecture](architecture/system-architecture.md): Concurrency model, memory isolation, pipeline orchestration, and language runtime support.
- [PQMesh Distributed Fleet Protocol](architecture/pqmesh-protocol.md): Cross-medium communication bus connecting CLI, IDE, Browser, Kubernetes, and AI agent nodes.
- [Security and Threat Model](architecture/security-and-threat-model.md): Memory safety invariants, strict offline air-gap controls, and SSRF prevention mechanisms.

### 3. Analysis Engines
Detailed mathematical and algorithmic specifications of the core inspection engines:
- [AST Traversal and Pattern Matching](engines/ast-and-pattern-matching.md): Multi-language Tree-sitter concrete syntax tree evaluation and pattern rules.
- [Concolic Execution and SMT Solving](engines/concolic-symbolic-execution.md): SSA intermediate representation lifting, symbolic memory models, and Z3 constraint generation.
- [Formal Verification via Homotopy Type Theory](engines/formal-verification-hott.md): Lean 4 proof synthesis, categorical equivalence, and mathematical safety certificates.
- [Thermodynamic Modeling and Hardware Diagnostics](engines/thermodynamics-and-hardware.md): Landauer limit heat dissipation calculations, CPA/DFA fault injection, and trace alignment.
- [Relativistic Causality and Pulsar Synchronization](engines/physics-and-astrophysics.md): WGS-84 Vincenty geodesic light-cone bounds and ATNF radio pulsar timing verification.
- [Post-Quantum Standards Mapping](engines/cryptographic-standards.md): NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 (Falcon), and CNSA 2.0 timelines.

### 4. Technical Reference
Comprehensive specifications and syntax references:
- [CLI Reference Manual](reference/cli-reference.md): Detailed parameter lists, subcommands, exit codes, and environment variables.
- [Configuration Schema](reference/configuration-schema.md): Complete declarative syntax for `.pqcanary.yaml` and `pqcanary.toml`.
- [REST API and Prometheus Metrics](reference/rest-api-and-metrics.md): Daemon endpoints, request/response models, and OpenMetrics exposition format.
- [Model Context Protocol Specification](reference/mcp-specification.md): Native tool interfaces for integration with autonomous LLM development agents.
- [CBOM and SARIF Data Formats](reference/cbom-and-sarif.md): CycloneDX 1.6 Cryptographic Bill of Materials and OASIS SARIF 2.1.0 output structures.

### 5. Practical How-To Guides
Step-by-step instructions for specific production use cases:
- [CI/CD Pipeline Integration](guides/ci-cd-pipelines.md): Automated quality gates, baseline comparison workflows, and GitHub Code Scanning alerts.
- [Cloud KMS and Infrastructure Auditing](guides/cloud-kms-auditing.md): Inspecting AWS KMS, Azure Key Vault, Google Cloud KMS, and Terraform HCL scripts.
- [Automated Remediation and Patching](guides/remediation-and-patching.md): Applying semantic replacements and generating automated Git pull requests.
- [Active Network Probing](guides/active-network-probing.md): Direct binary probing of TLS 1.3 hybrid key exchange and SSH 2.0 KEX negotiation.

---

## Additional Resources

- [Root Project README](../README.md): High-level project summary and quick orientation.
- [Contribution Guidelines](../CONTRIBUTING.md): Coding conventions, testing protocols, and pull request procedures.
- [Security Policy](../SECURITY.md): Vulnerability disclosure process and confidentiality guarantees.
- [License](../LICENSE): Apache License, Version 2.0 terms and copyright notices.
