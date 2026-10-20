import { createSignal, For, Show } from "solid-js";

export interface LandingPageProps {
  isDarkMode: boolean;
  onLaunchApp: () => void;
  themeCloudyGlassStyle: () => Record<string, any>;
  themeTextColor: () => string;
  themeSubTextColor: () => string;
  themeSidebarCardStyle: () => Record<string, any>;
}

type DocCategory = "getting-started" | "mediums" | "engines" | "reference" | "guides";

interface SubDoc {
  id: string;
  title: string;
  badge?: string;
  summary: string;
  content: {
    heading: string;
    description: string;
    codeSnippet?: {
      lang: string;
      code: string;
    };
    tableData?: {
      headers: string[];
      rows: string[][];
    };
    bulletPoints?: string[];
    note?: string;
  }[];
}

export function LandingPage(props: LandingPageProps) {
  const [activeCategory, setActiveCategory] = createSignal<DocCategory>("getting-started");
  const [activeSubDocId, setActiveSubDocId] = createSignal<string>("installation");
  const [copiedSnippet, setCopiedSnippet] = createSignal<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedSnippet(id);
      setTimeout(() => {
        setCopiedSnippet(null);
      }, 2000);
    }
  };

  const categories: { id: DocCategory; label: string; desc: string }[] = [
    { id: "getting-started", label: "Getting Started", desc: "Pre-built installers, build targets, initial audits & compliance grading" },
    { id: "mediums", label: "Operational Mediums", desc: "CLI, Web WASM, Desktop Tauri, IDEs, MCP Server, Kubernetes & Network Probes" },
    { id: "engines", label: "Analysis Engines", desc: "Tree-sitter AST, Z3 Concolic SMT, HoTT Lean 4, Landauer thermodynamics & HNDL" },
    { id: "reference", label: "Technical Reference", desc: "CLI flags, configuration schema, MCP tool catalog & REST daemon specification" },
    { id: "guides", label: "Guides & Playbooks", desc: "CI/CD quality gates, Cloud KMS auditing, active probing & automated code patches" },
  ];

  const docsData: Record<DocCategory, SubDoc[]> = {
    "getting-started": [
      {
        id: "installation",
        title: "Installation, Binaries & Installers",
        badge: "v1.0.0",
        summary: "Pre-compiled desktop installers (MSI, EXE, DEB, AppImage, APK), Cargo package manager, and container deployments.",
        content: [
          {
            heading: "Pre-Built Release Installers (GitHub Releases)",
            description: "PQCanary automatically builds and packages official pre-compiled native releases for all supported operating systems on every GitHub release tag:",
            tableData: {
              headers: ["Operating System", "Package / Installer Type", "Filename", "Installation Method"],
              rows: [
                ["Windows 10/11 x64", "Windows Installer (MSI)", "pqcanary-setup.msi", "Standard Windows MSI Installer wizard"],
                ["Windows 10/11 x64", "NSIS Setup Executable", "pqcanary-setup.exe", "Standalone NSIS installer with PATH auto-configuration"],
                ["Windows 10/11 x64", "Standalone CLI Executable", "pqcanary.exe", "Extract and run directly from PowerShell / CMD"],
                ["Linux (Debian / Ubuntu)", "Debian Package (.deb)", "pqcanary_amd64.deb", "sudo dpkg -i pqcanary_amd64.deb"],
                ["Linux (All Distributions)", "Standalone AppImage", "pqcanary.AppImage", "chmod +x pqcanary.AppImage && ./pqcanary.AppImage"],
                ["Linux (All Distributions)", "Standalone CLI Binary", "pqcanary (ELF)", "Extract and move to /usr/local/bin/pqcanary"],
                ["macOS (Apple Silicon & Intel)", "Apple Disk Image (.dmg)", "PQCanary.dmg", "Drag and drop to /Applications"],
                ["Android (Mobile / Tablet)", "Release APK", "pqcanary-release.apk", "Install via adb install or standard Android package installer"]
              ]
            }
          },
          {
            heading: "Rust Toolchain & Cargo Installation",
            description: "If you have a Rust development environment (1.80.0+), install the CLI and MCP server directly via Cargo:",
            codeSnippet: {
              lang: "bash",
              code: `# Install CLI scanner and Model Context Protocol daemon
cargo install pqcanary-cli --bin pqcanary --bin pqcanary-mcp

# Verify installation
pqcanary --version
pqcanary-mcp --help`
            }
          },
          {
            heading: "Building from Source (Standard Cargo)",
            description: "Clone the official repository and compile the workspace binaries in optimized release mode:",
            codeSnippet: {
              lang: "bash",
              code: `git clone https://github.com/Iqumnov/PQCanary.git
cd PQCanary

# Compile workspace binaries in release mode
cargo build --release --workspace

# Install CLI binary into user PATH
cargo install --path cli --bin pqcanary

# Verify installation
pqcanary --version`
            }
          },
          {
            heading: "IDE Extension Installation (VS Code, Cursor, Windsurf)",
            description: "Install the real-time developer workspace extension directly from the Visual Studio Marketplace or Open VSX Registry:",
            codeSnippet: {
              lang: "bash",
              code: `# Install via VS Code command-line interface
code --install-extension pqcanary.pqcanary-vscode

# Or install from local .vsix package
code --install-extension extensions/vscode/pqcanary-1.0.0.vsix`
            }
          },
          {
            heading: "AI Agent Registration (Model Context Protocol - MCP)",
            description: "Register the native pqcanary-mcp binary with your AI assistant (Claude Desktop, Cursor, Antigravity):",
            codeSnippet: {
              lang: "json",
              code: `{
  "mcpServers": {
    "pqcanary": {
      "command": "pqcanary-mcp",
      "args": ["--strict-nist"]
    }
  }
}`
            }
          },
          {
            heading: "Client-Side WebAssembly (WASM) Compilation",
            description: "PQCanary core compiles directly to WebAssembly using wasm-pack, executing completely inside the browser sandbox with zero network data egress:",
            codeSnippet: {
              lang: "bash",
              code: `# Ensure wasm32-unknown-unknown target is installed
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build the WebAssembly package for web targets
cd core
wasm-pack build --target web --out-dir ../web/public/wasm`
            }
          },
          {
            heading: "Containerized OCI Execution",
            description: "Run PQCanary in an isolated, lightweight container for headless scanning:",
            codeSnippet: {
              lang: "bash",
              code: `# Build minimal container image
docker build -t pqcanary/scanner .

# Scan current directory with local volume mount
docker run --rm -v $(pwd):/workspace pqcanary/scanner scan /workspace`
            }
          }
        ]
      },
      {
        id: "quickstart",
        title: "Quickstart & Workflow Overview",
        badge: "5 Min",
        summary: "Running an initial repository audit, interpreting security health grades, and exporting compliance reports.",
        content: [
          {
            heading: "Running Your First Audit",
            description: "Audit any directory, source code file, compiled binary, certificate, or cryptographic artifact:",
            codeSnippet: {
              lang: "bash",
              code: `# Scan current directory with automated engine selection
pqcanary scan .

# Run strict NIST FIPS 203/204 compliance check
pqcanary scan . --strict-nist --min-severity MEDIUM

# Generate standardized CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)
pqcanary cbom . --output ./cbom.json

# Audit against a baseline to fail only on new cryptographic regressions
pqcanary scan . --baseline baseline.json --fail-on-new`
            }
          },
          {
            heading: "Cryptographic Health Verdict Matrix",
            description: "PQCanary computes a holistic cryptographic posture grade based on identified algorithms, key sizes, and forward security:",
            tableData: {
              headers: ["Grade", "Posture Status", "Cryptographic Profile"],
              rows: [
                ["A+", "Quantum Resilient", "Standardized NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) active; forward-secure against HNDL attacks."],
                ["A", "Clean Posture", "Clean source code with verified post-quantum safe primitives or zero cryptographic attack surface."],
                ["B", "Migration In Progress", "Hybrid post-quantum key exchange (e.g. X25519-MLKEM768) enabled alongside classical primitives."],
                ["C", "Legacy Cryptography", "Classical public-key cryptography (RSA-2048/4096, ECDSA, ECDH) present without post-quantum fallback."],
                ["F", "Critical Exposure", "Deprecated algorithms (MD5, SHA-1, DES, 3DES, RC4, RSA-1024, ECB mode) with immediate classical and quantum risk."],
                ["N/A", "Non-Cryptographic", "Non-cryptographic code, plain text, or general documentation without cryptographic footprint."]
              ]
            }
          },
          {
            heading: "Universal Input Architecture",
            description: "The web scanner interface accepts any cryptographic input directly in the central input box: paste source code snippets, file paths, PEM certificates, JSON payloads, or drop binary files.",
            note: "All browser scanning is powered by client-side WebAssembly: your private keys, source code, and certificates never leave your machine."
          }
        ]
      }
    ],
    "mediums": [
      {
        id: "medium-overview",
        title: "The 10 Operational Mediums",
        badge: "Architecture",
        summary: "Overview of all 10 deployment mediums through which PQCanary delivers enterprise post-quantum intelligence.",
        content: [
          {
            heading: "Cross-Medium Deployment Architecture",
            description: "PQCanary is architected as a modular cryptographic platform operating seamlessly across 10 distinct operational mediums to provide continuous protection across the entire software development lifecycle:",
            tableData: {
              headers: ["#", "Operational Medium", "Primary Purpose", "Protocol / Artifact"],
              rows: [
                ["1", "Native CLI", "Developer workstations and automation scripts", "Terminal UI, SARIF, CBOM, CSV, HTML"],
                ["2", "Web Browser WASM", "100% private in-browser code and binary analysis", "Client-side WebAssembly, zero data egress"],
                ["3", "Desktop Tauri GUI", "Standalone native desktop application", "Native window for Linux, macOS, and Windows"],
                ["4", "IDE Extensions", "Real-time editor diagnostics and code actions", "VS Code Extension, Cursor, Windsurf, Neovim LSP"],
                ["5", "Stdio MCP Server", "Autonomous AI coding agent integration", "Model Context Protocol JSON-RPC 2.0 (`pqcanary-mcp`)"],
                ["6", "Cloud & Kubernetes", "In-cluster daemon and admission control", "DaemonSet volume auditor, Admission Webhook"],
                ["7", "Docker Containers", "Reproducible containerized scanning", "OCI-compliant minimal multi-stage image"],
                ["8", "GitHub Actions & CI", "Automated pull request compliance gate", "SARIF upload to GitHub Security Code Scanning tab"],
                ["9", "PQMesh Fleet Gossip", "Decentralized fleet-wide intelligence bus", "P2P WebSockets, WebRTC, and Unix domain sockets"],
                ["10", "Active Network Probing", "Non-invasive live endpoint handshake audit", "Direct TLS 1.3 ClientHello & SSH 2.0 KEX negotiation"]
              ]
            }
          }
        ]
      },
      {
        id: "cli-wasm-desktop",
        title: "CLI, Web WASM & Desktop Tauri",
        badge: "Clients",
        summary: "Detailed operations for local workstations, client-side browser execution, and native desktop installations.",
        content: [
          {
            heading: "Medium 1: Native Terminal CLI",
            description: "The high-performance command-line interface provides fast parallel AST audits, binary inspection, and pipeline automation:",
            codeSnippet: {
              lang: "bash",
              code: `# Recursive repository scan with SARIF output
pqcanary scan /path/to/project --format sarif -o report.sarif

# Enforce strict NIST compliance and exit with non-zero code on failure
pqcanary scan . --strict-nist --fail-on-new`
            }
          },
          {
            heading: "Medium 2: Client-Side WebAssembly (WASM)",
            description: "The web scanner runs PQCanary core compiled to wasm32-unknown-unknown. It operates with strict zero-telemetry: all syntax parsing, concolic checks, and report generation take place within the browser's isolated memory sandbox.",
            bulletPoints: [
              "Drag-and-drop support for directories, individual source files, and compiled binaries",
              "Instantaneous offline evaluation with zero server roundtrips",
              "In-browser generation of CycloneDX 1.6 CBOM, SARIF, and PDF compliance reports"
            ]
          },
          {
            heading: "Medium 3: Desktop Tauri GUI",
            description: "A lightweight cross-platform desktop application wrapping the web dashboard with native OS bindings via Tauri. Provides system file dialogs, background directory watchers, and local socket endpoints."
          }
        ]
      },
      {
        id: "ide-mcp-ai",
        title: "IDE Extensions & Stdio MCP Server",
        badge: "Developer Tools",
        summary: "Real-time editor feedback in VS Code/Cursor and native Model Context Protocol integration for AI coding assistants.",
        content: [
          {
            heading: "Medium 4: IDE Extensions (VS Code, Cursor, Neovim)",
            description: "The PQCanary IDE extension monitors active editor buffers in real time, highlighting quantum-vulnerable cryptography with inline diagnostics and providing QuickFix code actions to automatically modernize code.",
            bulletPoints: [
              "Diagnostic squiggles indicating quantum risk level (Critical, High, Medium)",
              "Hover tooltips displaying NIST FIPS 203/204 migration guidance and OID specifications",
              "One-click QuickFix code actions to replace legacy algorithms with post-quantum alternatives"
            ]
          },
          {
            heading: "Medium 5: Model Context Protocol (MCP) Server",
            description: "PQCanary provides a native Model Context Protocol (MCP) server over standard input/output (stdio), exposing standardized tools to AI coding agents like Claude, Gemini, Cursor, and Antigravity:",
            codeSnippet: {
              lang: "json",
              code: `{
  "mcpServers": {
    "pqcanary": {
      "command": "pqcanary-mcp",
      "args": ["--strict-nist"]
    }
  }
}`
            },
            bulletPoints: [
              "scan_repository: Audits workspace directories and returns structured findings",
              "audit_snippet: Performs in-memory AST and concolic checks on code snippets",
              "generate_cbom: Returns standardized CycloneDX 1.6 Cryptographic Bills of Materials",
              "generate_patch: Synthesizes unified git diffs modernizing vulnerable implementations"
            ]
          }
        ]
      },
      {
        id: "cloud-mesh-probe",
        title: "Cloud, Fleet Mesh & Network Probing",
        badge: "Infrastructure",
        summary: "Kubernetes cluster scanning, decentralized fleet synchronization, and live TLS/SSH protocol probing.",
        content: [
          {
            heading: "Medium 6 & 7: Kubernetes & Containerized Daemons",
            description: "PQCanary deploys in Kubernetes clusters as a DaemonSet to audit container image layers and persistent storage volumes, and as a ValidatingWebhookAdmissionController to reject deployments containing legacy cryptography.",
            codeSnippet: {
              lang: "yaml",
              code: `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: pqcanary-fleet-auditor
spec:
  template:
    spec:
      containers:
        - name: auditor
          image: pqcanary/scanner:latest
          args: ["mesh", "start", "--coordinator", "wss://mesh.internal:7890"]`
            }
          },
          {
            heading: "Medium 8: GitHub Actions & CI/CD Pipelines",
            description: "Integrate automated post-quantum pull request gates into CI/CD workflows, uploading SARIF alerts directly to GitHub Code Scanning.",
            codeSnippet: {
              lang: "yaml",
              code: `- uses: actions/checkout@v4
- name: Run PQCanary Post-Quantum Audit
  run: pqcanary scan . --strict-nist --format sarif -o results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif`
            }
          },
          {
            heading: "Medium 9: PQMesh Distributed Fleet Protocol",
            description: "A decentralized peer-to-peer gossip protocol coordinating cryptographic health across thousands of endpoints. Scanners stream finding fingerprints to local aggregators, computing real-time organizational QRAMM readiness scores."
          },
          {
            heading: "Medium 10: Active Network Probing",
            description: "Audits live network endpoints without invasive host agents by negotiating raw protocol handshakes:",
            bulletPoints: [
              "TLS 1.3 Probing: Synthesizes ClientHello with ML-KEM-768 / X25519MLKEM768 KeyShare extensions to test server support",
              "SSH 2.0 Probing: Inspects SSH_MSG_KEXINIT packets to detect sntrup761x25519-sha512@openssh.com and ML-KEM key exchange algorithms"
            ]
          }
        ]
      }
    ],
    "engines": [
      {
        id: "ast-concolic",
        title: "AST Tree-Sitter & Z3 Concolic SMT",
        badge: "Engines 1 & 2",
        summary: "Multi-language concrete syntax tree inspection and formal concolic constraint solving.",
        content: [
          {
            heading: "Engine 1: Multi-Language Concrete Syntax Tree (Tree-sitter)",
            description: "Unlike naive regex scanners that produce false positives, PQCanary parses source files into full syntax trees across 8 languages (Rust, TypeScript/JavaScript, Python, Go, Java, C, C++, Solidity) and matches 193+ detection rules across 22 cryptographic domains.",
            codeSnippet: {
              lang: "rust",
              code: `// Detection rule pattern: Flags classical RSA key pair generation
// Category: PQC_KEY_EXCHANGE | Severity: CRITICAL | Quantum Risk: VULNERABLE
let rsa_key = Rsa::generate(2048)?; // FLAGGED: Quantum vulnerable to Shor's algorithm
// Remediation: Replace with NIST FIPS 203 ML-KEM-768 or hybrid X25519-MLKEM768`
            }
          },
          {
            heading: "Engine 2: Concolic Symbolic Execution (Z3 SMT Solver)",
            description: "Lifts cryptographic decision logic to Static Single Assignment (SSA) form and generates first-order mathematical constraints. Microsoft Z3 mathematically solves whether classical fallback branches or insecure cipher suite negotiations can ever be executed.",
            bulletPoints: [
              "Proves absence of downgrade attacks in TLS handshake negotiation logic",
              "Validates symbolic memory boundaries to prevent buffer overruns in lattice implementations",
              "Identifies dead-code post-quantum paths that can never be reached during execution"
            ]
          }
        ]
      },
      {
        id: "hott-thermo-physics",
        title: "HoTT Proofs, Thermodynamics & Causality",
        badge: "Engines 3, 4 & 5",
        summary: "Lean 4 machine-checked proofs, Landauer thermal dissipation bounds, and relativistic causality synchronization.",
        content: [
          {
            heading: "Engine 3: Homotopy Type Theory (HoTT) & Lean 4 Proof Synthesis",
            description: "For mission-critical deployments, PQCanary synthesizes machine-checked Lean 4 formal proofs demonstrating that post-quantum implementations conform to NIST specifications and preserve IND-CPA security properties.",
            bulletPoints: [
              "Applies the Univalence Axiom to prove algorithm equivalence between reference and optimized implementations",
              "Constructs higher inductive types modeling cryptographic state machines",
              "Exports verified .lean theorem files for independent third-party mathematical audit"
            ]
          },
          {
            heading: "Engine 4: Landauer Thermodynamic Modeling & Side-Channel Analysis",
            description: "Computes fundamental thermodynamic dissipation bounds (E >= k_B * T * ln(2) per bit erasure) to measure entropy leakage. Evaluates hardware resilience against Differential Power Analysis (DPA) and Correlation Power Analysis (CPA)."
          },
          {
            heading: "Engine 5: Relativistic Light-Cone Causality & ATNF Pulsar Clocks",
            description: "Validates network handshake round-trip times against WGS-84 Vincenty geodesic light propagation bounds. Anchors verification timestamps to Australia Telescope National Facility (ATNF) radio pulsar timing arrays to guarantee tamper-proof audit trails."
          }
        ]
      },
      {
        id: "binary-runtime-hndl",
        title: "Binary Analysis, Host Auditing & HNDL Risk",
        badge: "Engines 6, 7 & 8",
        summary: "Goblin disassembler for ELF/PE/Mach-O binaries, live OS process memory inspection, and Mosca's HNDL theorem.",
        content: [
          {
            heading: "Engine 6: Binary Disassembly & Reverse Engineering",
            description: "Parses compiled ELF, PE, and Mach-O executables using Goblin and object parsers. Extracts cryptographic constants, imported symbols, and static key tables directly from compiled binaries without requiring source code access."
          },
          {
            heading: "Engine 7: Host OS & Live Runtime Process Memory Auditing",
            description: "Inspects operating system cryptographic providers (Windows CNG/Schannel, Linux OpenSSL/BoringSSL, macOS Security framework) and audits live runtime process memory to identify active in-memory cryptographic handles."
          },
          {
            heading: "Engine 8: Harvest Now, Decrypt Later (HNDL) Risk Modeling",
            description: "Applies Mosca's Theorem (X + Y > Z) to calculate immediate quantum vulnerability: migration timeline (X), data confidentiality shelf-life (Y), and the estimated arrival of Cryptanalytically Relevant Quantum Computers (Z).",
            bulletPoints: [
              "If X + Y > Z: Systems are in critical danger today from adversary data harvesting",
              "Calculates required migration velocity to achieve complete post-quantum posture before CRQC horizon"
            ]
          }
        ]
      },
      {
        id: "qramm-cbom-patch",
        title: "QRAMM Maturity, CBOM & Code Patching",
        badge: "Engines 9 & 10",
        summary: "5-dimension migration scorecard, CycloneDX 1.6 Cryptographic Bill of Materials, and automated unified diff synthesis.",
        content: [
          {
            heading: "Engine 9: Quantum Risk Assessment & Maturity Model (QRAMM)",
            description: "Evaluates enterprise post-quantum readiness across 5 core operational dimensions:",
            tableData: {
              headers: ["Dimension", "Score Range", "Evaluation Focus"],
              rows: [
                ["Discovery", "0 - 100%", "Completeness of cryptographic asset identification across repositories"],
                ["Inventory", "0 - 100%", "Standardized CBOM tracking of keys, algorithms, certificates, and libraries"],
                ["Agility", "0 - 100%", "Ability to replace cryptographic primitives without breaking application architecture"],
                ["Governance", "0 - 100%", "Enforcement of NIST FIPS 203/204 policies and CI/CD quality gates"],
                ["Migration", "0 - 100%", "Progress toward active deployment of ML-KEM, ML-DSA, and SLH-DSA"]
              ]
            }
          },
          {
            heading: "Engine 10: Standardized CBOM, SARIF & Automated Code Patching",
            description: "PQCanary automatically exports standardized compliance artifacts and synthesizes contextual code remediation diffs:",
            bulletPoints: [
              "CycloneDX 1.6 CBOM: Standardized cryptographic asset declarations formatted for enterprise risk management",
              "OASIS SARIF 2.1.0: Native security alerts for GitHub, GitLab, and Azure DevOps code scanning",
              "Contextual Diff Generation: Synthesizes unified git diffs replacing deprecated algorithms with NIST FIPS 203/204 compliant equivalents"
            ]
          }
        ]
      },
      {
        id: "omega-bio-qpu",
        title: "QPU, SNN, Tensor & Bio-Cryptography",
        badge: "Advanced Engines",
        summary: "QPU statevector simulation, Leaky Integrate-and-Fire neuromorphic SNNs, and in-vivo molecular computing.",
        content: [
          {
            heading: "Quantum Processing Unit (QPU) & OpenQASM 3.0 Offload",
            description: "Directly models quantum circuits and generates OpenQASM 3.0 specifications for execution on quantum hardware and statevector simulators. Synthesizes quantum Grover search oracles to benchmark symmetric key search hardness."
          },
          {
            heading: "Neuromorphic Spiking Neural Networks (SNN)",
            description: "Implements event-driven Leaky Integrate-and-Fire (LIF) artificial neurons for real-time cryptographic anomaly detection with sub-microsecond latency and picojoule energy consumption."
          },
          {
            heading: "Tensor Network Circuit Contraction",
            description: "Employs Matrix Product States (MPS) and tensor contraction algorithms to simulate noisy quantum circuits and compute entanglement entropy without exponential statevector scaling."
          },
          {
            heading: "Bio-Molecular DNA & Lindblad Decoherence",
            description: "Evaluates synthetic DNA storage codon encryption using SantaLucia nearest-neighbor thermodynamic melting temperatures, and models qubit density matrix decoherence via the open-system Lindblad Master Equation."
          }
        ]
      },
      {
        id: "enterprise-pqc",
        title: "Enterprise Drift, MTU, Agility & Roadmap",
        badge: "Engines 11 - 15",
        summary: "CBOM drift gatekeeper, Network MTU analyzer, NIST SP 800-227 agility scoring, topological migration sequencer, and zero-downtime KMS re-encryption playbooks.",
        content: [
          {
            heading: "Engine 11: CycloneDX 1.6 CBOM Semantic Drift & Regression Gatekeeper",
            description: "Compares consecutive CycloneDX 1.6 Cryptographic Bills of Materials to detect new assets, retired algorithms, cryptographic drift, and critical post-quantum downgrade regressions. Integrates into CI/CD pipelines to block merges on security regressions.",
            codeSnippet: {
              lang: "bash",
              code: `# Diff two CBOM snapshots and fail CI if quantum downgrades occur
pqcanary diff baseline-cbom.json current-cbom.json --fail-on-downgrade`
            }
          },
          {
            heading: "Engine 12: PQC Network MTU & TCP Packet Fragmentation Risk Analyzer",
            description: "Models public key and signature wire sizes against network Path MTU (e.g. 1500 bytes Ethernet, 1280 bytes IPv6). Calculates MSS packet counts, middlebox drop probabilities, and latency overhead penalties for ML-KEM, ML-DSA, SLH-DSA, and composite hybrids.",
            codeSnippet: {
              lang: "bash",
              code: `# Analyze packet segmentation and middlebox risk for ML-DSA-87
pqcanary mtu --algorithm ML-DSA-87 --mtu 1500`
            }
          },
          {
            heading: "Engine 13: NIST SP 800-227 Cryptographic Agility Score (CAS)",
            description: "Audits architectural decoupling of cryptographic operations against NIST SP 800-227 guidelines. Computes a 0 to 100 Cryptographic Agility Score (CAS) based on decoupled provider factories, config-driven cipher selection, and absence of hardcoded primitives.",
            codeSnippet: {
              lang: "bash",
              code: `# Audit cryptographic agility score across codebase
pqcanary agility ./src`
            }
          },
          {
            heading: "Engine 14: Topological DAG Migration Sequencer",
            description: "Generates an optimal, topologically ordered 5-phase migration roadmap conforming to US CNSA 2.0 and OMB M-23-02 directives. Computes strict prerequisite chains from Root PKI down through Intermediate CAs, Ingress, Microservices, and Storage-at-Rest.",
            codeSnippet: {
              lang: "bash",
              code: `# Generate enterprise topological migration roadmap
pqcanary roadmap ./src`
            }
          },
          {
            heading: "Engine 15: Zero-Downtime Data-at-Rest Re-encryption Playbook Generator",
            description: "Synthesizes complete 3-phase automated infrastructure code for AWS KMS, Azure Key Vault, and GCP KMS: Phase 1 dual-key Terraform HCL, Phase 2 online cursor batch re-encryption streaming workers, and Phase 3 classical KEK cryptographic erasure.",
            codeSnippet: {
              lang: "bash",
              code: `# Generate Terraform HCL and Python re-encryption worker for AWS KMS
pqcanary reencrypt --provider AWS --key-arn arn:aws:kms:us-east-1:123456789012:key/vault-01`
            }
          },
          {
            heading: "Engine 16: Shift-Left Git Pre-Commit Hook Manager",
            description: "Sub-15ms incremental pre-commit guardrail. Intercepts staged git commits, auditing modified files in memory and blocking commits containing critical quantum vulnerabilities before code leaves the local machine.",
            codeSnippet: {
              lang: "bash",
              code: `# Install sub-15ms local pre-commit guardrail
pqcanary hook install`
            }
          },
          {
            heading: "Engine 17: Passive eBPF Linux Kernel Handshake Sniffer & Wire Telemetry",
            description: "Zero-overhead non-intrusive traffic inspection. Generates C TC/XDP kernel socket filters and parses raw TLS 1.3 ClientHello / ServerHello packets on the wire to detect X25519MLKEM768 vs classical curves without proxying or terminating TLS.",
            codeSnippet: {
              lang: "bash",
              code: `# Generate eBPF C TC kernel filter or analyze packet
pqcanary ebpf --generate-probe`
            }
          },
          {
            heading: "Engine 18: Kubernetes Service Mesh & Ingress Auto-Remediation",
            description: "Cloud-native cluster gateway auto-injector. Generates production-grade Istio EnvoyFilter, Traefik TLSOption, NGINX Ingress annotations, and Kubernetes Gateway API v1 resources enforcing hybrid X25519MLKEM768 ciphers with zero application code changes and zero downtime.",
            codeSnippet: {
              lang: "bash",
              code: `# Generate Istio EnvoyFilter for hybrid PQC TLS 1.3 ingress
pqcanary k8s-mesh --platform istio --namespace istio-system`
            }
          },
          {
            heading: "Engine 19: Hardware Security Module (HSM) PKCS#11 v3.0 & KMIP Auditor",
            description: "Inspects physical and cloud HSM cryptographic tokens (Thales Luna 7, Entrust nShield, AWS CloudHSM, YubiKey 5 PQC) for NIST FIPS 203/204 mechanism support (CKM_ML_KEM_KEY_GEN, CKM_ML_DSA_KEY_GEN) and token key encapsulation readiness.",
            codeSnippet: {
              lang: "bash",
              code: `# Audit physical Thales Luna HSM token for FIPS 203 support
pqcanary hsm --provider luna --label Production-Root-CA`
            }
          },
          {
            heading: "Engine 20: Dynamic Runtime Cryptographic Interceptor (LD_PRELOAD / Detours)",
            description: "Solves the closed-source legacy monolith dilemma where source code is unavailable and binaries are stripped. Generates lightweight C shims intercepting OpenSSL and Win32 CryptoAPI key generation and curve selection at runtime.",
            codeSnippet: {
              lang: "bash",
              code: `# Generate dynamic C interceptor for closed-source legacy binaries
pqcanary runtime-shim --mode enforce --force-hybrid X25519MLKEM768:X25519`
            }
          },
          {
            heading: "Engine 21: Continuous Autonomous DevSecOps Bot & NIST OSCAL Exporter",
            description: "Autonomous PR synthesizer and regulatory compliance engine. Ingests Git webhook events to open pull requests with Lean 4 HoTT formal proofs, and exports Open Security Controls Assessment Language (OSCAL) JSON conforming to NIST SP 800-53 Rev 5, EU DORA Art 9, and PCI DSS 4.0.1.",
            codeSnippet: {
              lang: "bash",
              code: `# Export NIST SP 800-53 OSCAL assessment JSON and DORA matrix
pqcanary oscal --format json --output oscal-assessment.json`
            }
          },
          {
            heading: "Engine 22: Active Post-Quantum Downgrade Attack & Middlebox Tamper Simulator",
            description: "Simulates active adversary and middlebox tamper attacks against TLS 1.3 handshakes. Validates that servers enforce CNSA 2.0 fail-closed semantics when post-quantum extensions (0x11ec) are stripped, key shares are corrupted, or legacy cipher suites are forced.",
            codeSnippet: {
              lang: "bash",
              code: `# Actively simulate MitM downgrade attacks against remote gateway
pqcanary downgrade gateway.corp.internal:443 --strict-cnsa`
            }
          },
          {
            heading: "Engine 23: NIST CAVP / ACVP Known-Answer-Test (KAT) Conformance Harness",
            description: "Mathematical verification harness testing cryptographic implementations against official NIST CAVP / ACVP vectors for FIPS 203 (ML-KEM-768/1024), FIPS 204 (ML-DSA-65/87), and FIPS 205 (SLH-DSA). Evaluates NTT polynomial reductions, Montgomery constants, and rejection sampling bounds.",
            codeSnippet: {
              lang: "bash",
              code: `# Validate cryptographic binaries against NIST ACVP KAT test vectors
pqcanary acvp --library "RustCrypto-PQC" --algorithm all`
            }
          },
          {
            heading: "Engine 24: Hybrid & Dual-Key X.509 Composite Certificate Chain Validator",
            description: "Evaluates X.509 certificate chains against RFC 9758 dual-signature specifications and ITU-T X.509 v3 catalyst extensions. Validates composite SubjectPublicKeyInfo, altSignatureAlgorithm, altSignatureValue, and dual-root cross-signing path trust anchors.",
            codeSnippet: {
              lang: "bash",
              code: `# Validate composite dual-key certificate chain against RFC 9758
pqcanary composite-cert /etc/ssl/certs/composite-chain.pem`
            }
          },
          {
            heading: "Engine 25: OpenTelemetry (OTel) Cryptographic Semantic Conventions & SOC Streaming",
            description: "Exports structured cryptographic runtime telemetry conforming to OpenTelemetry Cryptography Semantic Conventions directly into enterprise SIEM / SOC pipelines (Splunk, Datadog, Elastic). Emits crypto.operation, crypto.algorithm, crypto.pqc.hybrid, and crypto.quantum_risk OTLP logs.",
            codeSnippet: {
              lang: "bash",
              code: `# Stream cryptographic telemetry directly to OTLP collector
pqcanary otel ./src --collector https://otel.internal:4318/v1/logs --service payment-engine`
            }
          },
          {
            heading: "Engine 26: Empirical Constant-Time Execution & Side-Channel Cache-Timing Verifier",
            description: "Dudect-inspired empirical statistical timing leakage analyzer. Employs Welch's two-sample t-test (|t| > 4.5 threshold) across fixed-vs-random input classes to detect cache-timing vulnerabilities and KyberSlash decapsulation timing leakage.",
            codeSnippet: {
              lang: "bash",
              code: `# Statistically verify constant-time execution over 50,000 trace samples
pqcanary constant-time --routine mlkem768_decaps_inner --samples 50000`
            }
          },
          {
            heading: "Engine 27: Cryptographic Supply Chain Provenance & Sigstore Attestation for CBOMs",
            description: "Wraps CycloneDX 1.6 Cryptographic Bills of Materials in Dead Simple Signing Envelopes (DSSE) and in-toto SLSA Provenance v1.0 predicates. Generates cryptographic SHA-256/512 artifact digests and Sigstore Cosign verification commands for tamper-proof software supply chains.",
            codeSnippet: {
              lang: "bash",
              code: `# Attest CBOM with in-toto SLSA Provenance v1.0 and Sigstore Cosign
pqcanary cbom-attest ./cbom.json --project enterprise-core --signer sec-ops@enterprise.internal`
            }
          }
        ]
      }
    ],
    "reference": [
      {
        id: "cli-reference",
        title: "CLI Command Reference Manual",
        badge: "CLI Reference",
        summary: "Complete command-line parameters, subcommands, exit codes, and environment variables.",
        content: [
          {
            heading: "Subcommand Catalog",
            description: "Comprehensive listing of primary commands supported by the pqcanary executable:",
            codeSnippet: {
              lang: "bash",
              code: `# Scan repository, file, or binary
pqcanary scan <PATH> [FLAGS]

# Generate standardized CycloneDX 1.6 CBOM
pqcanary cbom <PATH> --output cbom.json

# Probe remote endpoint for Post-Quantum TLS 1.3
pqcanary probe <HOST:PORT>

# Probe remote server for Post-Quantum SSH key exchange
pqcanary probe-ssh <HOST:PORT>

# Preview or apply semantic code remediation patch
pqcanary patch <FILE_PATH> [--dry-run]

# Compare CBOM snapshots for semantic drift and quantum downgrades
pqcanary diff <OLD_CBOM> <NEW_CBOM> [--fail-on-downgrade]

# Analyze PQC network MTU packet fragmentation & middlebox drops
pqcanary mtu [--algorithm <ALG>] [--mtu <BYTES>]

# Audit cryptographic agility score (NIST SP 800-227)
pqcanary agility <PATH>

# Generate topological migration roadmap (CNSA 2.0 / OMB M-23-02)
pqcanary roadmap <PATH>

# Generate zero-downtime Cloud KMS re-encryption playbook
pqcanary reencrypt --provider <AWS|AZURE|GCP> --key-arn <ARN>

# Install, uninstall, or run sub-15ms Git pre-commit hook
pqcanary hooks <install|uninstall|run>

# Start distributed PQMesh node
pqcanary mesh start [--port 7890] [--coordinator <URL>]

# Actively simulate quantum downgrade attacks & middlebox tampering
pqcanary downgrade <TARGET:PORT> [--strict-cnsa]

# Conformance test against NIST CAVP / ACVP test vectors
pqcanary acvp [--library <NAME>] [--algorithm <ALG>]

# Validate RFC 9758 hybrid composite certificates & dual signatures
pqcanary composite-cert <PATH_OR_PEM>

# Stream cryptographic telemetry using OpenTelemetry semantic conventions
pqcanary otel <PATH> [--collector <URL>] [--service <NAME>]

# Statistically verify constant-time execution via Dudect Welch t-test
pqcanary constant-time [--routine <NAME>] [--samples <N>]

# Generate in-toto SLSA Provenance v1.0 & Sigstore Cosign attestation
pqcanary cbom-attest <CBOM_PATH> [--project <NAME>] [--signer <EMAIL>]`
            }
          },
          {
            heading: "Global Command-Line Flags",
            description: "Parameters to configure audit depth and compliance policies:",
            tableData: {
              headers: ["Flag", "Type", "Default", "Description"],
              rows: [
                ["--strict-nist", "Boolean", "false", "Fail audit if any classical fallback exists without PQC."],
                ["--min-severity", "String", "LOW", "Severity floor: CRITICAL, HIGH, MEDIUM, LOW, INFO."],
                ["--format", "String", "json", "Output format: json, sarif, cbom, html, pdf, markdown, csv."],
                ["--z3-timeout", "Integer", "10", "Concolic SMT solver timeout in seconds."],
                ["--baseline", "Path", "None", "Compare findings against an approved baseline report."],
                ["--fail-on-new", "Boolean", "false", "Return non-zero exit code only on new regressions."],
                ["--threads", "Integer", "NumCPUs", "Worker thread pool size for parallel AST inspection."]
              ]
            }
          }
        ]
      },
      {
        id: "config-schema",
        title: "Configuration Schema (.pqcanary.yaml)",
        badge: "Config",
        summary: "Declarative project configuration file specification for CI/CD pipelines.",
        content: [
          {
            heading: "Specification Format",
            description: "Place a .pqcanary.yaml or pqcanary.toml file in your repository root to configure scanning behavior:",
            codeSnippet: {
              lang: "yaml",
              code: `version: "1.0"

settings:
  strict_nist_mode: true
  min_severity_floor: "MEDIUM"
  default_export_format: "sarif"
  z3_timeout_seconds: 15

scan:
  include:
    - "src/**/*"
    - "lib/**/*"
    - "config/crypto.yaml"
  exclude:
    - "target/**"
    - "node_modules/**"
    - "tests/fixtures/**"

suppress_rules:
  - id: "PQ-AST-RSA-GEN"
    reason: "Legacy compatibility test harness only"
    expires: "2026-12-31"`
            }
          }
        ]
      },
      {
        id: "mcp-specification",
        title: "Model Context Protocol (MCP) Tools",
        badge: "MCP Tools",
        summary: "Tool schemas exposed by pqcanary-mcp to autonomous AI coding agents.",
        content: [
          {
            heading: "Native AI Agent Tool Specifications",
            description: "The pqcanary-mcp binary exposes 42 standardized JSON-RPC 2.0 tools for AI coding assistants:",
            tableData: {
              headers: ["Tool Name", "Input Schema", "Output Schema", "Description"],
              rows: [
                ["scan_repository", "{ path: string, strict: boolean }", "{ findings: Finding[], grade: Grade }", "Scans directory and returns findings"],
                ["audit_snippet", "{ code: string, lang: string }", "{ findings: Finding[] }", "In-memory AST audit of code snippet"],
                ["generate_cbom", "{ path: string }", "{ cbom: CycloneDxBom }", "Generates CycloneDX 1.6 CBOM"],
                ["diff_cbom", "{ old_cbom: string, new_cbom: string }", "{ drift: CbomDriftReport }", "Compares CBOMs for additions and downgrades"],
                ["analyze_pqc_mtu", "{ algorithm: string, mtu: number }", "{ mtu_analysis: MtuResult }", "Analyzes TCP MTU packet fragmentation and drops"],
                ["audit_crypto_agility", "{ path: string }", "{ agility_score: AgilityReport }", "Audits NIST SP 800-227 agility decoupling"],
                ["generate_migration_roadmap", "{ path: string, framework: string }", "{ roadmap: Roadmap }", "Generates 5-phase topological migration DAG"],
                ["generate_reencrypt_playbook", "{ provider: string, key_arn: string }", "{ playbook: Playbook }", "Generates dual-key Terraform and Python worker"],
                ["solve_z3_constraints", "{ constraints: string[] }", "{ satisfiable: boolean, model: any }", "Evaluates branch reachability with Z3"],
                ["probe_endpoint", "{ host: string, port: number }", "{ pqc_supported: boolean, kem: string }", "Probes live TLS 1.3 endpoint for ML-KEM"],
                ["generate_patch", "{ file_path: string, finding_id: string }", "{ diff: string }", "Generates unified diff to remediate issue"],
                ["analyze_ebpf_handshake", "{ payload_hex: string }", "{ analysis: TlsHandshakeAnalysis }", "Decodes passive TLS 1.3 ClientHello wire packets"],
                ["generate_k8s_mesh_remediation", "{ platform: string, hybrid: string }", "{ manifest: K8sMeshRemediation }", "Generates Istio/Traefik PQC ingress manifests"],
                ["audit_hsm_token", "{ provider: string, firmware: string }", "{ report: HsmAuditReport }", "Audits PKCS#11 v3.0 / KMIP tokens for FIPS 203"],
                ["generate_runtime_shim", "{ mode: string, force_hybrid: string }", "{ shim: CShimSource }", "Generates LD_PRELOAD interceptor for legacy binaries"],
                ["generate_autonomous_pr", "{ path: string, repo: string }", "{ pull_request: AutonomousPr }", "Synthesizes PR with unified diff and Lean 4 proof"],
                ["export_oscal_compliance", "{ path: string, project: string }", "{ oscal: OscalReport }", "Exports NIST SP 800-53 OSCAL and DORA compliance"],
                ["simulate_quantum_downgrade", "{ target: string, strict_cnsa: boolean }", "{ simulation: DowngradeReport }", "Simulates MitM downgrade and middlebox stripping"],
                ["verify_acvp_kat_vectors", "{ library: string, algorithm: string }", "{ report: AcvpKatReport }", "Verifies NIST CAVP / ACVP Known-Answer-Test vectors"],
                ["validate_composite_certificate", "{ target: string, raw_pem: string }", "{ report: CompositeCertReport }", "Validates RFC 9758 composite certs and dual signatures"],
                ["export_otel_cryptography", "{ findings_json: string, service: string, collector: string }", "{ payload: OtelBatchPayload }", "Exports OpenTelemetry cryptographic telemetry"],
                ["verify_constant_time_execution", "{ routine: string, samples: number }", "{ report: ConstantTimeReport }", "Verifies constant-time execution with Welch t-test"],
                ["attest_cbom_provenance", "{ cbom_json: string, project: string, signer: string }", "{ envelope: CbomAttestationEnvelope }", "Generates SLSA Provenance v1.0 & Sigstore attestation"]
              ]
            }
          }
        ]
      }
    ],
    "guides": [
      {
        id: "cicd-pipelines",
        title: "CI/CD Pipeline Quality Gates",
        badge: "DevOps",
        summary: "Automate post-quantum audits in GitHub Actions, GitLab CI, and pre-commit hooks.",
        content: [
          {
            heading: "GitHub Actions Workflow Integration",
            description: "Enforce post-quantum compliance on every pull request, blocking merging if regressions are introduced:",
            codeSnippet: {
              lang: "yaml",
              code: `name: Post-Quantum Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  pqc-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install PQCanary
        run: cargo install pqcanary-cli --bin pqcanary

      - name: Audit Repository
        run: |
          pqcanary scan . --strict-nist --format sarif -o results.sarif

      - name: Upload Security Alerts to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif`
            }
          }
        ]
      },
      {
        id: "shift-left-hooks",
        title: "Shift-Left Git Pre-Commit Hooks",
        badge: "Shift-Left",
        summary: "Sub-15ms local staged file auditing to intercept quantum-vulnerable code before reaching Git remotes.",
        content: [
          {
            heading: "Local Pre-Commit Gatekeeper",
            description: "PQCanary provides a native, sub-15ms incremental pre-commit hook that inspects only files staged for commit (git diff --cached). If classical or deprecated primitives are introduced, the commit is intercepted locally with clear remediation instructions.",
            codeSnippet: {
              lang: "bash",
              code: `# Auto-install pre-commit hook in active Git repository
pqcanary hooks install

# Test hook execution manually against staged files
pqcanary hooks run

# Uninstall hook if no longer needed
pqcanary hooks uninstall`
            },
            bulletPoints: [
              "Sub-15ms execution time: zero noticeable developer lag when committing code",
              "Passes cleanly on non-git directories or when no code files are staged",
              "Guarantees that pull requests arrive in CI already post-quantum compliant"
            ]
          }
        ]
      },
      {
        id: "cloud-kms-auditing",
        title: "Cloud KMS Post-Quantum Auditing",
        badge: "Cloud Security",
        summary: "Audit AWS KMS, Google Cloud KMS, and Azure Key Vault configurations and Terraform code.",
        content: [
          {
            heading: "Cloud Key Management Audits",
            description: "Verify that cloud KMS key rings and infrastructure-as-code definitions use post-quantum safe key specs:",
            bulletPoints: [
              "AWS KMS: Flags RSA_2048 and ECC_NIST_P256; validates hybrid post-quantum TLS endpoint connections",
              "Google Cloud KMS: Inspects Cloud KMS key versions and flags classical asymmetric signing keys",
              "Azure Key Vault: Audits HSM-backed key types and validates TLS cipher suite policies",
              "Terraform / OpenTofu: Static AST inspection of cloud provider key resource blocks"
            ]
          }
        ]
      },
      {
        id: "remediation-playbook",
        title: "Automated Code Remediation Playbook",
        badge: "Remediation",
        summary: "Step-by-step guidance on reviewing and applying automated semantic diffs.",
        content: [
          {
            heading: "Reviewing & Applying Code Modernization Patches",
            description: "PQCanary automatically generates targeted unified diffs to replace deprecated and classical primitives:",
            codeSnippet: {
              lang: "bash",
              code: `# Generate and preview remediation diff
pqcanary patch ./src/crypto.rs --dry-run

# Apply verified patch directly to file
pqcanary patch ./src/crypto.rs

# Re-run audit to confirm quantum resilience
pqcanary scan ./src/crypto.rs --strict-nist`
            }
          }
        ]
      }
    ]
  };

  const currentDocs = () => docsData[activeCategory()] || [];
  const currentSubDoc = () => currentDocs().find((d) => d.id === activeSubDocId()) || currentDocs()[0];

  const handleSelectCategory = (cat: DocCategory) => {
    setActiveCategory(cat);
    const firstSub = docsData[cat]?.[0];
    if (firstSub) setActiveSubDocId(firstSub.id);
  };

  return (
    <div
      id="pq-landing-container"
      style={{
        width: "100%",
        "max-width": "1160px",
        margin: "0 auto",
        padding: "0 0 6rem 0",
        "box-sizing": "border-box"
      }}
    >
      <style>{`
        .pq-landing-action-btn {
          transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1),
                      box-shadow 0.22s cubic-bezier(0.16, 1, 0.3, 1),
                      filter 0.22s ease !important;
          will-change: transform;
          transform-origin: center;
        }
        .pq-landing-action-btn:hover {
          transform: scale(1.06) !important;
        }
        .pq-landing-action-btn:active {
          transform: scale(0.94) !important;
          transition: transform 0.08s ease-out !important;
        }

        .pq-landing-cat-btn {
          font-family: 'Syne', sans-serif !important;
          font-weight: 500 !important;
          font-size: 0.825rem !important;
          cursor: pointer !important;
          border-radius: 9999px !important;
          padding: 0.52rem 1.15rem !important;
          display: inline-flex !important;
          align-items: center !important;
          justify-content: center !important;
          outline: none !important;
          transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1),
                      color 0.22s ease,
                      border-color 0.22s ease,
                      background-color 0.22s ease !important;
        }
        .pq-landing-cat-btn:hover {
          transform: scale(1.04) !important;
        }
        .pq-landing-cat-btn:active {
          transform: scale(0.96) !important;
          transition: transform 0.08s ease-out !important;
        }
      `}</style>

      {/* Hero Header Section */}
      <section
        style={{
          "text-align": "center",
          padding: "clamp(1rem, 3.5vw, 2.5rem) 1rem clamp(2rem, 4vw, 3.5rem) 1rem",
          display: "flex",
          "flex-direction": "column",
          "align-items": "center",
          "justify-content": "center",
          gap: "1.25rem"
        }}
      >
        {/* Primary Headline — Exactly as requested */}
        <h1
          style={{
            margin: "0",
            "font-size": "clamp(1.85rem, 4.2vw, 3.25rem)",
            "font-weight": "300",
            "font-family": "'Syne', sans-serif",
            "letter-spacing": "-0.025em",
            "line-height": "1.18",
            color: props.themeTextColor(),
            "max-width": "880px"
          }}
        >
          PQCanary: Universal Post-Quantum Cryptographic Security & Audit Platform
        </h1>

        {/* Subtitle */}
        <p
          style={{
            margin: "0",
            "font-size": "clamp(0.95rem, 1.8vw, 1.15rem)",
            "font-weight": "300",
            "line-height": "1.65",
            color: props.themeSubTextColor(),
            "max-width": "760px"
          }}
        >
          Automated discovery, mathematical verification, Z3 concolic constraint solving, and CycloneDX 1.6 CBOM generation. Defend your codebase against Harvest Now, Decrypt Later (HNDL) quantum threats.
        </p>

        {/* Launch Buttons Row */}
        <div
          style={{
            display: "flex",
            "align-items": "center",
            "justify-content": "center",
            gap: "1rem",
            "flex-wrap": "wrap",
            "margin-top": "0.75rem"
          }}
        >
          {/* Launch Web Scanner Button — Styled EXACTLY like the Launch Audit button */}
          <button
            id="btn-try-the-app"
            type="button"
            class="pq-landing-action-btn"
            onClick={props.onLaunchApp}
            style={{
              background: "linear-gradient(135deg, #F59E0B 0%, #D97706 100%)",
              color: "#ffffff",
              border: "none",
              height: "44px",
              padding: "0 2.25rem",
              cursor: "pointer",
              "border-radius": "9999px",
              "font-weight": "500",
              "font-size": "0.92rem",
              "letter-spacing": "-0.01em",
              "white-space": "nowrap",
              display: "inline-flex",
              "align-items": "center",
              "justify-content": "center",
              gap: "0.5rem",
              outline: "none"
            }}
          >
            <span>Launch Web Scanner</span>
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="5" y1="12" x2="19" y2="12"></line>
              <polyline points="12 5 19 12 12 19"></polyline>
            </svg>
          </button>

          {/* GitHub Repository Link */}
          <a
            id="link-github-repo"
            class="pq-landing-action-btn"
            href="https://github.com/Iqumnov/PQCanary"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              ...props.themeCloudyGlassStyle(),
              display: "inline-flex",
              "align-items": "center",
              gap: "0.6rem",
              height: "44px",
              padding: "0 1.5rem",
              "border-radius": "9999px",
              color: props.themeTextColor(),
              "font-size": "0.875rem",
              "font-weight": "400",
              "text-decoration": "none",
              cursor: "pointer",
              outline: "none",
              "box-sizing": "border-box"
            }}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
              <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
            </svg>
            <span>GitHub (Iqumnov/PQCanary)</span>
          </a>
        </div>

        {/* Installation Commands Box (Positioned Directly Below the Launch Buttons) */}
        <div
          style={{
            display: "flex",
            "align-items": "center",
            "justify-content": "center",
            gap: "0.75rem",
            "flex-wrap": "wrap",
            "margin-top": "0.35rem"
          }}
        >
          <div
            style={{
              ...props.themeCloudyGlassStyle(),
              display: "inline-flex",
              "align-items": "center",
              gap: "0.65rem",
              padding: "0.48rem 0.95rem 0.48rem 1.15rem",
              "border-radius": "9999px",
              "font-family": "'JetBrains Mono', monospace",
              "font-size": "0.78rem",
              color: props.isDarkMode ? "#34d399" : "#047857"
            }}
          >
            <span>$ cargo install pqcanary-cli</span>
            <button
              type="button"
              class="pq-landing-action-btn"
              onClick={() => copyToClipboard("cargo install pqcanary-cli", "hero-cli")}
              title="Copy install command"
              aria-label="Copy install command"
              style={{
                background: "transparent",
                border: "none",
                cursor: "pointer",
                padding: "3px 6px",
                color: props.themeSubTextColor(),
                display: "flex",
                "align-items": "center",
                "border-radius": "6px",
                outline: "none"
              }}
            >
              <Show
                when={copiedSnippet() === "hero-cli"}
                fallback={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                }
              >
                <span style={{ "font-size": "0.7rem", color: "#10b981", "font-weight": "600" }}>Copied!</span>
              </Show>
            </button>
          </div>
        </div>

        {/* Feature Highlights Grid — Zero Emojis */}
        <div
          style={{
            display: "grid",
            "grid-template-columns": "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "0.85rem",
            width: "100%",
            "max-width": "1020px",
            "margin-top": "1.75rem"
          }}
        >
          <div style={{ ...props.themeSidebarCardStyle(), padding: "1.1rem 1.25rem", "text-align": "left" }}>
            <div style={{ "font-size": "0.72rem", color: "#F59E0B", "font-family": "'Space Grotesk', sans-serif", "font-weight": "600", "text-transform": "uppercase", "letter-spacing": "0.08em", "margin-bottom": "0.35rem" }}>Client-Side WASM</div>
            <strong style={{ display: "block", "font-size": "0.875rem", color: props.themeTextColor(), "margin-bottom": "0.25rem" }}>100% Private Sandbox</strong>
            <span style={{ "font-size": "0.76rem", color: props.themeSubTextColor(), "font-weight": "300", "line-height": "1.45" }}>In-browser parsing and evaluation. Private keys and code never leave your device.</span>
          </div>
          <div style={{ ...props.themeSidebarCardStyle(), padding: "1.1rem 1.25rem", "text-align": "left" }}>
            <div style={{ "font-size": "0.72rem", color: "#F59E0B", "font-family": "'Space Grotesk', sans-serif", "font-weight": "600", "text-transform": "uppercase", "letter-spacing": "0.08em", "margin-bottom": "0.35rem" }}>NIST Standards</div>
            <strong style={{ display: "block", "font-size": "0.875rem", color: props.themeTextColor(), "margin-bottom": "0.25rem" }}>FIPS 203 & 204 Verified</strong>
            <span style={{ "font-size": "0.76rem", color: props.themeSubTextColor(), "font-weight": "300", "line-height": "1.45" }}>Automated audit for ML-KEM, ML-DSA, SLH-DSA, and CNSA 2.0 migration timelines.</span>
          </div>
          <div style={{ ...props.themeSidebarCardStyle(), padding: "1.1rem 1.25rem", "text-align": "left" }}>
            <div style={{ "font-size": "0.72rem", color: "#F59E0B", "font-family": "'Space Grotesk', sans-serif", "font-weight": "600", "text-transform": "uppercase", "letter-spacing": "0.08em", "margin-bottom": "0.35rem" }}>Formal Methods</div>
            <strong style={{ display: "block", "font-size": "0.875rem", color: props.themeTextColor(), "margin-bottom": "0.25rem" }}>Z3 SMT & HoTT Proofs</strong>
            <span style={{ "font-size": "0.76rem", color: props.themeSubTextColor(), "font-weight": "300", "line-height": "1.45" }}>Concolic solver and Lean 4 proof synthesis mathematically prove absence of classical fallbacks.</span>
          </div>
          <div style={{ ...props.themeSidebarCardStyle(), padding: "1.1rem 1.25rem", "text-align": "left" }}>
            <div style={{ "font-size": "0.72rem", color: "#F59E0B", "font-family": "'Space Grotesk', sans-serif", "font-weight": "600", "text-transform": "uppercase", "letter-spacing": "0.08em", "margin-bottom": "0.35rem" }}>Enterprise Artifacts</div>
            <strong style={{ display: "block", "font-size": "0.875rem", color: props.themeTextColor(), "margin-bottom": "0.25rem" }}>CycloneDX 1.6 & SARIF</strong>
            <span style={{ "font-size": "0.76rem", color: props.themeSubTextColor(), "font-weight": "300", "line-height": "1.45" }}>Cryptographic Bill of Materials (CBOM) and native GitHub Code Scanning reports.</span>
          </div>
        </div>
      </section>

      {/* Interactive Documentation Portal */}
      <section style={{ "margin-top": "1.5rem" }}>
        {/* Section Heading */}
        <div style={{ "text-align": "center", "margin-bottom": "1.5rem" }}>
          <span style={{ "font-size": "0.725rem", color: "#F59E0B", "text-transform": "uppercase", "letter-spacing": "0.12em", "font-weight": "600", "font-family": "'Space Grotesk', sans-serif" }}>
            Technical Documentation Portal
          </span>
          <h2 style={{ margin: "0.3rem 0 0.5rem 0", "font-size": "1.75rem", color: props.themeTextColor(), "font-weight": "300", "font-family": "'Syne', sans-serif" }}>
            Architecture, Engines & Operational Mediums
          </h2>
          <p style={{ margin: "0", "font-size": "0.85rem", color: props.themeSubTextColor(), "font-weight": "300" }}>
            Comprehensive technical specification covering all 10 mediums, 15 analysis engines, and compliance standards.
          </p>
        </div>

        {/* 5-Category Navigation Tabs — Styled cleanly like main interface tabs with ZERO emojis */}
        <div
          style={{
            display: "flex",
            gap: "0.55rem",
            "justify-content": "center",
            "flex-wrap": "wrap",
            "margin-bottom": "1.75rem"
          }}
        >
          <For each={categories}>
            {(cat) => {
              const isActive = () => activeCategory() === cat.id;
              return (
                <button
                  type="button"
                  class="pq-landing-cat-btn"
                  onClick={() => handleSelectCategory(cat.id)}
                  style={{
                    ...props.themeCloudyGlassStyle(),
                    border: isActive()
                      ? "1px solid #F59E0B"
                      : (props.isDarkMode ? "1px solid rgba(0, 0, 0, 0.65)" : "1px solid rgba(255, 255, 255, 0.65)"),
                    background: isActive()
                      ? (props.isDarkMode ? "rgba(245, 158, 11, 0.14)" : "rgba(245, 158, 11, 0.1)")
                      : undefined,
                    color: isActive() ? "#F59E0B" : props.themeSubTextColor()
                  }}
                >
                  <span>{cat.label}</span>
                </button>
              );
            }}
          </For>
        </div>

        {/* Category Description Banner */}
        <div style={{ "text-align": "center", "margin-bottom": "1.25rem" }}>
          <span style={{ "font-size": "0.8rem", color: props.themeSubTextColor(), "font-weight": "300" }}>
            {categories.find((c) => c.id === activeCategory())?.desc}
          </span>
        </div>

        {/* Sub-document Content Layout (Sidebar Navigator + Main Document Reader) */}
        <div
          style={{
            display: "grid",
            "grid-template-columns": "repeat(auto-fit, minmax(290px, 1fr))",
            gap: "1.25rem",
            "align-items": "start"
          }}
        >
          {/* Sub-document Navigator Column */}
          <div style={{ display: "flex", "flex-direction": "column", gap: "0.65rem" }}>
            <For each={currentDocs()}>
              {(sub) => {
                const isSelected = () => activeSubDocId() === sub.id;
                return (
                  <div
                    onClick={() => setActiveSubDocId(sub.id)}
                    style={{
                      ...props.themeSidebarCardStyle(),
                      padding: "1rem 1.25rem",
                      cursor: "pointer",
                      border: isSelected()
                        ? "1px solid #F59E0B"
                        : (props.isDarkMode ? "1px solid rgba(0, 0, 0, 0.65)" : "1px solid rgba(255, 255, 255, 0.65)"),
                      background: isSelected()
                        ? (props.isDarkMode ? "rgba(245, 158, 11, 0.12)" : "rgba(251, 191, 36, 0.16)")
                        : undefined,
                      transition: "all 0.22s cubic-bezier(0.16, 1, 0.3, 1)"
                    }}
                  >
                    <div style={{ display: "flex", "justify-content": "space-between", "align-items": "center", "margin-bottom": "0.3rem" }}>
                      <strong style={{ "font-size": "0.875rem", color: isSelected() ? "#F59E0B" : props.themeTextColor(), "font-family": "'Space Grotesk', sans-serif" }}>
                        {sub.title}
                      </strong>
                      <Show when={sub.badge}>
                        <span style={{ "font-size": "0.68rem", padding: "0.15rem 0.45rem", "border-radius": "9999px", background: "rgba(245, 158, 11, 0.15)", color: "#F59E0B", "font-weight": "500" }}>
                          {sub.badge}
                        </span>
                      </Show>
                    </div>
                    <p style={{ margin: "0", "font-size": "0.775rem", color: props.themeSubTextColor(), "font-weight": "300", "line-height": "1.45" }}>
                      {sub.summary}
                    </p>
                  </div>
                );
              }}
            </For>
          </div>

          {/* Active Documentation Document Display */}
          <div style={{ ...props.themeCloudyGlassStyle(), padding: "1.75rem 2rem" }}>
            <Show when={currentSubDoc()}>
              {(doc) => (
                <div style={{ display: "flex", "flex-direction": "column", gap: "1.5rem" }}>
                  {/* Document Title Header */}
                  <div style={{ "border-bottom": props.isDarkMode ? "1px solid rgba(0, 0, 0, 0.6)" : "1px solid rgba(0, 0, 0, 0.08)", "padding-bottom": "1rem" }}>
                    <div style={{ display: "flex", "align-items": "center", gap: "0.65rem", "margin-bottom": "0.35rem" }}>
                      <h3 style={{ margin: 0, "font-size": "1.35rem", color: props.themeTextColor(), "font-weight": "400", "font-family": "'Syne', sans-serif" }}>
                        {doc().title}
                      </h3>
                      <Show when={doc().badge}>
                        <span style={{ "font-size": "0.7rem", padding: "0.2rem 0.55rem", "border-radius": "9999px", background: "rgba(245, 158, 11, 0.15)", color: "#F59E0B", "font-weight": "500" }}>
                          {doc().badge}
                        </span>
                      </Show>
                    </div>
                    <p style={{ margin: 0, "font-size": "0.85rem", color: props.themeSubTextColor(), "font-weight": "300" }}>
                      {doc().summary}
                    </p>
                  </div>

                  {/* Document Sub-sections */}
                  <For each={doc().content}>
                    {(sec) => (
                      <div style={{ display: "flex", "flex-direction": "column", gap: "0.75rem" }}>
                        <h4 style={{ margin: 0, "font-size": "0.95rem", color: "#F59E0B", "font-weight": "500", "font-family": "'Space Grotesk', sans-serif" }}>
                          {sec.heading}
                        </h4>
                        <p style={{ margin: 0, "font-size": "0.85rem", color: props.themeTextColor(), "line-height": "1.65", "font-weight": "300" }}>
                          {sec.description}
                        </p>

                        {/* Bullet Points */}
                        <Show when={sec.bulletPoints && sec.bulletPoints.length > 0}>
                          <ul style={{ margin: 0, "padding-left": "1.2rem", "font-size": "0.825rem", color: props.themeTextColor(), "line-height": "1.6", "font-weight": "300" }}>
                            <For each={sec.bulletPoints}>
                              {(pt) => <li style={{ "margin-bottom": "0.25rem" }}>{pt}</li>}
                            </For>
                          </ul>
                        </Show>

                        {/* Code Snippet */}
                        <Show when={sec.codeSnippet}>
                          <div style={{ position: "relative", "margin-top": "0.35rem" }}>
                            <div style={{ display: "flex", "justify-content": "space-between", "align-items": "center", padding: "0.4rem 0.85rem", "border-radius": "10px 10px 0 0", background: props.isDarkMode ? "rgba(0,0,0,0.6)" : "rgba(0,0,0,0.06)", "font-size": "0.7rem", color: props.themeSubTextColor(), "font-family": "monospace" }}>
                              <span>{sec.codeSnippet!.lang}</span>
                              <button
                                type="button"
                                class="pq-landing-action-btn"
                                onClick={() => copyToClipboard(sec.codeSnippet!.code, `code-${sec.heading}`)}
                                style={{ background: "transparent", border: "none", color: "#F59E0B", cursor: "pointer", "font-size": "0.7rem", "font-family": "'Space Grotesk', sans-serif" }}
                              >
                                {copiedSnippet() === `code-${sec.heading}` ? "Copied!" : "Copy"}
                              </button>
                            </div>
                            <pre
                              style={{
                                margin: 0,
                                padding: "0.85rem 1rem",
                                "border-radius": "0 0 10px 10px",
                                background: props.isDarkMode ? "#000000" : "#FFFFFF",
                                border: props.isDarkMode ? "1px solid rgba(0, 0, 0, 0.65)" : "1px solid rgba(0, 0, 0, 0.1)",
                                "border-top": "none",
                                "font-family": "'JetBrains Mono', monospace",
                                "font-size": "0.78rem",
                                color: props.isDarkMode ? "#34d399" : "#047857",
                                "line-height": "1.55",
                                "overflow-x": "auto",
                                "white-space": "pre"
                              }}
                            >
                              <code>{sec.codeSnippet!.code}</code>
                            </pre>
                          </div>
                        </Show>

                        {/* Table Data */}
                        <Show when={sec.tableData}>
                          <div style={{ "overflow-x": "auto", "margin-top": "0.35rem" }}>
                            <table style={{ width: "100%", "border-collapse": "collapse", "font-size": "0.8rem", "text-align": "left" }}>
                              <thead>
                                <tr style={{ "border-bottom": props.isDarkMode ? "1px solid rgba(0, 0, 0, 0.6)" : "1px solid rgba(0, 0, 0, 0.1)" }}>
                                  <For each={sec.tableData!.headers}>
                                    {(h) => <th style={{ padding: "0.5rem 0.65rem", color: props.themeSubTextColor(), "font-weight": "500", "font-family": "'Space Grotesk', sans-serif" }}>{h}</th>}
                                  </For>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={sec.tableData!.rows}>
                                  {(row) => (
                                    <tr style={{ "border-bottom": props.isDarkMode ? "1px solid rgba(0, 0, 0, 0.4)" : "1px solid rgba(0, 0, 0, 0.05)" }}>
                                      <For each={row}>
                                        {(cell, idx) => (
                                          <td style={{ padding: "0.5rem 0.65rem", color: idx() === 0 ? "#F59E0B" : props.themeTextColor(), "font-weight": idx() === 0 ? "500" : "300" }}>
                                            {cell}
                                          </td>
                                        )}
                                      </For>
                                    </tr>
                                  )}
                                </For>
                              </tbody>
                            </table>
                          </div>
                        </Show>

                        {/* Note Callout */}
                        <Show when={sec.note}>
                          <div
                            style={{
                              padding: "0.65rem 0.85rem",
                              "border-radius": "10px",
                              background: props.isDarkMode ? "rgba(16, 185, 129, 0.1)" : "rgba(16, 185, 129, 0.12)",
                              border: "1px solid rgba(16, 185, 129, 0.25)",
                              color: props.isDarkMode ? "#34d399" : "#047857",
                              "font-size": "0.8rem",
                              "font-weight": "300",
                              "line-height": "1.5"
                            }}
                          >
                            <strong>Note:</strong> {sec.note}
                          </div>
                        </Show>
                      </div>
                    )}
                  </For>

                  {/* Direct Launch Scanner CTA inside active document */}
                  <div
                    style={{
                      "border-top": props.isDarkMode ? "1px solid rgba(0, 0, 0, 0.6)" : "1px solid rgba(0, 0, 0, 0.08)",
                      "padding-top": "1.25rem",
                      display: "flex",
                      "justify-content": "space-between",
                      "align-items": "center",
                      "flex-wrap": "wrap",
                      gap: "0.75rem"
                    }}
                  >
                    <span style={{ "font-size": "0.8rem", color: props.themeSubTextColor(), "font-weight": "300" }}>
                      Ready to inspect your code for post-quantum safety?
                    </span>
                    <button
                      type="button"
                      class="pq-landing-action-btn"
                      onClick={props.onLaunchApp}
                      style={{
                        background: "linear-gradient(135deg, #F59E0B 0%, #D97706 100%)",
                        color: "#ffffff",
                        border: "none",
                        height: "38px",
                        padding: "0 1.5rem",
                        cursor: "pointer",
                        "border-radius": "9999px",
                        "font-weight": "500",
                        "font-size": "0.825rem",
                        "letter-spacing": "-0.01em",
                        "white-space": "nowrap",
                        display: "inline-flex",
                        "align-items": "center",
                        "justify-content": "center",
                        gap: "0.4rem",
                        outline: "none"
                      }}
                    >
                      <span>Launch Web Scanner</span>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                        <polyline points="12 5 19 12 12 19"></polyline>
                      </svg>
                    </button>
                  </div>
                </div>
              )}
            </Show>
          </div>
        </div>
      </section>
    </div>
  );
}
