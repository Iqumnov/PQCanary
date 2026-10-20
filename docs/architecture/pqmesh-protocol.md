# PQMesh Cross-Medium Fleet Protocol

This document specifies the PQMesh protocol, an asynchronous, distributed event bus designed to synchronize post-quantum security state, vulnerability findings, and remediation actions across diverse execution environments within an enterprise.

---

## 1. Problem Statement and Objectives

In enterprise settings, cryptographic audits often suffer from operational fragmentation:
- A developer runs an initial scan via a CLI tool or IDE extension.
- A CI/CD runner performs an independent audit on pull requests.
- A Kubernetes cluster runs containers whose runtime crypto state may differ from source control.
- Security teams monitor compliance through a centralized dashboard.

PQMesh unifies these environments into an interoperable fleet without requiring centralized persistent databases or invasive agents.

---

## 2. Supported Operational Mediums

PQMesh nodes identify themselves via one of seven standardized operational mediums:

| Medium Identifier | Node Type | Typical Runtime Context |
| :--- | :--- | :--- |
| `CliNode` | Ephemeral Runner | Local workstation shells, GitHub Actions, GitLab CI runners |
| `VsCodeExtension` | Developer Workspace | Visual Studio Code editor sessions |
| `NeovimExtension` | Developer Workspace | Neovim text editor sessions |
| `BrowserExtension` | Web Client | Chrome, Firefox, or Edge developer tools |
| `KubernetesDaemonSet` | Infrastructure Node | In-cluster daemon auditing running pod volumes |
| `WebDashboard` | Operator Console | Standalone Tauri desktop client or browser UI |
| `McpAgent` | Autonomous Assistant | Model Context Protocol AI agents (Claude, GPT, Gemini) |

---

## 3. Protocol Message Structure

PQMesh messages are encoded as JSON payloads exchanged over WebSocket or HTTP SSE streams. Every message conforms to the following schema:

```json
{
  "event_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp_utc": "2026-10-09T03:30:00Z",
  "source_node": {
    "node_id": "node-us-east-4821",
    "medium": "KubernetesDaemonSet",
    "version": "0.1.0",
    "hostname": "k8s-worker-prod-04"
  },
  "event_type": "SecurityFinding",
  "payload": {
    "file_path": "/var/run/secrets/tls.crt",
    "vulnerability_class": "Quantum-Vulnerable RSA Public Key",
    "rule_id": "PQC-CERT-RSA-OBSOLETE",
    "severity": "CRITICAL",
    "quantum_risk": "VULNERABLE",
    "line_number": 1,
    "fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "remediation": "Re-issue certificate with NIST FIPS 204 ML-DSA-65."
  }
}
```

### Event Types

PQMesh defines five standardized event types:

1. **`Discovery`**: Broadcast when a new node initializes and joins the mesh, announcing its capabilities and subscribed topics.
2. **`SecurityFinding`**: Broadcast when an inspection engine detects a cryptographic vulnerability, expired certificate, or classical algorithm.
3. **`PolicyViolation`**: Broadcast when a finding breaches an active compliance threshold (e.g., CNSA 2.0 deadline enforcement).
4. **`RemediationTrigger`**: Dispatched to request an automated patch application or PR generation on a participating node.
5. **`Heartbeat`**: Periodic keep-alive ping emitted every 30 seconds to maintain peer liveness tables.

---

## 4. Finding Deduplication and Fingerprinting

To prevent finding storms across multiple concurrent scans of identical files or repositories, PQMesh uses deterministic finding fingerprints.

A finding fingerprint is computed as:

$$\text{Fingerprint} = \text{SHA-256}(\text{normalized\_path} \parallel \text{rule\_id} \parallel \text{line\_number})$$

Nodes maintain an in-memory LRU ring buffer of recent fingerprints. Duplicate events observed within a configurable time window (default: 300 seconds) are acknowledged without re-broadcasting.

---

## 5. Security and Access Control

1. **Transport Encryption**: All inter-node communications over the network require TLS 1.3.
2. **Authentication**: Mesh nodes authenticate using shared pre-shared keys (PSK) or mutual TLS (mTLS) with certificates validated against an enterprise root CA.
3. **Offline Air-Gap Fallback**: When deployed in air-gapped environments without network connectivity, PQMesh operates over local filesystem sockets or local Named Pipes (`\\.\pipe\pqmesh-*` on Windows, `/var/run/pqmesh.sock` on Linux/macOS).
