---
name: Bug Report
about: Create a report to help us improve PQCanary
title: "[BUG] "
labels: ["bug", "triage"]
assignees: []
---

### Describe the Bug
A clear and concise description of what the bug is.

### Operational Medium / Component
Which medium or component did this occur in?
- [ ] Native CLI (`pqcanary scan`, `pqcanary probe`, etc.)
- [ ] Web Playground (WASM / Cloudflare Pages)
- [ ] Tauri Desktop Application
- [ ] Model Context Protocol (MCP Server)
- [ ] Docker Container / Kubernetes DaemonSet
- [ ] GitHub Action / CI Integration
- [ ] IDE Extension (VS Code / Neovim)

### Environment Details
- **PQCanary Version**: (e.g., `0.1.0` or git commit SHA)
- **Operating System & Distro**: (e.g., Void Linux musl, Ubuntu 24.04, Alpine 3.20, macOS 14.5, Windows 11)
- **Architecture**: (e.g., `x86_64`, `aarch64`, `arm64`)
- **C Library**: (e.g., `glibc 2.39`, `musl 1.2.5`)
- **Rust Toolchain** (if built from source): `rustc --version`
- **External Dependencies**: (e.g., `z3 4.12.2`)

### Steps to Reproduce
Steps to reproduce the behavior:
1. Run command: `pqcanary ...`
2. With target: `...`
3. See error output:

### Expected Behavior
A clear and concise description of what you expected to happen.

### Actual Output / Terminal Logs / SARIF Snippet
```text
Paste terminal logs, stack traces, or relevant SARIF / CBOM output here
```

### Additional Context
Add any other context about the problem here (e.g., proprietary codebase constraints, proxy or air-gapped network configuration).

