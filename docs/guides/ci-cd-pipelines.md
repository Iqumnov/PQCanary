# CI/CD Pipeline Integration Guide

This guide walks through integrating PQCanary into enterprise continuous integration and continuous delivery (CI/CD) pipelines to establish automated post-quantum quality gates.

---

## 1. GitHub Actions Integration

PQCanary natively integrates with GitHub Advanced Security by exporting OASIS SARIF 2.1.0, rendering interactive finding alerts directly in pull request diffs and the repository Security tab.

### 1.1. Basic Audit and SARIF Upload

Create `.github/workflows/pqcanary.yml`:

```yaml
name: Post-Quantum Cryptographic Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    # Run daily at midnight to catch new cryptographic research advisories
    - cron: '0 0 * * *'

permissions:
  contents: read
  security-events: write

jobs:
  pqcanary-audit:
    name: PQCanary Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Install Rust Toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Cache Cargo Dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/bin/
            ~/.cargo/registry/index/
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            target/
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Install PQCanary
        run: |
          cargo install --path ./cli --bin pqcanary

      - name: Run Cryptographic Audit
        run: |
          pqcanary scan . \
            --format sarif \
            --output pqcanary.sarif \
            --fail-on high

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: pqcanary.sarif
          category: pqcanary
```

---

## 2. Differential Regression Auditing (Baseline Gates)

In large legacy codebases, failing builds on existing classical cryptography can block deployment velocity. PQCanary solves this using **baseline differential auditing**: developers only fail the build if a PR introduces *new* cryptographic vulnerabilities.

### 2.1. Baseline Workflow

```yaml
      - name: Download Main Branch Baseline
        uses: actions/download-artifact@v4
        continue-on-error: true
        with:
          name: pqcanary-baseline
          path: ./baseline/

      - name: Audit Against Baseline
        run: |
          if [ -f "./baseline/baseline.json" ]; then
            echo "Running differential audit against main baseline..."
            pqcanary scan . \
              --baseline ./baseline/baseline.json \
              --fail-on-new
          else
            echo "No baseline found; recording initial baseline..."
            pqcanary scan . \
              --format json \
              --output baseline.json
          fi

      - name: Persist Baseline on Main Branch
        if: github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@v4
        with:
          name: pqcanary-baseline
          path: baseline.json
```

---

## 3. GitLab CI/CD Pipeline

Add the following job to `.gitlab-ci.yml`:

```yaml
stages:
  - security

pqcanary_audit:
  stage: security
  image: rust:latest
  before_script:
    - cargo install --path ./cli --bin pqcanary
  script:
    - pqcanary scan . --format json --output pqcanary-results.json --fail-on critical
  artifacts:
    when: always
    paths:
      - pqcanary-results.json
    reports:
      sast: pqcanary-results.json
```

---

## 4. Azure DevOps Pipelines

Add the following step to `azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UseRust@0
    inputs:
      rustVersion: 'stable'

  - script: |
      cargo install --path ./cli --bin pqcanary
      pqcanary scan . --format sarif --output $(Build.ArtifactStagingDirectory)/pqcanary.sarif --fail-on high
    displayName: 'Execute PQCanary Post-Quantum Audit'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/pqcanary.sarif'
      ArtifactName: 'CodeAnalysisLogs'
      publishLocation: 'Container'
```

---

## 5. Local Git Pre-Commit Hook

To prevent engineers from accidentally committing hardcoded private keys or classical ciphers locally, configure a Git pre-commit hook:

Create `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
set -e

echo "Running PQCanary pre-commit cryptographic check..."
pqcanary scan . --severity CRITICAL --fail-on critical

echo "PQCanary check passed: no critical cryptographic violations."
exit 0
```

Make the script executable:
```bash
chmod +x .git/hooks/pre-commit
```
