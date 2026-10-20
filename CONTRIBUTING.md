# Contributing to PQCanary

Thank you for your interest in contributing to PQCanary. This document outlines the technical standards, architectural requirements, coding conventions, and pull request workflow for the project.

---

## 1. Architectural Invariants

All contributions must strictly respect the following core architectural invariants:

1. **Strict Memory Safety**: The `pqcanary-core` library enforces `#![forbid(unsafe_code)]`. Any pull request introducing `unsafe` blocks in `core/` will be rejected.
2. **Deterministic Memory Scrubbing**: Sensitive extracted cryptographic key material, certificates, and credentials must be encapsulated in data structures implementing `zeroize::ZeroizeOnDrop` (e.g., `SecureMaterial`).
3. **Air-Gap Default (Zero Unsolicited Network Egress)**: By default, scanning operations must run entirely offline. Network connections are only permitted when the operator explicitly invokes remote targets (such as `pqcanary probe` or cloning a Git URL).
4. **Zero Emojis in Source and Documentation**: In accordance with enterprise documentation and formatting standards, no unicode emojis are permitted anywhere in code, comments, documentation, commit messages, or terminal outputs.
5. **Deterministic Testing**: All tests must be hermetic and reproducible without requiring active internet connectivity or external credentials.

---

## 2. Development Environment Setup

### Prerequisites
- **Rust Toolchain**: Rust 1.80+ (stable).
- **Cargo Components**: `rustfmt` and `clippy`.
- **WebAssembly Target**: `rustup target add wasm32-unknown-unknown`
- **Optional Tools**: `wasm-pack` (for compiling WebAssembly artifacts), `Node.js` 18+ (for testing web and extension packages).

### Cloning and Verification

```bash
# Clone the repository
git clone https://github.com/Iqumnov/PQCanary.git
cd pqcanary

# Verify compilation across all workspace members
cargo check --workspace --all-targets

# Run the test suite
cargo test --workspace

# Run linting checks
cargo clippy --workspace -- -D warnings

# Verify formatting
cargo fmt --all -- --check
```

---

## 3. Code Style and Conventions

### Rust Conventions
- Follow standard Rust naming conventions (`UpperCamelCase` for types, `snake_case` for functions/modules/variables, `SCREAMING_SNAKE_CASE` for constants).
- Prefer explicit error handling via `Result<T, E>` over `unwrap()` or `expect()` in production library code. Reserve `unwrap()` exclusively for hermetic unit tests.
- Document all public items with doc comments (`///`) explaining arguments, return types, and possible errors.
- Ensure all regex patterns in `core/src/scanner/patterns.rs` are compiled lazily (`std::sync::LazyLock` or `OnceLock`).

### Adding New Detection Rules
When contributing new cryptographic detection rules to `core/src/scanner/patterns.rs`:
1. Assign a unique, uppercase rule identifier (e.g., `PQC-ASYM-DH-001`).
2. Specify the correct `QuantumRisk` variant (`Safe`, `Partial`, `Hybrid`, `Vulnerable`, or `Unknown`).
3. Set an appropriate default severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`).
4. Provide a clear, actionable remediation message referencing relevant NIST or RFC standards.
5. Include a corresponding unit test in `core/src/tests.rs` verifying positive and negative matches.

---

## 4. Pull Request Workflow

1. **Fork and Branch**: Create a feature branch originating from `main` using descriptive naming:
   - `feat/ml-dsa-expansion`
   - `fix/sarif-uri-normalization`
   - `docs/clarify-concolic-bounds`
2. **Commit Conventions**: Use Conventional Commits formatting:
   - `feat(scanner): add NIST FIPS 206 FN-DSA pattern detection`
   - `fix(cli): correct exit code handling for baseline differential audits`
   - `docs(engine): expand Landauer thermodynamic derivation`
3. **Run Pre-Commit Checks**: Ensure `cargo fmt`, `cargo clippy`, and `cargo test` pass without warnings.
4. **Submit PR**: Open a pull request against the `main` branch. Provide a comprehensive description detailing the problem solved, testing methodology, and any potential breaking changes.

---

## 5. Licensing and Copyright

PQCanary is licensed under the Apache License, Version 2.0. By submitting a pull request, you agree that your contributions will be licensed under the Apache-2.0 terms with copyright attributed to Matvei Igumnov.
