## Summary

Provide a brief description of the changes introduced by this pull request.

Closes # (issue number)

---

## Type of Change

- [ ] **Bug fix** (non-breaking change fixing an issue or false-positive/negative)
- [ ] **New feature** (non-breaking change adding a new capability or medium)
- [ ] **Cryptographic rule / pattern** (new detection pattern or NIST FIPS mapping)
- [ ] **Formal verification / SMT solver** (enhancement to Z3, HoTT Lean 4, or AST engine)
- [ ] **Performance optimization** (reduction in memory allocations, latency, or binary size)
- [ ] **Documentation update** (improvements to docs, guides, or examples)
- [ ] **Breaking change** (fix or feature that causes existing functionality or CLI flags to change)

---

## Safety & Architectural Guarantees

- [ ] **Memory Safety Guaranteed**: This PR respects `#![forbid(unsafe_code)]` across all Rust crates. No `unsafe` blocks are introduced.
- [ ] **Air-Gap Integrity**: The scanning engine does not emit unexpected outbound network calls or telemetry during local analysis.
- [ ] **Deterministic Results**: Given the same input files, scan results and CBOM fingerprints are 100% reproducible.

---

## Testing & Verification Checklist

- [ ] `cargo test --workspace` passes without errors or regressions.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` runs cleanly with zero warnings.
- [ ] `cargo fmt --check` passes.
- [ ] If modifying the web dashboard (`web/`), `pnpm run build` completes cleanly.
- [ ] Added unit or integration tests covering new code paths and edge cases.
- [ ] Added or updated relevant documentation in `docs/`.

---

## Cryptographic & Security Impact

Does this PR alter how cryptographic risk is calculated, modify Landauer thermodynamic limits, or change compliance classifications? If so, please summarize the mathematical or regulatory rationale.

