# PQCanary Formal Verification Engine (Lean 4 & HoTT)

This directory contains interactive theorem prover specifications in **Lean 4** implementing Homotopy Type Theory (HoTT) verification for Post-Quantum Cryptographic primitives (NIST FIPS 203 / ML-KEM).

## Building & Verifying Proofs

Prerequisites: [Lean 4 & Lake](https://lean-lang.org/) (4.8.0 or newer).

```bash
cd proofs
lake build
lake run verify_pqc
```

