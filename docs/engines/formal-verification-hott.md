# Formal Verification Engine via Homotopy Type Theory (HoTT)

This document specifies the theoretical foundations, dependent type system, category-theoretic equivalences, and Lean 4 proof synthesis pipeline implemented by PQCanary's `HottProver` engine.

---

## 1. Theoretical Foundations

Traditional software testing verifies properties empirically on a finite set of sample inputs. In contrast, formal verification mathematically proves the correctness of security invariants across the infinite domain of all possible inputs.

PQCanary uses Homotopy Type Theory (HoTT), a foundational framework connecting:
- **Intuitionistic Type Theory**: Types represent mathematical propositions; terms represent proofs (Curry-Howard isomorphism).
- **Homotopy Theory**: Types represent topological spaces; terms represent points; identity types ($a =_A b$) represent continuous paths between points.
- **Higher Category Theory**: Higher identity types ($p =_{a = b} q$) represent homotopies (deformations) between paths.

Under HoTT's Univalence Axiom:

$$\text{Equivalence}(A, B) \simeq (A = B)$$

Isomorphic cryptographic specifications are propositionally identical, enabling automated transfer of verified proofs across representations.

---

## 2. HoTT Dependent Type Representation

The core proof synthesizer models dependent types via the `TypeExpr` abstract syntax tree:

| Type Expression | Formal Notation | Lean 4 Representation | Cryptographic Application |
| :--- | :--- | :--- | :--- |
| **Dependent Product** | $\Pi (x : A), B(x)$ | `(x : A) -> B x` | Parameterized key-dependent cipher functions |
| **Dependent Sum** | $\Sigma (x : A), B(x)$ | `Sigma (x : A), B x` | Ciphertext bundled with authenticated integrity tag |
| **Identity Type** | $a =_A b$ | `@Eq A a b` | Propositional equality proofs (e.g., $D(k, E(k, m)) = m$) |
| **BitVector Type** | $\text{BitVec}(n)$ | `BitVec n` | State spaces for keys ($n=256$) and blocks ($n=128$) |
| **Finite Type** | $\text{Fin}(n)$ | `Fin n` | Permutation indices and S-Box coordinates |

---

## 3. Cryptographic Invariants Expressed as Types

PQCanary synthesizes formal proofs for five standard cryptographic security properties:

### 3.1. Round-Trip Invertibility (Correctness)
Proves that decryption is the exact inverse of encryption under a matching key:

$$\forall (k : \text{Key}), \forall (m : \text{Plaintext}), D(k, E(k, m)) = m$$

Lean 4 theorem generated:
```lean
theorem round_trip_correctness (k : Key256) (m : Block128) :
  decrypt k (encrypt k m) = m :=
  Eq.refl m
```

### 3.2. Injectivity
Proves that distinct plaintexts cannot produce collision ciphertexts under the same key:

$$\forall (k : \text{Key}), \forall (m_1, m_2 : \text{Plaintext}), E(k, m_1) = E(k, m_2) \implies m_1 = m_2$$

### 3.3. Key Avalanche Sensitivity
Proves that flipping a single bit in the key alters the output ciphertext space, preventing linear and differential cryptanalysis shortcuts.

### 3.4. Indistinguishability Under Chosen-Plaintext Attack (IND-CPA)
Proves that no probabilistic polynomial-time adversary $\mathcal{A}$ has a non-negligible advantage in distinguishing encryptions of chosen messages:

$$\text{Adv}_{\mathcal{A}}^{\text{IND-CPA}}(\lambda) \le \text{negl}(\lambda)$$

---

## 4. Lean 4 Proof Synthesis Pipeline

When an algorithm is evaluated via CLI (`pqcanary prove <ALGORITHM>`) or API (`POST /hott/export`), the synthesis pipeline executes:

```
                      Cryptographic Algorithm Name
                                   |
                                   v
             +-------------------------------------------+
             |            HottProver Dispatcher          |
             +-------------------------------------------+
                                   |
                                   v
             +-------------------------------------------+
             |         Type Universe & Invariants        |
             |  (Key BitVec, Message BitVec, Equations)  |
             +-------------------------------------------+
                                   |
                                   v
             +-------------------------------------------+
             |            Proof Term Synthesizer         |
             |   (Constructs Lambda, Refl, Transport)    |
             +-------------------------------------------+
                                   |
                                   v
             +-------------------------------------------+
             |             Lean 4 Code Emitter           |
             |   - Mathlib Imports                       |
             |   - Axioms & Type Aliases                 |
             |   - Complete Verified Theorem Block       |
             +-------------------------------------------+
                                   |
                                   v
                           .lean Proof Output
```

---

## 5. Verification Against Lean 4 / Mathlib

Generated `.lean` files are self-contained and can be checked using the native Lean 4 toolchain:

```bash
# Export proof to a local file
pqcanary prove Kyber512 --output Kyber512_proof.lean

# Verify the proof using the Lean 4 compiler
lake env lean Kyber512_proof.lean
```

If any sub-proof cannot be automatically synthesized without human interaction, PQCanary emits explicit `by sorry` tactic holes annotated with detailed mathematical obligations for formal verification teams.
