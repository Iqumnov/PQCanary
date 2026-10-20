# Concolic and Symbolic Execution Engine

This document specifies the architecture, SSA Intermediate Representation, symbolic memory model, and Microsoft Z3 SMT solver integration of PQCanary's concolic execution engine.

---

## 1. Concolic Testing Methodology

Concolic (concrete + symbolic) execution combines concrete program execution with symbolic constraint solving to explore program paths and prove cryptographic safety invariants.

While pure static analysis may report false positives due to complex control flow, PQCanary's concolic engine generates mathematical reachability proofs for candidate vulnerabilities:

```
                            Source Code Snippet
                                     |
                                     v
                       +---------------------------+
                       |      Tree-Sitter CST      |
                       +---------------------------+
                                     |
                                     v
                       +---------------------------+
                       |     SSA Lifter Engine     |
                       |  (Variable Versioning,    |
                       |   Basic Blocks, CFG)      |
                       +---------------------------+
                                     |
                                     v
                       +---------------------------+
                       |   Symbolic Memory Model   |
                       |  (Pointers, Buffer Sizes, |
                       |   Symbolic Taint Arrays)  |
                       +---------------------------+
                                     |
                                     v
                       +---------------------------+
                       |      Z3 SMT Solver        |
                       | (Path Condition Negation, |
                       |  Bitvector Constraints)   |
                       +---------------------------+
                                     |
                        +------------+------------+
                        |                         |
                        v                         v
                 [SAT: Vulnerable]         [UNSAT: Safe]
                 Concrete Counter-        Mathematically
                 example Input            Verified Invariant
```

---

## 2. SSA Intermediate Representation (IR)

The `ssa_lifter` module transforms AST function bodies into a flattened control flow graph (CFG) of basic blocks populated by Static Single Assignment instructions:

```rust
pub enum SsaInstruction {
    Alloc { var: String, size_bytes: usize },
    Assign { var: String, val: SsaValue },
    Load { dest: String, src_ptr: String, offset: SsaValue },
    Store { dest_ptr: String, offset: SsaValue, value: SsaValue },
    BinOp { dest: String, op: BinaryOperator, left: SsaValue, right: SsaValue },
    Branch { condition: SsaValue, true_label: String, false_label: String },
    Jump { target_label: String },
    Call { dest: Option<String>, func_name: String, args: Vec<SsaValue> },
    Return { val: Option<SsaValue> },
}
```

### SSA Transformations
1. **Single Assignment**: Variables are uniquely indexed upon mutation (e.g., $x_0, x_1, x_2$).
2. **$\phi$-Node Placement**: Branch convergences introduce join nodes that select variable versions based on the executing path condition.
3. **Dead Code Elimination**: Basic blocks unreachable from the entry node are pruned before symbolic analysis.

---

## 3. Symbolic Memory Model

The symbolic memory model abstractly represents heap and stack allocations:
- **Allocation Descriptors**: Tracks base address, allocated capacity, and symbolic bounds for every buffer.
- **Symbolic Pointer Arithmetic**: A pointer dereference $p + i$ produces a symbolic expression representing the resolved address.
- **Out-of-Bounds Detection**: For any load or store instruction targeting buffer $B$ at offset $i$:

$$\text{Safety Condition} = (i \ge 0) \land (i < \text{capacity}(B))$$

If the Z3 SMT solver finds a satisfying assignment ($\text{SAT}$) for:

$$\text{Path Condition} \land \neg(\text{Safety Condition})$$

The engine flags an exploitable buffer overflow or out-of-bounds memory vulnerability and outputs the exact counterexample input vector.

---

## 4. Microsoft Z3 SMT Solver Integration

PQCanary interfaces with Z3 via native FFI bindings or an isolated process bridge:
1. **Bitvector Logic (QF_BV)**: Models 8-bit, 32-bit, and 64-bit integer overflows, circular shifts, and bitwise XOR operations typical of cryptographic ciphers.
2. **Array Theory (QF_ABV)**: Encodes non-constant array lookups (such as AES S-Box substitutions or lattice polynomial coefficient tables).
3. **Timeout Controls**: Enforces a strict per-query timeout (default: 5,000 milliseconds) to prevent execution hangs on NP-hard constraint systems.

---

## 5. Automated Counterexample Generation

When a vulnerability is verified by the solver, PQCanary returns a concrete evaluation payload:
- **Input Variables**: The specific byte or integer sequence that triggers the target branch.
- **Trace Path**: The sequence of branch decisions executed from entry point to the vulnerability.
- **Remediation Suggestion**: Automatic patch boundary recommending safe bounds checking or constant-time memory comparisons.
