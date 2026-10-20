# AST Traversal and Pattern Matching Engine

This document specifies the concrete syntax tree (CST) traversal mechanisms, multi-language Tree-sitter parsers, 193+ pattern catalog, suppression comment grammar, and Shannon entropy heuristics used by the PQCanary static analysis engine.

---

## 1. Engine Architecture

The AST and Pattern Matching Engine operates at the core of PQCanary's static analysis pipeline. It combines two complementary analysis techniques:
1. **Concrete Syntax Tree (CST) Traversal**: Deep semantic parsing using Tree-sitter grammar parsers across eight programming languages to extract function calls, import statements, variable assignments, and cryptographic parameters without lexical ambiguity.
2. **High-Precision Pattern Catalog**: 193+ compiled regular expressions evaluated with streaming heuristics, Shannon entropy secret scoring, and logging-text false-positive suppression.

```
                           Source File Input
                                   |
                                   v
             +-------------------------------------------+
             |           Language Dispatcher             |
             +-------------------------------------------+
               /           |           |           \
              v            v           v            v
           Rust/C/C++  Python/Java  JS/TS/Go   Manifest/Cert
              |            |           |            |
              v            v           v            v
        +------------------------------------------------+
        |         Tree-Sitter Concrete Syntax Tree       |
        +------------------------------------------------+
                               |
                               v
        +------------------------------------------------+
        |       Pattern Matcher & Shannon Entropy        |
        |     (193+ Rules across 22 Security Groups)     |
        +------------------------------------------------+
                               |
                               v
        +------------------------------------------------+
        |           Suppression & Filter Gate            |
        |  - // pqcanary:ignore rule-id                  |
        |  - Comment & Log/Help text filter              |
        |  - Finding Fingerprint & Deduplication         |
        +------------------------------------------------+
                               |
                               v
                        Verified Findings
```

---

## 2. Supported Languages and AST Parsers

The Tree-sitter engine generates language-specific abstract syntax trees for the following targets:

| Language | File Extensions | Tree-Sitter Parser | Key Semantic Extractions |
| :--- | :--- | :--- | :--- |
| **Rust** | `.rs` | `tree-sitter-rust` | FFI declarations (`extern "C"`), unsafe blocks, crypto crates |
| **TypeScript** | `.ts`, `.tsx` | `tree-sitter-typescript` | Node.js `crypto` calls, Web Crypto API, JWT sign/verify |
| **JavaScript** | `.js`, `.jsx`, `.mjs` | `tree-sitter-javascript` | Browser crypto, dynamic imports, hardcoded tokens |
| **Python** | `.py` | `tree-sitter-python` | `cryptography`, `hashlib`, `PyCryptodome`, `ssl` contexts |
| **Go** | `.go` | `tree-sitter-go` | `crypto/tls`, `crypto/rsa`, `crypto/ecdsa`, `golang.org/x/crypto` |
| **Java** | `.java` | `tree-sitter-java` | `java.security`, `javax.crypto`, BouncyCastle provider calls |
| **C / C++** | `.c`, `.cpp`, `.h`, `.hpp` | `tree-sitter-c`, `cpp` | OpenSSL EVP APIs, manual bitshifts, buffer copy primitives |

---

## 3. Pattern Catalog Categories

The 193+ detection rules are partitioned into 22 distinct security domains:

| Category Name | Typical Rules & Vulnerability Classes | Default Severity | Quantum Risk |
| :--- | :--- | :--- | :--- |
| **Post-Quantum Cryptography** | ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon (FIPS 206) | INFO | SAFE |
| **Hybrid Key Encapsulation** | X25519MLKEM768, SecP256r1MLKEM768, draft Kyber hybrids | INFO | HYBRID |
| **Asymmetric Public Key** | RSA-1024/2048/4096, Diffie-Hellman, DSA, ElGamal | CRITICAL / HIGH | VULNERABLE |
| **Elliptic Curve Cryptography** | ECDSA, ECDH, Ed25519, Secp256k1, NIST P-256/P-384 | HIGH | VULNERABLE |
| **Symmetric Ciphers** | DES, 3DES, RC4, Blowfish, AES-ECB, ChaCha20 | CRITICAL to LOW | SAFE / VULNERABLE |
| **Cryptographic Hash Functions** | MD5, SHA-1, RIPEMD160, SHA-256, SHA-3, BLAKE3 | HIGH to INFO | SAFE / VULNERABLE |
| **Key Derivation (KDF)** | PBKDF2 (low iteration count), scrypt, Argon2id, HKDF | MEDIUM / INFO | SAFE |
| **Certificates and Key Material** | Hardcoded private keys (PKCS#1, PKCS#8), self-signed certs | CRITICAL / HIGH | VULNERABLE |
| **Hardcoded Secrets** | AWS access keys, GitHub PATs, generic API tokens, high entropy | CRITICAL / HIGH | UNKNOWN |
| **JSON Web Tokens (JWT)** | `none` algorithm, weak HMAC-SHA256 secret, missing verification | CRITICAL / HIGH | VULNERABLE |
| **TLS and Transport Security** | SSL 2.0/3.0, TLS 1.0/1.1, insecure cipher suites, disabled verify | CRITICAL / HIGH | VULNERABLE |
| **Cloud Key Management (KMS)** | AWS KMS RSA keys, Azure KV RSA keys, GCP Cloud KMS RSA keys | HIGH | VULNERABLE |
| **Dependency Manifests** | Vulnerable npm, Cargo, pip, Go modules with known crypto CVEs | HIGH / MEDIUM | VULNERABLE |
| **Pseudo-Random Number Gen** | `Math.random()`, `rand()`, `random.random()`, unseeded PRNG | HIGH | VULNERABLE |
| **Smart Contracts (Solidity)** | `ecrecover` signature malleability, weak block timestamp entropy | HIGH | VULNERABLE |
| **SSH Transport & Config** | Classical SSH host keys (`ssh-rsa`, `ecdsa-sha2-nistp256`) | HIGH | VULNERABLE |
| **Middleware & Reverse Proxy** | Nginx, Envoy, Traefik TLS configs lacking PQC hybrid groups | MEDIUM | VULNERABLE |
| **Real-World Cryptographic CVEs** | Heartbleed, Logjam, DROWN, ROBOT, ROCA, CurveBall patterns | CRITICAL | VULNERABLE |
| **Quantum Vulnerability Research**| Stateful hash reuse (XMSS/LMS), Grover key-length bounds | HIGH | VULNERABLE |
| **Bleeding-Edge Research** | Fujisaki-Okamoto oracle attacks, psychic signatures, downchecks | HIGH | VULNERABLE |
| **Thermodynamic Side Channels** | Unmasked cryptographic operations, non-reversible gate logic | MEDIUM | PARTIAL |
| **Hardware & Timing Channels** | Non-constant-time comparisons (`memcmp`, `==` on signatures) | HIGH | VULNERABLE |

---

## 4. Shannon Entropy Secret Scoring

To detect previously undisclosed API keys and hardcoded private keys without relying exclusively on known regex prefixes, PQCanary calculates the Shannon entropy:

$$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the observed frequency of byte $x_i$ within candidate string $X$.
- Strings with length $\ge 20$ characters and Shannon entropy $H(X) > 4.5$ bits/char are flagged for inspection.
- Entropy matches undergo false-positive pruning to eliminate base64 image data, binary hashes, and hexadecimal UUID strings.

---

## 5. Inline Suppression Grammar

Developers can suppress false positives or accepted risks directly in source code using inline comments. The suppression applies to either the current line or the immediately following line:

### Syntax Variations

```
// Suppress by specific rule ID
// pqcanary:ignore PQC-ASYM-RSA-001

// Suppress with rationale
// pqcanary:ignore PQC-ASYM-RSA-001 -- legacy backwards compatibility test fixture

// Suppress by entire category
# pqcanary:ignore category:Asymmetric Public Key

// Block comment suppression (C / C++ / Java / Rust)
/* pqcanary:ignore PQC-HASH-MD5-001 */

// HTML / XML comment suppression
<!-- pqcanary:ignore PQC-CERT-PRIVKEY -->
```

### Automatic Context Filtering
The engine automatically ignores:
- Standard log statements (`console.log`, `logger.info`, `println!`).
- CLI usage, help texts, and manual strings (`--help`, `synopsis`, `@param`).
- Documentation files (`.md`, `.txt`, `.rst`, files located in `docs/`).
