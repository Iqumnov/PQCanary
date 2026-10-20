# Post-Quantum Cryptographic Standards Mapping

This document details how PQCanary aligns with NIST Federal Information Processing Standards (FIPS), the NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0), White House OMB M-23-02, and Mosca's Theorem for Harvest-Now-Decrypt-Later (HNDL) risk calculations.

---

## 1. NIST Post-Quantum Cryptography Standards

PQCanary evaluates cryptographic assets against the final standards published by the National Institute of Standards and Technology (NIST):

| Standard | Algorithm Name | Mathematical Primitive | Parameter Sets | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **FIPS 203** | **ML-KEM** (Kyber) | Module Learning With Errors (M-LWE) | ML-KEM-512 (Cat 1)<br>ML-KEM-768 (Cat 3)<br>ML-KEM-1024 (Cat 5) | General public-key encryption and key encapsulation |
| **FIPS 204** | **ML-DSA** (Dilithium) | Module Learning With Errors (M-LWE) | ML-DSA-44 (Cat 2)<br>ML-DSA-65 (Cat 3)<br>ML-DSA-87 (Cat 5) | General digital signatures for identity and transactions |
| **FIPS 205** | **SLH-DSA** (SPHINCS+) | Stateless Hash-Based Trees | SLH-DSA-SHA2-128/192/256<br>SLH-DSA-SHAKE-128/192/256 | High-assurance signatures without lattice assumptions |
| **FIPS 206** | **FN-DSA** (Falcon) | Fast-Fourier Lattice Vectors | Falcon-512<br>Falcon-1024 | Compact digital signatures for constrained bandwidth |

---

## 2. NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)

For National Security Systems (NSS) and high-consequence enterprise environments, the US National Security Agency mandates strict migration timelines under CNSA 2.0:

| Security Domain | Classical Requirement | CNSA 2.0 Algorithm | Adoption Milestone | Exclusivity Deadline |
| :--- | :--- | :--- | :--- | :--- |
| **Software & Firmware Signing** | RSA-4096 / ECDSA P-384 | ML-DSA-87 / SLH-DSA-256 | Immediate (2025) | 2030 (Classical Forbidden) |
| **Web Browsers & Servers (TLS)** | RSA-2048 / ECDHE P-256 | ML-KEM-1024 & ML-DSA-87 | Preferred (2026) | 2033 (Classical Forbidden) |
| **Cloud Key Management (KMS)** | AES-128 / RSA-2048 | AES-256 / ML-KEM-1024 | Planning (2025) | 2031 (Classical Forbidden) |
| **Network Infrastructure (VPN)** | IKEv2 / IPsec ECDHE | ML-KEM-1024 / PQC Hybrid | Immediate (2026) | 2030 (Classical Forbidden) |
| **Symmetric Encryption** | AES-128 / AES-192 | AES-256 | Mandatory | Mandatory |
| **Cryptographic Hashing** | SHA-256 | SHA-384 / SHA-512 | Mandatory | Mandatory |

PQCanary flags any asset violating CNSA 2.0 milestones as `CRITICAL` or `HIGH` based on target year boundaries.

---

## 3. Harvest-Now-Decrypt-Later (HNDL) and Mosca's Theorem

State-sponsored adversaries routinely intercept and store encrypted network traffic traversing global transit routes today, intending to decrypt it once a Cryptographically Relevant Quantum Computer (CRQC) becomes operational.

PQCanary models this threat using Dr. Michele Mosca's Theorem:

$$\text{Risk Window} = (X + Y) - Z$$

Where:
- $X$ = Migration time: Years required to audit, re-architect, and deploy post-quantum cryptography across an organization.
- $Y$ = Data shelf-life: Years that encrypted data must legally, competitively, or operationally remain confidential.
- $Z$ = Quantum threat horizon: Years until a Cryptographically Relevant Quantum Computer becomes capable of breaking RSA/ECC via Shor's algorithm.

```
Time Horizon (Years):
[Today] ------------ X (Migration) ------------> [PQC Deployed]
[Today] ------------------------ Y (Shelf-Life) ------------------------> [Data Stale]
[Today] ---------------- Z (CRQC Arrival) ----------------> [Quantum Threat Active]

Condition: If (X + Y) > Z, data harvested today WILL be decrypted in the future.
```

### Risk Playbook
Using `pqcanary hndl -x <MIGRATION> -y <SHELF_LIFE> -z <THREAT>`, PQCanary calculates the vulnerability window and generates remediation playbooks for Nginx, Envoy, OpenSSH, and AWS KMS.

---

## 4. Quantum Risk Assessment and Migration Model (QRAMM)

PQCanary provides an automated implementation of the QRAMM framework, assigning organizations a composite Post-Quantum Readiness Score (0 to 100) based on five capability dimensions:

1. **Cryptographic Discovery & Inventory (25%)**: Completeness of CBOM asset identification across source, binaries, and network endpoints.
2. **Vulnerability Mitigation (25%)**: Proportion of classical asymmetric keys (RSA, ECC) replaced with NIST PQC or hybrid algorithms.
3. **Cryptographic Agility (20%)**: Decoupling of cipher implementations from business logic to enable seamless key and algorithm rotation.
4. **Hardware & Physical Security (15%)**: Protection against thermodynamic and differential fault side channels.
5. **Policy & Compliance Governance (15%)**: Automated CI/CD quality gates preventing classical cryptographic regressions.
