//! Comprehensive Cryptographic Pattern Catalog & Detection Engine
//!
//! Provides 193+ high-precision cryptographic detection patterns across 22 categories,
//! covering Post-Quantum, Hybrid, Asymmetric, Symmetric, Hash, MAC, KDF, Certificates & Keys,
//! Hardcoded Secrets, JWT, TLS/SSL, Cloud KMS, Dependency Manifests, PRNG, Smart Contracts,
//! SSH Configuration, Cloud/Kubernetes/Proxy Middleware, Real-World Cryptographic CVEs,
//! Quantum Vulnerability Research (Stateful Hash Reuse, Grover Bounds, HNDL),
//! and Bleeding-Edge Cryptographic Research (Downcheck, Psychic Signatures, Fujisaki-Okamoto Oracles).
//!
//! Includes confidence scoring, quantum risk rating, source context extraction,
//! automated credential sanitization, and inline suppression (// pqcanary:ignore) support.

use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QuantumRisk {
    Safe,
    Partial,
    Hybrid,
    Vulnerable,
    Unknown,
}

impl QuantumRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuantumRisk::Safe => "SAFE",
            QuantumRisk::Partial => "PARTIAL",
            QuantumRisk::Hybrid => "HYBRID",
            QuantumRisk::Vulnerable => "VULNERABLE",
            QuantumRisk::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PatternDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub regex_pattern: &'static str,
    pub severity: &'static str,
    pub quantum_risk: QuantumRisk,
    pub default_confidence: Confidence,
    pub description: &'static str,
    pub remediation: &'static str,
    pub tags: &'static [&'static str],
}

pub struct CompiledPattern {
    pub def: PatternDefinition,
    pub regex: Regex,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PatternMatch {
    pub rule_id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub quantum_risk: String,
    pub confidence: String,
    pub file_path: String,
    pub line_number: u32,
    pub column_number: u32,
    pub matched_text: String,
    pub snippet: String,
    pub description: String,
    pub remediation: String,
    pub tags: Vec<String>,
    pub fingerprint: String,
}

/// Catalog of 193+ Enterprise Cryptographic Detection Patterns
pub static ALL_PATTERNS: LazyLock<Vec<CompiledPattern>> = LazyLock::new(|| {
    let raw_defs: Vec<PatternDefinition> = vec![
        // ─── 1. POST-QUANTUM CRYPTOGRAPHY (SAFE / INFO) ──────────────────────
        PatternDefinition {
            id: "PQC-MLKEM-001",
            name: "ML-KEM Key Encapsulation (FIPS 203)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(ML-KEM-512|ML-KEM-768|ML-KEM-1024|Kyber512|Kyber768|Kyber1024|pqc_kem_kyber)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 203 standardized post-quantum key encapsulation mechanism.",
            remediation: "Compliant post-quantum key encapsulation algorithm. Maintain according to NIST FIPS 203.",
            tags: &["pqc", "fips-203", "kem", "lattice", "kyber"],
        },
        PatternDefinition {
            id: "PQC-MLDSA-001",
            name: "ML-DSA Digital Signatures (FIPS 204)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(ML-DSA-44|ML-DSA-65|ML-DSA-87|Dilithium2|Dilithium3|Dilithium5|pqc_sig_dilithium)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 204 standardized post-quantum digital signature algorithm.",
            remediation: "Compliant post-quantum digital signature algorithm. Maintain according to NIST FIPS 204.",
            tags: &["pqc", "fips-204", "signatures", "lattice", "dilithium"],
        },
        PatternDefinition {
            id: "PQC-SLHDSA-001",
            name: "SLH-DSA Stateless Hash-Based Signatures (FIPS 205)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(SLH-DSA-128f|SLH-DSA-128s|SLH-DSA-192f|SLH-DSA-192s|SLH-DSA-256f|SLH-DSA-256s|SPHINCS\+|SPHINCSplus)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 205 stateless hash-based digital signature algorithm.",
            remediation: "Compliant post-quantum hash-based signature. Suitable for high-assurance code signing.",
            tags: &["pqc", "fips-205", "signatures", "hash-based", "sphincs"],
        },
        PatternDefinition {
            id: "PQC-FNDSA-001",
            name: "FN-DSA Falcon Signatures (FIPS 206)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(FN-DSA-512|FN-DSA-1024|Falcon-512|Falcon-1024)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 206 fast-Fourier lattice-based digital signature scheme.",
            remediation: "Compliant post-quantum signature. Note: requires constant-time floating point execution.",
            tags: &["pqc", "fips-206", "signatures", "falcon"],
        },
        PatternDefinition {
            id: "PQC-XMSS-001",
            name: "XMSS Stateful Hash-Based Signatures",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(XMSS-SHA2_10_256|XMSS-SHAKE_20_256|XMSSMT|xmss_fast)\b"#,

            severity: "LOW",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST SP 800-208 / RFC 8391 stateful hash-based digital signature.",
            remediation: "Quantum-safe stateful signature. Caution: ensure strict non-volatile key state synchronization to prevent one-time-key reuse.",
            tags: &["pqc", "stateful-hash", "xmss", "sp-800-208"],
        },
        PatternDefinition {
            id: "PQC-LMS-001",
            name: "LMS/HSS Stateful Hash-Based Signatures",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(LMS_SHA256_M24_H10|LMS_SHA256|HSS_LMS|Leighton-Micali)\b"#,

            severity: "LOW",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST SP 800-208 / RFC 8554 Leighton-Micali Signature scheme.",
            remediation: "Quantum-safe stateful signature. Ensure hardware security module backing for leaf state counters.",
            tags: &["pqc", "stateful-hash", "lms", "hss"],
        },

        // ─── 2. HYBRID CRYPTOGRAPHY (TRANSITION / DEFENSE-IN-DEPTH) ──────────
        PatternDefinition {
            id: "HYBRID-KEM-001",
            name: "X25519 + ML-KEM Hybrid Key Exchange",
            category: "Hybrid Cryptography",
            regex_pattern: r#"(?i)\b(X25519MLKEM768|X25519Kyber768Draft00|SecP256r1MLKEM768|hybrid_kem)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Hybrid,
            default_confidence: Confidence::High,
            description: "Hybrid post-quantum key exchange combining classical elliptic curve with ML-KEM.",
            remediation: "Best practice transition mechanism recommended by NIST, BSI, and NSA CNSA 2.0.",
            tags: &["hybrid", "pqc", "x25519", "ml-kem", "key-exchange"],
        },
        PatternDefinition {
            id: "HYBRID-SIG-001",
            name: "ECDSA + ML-DSA Composite Signatures",
            category: "Hybrid Cryptography",
            regex_pattern: r#"(?i)\b(MLDSA65-ECDSA-P256|Dilithium3-ECDSA|composite_signature|dual_signature)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Hybrid,
            default_confidence: Confidence::High,
            description: "Dual-signing combining classical ECDSA with post-quantum ML-DSA.",
            remediation: "Compliant hybrid signature scheme providing cryptographic defense-in-depth.",
            tags: &["hybrid", "pqc", "ecdsa", "ml-dsa", "signatures"],
        },
        PatternDefinition {
            id: "HYBRID-SIG-002",
            name: "RSA + ML-DSA Composite Signatures",
            category: "Hybrid Cryptography",
            regex_pattern: r#"(?i)\b(MLDSA65-RSA3072|Dilithium3-RSA|composite_rsa_pqc)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Hybrid,
            default_confidence: Confidence::High,
            description: "Dual-signing combining classical RSA-3072+ with post-quantum ML-DSA.",
            remediation: "Compliant hybrid signature during transition phase.",
            tags: &["hybrid", "pqc", "rsa", "ml-dsa"],
        },

        // ─── 3. ASYMMETRIC ENCRYPTION & SIGNATURES (VULNERABLE TO SHOR) ──────
        PatternDefinition {
            id: "RSA-1024",
            name: "RSA-1024 Key Size (Critically Broken)",
            category: "Asymmetric Encryption",
            regex_pattern: r#"(?i)\b(RSA[_\-\s]?1024|1024[\s\-]?bit[\s\-]?RSA|KEY_SIZE\s*=\s*1024|key_size:\s*1024)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "1024-bit RSA key length. Broken classically by factorization and immediately broken by Shor's algorithm.",
            remediation: "Immediately replace with ML-KEM-768 or ML-DSA-65. Minimum temporary classical fallback is RSA-3072.",
            tags: &["rsa", "broken", "critical", "factorization", "shor"],
        },
        PatternDefinition {
            id: "RSA-2048",
            name: "RSA-2048 Key Size (Quantum Vulnerable)",
            category: "Asymmetric Encryption",
            regex_pattern: r#"(?i)\b(RSA[_\-\s]?2048|2048[\s\-]?bit[\s\-]?RSA|KEY_SIZE\s*=\s*2048|key_size:\s*2048)\b"#,

            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "2048-bit RSA key. Acceptable classically until 2030, but completely compromised by Shor's quantum algorithm.",
            remediation: "Migrate to ML-KEM-768 (key exchange) or ML-DSA-65 (signatures).",
            tags: &["rsa", "quantum-vulnerable", "shor"],
        },
        PatternDefinition {
            id: "RSA-001",
            name: "RSA Algorithm Usage",
            category: "Asymmetric Encryption",
            regex_pattern: r#"(?i)\b(RSA_PKCS1_PADDING|RSA_NO_PADDING|RSASSA-PKCS1-v1_5|RSA_generate_key|rsa\.GenerateKey|RSA\.generate|RSAPublicKey|RSAPrivateKey|crypto/rsa)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "RSA asymmetric algorithm detected. Vulnerable to polynomial-time Shor's quantum algorithm factorization.",
            remediation: "Migrate asymmetric operations to NIST post-quantum standards: ML-KEM (FIPS 203) or ML-DSA (FIPS 204).",
            tags: &["rsa", "quantum-vulnerable", "shor", "nist-migration"],
        },
        PatternDefinition {
            id: "ECC-001",
            name: "Elliptic Curve Cryptography (ECDSA/ECDH)",
            category: "Asymmetric Encryption",
            regex_pattern: r#"(?i)\b(ECDSA|ECDH|secp256k1|secp256r1|secp384r1|prime256v1|P-256|P-384|P-521|crypto/ecdsa|crypto/elliptic)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Elliptic curve cryptography detected. Discrete logarithms over elliptic curves are broken by Shor's algorithm.",
            remediation: "Transition key exchange to ML-KEM (FIPS 203) and signatures to ML-DSA (FIPS 204).",
            tags: &["ecc", "ecdsa", "ecdh", "quantum-vulnerable", "shor"],
        },
        PatternDefinition {
            id: "ED25519-001",
            name: "Ed25519 / Curve25519 (Quantum Vulnerable)",
            category: "Asymmetric Encryption",
            regex_pattern: r#"(?i)\b(ed25519|curve25519|x25519\b|crypto/ed25519)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Edwards/Montgomery curve 25519 detected. Highly secure classically, but fully vulnerable to Shor's algorithm.",
            remediation: "Use X25519MLKEM768 hybrid mode or transition directly to ML-KEM-768 / ML-DSA-65.",
            tags: &["curve25519", "ed25519", "quantum-vulnerable"],
        },
        PatternDefinition {
            id: "DSA-001",
            name: "DSA Digital Signature Algorithm (Deprecated & Vulnerable)",
            category: "Asymmetric Encryption",
            regex_pattern: r#"(?i)\b(dsa_key|crypto/dsa|DSAParameters|ssh-dss|EVP_PKEY_DSA|MessageDigestAlgorithms\.DSA)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "DSA algorithm is deprecated by NIST SP 800-131A Rev 2 and broken by Shor's algorithm.",
            remediation: "Replace DSA immediately with ML-DSA-44 or Ed25519.",
            tags: &["dsa", "deprecated", "broken", "shor"],
        },
        PatternDefinition {
            id: "DH-001",
            name: "Diffie-Hellman Key Exchange",
            category: "Asymmetric Encryption",
            regex_pattern: r#"(?i)\b(DiffieHellman|DHE-RSA|ECDHE-RSA|DH_generate_key|crypto/dh|EVP_PKEY_DH)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Finite-field Diffie-Hellman key exchange is broken by quantum computers running Shor's algorithm.",
            remediation: "Migrate to ML-KEM (FIPS 203) or hybrid X25519MLKEM768 key encapsulation.",
            tags: &["dh", "diffie-hellman", "quantum-vulnerable"],
        },

        // ─── 4. SYMMETRIC ENCRYPTION ─────────────────────────────────────────
        PatternDefinition {
            id: "AES-ECB-001",
            name: "AES-ECB Mode (Electronic Codebook - Insecure)",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(AES[_\-\/]?ECB|AES-128-ECB|AES-256-ECB|ECB_MODE|CipherMode\.ECB)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Electronic Codebook (ECB) mode preserves data patterns and leaks plaintext structure.",
            remediation: "Never use ECB mode. Migrate immediately to AES-256-GCM or ChaCha20-Poly1305 (AEAD).",
            tags: &["aes", "ecb", "insecure-mode", "leakage"],
        },
        PatternDefinition {
            id: "DES-001",
            name: "DES Encryption (Single DES - Broken)",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(DES_ecb_encrypt|DES_cbc_encrypt|crypto/des\b|DESCryptoServiceProvider|"DES"\b|'DES'\b)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "56-bit DES is broken by brute force in hours classically, and instantly broken by Grover's algorithm.",
            remediation: "Replace with AES-256-GCM immediately.",
            tags: &["des", "broken", "legacy"],
        },
        PatternDefinition {
            id: "3DES-001",
            name: "Triple DES (3DES/TDEA - Deprecated)",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(3DES|TripleDES|DESede|DES_ede3_cbc|TDEA\b)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Triple DES is officially retired by NIST as of Dec 31, 2023. Vulnerable to Sweet32 64-bit block collision attacks.",
            remediation: "Upgrade to AES-256-GCM (NIST SP 800-38D).",
            tags: &["3des", "deprecated", "sweet32"],
        },
        PatternDefinition {
            id: "RC4-001",
            name: "RC4 / ARC4 Stream Cipher (Broken)",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(RC4|ARC4|ARCFOUR|crypto/rc4|RC4_set_key|RC4CryptoServiceProvider)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "RC4 contains fatal statistical keystream biases (RFC 7465 prohibits RC4 in TLS).",
            remediation: "Replace with ChaCha20-Poly1305 or AES-256-GCM.",
            tags: &["rc4", "broken", "stream-cipher"],
        },
        PatternDefinition {
            id: "BLOWFISH-001",
            name: "Blowfish 64-bit Block Cipher",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(blowfish|bf_ecb|bf_cbc|BF_set_key)\b"#,

            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Blowfish uses a 64-bit block size vulnerable to Sweet32 collision attacks on large datasets.",
            remediation: "Upgrade to AES-256-GCM or Twofish with 128-bit block.",
            tags: &["blowfish", "sweet32"],
        },
        PatternDefinition {
            id: "CAMELLIA-001",
            name: "Camellia Cipher",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(camellia[_\-0-9]*|camellia_cbc)\b"#,

            severity: "LOW",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "Camellia block cipher. Secure with 256-bit key; ensure GCM mode is used.",
            remediation: "Prefer standard AES-256-GCM for universal hardware acceleration.",
            tags: &["camellia", "symmetric"],
        },
        PatternDefinition {
            id: "IDEA-001",
            name: "IDEA Cipher",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(idea_ecb|idea_cbc|idea_encrypt)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "IDEA uses a 64-bit block size vulnerable to birthday attacks on large volumes.",
            remediation: "Migrate to AES-256-GCM.",
            tags: &["idea", "64bit-block"],
        },
        PatternDefinition {
            id: "CAST5-001",
            name: "CAST5 / CAST-128 Cipher",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(cast5|cast128|cast_ecb|cast_cbc)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "CAST-128 has a 64-bit block size vulnerable to Sweet32 collisions.",
            remediation: "Migrate to AES-256-GCM.",
            tags: &["cast5", "64bit-block"],
        },
        PatternDefinition {
            id: "RC2-001",
            name: "RC2 Cipher (Broken)",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(RC2_ecb|RC2_cbc|RC2CryptoServiceProvider)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "RC2 is an obsolete cipher with 64-bit block size and related-key attacks.",
            remediation: "Migrate immediately to AES-256-GCM.",
            tags: &["rc2", "broken"],
        },
        PatternDefinition {
            id: "AES-GCM-001",
            name: "AES-GCM Authenticated Encryption",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(aes-256-gcm|aes-128-gcm|AES_GCM|Cipher\.getInstance\("AES/GCM/NoPadding"\))\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST SP 800-38D approved AEAD authenticated encryption mode.",
            remediation: "Ensure 256-bit keys are used for post-quantum resistance against Grover's algorithm, and nonces are never reused.",
            tags: &["aes-gcm", "aead", "quantum-safe-256"],
        },
        PatternDefinition {
            id: "CHACHA-001",
            name: "ChaCha20-Poly1305 AEAD",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(chacha20-poly1305|ChaCha20Poly1305|crypto_aead_chacha20poly1305)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "RFC 8439 standardized high-speed authenticated encryption with 256-bit security.",
            remediation: "Post-quantum safe symmetric cipher. Ensure 96-bit nonce uniqueness per key.",
            tags: &["chacha20", "poly1305", "aead", "quantum-safe"],
        },
        PatternDefinition {
            id: "AES-001",
            name: "Generic AES / CBC Mode",
            category: "Symmetric Encryption",
            regex_pattern: r#"(?i)\b(AES-128-CBC|AES-256-CBC|AES/CBC/PKCS5Padding|AES/CBC/PKCS7Padding)\b"#,

            severity: "LOW",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "AES-CBC mode requires HMAC integrity protection to prevent padding oracle attacks.",
            remediation: "Migrate from CBC mode to authenticated encryption (AES-256-GCM).",
            tags: &["aes-cbc", "padding-oracle"],
        },

        // ─── 5. HASH FUNCTIONS ───────────────────────────────────────────────
        PatternDefinition {
            id: "MD5-001",
            name: "MD5 Message Digest (Broken Collision Resistance)",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(md5\s*\(|hashlib\.md5|crypto\.createHash\(['"]md5['"]\)|crypto/md5|EVP_md5|MD5CryptoServiceProvider|MessageDigest\.getInstance\(['"]MD5['"]\))\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "MD5 collision resistance is completely broken ($2^{16}$ collision complexity). Insecure for security purposes.",
            remediation: "Replace with SHA-256 or SHA-3/SHAKE256 immediately.",
            tags: &["md5", "broken", "collision"],
        },
        PatternDefinition {
            id: "MD4-001",
            name: "MD4 Message Digest (Broken)",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(md4\s*\(|crypto/md4|EVP_md4|MessageDigest\.getInstance\(['"]MD4['"]\))\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "MD4 is trivially broken with practical collision attacks.",
            remediation: "Replace with SHA-256 or SHA-3.",
            tags: &["md4", "broken"],
        },
        PatternDefinition {
            id: "MD2-001",
            name: "MD2 Message Digest (Broken)",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(md2\s*\(|EVP_md2|MessageDigest\.getInstance\(['"]MD2['"]\))\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "MD2 is an obsolete, broken hash function.",
            remediation: "Replace with SHA-256 or SHA-3.",
            tags: &["md2", "broken"],
        },
        PatternDefinition {
            id: "SHA1-001",
            name: "SHA-1 Hash Function (Broken Collision Resistance)",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(sha1\s*\(|sha-1\b|hashlib\.sha1|crypto\.createHash\(['"]sha1['"]\)|crypto/sha1|EVP_sha1|SHA1CryptoServiceProvider|MessageDigest\.getInstance\(['"]SHA-?1['"]\))\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "SHA-1 is broken by SHAttered collision attacks and deprecated by NIST SP 800-131A.",
            remediation: "Migrate to SHA-256, SHA-384, or SHA-3.",
            tags: &["sha1", "shattered", "collision-broken"],
        },
        PatternDefinition {
            id: "SHA2-001",
            name: "SHA-2 Family (SHA-256 / SHA-384 / SHA-512)",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(SHA-?256|SHA-?384|SHA-?512|hashlib\.sha256|crypto\.createHash\(['"]sha256['"]\)|crypto/sha256|crypto/sha512)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "FIPS 180-4 standard secure cryptographic hash family.",
            remediation: "SHA-256 provides 128-bit quantum collision resistance against Grover search. For 256-bit quantum safety, use SHA-384 or SHA-512.",
            tags: &["sha2", "sha256", "sha512", "fips-180-4"],
        },
        PatternDefinition {
            id: "SHA3-001",
            name: "SHA-3 Keccak Permutation Hash",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(SHA3-256|SHA3-384|SHA3-512|crypto/sha3|golang\.org/x/crypto/sha3)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 202 sponge-construction hash function resistant to length extension attacks.",
            remediation: "Fully quantum-resistant hash function family.",
            tags: &["sha3", "keccak", "fips-202", "quantum-safe"],
        },
        PatternDefinition {
            id: "SHAKE-001",
            name: "SHAKE Extendable-Output Function (XOF)",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(SHAKE128|SHAKE256|shake256_xof)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "FIPS 202 extendable-output function used in NIST post-quantum standards.",
            remediation: "Compliant post-quantum cryptographic primitive.",
            tags: &["shake", "xof", "fips-202", "pqc"],
        },
        PatternDefinition {
            id: "BLAKE2-001",
            name: "BLAKE2b / BLAKE2s Hash",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(blake2b|blake2s|crypto/blake2b|golang\.org/x/crypto/blake2b)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "RFC 7693 high-performance cryptographic hash function immune to length extension.",
            remediation: "Quantum safe. BLAKE2b-512 provides maximum security margin.",
            tags: &["blake2", "hash"],
        },
        PatternDefinition {
            id: "BLAKE3-001",
            name: "BLAKE3 Tree Hash",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(blake3|blake3::Hasher|blake3_hasher)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "High-performance Merkle tree cryptographic hash with 128-bit quantum security.",
            remediation: "Compliant modern hash function.",
            tags: &["blake3", "merkle-tree"],
        },
        PatternDefinition {
            id: "RIPEMD160-001",
            name: "RIPEMD-160 Hash",
            category: "Hash Functions",
            regex_pattern: r#"(?i)\b(ripemd160|RIPEMD-160|crypto/ripemd160)\b"#,

            severity: "LOW",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "Legacy 160-bit hash function used in Bitcoin address generation.",
            remediation: "Prefer SHA-256 or SHA-3 for general application security.",
            tags: &["ripemd160"],
        },

        // ─── 6. MESSAGE AUTHENTICATION CODES (MACS) ──────────────────────────
        PatternDefinition {
            id: "MAC-HMAC-256",
            name: "HMAC-SHA256",
            category: "MACs",
            regex_pattern: r#"(?i)\b(HMAC-SHA256|hmac\.New\(sha256\.New|crypto\.createHmac\(['"]sha256['"]\)|hash_hmac\(['"]sha256['"]\))\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 198-1 Keyed-Hash Message Authentication Code.",
            remediation: "Post-quantum safe message authentication code.",
            tags: &["hmac", "sha256", "fips-198-1"],
        },
        PatternDefinition {
            id: "MAC-HMAC-384",
            name: "HMAC-SHA384",
            category: "MACs",
            regex_pattern: r#"(?i)\b(HMAC-SHA384|hmac\.New\(sha384\.New|crypto\.createHmac\(['"]sha384['"]\))\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "High-assurance 384-bit HMAC for CNSA 2.0 quantum transition compliance.",
            remediation: "Compliant post-quantum MAC.",
            tags: &["hmac", "sha384", "cnsa-2.0"],
        },
        PatternDefinition {
            id: "MAC-HMAC-512",
            name: "HMAC-SHA512",
            category: "MACs",
            regex_pattern: r#"(?i)\b(HMAC-SHA512|hmac\.New\(sha512\.New|crypto\.createHmac\(['"]sha512['"]\))\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "512-bit HMAC for maximum collision and pre-image resistance.",
            remediation: "Compliant post-quantum MAC.",
            tags: &["hmac", "sha512"],
        },
        PatternDefinition {
            id: "MAC-KMAC-001",
            name: "KMAC128 / KMAC256 (NIST SP 800-185)",
            category: "MACs",
            regex_pattern: r#"(?i)\b(KMAC128|KMAC256|sha3\.NewKMAC|kmac256)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Keccak Message Authentication Code designed specifically for NIST post-quantum security.",
            remediation: "Recommended post-quantum MAC standard (NIST SP 800-185).",
            tags: &["kmac", "sp-800-185", "quantum-safe", "pqc"],
        },
        PatternDefinition {
            id: "MAC-CMAC-001",
            name: "CMAC / AES-CMAC",
            category: "MACs",
            regex_pattern: r#"(?i)\b(AES-CMAC|CMAC-AES|crypto/cmac)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "NIST SP 800-38B cipher-based MAC.",
            remediation: "Ensure AES-256 is used as the underlying cipher.",
            tags: &["cmac", "sp-800-38b"],
        },
        PatternDefinition {
            id: "MAC-GMAC-001",
            name: "GMAC (Galois Message Authentication Code)",
            category: "MACs",
            regex_pattern: r#"(?i)\b(GMAC|AES-GMAC)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Galois MAC authentication. Critical: never reuse an initialization vector with the same key.",
            remediation: "Ensure strict IV uniqueness.",
            tags: &["gmac"],
        },
        PatternDefinition {
            id: "MAC-POLY1305-001",
            name: "Poly1305 One-Time Authenticator",
            category: "MACs",
            regex_pattern: r#"(?i)\b(poly1305|crypto/poly1305|golang\.org/x/crypto/poly1305)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "One-time universal hash authenticator. One-time key reuse catastrophic.",
            remediation: "Use only as part of ChaCha20-Poly1305 AEAD construction.",
            tags: &["poly1305"],
        },
        PatternDefinition {
            id: "MAC-CBC-001",
            name: "CBC-MAC (Insecure for Variable-Length Data)",
            category: "MACs",
            regex_pattern: r#"(?i)\b(CBC-MAC|cbcmac)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Plain CBC-MAC is insecure for variable-length messages due to extension forgery attacks.",
            remediation: "Replace with CMAC (NIST SP 800-38B) or HMAC-SHA256.",
            tags: &["cbc-mac", "forgery"],
        },

        // ─── 7. KEY DERIVATION FUNCTIONS (KDFS) ──────────────────────────────
        PatternDefinition {
            id: "KDF-HKDF-001",
            name: "HKDF (HMAC-based Extract-and-Expand Key Derivation)",
            category: "KDFs",
            regex_pattern: r#"(?i)\b(HKDF|hkdf\.New|crypto\.hkdfSync|golang\.org/x/crypto/hkdf)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "RFC 5869 / NIST SP 800-56C key derivation from high-entropy secrets.",
            remediation: "Compliant key derivation standard for TLS 1.3 and hybrid key exchanges.",
            tags: &["hkdf", "sp-800-56c", "kdf"],
        },
        PatternDefinition {
            id: "KDF-ARGON2-001",
            name: "Argon2id Memory-Hard Password KDF",
            category: "KDFs",
            regex_pattern: r#"(?i)\b(argon2id|argon2\.IDKey|argon2_hash|argon2::Argon2)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "RFC 9106 password hashing competition winner with high GPU/ASIC resistance.",
            remediation: "Recommended password hashing standard (OWASP 2024).",
            tags: &["argon2", "rfc-9106", "password-kdf"],
        },
        PatternDefinition {
            id: "KDF-SCRYPT-001",
            name: "scrypt Memory-Hard KDF",
            category: "KDFs",
            regex_pattern: r#"(?i)\b(scrypt|crypto\.scrypt|golang\.org/x/crypto/scrypt)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "RFC 7914 memory-hard key derivation function.",
            remediation: "Secure password hashing algorithm.",
            tags: &["scrypt"],
        },
        PatternDefinition {
            id: "KDF-BCRYPT-001",
            name: "bcrypt Password Hash",
            category: "KDFs",
            regex_pattern: r#"(?i)\b(bcrypt|bcrypt\.GenerateFromPassword|bcrypt\.hashpw)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Blowfish-based adaptive password hashing function.",
            remediation: "Secure password hash; use minimum work factor of 12.",
            tags: &["bcrypt"],
        },
        PatternDefinition {
            id: "KDF-PBKDF2-001",
            name: "PBKDF2 Password-Based Key Derivation",
            category: "KDFs",
            regex_pattern: r#"(?i)\b(PBKDF2|pbkdf2\.Key|crypto\.pbkdf2|Rfc2898DeriveBytes)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "NIST SP 800-132 password-based key derivation.",
            remediation: "Ensure minimum 600,000 iterations with SHA-256 (OWASP 2024). Prefer Argon2id for new applications.",
            tags: &["pbkdf2", "sp-800-132"],
        },
        PatternDefinition {
            id: "KDF-PBKDF1-001",
            name: "PBKDF1 (Deprecated & Insecure)",
            category: "KDFs",
            regex_pattern: r#"(?i)\b(PBKDF1|EVP_BytesToKey)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "PBKDF1 only supports keys up to 160 bits and is deprecated by RFC 8018.",
            remediation: "Migrate immediately to PBKDF2, Argon2id, or HKDF.",
            tags: &["pbkdf1", "deprecated"],
        },

        // ─── 8. CERTIFICATES & PKI INFRASTRUCTURE ────────────────────────────
        PatternDefinition {
            id: "CERT-001",
            name: "Hardcoded X.509 Certificate",
            category: "Certificates",
            regex_pattern: r#"-----BEGIN CERTIFICATE-----"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Embedded X.509 public certificate found in source code.",
            remediation: "Inspect public key algorithm. If RSA or ECDSA, prepare migration to PQC certificate profile (ML-DSA / Composite).",
            tags: &["x509", "pki", "certificate"],
        },
        PatternDefinition {
            id: "CERT-CSR-001",
            name: "Certificate Signing Request (CSR)",
            category: "Certificates",
            regex_pattern: r#"-----BEGIN (CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST)-----"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Certificate Signing Request PKCS#10 found.",
            remediation: "Ensure the CSR requests modern algorithms (RSA-3072+, P-384, or ML-DSA).",
            tags: &["csr", "pkcs10"],
        },
        PatternDefinition {
            id: "CERT-PKCS12-001",
            name: "PKCS#12 / PFX Keystore Container",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(\.p12|\.pfx|PKCS12|KeyStore\.getInstance\(['"]PKCS12['"]\))\b"#,

            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Medium,
            description: "PKCS#12 archive contains private keys and certificate bundles.",
            remediation: "Ensure PFX container is encrypted with modern AES-256-GCM / PBKDF2-SHA256, not legacy RC2/3DES.",
            tags: &["pkcs12", "pfx", "keystore"],
        },
        PatternDefinition {
            id: "CERT-CHAIN-001",
            name: "Certificate Chain / CA Bundle",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(ca_bundle|cert_chain|trust_anchor|root_ca_bundle)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Low,
            description: "Certificate trust chain configuration reference.",
            remediation: "Review root CA certificates for quantum migration roadmap and validity periods.",
            tags: &["ca", "trust-anchor"],
        },
        PatternDefinition {
            id: "CERT-TRUSTED-001",
            name: "Explicit Trusted Certificate Anchor",
            category: "Certificates",
            regex_pattern: r#"-----BEGIN TRUSTED CERTIFICATE-----"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "OpenSSL explicit trust anchor certificate.",
            remediation: "Verify trust anchor provenance and ensure it does not bypass standard validation.",
            tags: &["trusted-cert"],
        },
        PatternDefinition {
            id: "CERT-SIGALG-WEAK-001",
            name: "Weak Certificate Signature Algorithm (MD5 / SHA-1)",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(md5WithRSAEncryption|sha1WithRSAEncryption|sha1WithRSA|ecdsa-with-SHA1)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Certificate signed with broken hash algorithm (MD5 or SHA-1). Vulnerable to forged certificate authority attacks (Flame malware attack vector).",
            remediation: "Revoke and reissue certificate with SHA-256 or SHA-384 immediately.",
            tags: &["weak-signature", "flame", "critical"],
        },
        PatternDefinition {
            id: "CERT-SIGALG-001",
            name: "Classical Certificate Signature Algorithm (RSA / ECDSA)",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(sha256WithRSAEncryption|sha384WithRSAEncryption|sha512WithRSAEncryption|ecdsa-with-SHA256|ecdsa-with-SHA384)\b"#,

            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Certificate signed with classical asymmetric key. Vulnerable to Shor's algorithm for quantum forgery.",
            remediation: "Plan migration to hybrid X.509 certificates (IETF LAMPS draft-ietf-lamps-cert-binding-for-multi-auth) or pure ML-DSA.",
            tags: &["sigalg", "quantum-vulnerable"],
        },
        PatternDefinition {
            id: "CERT-VALIDATION-BYPASS-001",
            name: "TLS / Certificate Validation Bypass (MITM Vulnerability)",
            category: "Certificates",
            regex_pattern: r#"(?i)(InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|check_hostname\s*=\s*False|CERT_NONE|TrustAllCertificatePolicy|setServerVerificationDisabled|NullTrustManager)"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "TLS certificate validation disabled. Allows man-in-the-middle attackers to intercept, decrypt, and tamper with all traffic.",
            remediation: "Never disable TLS certificate validation in production. Remove InsecureSkipVerify / verify=False.",
            tags: &["mitm", "tls-bypass", "critical-vulnerability"],
        },
        PatternDefinition {
            id: "CERT-SELFSIGNED-001",
            name: "Self-Signed Certificate Generation",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(generateSelfSignedCert|createSelfSignedCertificate|openssl req -x509)\b"#,

            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Medium,
            description: "Generation of self-signed certificate detected.",
            remediation: "Use enterprise CA or ACME (Let's Encrypt) in production environments.",
            tags: &["self-signed"],
        },
        PatternDefinition {
            id: "CERT-MTLS-001",
            name: "Mutual TLS (mTLS) Authentication",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(RequireAndVerifyClientCert|mutual_tls|client_cert_auth|ClientAuthType\.RequireClientCert)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Mutual TLS client authentication configuration.",
            remediation: "Ensure both client and server certificates are cataloged for quantum migration.",
            tags: &["mtls", "zero-trust"],
        },
        PatternDefinition {
            id: "CERT-REVOCATION-001",
            name: "Certificate Revocation Checking (OCSP / CRL)",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(OCSP|crl_distribution_points|checkRevocation|X509_CRL)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Low,
            description: "OCSP stapling or CRL certificate revocation mechanism.",
            remediation: "Ensure OCSP stapling is enabled to protect client privacy and performance.",
            tags: &["ocsp", "crl", "revocation"],
        },
        PatternDefinition {
            id: "CERT-PINNING-001",
            name: "Certificate / Public Key Pinning",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(certificatePinner|PublicKeyPinning|pin-sha256|cert_pin)\b"#,

            severity: "LOW",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Medium,
            description: "Certificate public key pinning detected.",
            remediation: "Caution: Hardcoded public key pinning can cause outages during emergency key rotation and quantum migration.",
            tags: &["pinning", "operational-risk"],
        },
        PatternDefinition {
            id: "CERT-ACME-001",
            name: "ACME Automated Certificate Management",
            category: "Certificates",
            regex_pattern: r#"(?i)\b(letsencrypt|certbot|acme_challenge|acme-v02\.api\.letsencrypt\.org)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Medium,
            description: "Automated Certificate Management Environment (ACME / Let's Encrypt).",
            remediation: "Automated certificate renewal simplifies future post-quantum certificate rotation.",
            tags: &["acme", "automation"],
        },
        PatternDefinition {
            id: "KEY-JWK-001",
            name: "JSON Web Key (JWK) Quantum-Vulnerable Key",
            category: "Certificates",
            regex_pattern: r#"(?i)("kty"\s*:\s*"RSA"|"kty"\s*:\s*"EC"|"crv"\s*:\s*"(P-256|P-384|Ed25519)")"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "JSON Web Key containing classical RSA or Elliptic Curve public key parameters.",
            remediation: "Plan JWK schema extension for ML-DSA and composite keys.",
            tags: &["jwk", "jose"],
        },

        // ─── 9. JSON WEB TOKENS (JWTS) ───────────────────────────────────────
        PatternDefinition {
            id: "JWT-ALG-NONE-001",
            name: "JWT Algorithm 'none' Signature Bypass",
            category: "JWTs",
            regex_pattern: r#"(?i)("alg"\s*:\s*"none"|alg:\s*['"]none['"]|algorithms\s*=\s*\[.*['"]none['"].*\])"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "JWT header explicitly allows algorithm 'none', allowing arbitrary forgery of claims without a signature.",
            remediation: "Strictly reject algorithm 'none' in JWT verification middleware.",
            tags: &["jwt", "signature-bypass", "critical"],
        },
        PatternDefinition {
            id: "JWT-RS256-001",
            name: "JWT RS256 / RS384 / RS512 (RSA-Signed)",
            category: "JWTs",
            regex_pattern: r#"(?i)("alg"\s*:\s*"RS(256|384|512)"|alg:\s*['"]RS(256|384|512)['"]|algorithm\s*=\s*['"]RS(256|384|512)['"])"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "JWT signed with RSA private key. Quantum computers can forge valid tokens by computing the private key from the public JWK via Shor's algorithm.",
            remediation: "Transition auth tokens to ML-DSA signatures or symmetric HS256/HMAC-SHA256 with 256-bit secret.",
            tags: &["jwt", "rs256", "quantum-vulnerable"],
        },
        PatternDefinition {
            id: "JWT-ES256-001",
            name: "JWT ES256 / ES384 / ES512 (ECDSA-Signed)",
            category: "JWTs",
            regex_pattern: r#"(?i)("alg"\s*:\s*"ES(256|384|512)"|alg:\s*['"]ES(256|384|512)['"]|algorithm\s*=\s*['"]ES(256|384|512)['"])"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "JWT signed with ECDSA curve. Quantum vulnerable via Shor's discrete logarithm attack.",
            remediation: "Migrate to ML-DSA-65 or hybrid ECDSA+ML-DSA signatures.",
            tags: &["jwt", "es256", "quantum-vulnerable"],
        },
        PatternDefinition {
            id: "SECRET-JWT-001",
            name: "Hardcoded JWT Secret",
            category: "JWTs",
            regex_pattern: r#"(?i)(jwt_secret|jwtSecret|JWT_SECRET|jwt_token_secret)\s*[:=]\s*['"][^'"]{8,}['"]"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Hardcoded symmetric JWT signing secret in source code.",
            remediation: "Move JWT signing secret to KMS / secret manager with automated rotation.",
            tags: &["jwt", "hardcoded-secret", "critical"],
        },

        // ─── 10. TLS/SSL PROTOCOLS & WEAK CIPHERS ────────────────────────────
        PatternDefinition {
            id: "TLS-001",
            name: "Legacy / Insecure SSL/TLS Version (SSLv2, SSLv3, TLS 1.0, TLS 1.1)",
            category: "TLS/SSL Protocols",
            regex_pattern: r#"(?i)\b(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1_client_method|TLSv1_server_method|SSL_PROTOCOL_TLSV1)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Obsolete TLS 1.0/1.1 or SSLv2/v3 protocols vulnerable to POODLE, BEAST, and CRIME attacks.",
            remediation: "Enforce TLS 1.2 minimum, prefer TLS 1.3 (RFC 8446).",
            tags: &["tls", "poodle", "beast", "critical"],
        },
        PatternDefinition {
            id: "TLS-002",
            name: "TLS 1.2 / TLS 1.3 Protocol",
            category: "TLS/SSL Protocols",
            regex_pattern: r#"(?i)\b(TLSv1\.2|TLSv1\.3|TLS_1_2|TLS_1_3)\b"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Modern TLS protocol configuration.",
            remediation: "For quantum safety, configure TLS 1.3 with X25519MLKEM768 hybrid key exchange (RFC 9370).",
            tags: &["tls13", "hybrid-tls"],
        },
        PatternDefinition {
            id: "CIPHER-WEAK-001",
            name: "Weak TLS Cipher Suite",
            category: "TLS/SSL Protocols",
            regex_pattern: r#"(?i)\b(NULL-MD5|NULL-SHA|RC4-MD5|RC4-SHA|DES-CBC-SHA|EDH-RSA-DES-CBC-SHA|ADH-AES128-SHA|AECDH-AES128-SHA|EXP-)\b"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Insecure TLS cipher suite (NULL encryption, export grade, anonymous DH, or RC4/DES).",
            remediation: "Configure cipher suites to only allow ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, or TLS 1.3 ciphers.",
            tags: &["weak-ciphers", "export-cipher", "critical"],
        },

        // ─── 11. KEY MATERIAL & SECRETS IN CODE ──────────────────────────────
        PatternDefinition {
            id: "KEY-RSA-001",
            name: "Embedded RSA Private Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"-----BEGIN RSA PRIVATE KEY-----"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Unencrypted PKCS#1 RSA private key committed to source code repository.",
            remediation: "Immediately revoke and rotate the private key. Use HashiCorp Vault or AWS KMS.",
            tags: &["rsa", "private-key", "secret-leak", "critical"],
        },
        PatternDefinition {
            id: "KEY-EC-001",
            name: "Embedded EC Private Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"-----BEGIN EC PRIVATE KEY-----"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Unencrypted SEC1 Elliptic Curve private key found in repository.",
            remediation: "Immediately revoke and rotate the key.",
            tags: &["ec", "private-key", "secret-leak", "critical"],
        },
        PatternDefinition {
            id: "KEY-DSA-001",
            name: "Embedded DSA Private Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"-----BEGIN DSA PRIVATE KEY-----"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Unencrypted DSA private key committed to repository.",
            remediation: "Revoke key and migrate to post-quantum signature.",
            tags: &["dsa", "private-key", "critical"],
        },
        PatternDefinition {
            id: "KEY-OPENSSH-001",
            name: "Embedded OpenSSH Private Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"-----BEGIN OPENSSH PRIVATE KEY-----"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "OpenSSH private key leaked in repository.",
            remediation: "Revoke authorized key across all servers immediately.",
            tags: &["openssh", "private-key", "critical"],
        },
        PatternDefinition {
            id: "KEY-PGP-001",
            name: "Embedded PGP / GPG Private Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"-----BEGIN PGP PRIVATE KEY BLOCK-----"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "PGP/GPG secret key block exposed in code.",
            remediation: "Revoke PGP key on keyservers and reissue.",
            tags: &["pgp", "private-key", "critical"],
        },
        PatternDefinition {
            id: "KEY-PKCS8-001",
            name: "Embedded PKCS#8 Private Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"-----BEGIN PRIVATE KEY-----"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Standard PKCS#8 private key leaked in source code.",
            remediation: "Revoke the key immediately.",
            tags: &["pkcs8", "private-key", "critical"],
        },
        PatternDefinition {
            id: "SECRET-KEY-001",
            name: "Hardcoded Symmetric Encryption Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"(?i)(aes_key|encryption_key|secret_key|AES_SECRET)\s*[:=]\s*['"][0-9a-fA-F]{32,64}['"]"#,

            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Raw hex-encoded encryption key hardcoded in plaintext.",
            remediation: "Inject encryption keys at runtime using a secure KMS envelope encryption model.",
            tags: &["hardcoded-key", "critical"],
        },
        PatternDefinition {
            id: "SECRET-HMAC-001",
            name: "Hardcoded HMAC Signing Key",
            category: "Key Material & Secrets",
            regex_pattern: r#"(?i)(hmac_key|hmac_secret|signing_key)\s*[:=]\s*['"][^'"]{16,}['"]"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "Hardcoded HMAC signing key in source code.",
            remediation: "Use external secrets management.",
            tags: &["hmac", "secret-leak"],
        },

        // ─── 12. CLOUD KMS SERVICES ──────────────────────────────────────────
        PatternDefinition {
            id: "SECRET-KMS-AWS-001",
            name: "AWS KMS Key ARN",
            category: "Cloud KMS",
            regex_pattern: r#"arn:aws:kms:[a-z0-9\-]+:[0-9]{12}:key/[a-f0-9\-]{36}"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "AWS KMS Customer Master Key ARN reference.",
            remediation: "Verify key specification. If RSA_2048 or ECC_NIST_P256, schedule transition to hybrid or post-quantum KMS key specs when available.",
            tags: &["aws", "kms", "cloud-crypto"],
        },
        PatternDefinition {
            id: "SECRET-KMS-GCP-001",
            name: "Google Cloud KMS CryptoKey",
            category: "Cloud KMS",
            regex_pattern: r#"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "GCP Cloud KMS key reference.",
            remediation: "Check Cloud KMS key version algorithm. Ensure AES-256 for symmetric or prepare for PQC algorithms.",
            tags: &["gcp", "kms", "cloud-crypto"],
        },
        PatternDefinition {
            id: "SECRET-VAULT-AZURE-001",
            name: "Azure Key Vault Key URL",
            category: "Cloud KMS",
            regex_pattern: r#"https://[a-zA-Z0-9\-]+\.vault\.azure\.net/keys/[^/\s]+"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Azure Key Vault key reference.",
            remediation: "Verify key size (prefer RSA-4096 or EC P-384 until PQC keys are standard).",
            tags: &["azure", "keyvault", "cloud-crypto"],
        },
        PatternDefinition {
            id: "SECRET-VAULT-HASHI-001",
            name: "HashiCorp Vault Transit Engine",
            category: "Cloud KMS",
            regex_pattern: r#"(?i)(vault[\s_]addr|v1/transit/encrypt/|v1/transit/decrypt/|vault\.read\(['"]transit/)"#,

            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Medium,
            description: "HashiCorp Vault Transit encryption as a service.",
            remediation: "Transit engine centralizes crypto migration. Configure aes256-gcm96 or chacha20-poly1305 key types.",
            tags: &["hashicorp", "vault", "transit"],
        },

        // ─── 13. DEPENDENCY MANIFESTS CRYPTO AUDIT ───────────────────────────
        PatternDefinition {
            id: "DEP-NPM-WEAK-001",
            name: "NPM Package: Deprecated / Broken Crypto Library",
            category: "Dependency Manifests",
            regex_pattern: r#"(?i)"(crypto-js|node-forge|js-md5|js-sha1|node-rsa|ursa|ursa-purejs)"\s*:"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "JavaScript package using legacy unmaintained or classical crypto library (crypto-js, node-forge, node-rsa).",
            remediation: "Migrate to Web Cryptography API (`globalThis.crypto.subtle`) or modern PQC libraries (`@noble/ciphers`, `@noble/hashes`).",
            tags: &["npm", "package-json", "legacy-crypto"],
        },
        PatternDefinition {
            id: "DEP-CARGO-WEAK-001",
            name: "Cargo Dependency: Classical / Weak Crypto Crate",
            category: "Dependency Manifests",
            regex_pattern: r#"(?i)\b(md5\s*=\s*|sha1\s*=\s*|des\s*=\s*|rc4\s*=\s*|rsa\s*=\s*|ed25519-dalek\s*=\s*)"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Rust Cargo.toml dependency on legacy hash or classical asymmetric signature crate.",
            remediation: "Add post-quantum dependencies: `ml-kem`, `ml-dsa`, or `hybrid-array`.",
            tags: &["cargo", "rust-dependencies"],
        },
        PatternDefinition {
            id: "DEP-PY-WEAK-001",
            name: "Python Dependency: Classical / Legacy Crypto Package",
            category: "Dependency Manifests",
            regex_pattern: r#"(?i)\b(pycrypto\b|pycryptodome\b|rsa\b|ecdsa\b)\s*([=><~]|\n)"#,

            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Python requirements.txt or pyproject.toml specifying PyCrypto (unmaintained) or classical RSA/ECDSA packages.",
            remediation: "Use standard `cryptography` library with post-quantum extensions or liboqs-python.",
            tags: &["python", "requirements", "dependencies"],
        },
        PatternDefinition {
            id: "DEP-GO-WEAK-001",
            name: "Go Module: Deprecated Crypto Dependency",
            category: "Dependency Manifests",
            regex_pattern: r#"(?i)\b(golang\.org/x/crypto/md4|golang\.org/x/crypto/ripemd160|golang\.org/x/crypto/blowfish)\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Go go.mod dependency importing obsolete or deprecated cryptographic modules.",
            remediation: "Remove deprecated crypto modules; migrate to standard library `crypto/sha256` or `crypto/tls`.",
            tags: &["go-mod", "dependencies"],
        },
        PatternDefinition {
            id: "DEP-MAVEN-WEAK-001",
            name: "Maven / Gradle: Legacy BouncyCastle or Crypto Library",
            category: "Dependency Manifests",
            regex_pattern: r#"(?i)(<artifactId>bcprov-jdk15on</artifactId>|implementation.*['"]org\.bouncycastle:bcprov-jdk15on['"])"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Outdated BouncyCastle jdk15on dependency. Known CVEs and lacks FIPS 203/204/205 PQC support.",
            remediation: "Upgrade to `bcprov-jdk18on` (version 1.78+) which includes NIST ML-KEM, ML-DSA, and SLH-DSA.",
            tags: &["maven", "bouncycastle", "java"],
        },

        // ─── 14. CRYPTOGRAPHIC PRNG (WEAK RANDOMNESS) ────────────────────────
        PatternDefinition {
            id: "PRNG-WEAK-001",
            name: "Non-Cryptographic Pseudo-Random Number Generator",
            category: "Random Number Generation",
            regex_pattern: r#"(?i)\b(Math\.random\s*\(\)|rand\.Float64\s*\(\)|rand\.Intn\s*\(|new\s+java\.util\.Random\b|System\.currentTimeMillis\s*\(\)|rand\s*\(\)|std::rand\b)\b"#,

            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::Medium,
            description: "Predictable pseudo-random generator used in potentially sensitive context. State can be reconstructed from output.",
            remediation: "Use cryptographically secure PRNG: `crypto.getRandomValues()` (Web), `crypto/rand` (Go), `rand::rngs::OsRng` (Rust), `secrets` (Python), `SecureRandom` (Java).",
            tags: &["prng", "weak-random", "cwe-338"],
        },

        // ─── 15. SMART CONTRACT CRYPTOGRAPHY (SOLIDITY) ──────────────────────
        PatternDefinition {
            id: "SOL-TX-ORIGIN-001",
            name: "Solidity Phishing Vulnerability (tx.origin)",
            category: "Smart Contracts",
            regex_pattern: r#"\btx\.origin\b"#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Using tx.origin for authorization allows phishing contract attacks via call forwarding.",
            remediation: "Use msg.sender for authorization in Ethereum / EVM contracts.",
            tags: &["solidity", "smart-contract", "tx-origin"],
        },
        PatternDefinition {
            id: "SOL-SELFDESTRUCT-001",
            name: "Solidity Deprecated selfdestruct",
            category: "Smart Contracts",
            regex_pattern: r#"\bselfdestruct\s*\("#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "selfdestruct is deprecated (EIP-6780 Cancun upgrade) and alters contract state unpredictably.",
            remediation: "Remove selfdestruct. Use pausable or upgradeable proxy patterns.",
            tags: &["solidity", "selfdestruct", "cancun"],
        },
        PatternDefinition {
            id: "SOL-DELEGATECALL-001",
            name: "Solidity delegatecall to Untrusted Target",
            category: "Smart Contracts",
            regex_pattern: r#"\.delegatecall\s*\("#,

            severity: "HIGH",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Medium,
            description: "delegatecall preserves execution context (msg.sender, storage). Untrusted targets can wipe or hijack contract state.",
            remediation: "Ensure delegatecall destination is immutable or verified in an authorized registry.",
            tags: &["solidity", "delegatecall", "storage-hijack"],
        },

        // ─── 16. SECURE SHELL (SSH) PROTOCOL & HOST CONFIGURATION ────────────
        PatternDefinition {
            id: "PQC-SSH-001",
            name: "SSH RSA Key Exchange or Algorithm",
            category: "SSH Configuration",
            regex_pattern: r#"\bssh-rsa\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "SSH ssh-rsa algorithm configured in sshd_config, client config, or authorized_keys. Vulnerable to Shor's algorithm.",
            remediation: "Migrate to OpenSSH post-quantum hybrid key exchange (sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha512@openssh.com) and ssh-ed25519.",
            tags: &["ssh", "rsa", "sshd", "pqc-migration"],
        },
        PatternDefinition {
            id: "PQC-SSH-002",
            name: "Deprecated SSH Digital Signature Algorithm (DSA)",
            category: "SSH Configuration",
            regex_pattern: r#"\bssh-dss\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Deprecated ssh-dss (DSA 1024-bit) algorithm detected. Insecure against classical attacks and trivially broken by Shor's algorithm.",
            remediation: "Remove ssh-dss immediately. Use OpenSSH 9.0+ defaults or post-quantum hybrid signature algorithms.",
            tags: &["ssh", "dsa", "deprecated"],
        },
        PatternDefinition {
            id: "PQC-SSH-003",
            name: "Legacy SHA-1 SSH Key Exchange Group",
            category: "SSH Configuration",
            regex_pattern: r#"\bdiffie-hellman-group1(?:4)?-sha1\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Legacy Diffie-Hellman Group 1/14 with SHA-1 key exchange algorithm detected in SSH configuration.",
            remediation: "Disable SHA-1 DH groups. Configure KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256 in sshd_config.",
            tags: &["ssh", "kex", "diffie-hellman", "sha1"],
        },
        PatternDefinition {
            id: "PQC-SSH-004",
            name: "SSH RSA-SHA2 Host Key Algorithm",
            category: "SSH Configuration",
            regex_pattern: r#"\brsa-sha2-(?:256|512)\b"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::Medium,
            description: "RSA-SHA2 public key algorithm configured in SSH settings. Classical RSA is vulnerable to Store-Now-Decrypt-Later.",
            remediation: "Plan transition to post-quantum signature schemes and stateful hash-based signatures for host keys.",
            tags: &["ssh", "rsa-sha2", "hostkey"],
        },
        PatternDefinition {
            id: "PQC-SSH-005",
            name: "SSH Host Key / Authorized Key (RSA)",
            category: "SSH Configuration",
            regex_pattern: r#"(?i)(?:HostKey\s+.*ssh_host_rsa_key|^\s*ssh-rsa\s+[A-Za-z0-9+/=]+)"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::Medium,
            description: "RSA host key configured or RSA public key provisioned in authorized_keys.",
            remediation: "Rotate host keys and authorized_keys to modern curves (ssh-ed25519) and prepare for PQC stateful hash-based authentication.",
            tags: &["ssh", "authorized_keys", "hostkey"],
        },

        // ─── 17. CLOUD, KUBERNETES & REVERSE PROXY MIDDLEWARE ────────────────
        PatternDefinition {
            id: "PQC-K8S-001",
            name: "Kubernetes Ingress: Insecure / Classical TLS Configuration",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)nginx\.ingress\.kubernetes\.io/ssl-(?:ciphers|protocols)\s*:\s*['"]?[^\n"]*(?:RSA|DES|3DES|RC4|TLSv1(?:\.0|\.1)?)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Kubernetes Ingress annotation configures deprecated TLS protocols or RSA/legacy cipher suites.",
            remediation: "Configure `ssl-protocols: 'TLSv1.2 TLSv1.3'` and enforce forward-secret ECDHE/PQC ciphers.",
            tags: &["kubernetes", "ingress", "tls", "middleware"],
        },
        PatternDefinition {
            id: "PQC-K8S-002",
            name: "Kubernetes Gateway / Service Mesh: Legacy Minimum TLS Version",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)(?:minVersion|minProtocolVersion)\s*:\s*['"]?(?:TLSv1(?:[._][01])?|versiontls1[01])\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Kubernetes Gateway API, Istio DestinationRule, or Service Mesh config permits TLS 1.0 or TLS 1.1.",
            remediation: "Raise minVersion/minProtocolVersion to TLSv1_2 or TLSv1_3 in service mesh policies.",
            tags: &["kubernetes", "istio", "gateway-api", "service-mesh"],
        },
        PatternDefinition {
            id: "PQC-PROXY-001",
            name: "Web Server: Deprecated / Non-Forward-Secret Cipher Suite",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?m)^\s*(?:ssl_ciphers|SSLCipherSuite)\s+[^;]*(?:RSA|DES-CBC3-SHA|3DES|RC4|DES)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Nginx ssl_ciphers or Apache SSLCipherSuite directive enables static RSA key exchange or broken ciphers (3DES, RC4).",
            remediation: "Remove static RSA and 3DES/RC4 cipher suites. Configure modern AEAD ciphers with hybrid post-quantum key exchange.",
            tags: &["nginx", "apache", "ciphers", "ssl"],
        },
        PatternDefinition {
            id: "PQC-PROXY-002",
            name: "Web Server: Legacy TLS 1.0 / 1.1 Protocol Enabled",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?m)^\s*(?:ssl_protocols|SSLProtocol|proxy_ssl_protocols)\s+[^;]*(?:TLSv1(?:\.0|\.1)?(?:$|[^0-9.]))"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Nginx or Apache configuration allows legacy TLS 1.0 or TLS 1.1 protocol handshakes.",
            remediation: "Update configuration to allow only TLSv1.2 and TLSv1.3 (e.g. `ssl_protocols TLSv1.2 TLSv1.3;`).",
            tags: &["nginx", "apache", "protocols", "tls"],
        },
        PatternDefinition {
            id: "PQC-PROXY-003",
            name: "Envoy Proxy: Legacy TLS Version or RSA Ciphers",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)(?:tls_minimum_protocol_version\s*:\s*TLSv1_[01]|cipher_suites\s*:\s*\[[^\]]*(?:RSA|3DES|RC4))"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Envoy proxy downstream/upstream TLS configuration allows obsolete protocols or RSA key exchange.",
            remediation: "Set tls_minimum_protocol_version to TLSv1_3 or TLSv1_2 and restrict cipher_suites to ECDHE/PQC.",
            tags: &["envoy", "proxy", "cloud-native"],
        },
        PatternDefinition {
            id: "PQC-PROXY-004",
            name: "HAProxy / Traefik: Obsolete TLS Version Configuration",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)(?:bind\s+[^\n]*\bssl\b[^\n]*(?:tlsv10|tlsv11)|minversion\s*:\s*versiontls1[01])"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "HAProxy bind options or Traefik TLS options explicitly enable TLS 1.0 or 1.1.",
            remediation: "Specify ssl-min-ver TLSv1.2 or TLSv1.3 in HAProxy / Traefik configuration.",
            tags: &["haproxy", "traefik", "reverse-proxy"],
        },
        PatternDefinition {
            id: "PQC-CONF-OPENSSL-001",
            name: "OpenSSL Config: Insecure CipherString or Security Level",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)CipherString\s*=\s*DEFAULT@SECLEVEL=[01]\b|CipherString\s*=\s*[^;\n]*(?:RC4|3DES|DES|EXPORT|NULL)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "OpenSSL configuration (openssl.cnf) defines a weak CipherString with SECLEVEL <= 1 or obsolete ciphers.",
            remediation: "Set `CipherString = DEFAULT@SECLEVEL=2` or higher, and configure modern post-quantum hybrid key exchange groups.",
            tags: &["openssl", "config", "ciphers", "seclevel"],
        },
        PatternDefinition {
            id: "PQC-CONF-OPENSSL-002",
            name: "OpenSSL Config: Obsolete Minimum TLS Protocol",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)MinProtocol\s*=\s*(?:TLSv1(?:\.0|\.1)?|SSLv[23])\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "OpenSSL configuration permits obsolete SSLv3 or TLS 1.0/1.1 protocols.",
            remediation: "Set `MinProtocol = TLSv1.2` or `MinProtocol = TLSv1.3` in openssl.cnf.",
            tags: &["openssl", "config", "protocol", "minprotocol"],
        },
        PatternDefinition {
            id: "PQC-CONF-OPENSSL-003",
            name: "OpenSSL Config: Broken Default Message Digest",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)default_md\s*=\s*(?:md5|sha1)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "OpenSSL configuration sets default_md to broken hash algorithms (MD5 or SHA-1).",
            remediation: "Set `default_md = sha256` or `default_md = sha384` in openssl.cnf.",
            tags: &["openssl", "config", "hash", "default_md"],
        },
        PatternDefinition {
            id: "PQC-CONF-JAVA-001",
            name: "Java Security Config: Weak Disabled Algorithms",
            category: "Cloud & Middleware",
            regex_pattern: r#"(?i)jdk\.(?:tls|certpath)\.disabledAlgorithms\s*=\s*[^;\n]*\b(?:TLSv1(?:\.0|\.1)?|MD5|RC4)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Java security configuration (java.security) explicitly references legacy algorithms in disabled settings.",
            remediation: "Ensure `jdk.tls.disabledAlgorithms` disables SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, and DH keySize < 2048.",
            tags: &["java", "security", "config", "disabled-algorithms"],
        },

        // ─── 18. CERTIFICATES & ASYMMETRIC PRIVATE KEYS ─────────────────────
        PatternDefinition {
            id: "PQC-CERT-001",
            name: "X.509 Certificate Block",
            category: "Certificates & Keys",
            regex_pattern: r#"-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "X.509 Certificate detected. Classical public key infrastructure (RSA/ECDSA) certificates require migration to ML-DSA/Falcon.",
            remediation: "Audit certificate key algorithm and signature. Plan transition to post-quantum certificates (RFC 9700 / X.509 ML-DSA).",
            tags: &["x509", "certificate", "pki"],
        },
        PatternDefinition {
            id: "PQC-KEY-RSA-001",
            name: "RSA Private Key Material",
            category: "Certificates & Keys",
            regex_pattern: r#"-----BEGIN RSA PRIVATE KEY-----"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Unencrypted or PKCS#1 RSA private key stored in file. RSA is vulnerable to polynomial-time factoring via Shor's algorithm.",
            remediation: "Never store private keys unencrypted. Migrate asymmetric authentication to ML-DSA-65 or stateful hash-based LMS/XMSS.",
            tags: &["rsa", "private-key", "shor", "pkcs1"],
        },
        PatternDefinition {
            id: "PQC-KEY-EC-001",
            name: "Elliptic Curve (EC) Private Key Material",
            category: "Certificates & Keys",
            regex_pattern: r#"-----BEGIN EC PRIVATE KEY-----"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Elliptic Curve private key detected. ECC discrete logarithm is broken by Shor's quantum algorithm.",
            remediation: "Migrate private keys to NIST FIPS 204 (ML-DSA) or hybrid ECDSA+ML-DSA schemes.",
            tags: &["ec", "ecdsa", "private-key", "shor"],
        },
        PatternDefinition {
            id: "PQC-KEY-SSH-001",
            name: "OpenSSH Private Key Material",
            category: "Certificates & Keys",
            regex_pattern: r#"-----BEGIN OPENSSH PRIVATE KEY-----"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "OpenSSH private key block detected. Classical host/user keys should be audited for quantum migration readiness.",
            remediation: "Protect private keys with strong passphrases. Upgrade OpenSSH to use post-quantum hybrid keys.",
            tags: &["ssh", "openssh", "private-key"],
        },
        PatternDefinition {
            id: "PQC-KEY-DSA-001",
            name: "DSA Private Key Material (Deprecated & Broken)",
            category: "Certificates & Keys",
            regex_pattern: r#"-----BEGIN DSA PRIVATE KEY-----"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "DSA private key detected. DSA is classically deprecated (FIPS 186-5) and completely broken by quantum algorithms.",
            remediation: "Revoke DSA key immediately and replace with ML-DSA-65 or Ed25519.",
            tags: &["dsa", "deprecated", "critical", "broken"],
        },
        PatternDefinition {
            id: "PQC-KEY-PGP-001",
            name: "PGP / GPG Private Key Block",
            category: "Certificates & Keys",
            regex_pattern: r#"-----BEGIN PGP PRIVATE KEY BLOCK-----"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "PGP/GPG private key block detected. Encrypted emails and signed git commits using classical RSA/ElGamal keys are vulnerable to Store-Now-Decrypt-Later.",
            remediation: "Prepare OpenPGP infrastructure for post-quantum algorithms (draft-ietf-openpgp-pqc).",
            tags: &["pgp", "gpg", "private-key"],
        },
        PatternDefinition {
            id: "PQC-KEY-PKCS8-001",
            name: "PKCS#8 Private Key Container",
            category: "Certificates & Keys",
            regex_pattern: r#"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "PKCS#8 private key structure detected.",
            remediation: "Verify underlying algorithm is post-quantum safe or hybrid. Ensure encryption at rest.",
            tags: &["pkcs8", "private-key"],
        },

        // ─── 19. HARDCODED SECRETS & SENSITIVE CREDENTIALS ───────────────────
        PatternDefinition {
            id: "PQC-SEC-AWS-001",
            name: "Hardcoded AWS Access Key ID",
            category: "Secrets & Credentials",
            regex_pattern: r#"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Active AWS access key ID detected in source code or configuration.",
            remediation: "Revoke credential immediately. Use IAM roles, AWS Secrets Manager, or environment variables.",
            tags: &["aws", "secrets", "cwe-798"],
        },
        PatternDefinition {
            id: "PQC-SEC-KEY-001",
            name: "Hardcoded Cryptographic Secret Key Assignment",
            category: "Secrets & Credentials",
            regex_pattern: r#"(?i)(?:api[_-]?key|secret[_-]?key|private[_-]?key|jwt[_-]?secret|encryption[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{16,}['"]"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Hardcoded secret or private key assigned in code or configuration file.",
            remediation: "Remove hardcoded credentials from source code. Load secrets dynamically from a KMS or secret store.",
            tags: &["secrets", "credentials", "cwe-798"],
        },
        PatternDefinition {
            id: "PQC-SEC-JWT-001",
            name: "Hardcoded JWT Token",
            category: "Secrets & Credentials",
            regex_pattern: r#"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Static JWT Bearer token committed to repository.",
            remediation: "Invalidate static token. Generate ephemeral tokens dynamically with short lifespans.",
            tags: &["jwt", "token", "secrets"],
        },
        PatternDefinition {
            id: "PQC-SEC-GH-001",
            name: "Hardcoded GitHub Personal Access Token",
            category: "Secrets & Credentials",
            regex_pattern: r#"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Active GitHub Personal Access Token detected in repository.",
            remediation: "Revoke token immediately in GitHub Settings -> Developer settings -> Personal access tokens.",
            tags: &["github", "token", "secrets", "cwe-798"],
        },

        // ── 20. TLS Validation Bypass & Weak Certificate Controls ──
        PatternDefinition {
            id: "PQC-TLS-BYPASS-001",
            name: "Node.js TLS Verification Disabled",
            category: "TLS & Network Protocols",
            regex_pattern: r#"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Environment variable NODE_TLS_REJECT_UNAUTHORIZED is set to 0, globally disabling TLS certificate verification in Node.js.",
            remediation: "Remove NODE_TLS_REJECT_UNAUTHORIZED=0. Always enforce strict TLS certificate validation in all environments.",
            tags: &["tls", "mitm", "certificate", "cwe-295"],
        },
        PatternDefinition {
            id: "PQC-TLS-BYPASS-002",
            name: "Go TLS InsecureSkipVerify Enabled",
            category: "TLS & Network Protocols",
            regex_pattern: r#"\bInsecureSkipVerify\s*:\s*true\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Go crypto/tls Config has InsecureSkipVerify set to true, disabling server certificate and hostname verification.",
            remediation: "Set InsecureSkipVerify to false. Configure custom RootCAs if private certificate authorities are required.",
            tags: &["tls", "golang", "mitm", "cwe-295"],
        },
        PatternDefinition {
            id: "PQC-TLS-BYPASS-003",
            name: "Python Requests verify=False",
            category: "TLS & Network Protocols",
            regex_pattern: r#"\bverify\s*=\s*False\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Python HTTP request disables SSL/TLS certificate verification (verify=False), allowing Man-in-the-Middle attacks.",
            remediation: "Remove verify=False or supply path to trusted CA certificate bundle (verify='/path/to/cacert.pem').",
            tags: &["python", "requests", "tls", "mitm", "cwe-295"],
        },
        PatternDefinition {
            id: "PQC-TLS-BYPASS-004",
            name: "Java Blind TrustManager Implementation",
            category: "TLS & Network Protocols",
            regex_pattern: r#"\b(TrustAllCerts|NullTrustManager|X509TrustManager\s*\{\s*public\s+void\s+checkClientTrusted|X509TrustManager\s*\{\s*public\s+void\s+checkServerTrusted)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Java X509TrustManager blindly trusts all certificates without verifying against a trust store.",
            remediation: "Use standard Java TrustManagerFactory initialized with a valid KeyStore containing verified root certificates.",
            tags: &["java", "tls", "trustmanager", "cwe-295"],
        },
        PatternDefinition {
            id: "PQC-TLS-BYPASS-005",
            name: "Node.js HTTPS rejectUnauthorized: false",
            category: "TLS & Network Protocols",
            regex_pattern: r#"\brejectUnauthorized\s*:\s*false\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Node.js TLS/HTTPS client configuration explicitly disables certificate verification.",
            remediation: "Ensure rejectUnauthorized is true (default) and provide trusted CA cert in the ca agent option.",
            tags: &["nodejs", "tls", "https", "cwe-295"],
        },
        PatternDefinition {
            id: "PQC-TLS-BYPASS-006",
            name: "Insecure curl TLS Verification Flag",
            category: "TLS & Network Protocols",
            regex_pattern: r#"\bcurl\s+[^;\n]*(-k\b|--insecure\b)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "curl command executed with --insecure or -k flag, bypassing SSL/TLS certificate validation.",
            remediation: "Remove --insecure/-k and install necessary root CA certificates into the system trust store.",
            tags: &["curl", "tls", "mitm", "cwe-295"],
        },

        // ── 21. Insecure Block Cipher Modes ──
        PatternDefinition {
            id: "PQC-CIPHER-MODE-001",
            name: "Insecure ECB Cipher Mode",
            category: "Symmetric Ciphers",
            regex_pattern: r#"(?:/(?:ECB|Electronic\s*Codebook)|(?:CipherMode|AES|DES)\.ECB|MODE_ECB)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Electronic Codebook (ECB) mode of operation detected. Lacks diffusion and leaks plaintext patterns.",
            remediation: "Migrate to authenticated encryption with associated data (AEAD) mode such as AES-256-GCM or ChaCha20-Poly1305.",
            tags: &["ecb", "symmetric", "cwe-327"],
        },
        PatternDefinition {
            id: "PQC-CIPHER-MODE-002",
            name: "Unauthenticated CBC Mode with PKCS5/7 Padding",
            category: "Symmetric Ciphers",
            regex_pattern: r#"(?:/(?:CBC)/PKCS[57]Padding|MODE_CBC.*PKCS[57])"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "CBC mode with PKCS5/PKCS7 padding is susceptible to padding oracle attacks if authentication (MAC) is missing.",
            remediation: "Migrate to authenticated encryption (AES-256-GCM) to ensure both confidentiality and integrity.",
            tags: &["cbc", "padding-oracle", "cwe-327"],
        },

        // ── 22. Certificate Pinning & Zero-Trust mTLS ──
        PatternDefinition {
            id: "PQC-PINNING-001",
            name: "Certificate Pinning Control",
            category: "Certificates & Keys",
            regex_pattern: r#"(?i)\b(CertificatePinner|TrustKit|ssl_pinning|pinnedCertificates|pinning\.setPinned)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Certificate or public key pinning control detected. Hardens TLS against compromised Certificate Authorities.",
            remediation: "Ensure pinned public key hashes are monitored for rotation and include PQC certificate backup pins.",
            tags: &["pinning", "hardening", "pki"],
        },
        PatternDefinition {
            id: "PQC-MTLS-001",
            name: "Mutual TLS (mTLS) Authentication",
            category: "TLS & Network Protocols",
            regex_pattern: r#"(?i)\b(ssl_client_certificate|ssl_verify_client\s+on|ClientAuthType\.RequireAndVerifyClientCert|ClientAuth\s*:\s*tls\.RequireAndVerifyClientCert)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Mutual TLS (mTLS) bidirectional certificate authentication configured.",
            remediation: "mTLS provides strong client identity verification. Plan transition of both client and server certs to PQC (ML-DSA).",
            tags: &["mtls", "zero-trust", "authentication"],
        },

        // ── 23. Verified Post-Quantum Standard Libraries ──
        PatternDefinition {
            id: "PQC-LIB-FIPS203-001",
            name: "NIST FIPS 203 ML-KEM Standard Library",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(fips203|ml-kem|pqcrypto-kyber|noble-post-quantum|@noble/post-quantum)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 203 standardized Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) library active.",
            remediation: "NIST Post-Quantum standard primitive active. Maintain dependency updates.",
            tags: &["pqc", "ml-kem", "fips-203", "post-quantum"],
        },
        PatternDefinition {
            id: "PQC-LIB-FIPS204-001",
            name: "NIST FIPS 204 ML-DSA Standard Library",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(fips204|ml-dsa|pqcrypto-dilithium)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 204 standardized Module-Lattice-Based Digital Signature Algorithm (ML-DSA) library active.",
            remediation: "NIST Post-Quantum standard signature primitive active. Maintain dependency updates.",
            tags: &["pqc", "ml-dsa", "fips-204", "post-quantum"],
        },
        PatternDefinition {
            id: "PQC-LIB-FIPS205-001",
            name: "NIST FIPS 205 SLH-DSA Standard Library",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(fips205|slh-dsa|pqcrypto-sphincsplus)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST FIPS 205 standardized Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) library active.",
            remediation: "NIST Post-Quantum standard stateless signature primitive active. Maintain dependency updates.",
            tags: &["pqc", "slh-dsa", "fips-205", "post-quantum"],
        },
        // ── 24. Real-World Cryptographic CVEs & Academic Vulnerability Research ──
        PatternDefinition {
            id: "CVE-KYBERSLASH-001",
            name: "KyberSlash 1 & 2 Secret Division Timing Leak (CVE-2024-56145 / CVE-2024-56146)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bkyberslash\b|poly_frommsg\s*\([^)]*\/|\bliboqs\s*<\s*0\.9\.2|\bpqclean_kyber.*division\b)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Secret-dependent integer division in ML-KEM/Kyber reference decapsulation leaking private key bits (CVE-2024-56145/CVE-2024-56146).",
            remediation: "Upgrade ML-KEM / Kyber implementations to patched constant-time releases (e.g. liboqs >= 0.9.2, PQClean >= Jan 2024, or FIPS 203 compliant constant-time code).",
            tags: &["cve-2024-56145", "cve-2024-56146", "kyberslash", "timing-attack", "side-channel", "pqc", "ml-kem"],
        },
        PatternDefinition {
            id: "CVE-SIKE-SIDH-001",
            name: "Castryck-Decru Broken Isogeny Cryptosystem (SIKE / SIDH)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(sike_p434|sike_p503|sike_p610|sike_p751|sidh_p434|sidh_p503|sidh_p610|sidh_p751|pqc_kem_sike|liboqs.*sike)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Supersingular Isogeny Diffie-Hellman (SIDH) / SIKE broken in polynomial time by Castryck-Decru attack using auxiliary torsion points.",
            remediation: "Immediately replace SIKE/SIDH with NIST standardized post-quantum algorithms: ML-KEM (FIPS 203) or ML-DSA (FIPS 204). SIKE is completely insecure classically.",
            tags: &["sike", "sidh", "castryck-decru", "isogeny", "broken-pqc", "cwe-327"],
        },
        PatternDefinition {
            id: "CVE-RAINBOW-001",
            name: "Beullens MinRank Broken Multivariate Cryptosystem (Rainbow)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(rainbow_classic|rainbow_circumzenithal|rainbow_compressed|pqcrypto_rainbow|pqc_sig_rainbow)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Rainbow multivariate signature scheme broken in classical polynomial time by Ward Beullens' MinRank attack.",
            remediation: "Immediately migrate from Rainbow to NIST standardized post-quantum signatures: ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
            tags: &["rainbow", "minrank", "broken-pqc", "multivariate", "cwe-327"],
        },
        PatternDefinition {
            id: "CVE-MARVIN-001",
            name: "Marvin Attack RSA PKCS#1 v1.5 Decryption Timing Oracle (CVE-2023-46809)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\brsa\.DecryptPKCS1v15\b|\bRSA_PKCS1_PADDING\b|\bRSA/ECB/PKCS1Padding\b|Cipher\.getInstance\(["']RSA/ECB/PKCS1Padding["']\)|openssl_private_decrypt.*OPENSSL_PKCS1_PADDING)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "RSA PKCS#1 v1.5 padding timing differences re-enabling Bleichenbacher plaintext recovery (CVE-2023-46809, Marvin Attack).",
            remediation: "Migrate to RSA-OAEP with SHA-256 for classical encryption, or transition directly to ML-KEM (FIPS 203) for post-quantum forward secrecy.",
            tags: &["cve-2023-46809", "marvin", "bleichenbacher", "padding-oracle", "timing-attack", "rsa"],
        },
        PatternDefinition {
            id: "CVE-ROBOT-001",
            name: "ROBOT Bleichenbacher RSA TLS Key Exchange Oracle (CVE-2017-13099)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(TLS_RSA_WITH_AES_128_CBC_SHA|TLS_RSA_WITH_AES_256_CBC_SHA|TLS_RSA_WITH_AES_128_GCM_SHA256|TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_3DES_EDE_CBC_SHA)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Static RSA cipher suites vulnerable to the Return Of Bleichenbacher's Oracle Threat (ROBOT / CVE-2017-13099).",
            remediation: "Disable static RSA cipher suites (TLS_RSA_*). Use Ephemeral Diffie-Hellman (ECDHE) or post-quantum hybrid key exchange (X25519MLKEM768).",
            tags: &["cve-2017-13099", "robot", "bleichenbacher", "tls", "rsa-key-exchange"],
        },
        PatternDefinition {
            id: "CVE-SWEET32-001",
            name: "Sweet32 64-bit Block Cipher Birthday Collision (CVE-2016-2183 / CVE-2016-6329)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bDES-CBC3-SHA\b|\bEDH-RSA-DES-CBC3-SHA\b|\bECDHE-RSA-DES-CBC3-SHA\b|\b3DES-EDE\b|\bBlowfish-CBC\b|cipher\s*=\s*['"]?DES-EDE3-CBC['"]?)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Birthday attacks against 64-bit block ciphers (3DES, Blowfish) in CBC mode leaking session plaintext (CVE-2016-2183, Sweet32).",
            remediation: "Disable 3DES and Blowfish cipher suites. Upgrade to 128-bit or 256-bit block ciphers in AEAD mode (AES-256-GCM, ChaCha20-Poly1305).",
            tags: &["cve-2016-2183", "cve-2016-6329", "sweet32", "3des", "blowfish", "collision"],
        },
        PatternDefinition {
            id: "CVE-DROWN-001",
            name: "DROWN Cross-Protocol RSA Decryption via SSLv2 (CVE-2016-0800)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bSSLv2_method\b|\bSSLv2_server_method\b|SSLv23_method.*SSL_OP_NO_SSLv2|ssl_protocols.*SSLv2|Protocols\s*\+?SSLv2)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Cross-protocol Bleichenbacher attack leveraging shared RSA private keys with obsolete SSLv2 servers (CVE-2016-0800, DROWN).",
            remediation: "Completely disable SSLv2 protocol across all servers and firewalls. Ensure private keys are never reused on legacy endpoints.",
            tags: &["cve-2016-0800", "drown", "sslv2", "cross-protocol", "rsa"],
        },
        PatternDefinition {
            id: "CVE-LOGJAM-001",
            name: "Logjam Discrete Logarithm Export Downgrade (CVE-2015-4000)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bEXP-EDH-RSA-DES-CBC-SHA\b|\bEXP-EDH-DSS-DES-CBC-SHA\b|\bDHE_EXPORT\b|ssl_ciphers.*EXPORT|SSLCipherSuite.*EXPORT)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Export-grade 512-bit Diffie-Hellman parameters precomputation and downgrade attack (CVE-2015-4000, Logjam).",
            remediation: "Disable all export cipher suites. Require minimum 2048-bit Diffie-Hellman parameters or switch to ECDHE / ML-KEM-768.",
            tags: &["cve-2015-4000", "logjam", "dhe-export", "dh-downgrade"],
        },
        PatternDefinition {
            id: "CVE-SLOTH-001",
            name: "SLOTH Transcript Hash Collision Attack (CVE-2015-7575)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bMD5_WITH_RSA_ENCRYPTION\b|\bRSA_PKCS1_MD5\b|\bmd5WithRSAEncryption\b|SignatureAndHashAlgorithm\s*=\s*\{\s*HashAlgorithm\.md5|SignatureAlgorithms.*md5)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "MD5/SHA-1 transcript collision attacks on TLS 1.2 client certificate authentication and ServerKeyExchange (CVE-2015-7575, SLOTH).",
            remediation: "Disable MD5 and SHA-1 signature algorithms in TLS configurations. Enforce SHA-256, SHA-384, or post-quantum signatures (ML-DSA).",
            tags: &["cve-2015-7575", "sloth", "md5-tls", "hash-collision"],
        },
        PatternDefinition {
            id: "CVE-MINERVA-001",
            name: "Minerva ECDSA Scalar Multiplication Nonce Bit-Length Leak (CVE-2019-15809)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(crypto_scalarmult_curve25519_variable|EC_POINT_mul_var|scalar_multiplication_variable_time|leading_zeros_nonce)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::Medium,
            description: "Variable-time scalar multiplication in ECDSA leaking secret nonce bit length through timing side-channels (CVE-2019-15809, Minerva).",
            remediation: "Ensure all elliptic curve scalar multiplications use constant-time Montgomery ladder or blinded scalar algorithms.",
            tags: &["cve-2019-15809", "minerva", "ecdsa-timing", "nonce-leak"],
        },
        PatternDefinition {
            id: "CVE-CURVEBALL-001",
            name: "CurveBall Explicit Elliptic Curve Parameter Spoofing (CVE-2020-0601)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bspecifiedCurve\b|ECParameters\(explicit\)|ASN1_SEQUENCE_OF_EC_PARAMETERS|curve_type\s*=\s*['"]?explicit['"]?)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Arbitrary explicit elliptic curve parameters enabling generator G' manipulation and CA certificate spoofing (CVE-2020-0601, CurveBall).",
            remediation: "Reject explicit EC parameters. Enforce standard named curves (secp256r1, secp384r1) and validate generator point order.",
            tags: &["cve-2020-0601", "curveball", "explicit-ec-params", "spoofing"],
        },
        PatternDefinition {
            id: "CVE-HEARTBLEED-001",
            name: "Heartbleed OpenSSL TLS Heartbeat Memory Disclosure (CVE-2014-0160)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bopenssl\s*(?:==|:)?\s*1\.0\.1[a-f]\b|\bOPENSSL_1_0_1[A-F]\b|\blibssl\.so\.1\.0\.1\b)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Missing bounds check in TLS Heartbeat extension leaking up to 64KB private memory per payload (CVE-2014-0160, Heartbleed).",
            remediation: "Upgrade OpenSSL to 1.0.1g+ or modern OpenSSL 3.0+ / Rustls, or compile with -DOPENSSL_NO_HEARTBEATS.",
            tags: &["cve-2014-0160", "heartbleed", "openssl", "memory-leak"],
        },
        PatternDefinition {
            id: "CVE-DUALEC-001",
            name: "Dual_EC_DRBG Kleptographic Backdoor Generator (NIST SP 800-90A)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(Dual_EC_DRBG|DualECDRBG|dual_ec_drbg|DualEllipticCurveDRBG)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Kleptographic backdoor in Dual Elliptic Curve Deterministic Random Bit Generator allowing key recovery via known point relationship.",
            remediation: "Immediately remove Dual_EC_DRBG. Use NIST SP 800-90A Rev 1 approved DRBGs: CTR_DRBG with AES-256 or HMAC_DRBG with SHA-256.",
            tags: &["dual-ec-drbg", "backdoor", "nsa", "cwe-327"],
        },
        PatternDefinition {
            id: "CVE-NONCE-REUSE-001",
            name: "ECDSA / DSA Static Nonce Reuse Key Extraction (RFC 6979 Violation)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:sign_with_k\s*\(|k\s*=\s*['"][0-9a-fA-F]{32,}['"]|k\s*=\s*(?:12345|0x12345|1337)\b|fixed_nonce\s*=\s*true)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Repeated or deterministic nonce failure in DSA/ECDSA signatures allowing instantaneous algebraic private key extraction (Sony PS3 flaw).",
            remediation: "Always generate cryptographically uniform unique random nonces via CSPRNG or enforce deterministic RFC 6979 HMAC nonce generation.",
            tags: &["nonce-reuse", "rfc-6979", "fail0verflow", "key-recovery", "ecdsa"],
        },
        // ── 25. Quantum Vulnerability Research, Stateful Hash Reuse & Grover Bounds ──
        PatternDefinition {
            id: "CVE-STATEFUL-HASH-001",
            name: "Stateful Hash-Based Signature State Counter Reuse (LMS / XMSS / SP 800-208)",
            category: "Quantum Vulnerability Research",
            regex_pattern: r#"(?i)\b(lms_sign|xmss_sign|xmssmt_sign|ots_sign|wots_sign|hss_sign)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Stateful hash-based signature (LMS/XMSS) detected. Duplicate OTS counter usage (e.g. from VM snapshots, concurrent threads, or uncommitted NVRAM) completely breaks Winternitz OTS, enabling private key forgery.",
            remediation: "Enforce hardware-enforced monotonic state counter synchronization or migrate to stateless post-quantum signatures: SLH-DSA (FIPS 205 / SPHINCS+) or ML-DSA (FIPS 204).",
            tags: &["lms", "xmss", "sp800-208", "state-reuse", "ots-compromise", "pqc"],
        },
        PatternDefinition {
            id: "CVE-TERRAPIN-001",
            name: "Terrapin SSH BPP Sequence Downgrade Attack (CVE-2023-48795)",
            category: "Quantum Vulnerability Research",
            regex_pattern: r#"(?i)\b(chacha20-poly1305@openssh\.com|hmac-sha2-512-etm@openssh\.com|hmac-sha2-256-etm@openssh\.com)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "SSH channel vulnerability allowing MiTM sequence manipulation to strip extension negotiation and downgrade algorithms before post-quantum key exchange (CVE-2023-48795, Terrapin).",
            remediation: "Enable Strict KEX extension (kex-strict-c-v00@openssh.com and kex-strict-s-v00@openssh.com) and update OpenSSH to >= 9.6.",
            tags: &["cve-2023-48795", "terrapin", "ssh", "mitm", "strict-kex"],
        },
        PatternDefinition {
            id: "PQC-GROVER-AES128-001",
            name: "Grover's Algorithm AES-128 Key Space Reduction (CNSA 2.0 Inadequacy)",
            category: "Quantum Vulnerability Research",
            regex_pattern: r#"(?i)\b(aes-128-gcm|aes-128-cbc|aes128|crypto_aead_aes128gcm|Cipher\.getInstance\(["']AES/GCM/NoPadding["'],\s*128\))\b"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::High,
            description: "128-bit symmetric key space reduced to 64 bits of quantum security by Grover's algorithm (O(2^{n/2})). Non-compliant with CNSA 2.0 and NIST PQC quantum resilience guidelines.",
            remediation: "Upgrade symmetric key lengths to AES-256-GCM or ChaCha20-Poly1305 (minimum 256 bits) to maintain 128 bits of post-quantum security.",
            tags: &["grover", "aes-128", "cnsa-2.0", "key-space-halving", "symmetric-quantum"],
        },
        PatternDefinition {
            id: "PQC-GROVER-HASH-001",
            name: "Quantum Collision Search Preimage Weakness (SHA-1 / SHA-224 / MD5)",
            category: "Quantum Vulnerability Research",
            regex_pattern: r#"(?i)\b(sha1|sha-1|sha224|sha-224|ripemd160)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Hash function vulnerable to classical collision and quantum BHT (O(2^{n/3})) collision algorithms. Inadequate quantum security margin.",
            remediation: "Upgrade to SHA-384, SHA-512, or SHA3-384 / SHAKE-256 as mandated by CNSA 2.0.",
            tags: &["bht-algorithm", "quantum-collision", "grover-hash", "cnsa-2.0"],
        },
        PatternDefinition {
            id: "CVE-FALCON-FLOAT-001",
            name: "Falcon (FN-DSA) IEEE 754 Floating-Point Side-Channel Timing Leak",
            category: "Quantum Vulnerability Research",
            regex_pattern: r#"(?i)\b(falcon_vrfy_float|falcon_inner_fft|fpr_mul|fpr_add|fpr_norm)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Native hardware floating-point operations in Falcon lattice sampler leaking secret polynomial coefficients via microarchitectural timing differences.",
            remediation: "Use Karney constant-time emulation or constant-time fixed-point integer arithmetic for Falcon / FN-DSA (NIST FIPS 206) signature generation.",
            tags: &["falcon", "fn-dsa", "fips-206", "floating-point-sca", "timing-leak"],
        },
        PatternDefinition {
            id: "PQC-HNDL-EXPOSURE-001",
            name: "Harvest Now, Decrypt Later (HNDL) Unhybridized Classical Key Exchange",
            category: "Quantum Vulnerability Research",
            regex_pattern: r#"(?i)\b(ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-RSA-AES128-GCM-SHA256|curve25519-sha256@libssh\.org|ecdh-sha2-nistp256)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::Medium,
            description: "Classical-only ephemeral key exchange without post-quantum hybrid KEM (ML-KEM-768). Traffic is vulnerable to passive recording for retrospective decryption by future quantum computers (HNDL).",
            remediation: "Configure hybrid post-quantum key exchange: X25519MLKEM768 (TLS group 0x11ec / 4588) or SecP256r1MLKEM768 in TLS and SSH servers.",
            tags: &["hndl", "harvest-now-decrypt-later", "hybrid-kem", "x25519mlkem768", "forward-secrecy"],
        },
        // ── 26. Bleeding-Edge Cryptographic Research, Downcheck & Algorithmic Oracles ──
        PatternDefinition {
            id: "CVE-PSYCHIC-SIG-001",
            name: "Psychic Signatures Zero Parameter ECDSA Verification Bypass (CVE-2022-21449)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:Signature\.getInstance\(["']SHA256withECDSA["']\)|ecdsa\.Verify\(.*,\s*0,\s*0\)|r\.signum\(\)\s*==\s*0|s\.signum\(\)\s*==\s*0)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Missing zero checks for ECDSA signature parameters (r=0, s=0) allowing arbitrary signature forgery for any message (CVE-2022-21449, Psychic Signatures).",
            remediation: "Verify that signature parameters r and s are strictly non-zero and in the range [1, n-1]. Upgrade Java to 15.0.7, 17.0.3, 18.0.1 or higher.",
            tags: &["cve-2022-21449", "psychic-signatures", "ecdsa-bypass", "java", "forgery"],
        },
        PatternDefinition {
            id: "CVE-OPENSSL-MODSQRT-001",
            name: "OpenSSL BN_mod_sqrt Infinite Loop Certificate DoS (CVE-2022-0778)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:\bBN_mod_sqrt\b|openssl\s*(?:==|:)?\s*(?:1\.0\.2|1\.1\.1[a-m]|3\.0\.[01])\b)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Malformed non-prime modulus in elliptic curve certificate triggering an infinite loop in modular square root calculation (CVE-2022-0778).",
            remediation: "Upgrade OpenSSL to 1.1.1n, 3.0.2 or higher. Ensure certificate validation explicitly validates curve prime order.",
            tags: &["cve-2022-0778", "openssl", "dos", "infinite-loop", "bn_mod_sqrt"],
        },
        PatternDefinition {
            id: "CVE-XZ-BACKDOOR-001",
            name: "XZ Utils liblzma Backdoored IFUNC Hooking (CVE-2024-3094)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:\bliblzma\.(?:so|5\.6\.[01])\b|\bxz-(?:5\.6\.0|5\.6\.1)\b|_get_cpuid.*lzma_alloc)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Upstream supply-chain backdoor in liblzma / XZ Utils intercepting OpenSSH RSA_public_decrypt IFUNC resolution (CVE-2024-3094).",
            remediation: "Downgrade or upgrade XZ Utils to a known clean version (5.4.x or >= 5.6.2). Audit shared library IFUNC dependencies.",
            tags: &["cve-2024-3094", "xz-backdoor", "supply-chain", "ssh", "ifunc"],
        },
        PatternDefinition {
            id: "PQC-IMPLICIT-REJECT-001",
            name: "PQC Chosen-Ciphertext Oracle Explicit Rejection Flaw (FIPS 203 Section 7)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:throw\s+new\s+.*DecapsulationException|return\s+Err\(.*DecapFailed|if\s*\(c\s*!=\s*c_prime\)\s*return\s*false)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::Medium,
            description: "Explicit rejection on invalid ciphertext during ML-KEM/Kyber decapsulation creates a 1-bit chosen-ciphertext oracle leaking secret lattice vectors.",
            remediation: "Enforce implicit rejection per NIST FIPS 203 Section 7: return pseudorandom key K = SHAKE256(z || c) when re-encryption check c != c' fails.",
            tags: &["fips-203", "implicit-rejection", "fujisaki-okamoto", "chosen-ciphertext", "pqc"],
        },
        PatternDefinition {
            id: "PQC-HYBRID-DOWNCHECK-001",
            name: "Hybrid Post-Quantum Key Exchange Transcript Downcheck Vulnerability",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:\bhybrid_kex_fallback_to_classical\b|\ballow_classical_downgrade\s*=\s*true\b|\bignore_pqc_extension\b)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Missing transcript binding in hybrid key exchange allowing active network adversaries to strip post-quantum shares without handshake failure.",
            remediation: "Enforce strict hybrid transcript hashing where shared secret SS = KDF(SS_classical || SS_pqc). Disallow unauthenticated downgrade fallbacks.",
            tags: &["hybrid-kem", "downcheck", "downgrade-attack", "transcript-binding", "tls1.3"],
        },
        PatternDefinition {
            id: "CVE-ZEROLOGON-001",
            name: "ZeroLogon Static All-Zero IV in AES-CFB8 (CVE-2020-1472)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:\bComputeNetlogonCredential\b|\bNetrServerAuthenticate\b|aes_cfb8.*(?:0000000000000000|zeros\(16\)))"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "All-zero static initialization vector in AES-CFB8 mode in Microsoft Netlogon protocol enabling domain controller takeover (CVE-2020-1472, ZeroLogon).",
            remediation: "Enforce secure RPC with randomized session keys and disable legacy unauthenticated Netlogon connections.",
            tags: &["cve-2020-1472", "zerologon", "aes-cfb8", "static-iv", "active-directory"],
        },
        PatternDefinition {
            id: "CVE-PUTTY-P521-001",
            name: "PuTTY Biased P-521 Nonce Secret Key Recovery (CVE-2024-31497)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:\bputty\b.*(?:0\.[6-7][0-9]|0\.80)\b|ecdsa-sha2-nistp521.*(?:putty|pageant)|deterministic_p521_nonce)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "PuTTY versions 0.68-0.80 generated biased ECDSA P-521 nonces with first 9 bits set to zero, enabling full private key recovery from 60 SSH signatures (CVE-2024-31497).",
            remediation: "Upgrade PuTTY/Pageant to >= 0.81 immediately. Revoke all P-521 SSH keys loaded into affected versions and replace with ML-KEM/ML-DSA hybrid SSH keys (mlkem768x25519-sha512).",
            tags: &["cve-2024-31497", "putty", "p521", "nonce-bias", "ssh", "lattice-attack"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-MLDSA-DFA-001",
            name: "NIST FIPS 204 ML-DSA Deterministic Fault Injection Vulnerability (Lattice DFA)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:dilithium_sign_deterministic\b|mldsa_sign.*(?:deterministic\s*:\s*true|rnd\s*=\s*NULL|opt_rand.*zeros)|deterministic_signing\s*=\s*true)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Deterministic ML-DSA / Dilithium signing without fresh randomness (rnd = 0) is vulnerable to Differential Fault Analysis (DFA); a single bit flip during polynomial signing recovers private key vectors s1 and s2.",
            remediation: "Use randomized (hedged) ML-DSA signing per FIPS 204 Section 5.4: inject 32 bytes of cryptographically secure random entropy (rnd) into every signature generation.",
            tags: &["fips-204", "ml-dsa", "dilithium", "dfa", "fault-injection", "deterministic-signing"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-SLHDSA-OPTRAND-001",
            name: "NIST FIPS 205 SLH-DSA Zero Randomizer Multi-Target Collision (Stateless Hash Attack)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:slh_dsa_sign.*(?:NULL|0x0|opt_rand\s*=\s*0)|SPHINCS_OPT_RAND_ZERO\b|sphincs_sign.*opt_rand.*(?:zeros|None))"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Passing a null or zero opt_rand buffer to SLH-DSA (SPHINCS+) eliminates hedged randomized hashing, opening the FORS tree signatures to multi-target second-preimage birthday attacks.",
            remediation: "Provide 32 bytes of secure random noise to `opt_rand` parameter in FIPS 205 SLH-DSA signing calls to safeguard FORS trees against multi-target cryptanalysis.",
            tags: &["fips-205", "slh-dsa", "sphincs-plus", "opt-rand", "hash-signatures", "multi-target"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-NTT-CACHE-001",
            name: "ML-KEM / ML-DSA Non-Constant-Time NTT Multiplication Cache Leakage",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:ntt_custom\b|poly_mul_unmasked\b|barrett_reduce_variable\b|montgomery_reduce_variable\b|table_lookup_ntt\[)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::Medium,
            description: "Variable-time Number Theoretic Transform (NTT) or secret-dependent table lookups in lattice polynomial multiplication leak private key coefficients via CPU cache-timing channels.",
            remediation: "Employ constant-time SIMD / AVX2 / NEON NTT implementations (such as PQClean or libcrux) with verified constant execution time across all input operands.",
            tags: &["ntt", "cache-timing", "side-channel", "lattice-pqc", "constant-time"],
        },
        PatternDefinition {
            id: "PQC-CVE-2024-24576-001",
            name: "Windows Batch Command Injection in PQC Deployment Toolchains (CVE-2024-24576)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:Command::new\s*\(\s*["'][^"']*\.(?:bat|cmd)["']\s*\)|cmd\.exe\s+/c\s+.*%[a-zA-Z0-9_]+%)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::High,
            description: "Unsanitized argument passing to Windows .bat / .cmd batch files bypasses cmd.exe escaping, allowing arbitrary command execution in automated cryptographic build pipelines (CVE-2024-24576).",
            remediation: "Upgrade Rust toolchains to >= 1.77.2. Explicitly validate and escape arguments when invoking Windows shell scripts, or invoke native binaries directly without cmd.exe wrapping.",
            tags: &["cve-2024-24576", "command-injection", "windows", "rust-security", "toolchain"],
        },
        PatternDefinition {
            id: "PQC-CVE-2023-3817-001",
            name: "OpenSSL DH Parameter Validation CPU Exhaustion DoS (CVE-2023-3817)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:DH_check\s*\(|EVP_PKEY_param_check\s*\(.*openssl.*(?:3\.0\.[0-9]|3\.1\.[0-1]))"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Excessive polynomial testing during Diffie-Hellman parameter verification in OpenSSL 3.0/3.1 allows remote untrusted inputs to trigger persistent CPU resource exhaustion (CVE-2023-3817).",
            remediation: "Upgrade OpenSSL to >= 3.0.10 or >= 3.1.2. Restrict DH parameter acceptance to standardized RFC 7919 FFDHE groups or migrate directly to ML-KEM-768.",
            tags: &["cve-2023-3817", "openssl", "dh", "denial-of-service", "cpu-exhaustion"],
        },
        PatternDefinition {
            id: "PQC-CVE-2024-0727-001",
            name: "OpenSSL PKCS12 Malformed SafeContents Crash DoS (CVE-2024-0727)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:PKCS12_parse\s*\(|d2i_PKCS12_bio\s*\(|d2i_PKCS12_fp\s*\))"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Unknown,
            default_confidence: Confidence::Medium,
            description: "Parsing malformed PKCS12 structures with omitted attributes causes a NULL pointer dereference and crash in OpenSSL (CVE-2024-0727).",
            remediation: "Upgrade OpenSSL to >= 3.2.1, >= 3.1.5, or >= 3.0.13. Validate ASN.1 envelope integrity prior to parsing untrusted PKCS#12 bundles.",
            tags: &["cve-2024-0727", "openssl", "pkcs12", "null-dereference", "dos"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-X25519-CLAMP-001",
            name: "X25519 Missing Scalar Clamping Small-Subgroup Confinement Attack",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:\bx25519_without_clamping\b|\bunclamped_scalar_mul\b|\bcurve25519_unclamped\b|\bcustom_x25519_ladder\b)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::Medium,
            description: "Custom X25519 scalar multiplication omitting bit clamping (k[0] &= 248; k[31] &= 127; k[31] |= 64) allows low-order point attacks leaking scalar bits modulo 8.",
            remediation: "Always clamp private scalars per RFC 7748 Section 5: clear bottom 3 bits and top bit, and set bit 254 before performing Montgomery ladder multiplication.",
            tags: &["rfc-7748", "x25519", "clamping", "subgroup-attack", "ecc"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-FO-TRANSFORM-001",
            name: "Incomplete Fujisaki-Okamoto Transform Re-encryption Skip Flaw",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:skip_reencryption\s*=\s*true|fo_transform_optimistic|disable_ciphertext_verification)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Skipping the re-encryption check (c' == c) in the Fujisaki-Okamoto (FO) transform converts IND-CCA2 ML-KEM down to IND-CPA, allowing full key recovery via chosen ciphertexts.",
            remediation: "Never bypass FO re-encryption in KEM decapsulation. Always re-encrypt the recovered message and verify byte-for-byte equality with input ciphertext c in constant time.",
            tags: &["fujisaki-okamoto", "ml-kem", "cca2", "ind-cca", "pqc-security"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-SP800-208-VOLATILE-001",
            name: "Stateful Hash Signature Volatile RAM Index Counter Violation (NIST SP 800-208)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:static\s+mut\s+lms_idx\b|xmss_index\s*\+\+|atomic_fetch_add.*(?:lms_seq|xmss_seq)|in_memory_stateful_index)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Storing LMS/XMSS stateful hash signature sequence counters in volatile RAM without hardware write-before-sign NVRAM synchronization violates NIST SP 800-208 and guarantees catastrophic OTS key reuse on crash/reboot.",
            remediation: "Enforce persistent non-volatile atomic increment before signing per NIST SP 800-208, or migrate to stateless signatures (SLH-DSA FIPS 205 / ML-DSA FIPS 204).",
            tags: &["sp-800-208", "lms", "xmss", "stateful-hash", "ots-reuse", "hardware-security"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-XOR-COMBINER-001",
            name: "Insecure XOR Hybrid Shared Secret Combiner (Lacks Dual-PRF HKDF)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:shared_secret\[i\]\s*=\s*ss_classical\[i\]\s*\^\s*ss_pqc\[i\]|ss_combined\s*=\s*ss_ecdh\s*\^\s*ss_kem)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Combining classical and post-quantum shared secrets using bitwise XOR instead of dual-PRF HKDF-Extract(classical || pqc) violates IETF hybrid design specifications.",
            remediation: "Use standard HKDF combiner per draft-ietf-tls-hybrid-design: `SS = HKDF-Extract(0, SS_classical || SS_pqc)` ensuring cryptographic security holds if either primitive is unbroken.",
            tags: &["hybrid-combiner", "xor-flaw", "dual-prf", "hkdf", "tls-hybrid", "draft-ietf-tls-hybrid-design"],
        },
        PatternDefinition {
            id: "CVE-RACCOON-001",
            name: "Raccoon Attack TLS Diffie-Hellman Secret Zero-Stripping Timing Leak (CVE-2020-15999)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:strip_leading_zeros\b|leading_zero_strip\b|dhe_strip_zero|raccoon_attack|BN_bn2bin\s*\(.*pms)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Stripping leading zero bytes from the Diffie-Hellman pre-master secret rather than constant-time padding creates a timing side channel that allows recovering the shared secret (CVE-2020-15999, Raccoon Attack).",
            remediation: "Enforce constant-time left-padding of DH shared secrets to key length, or disable classical DHE in favor of ML-KEM-768 hybrid key encapsulation.",
            tags: &["cve-2020-15999", "raccoon-attack", "diffie-hellman", "timing-leak", "tls"],
        },
        PatternDefinition {
            id: "CVE-FREAK-001",
            name: "FREAK Attack RSA 512-bit Export Key Downgrade (CVE-2015-0204)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:TLS_RSA_EXPORT_WITH_|SSL_RSA_EXPORT_WITH_|RSA_EXPORT\b|export_512_rsa|allow_export_ciphers)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Accepting export-grade 512-bit RSA keys (RSA_EXPORT) permits a man-in-the-middle attacker to downgrade the TLS connection and factor the modulus (CVE-2015-0204, FREAK).",
            remediation: "Completely disable export-grade cipher suites in TLS configurations and migrate key exchange to NIST FIPS 203 (ML-KEM).",
            tags: &["cve-2015-0204", "freak-attack", "rsa-export", "downgrade", "tls"],
        },
        PatternDefinition {
            id: "CVE-BLEICHENBACHER-E3-001",
            name: "Bleichenbacher e=3 Low-Exponent RSA Signature Forgery (CVE-2006-4339)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)(?:rsa_verify_e3\b|bleichenbacher_e3|pkcs1v15_loose_verify|skip_trailing_garbage_check)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Incomplete PKCS#1 v1.5 padding validation with small public exponent e=3 allows forging RSA signatures without private key knowledge by embedding arbitrary garbage after the ASN.1 digest header.",
            remediation: "Enforce strict length and byte checks over the entire PKCS#1 v1.5 padding block, migrate to RSA-PSS, or adopt NIST FIPS 204 (ML-DSA) post-quantum signatures.",
            tags: &["cve-2006-4339", "bleichenbacher", "rsa-e3", "signature-forgery", "pkcs1v15"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-FALCON-SAMPLER-001",
            name: "Falcon (FN-DSA) Gaussian Sampler Denormal Timing Leak (FIPS 206)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:gaussian_sampler_denormal\b|falcon_ldl_float\b|ffSampling_fft\b|subnormal_fp_sample)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::Medium,
            description: "Variable CPU cycle execution caused by denormal floating-point values in Falcon's fast Fourier Gaussian sampler allows timing side-channel recovery of secret lattice basis vectors.",
            remediation: "Enable Flush-To-Zero (FTZ) and Denormals-Are-Zero (DAZ) in CPU control registers during Falcon signature generation, or use constant-time fixed-point emulators.",
            tags: &["fips-206", "falcon", "fn-dsa", "gaussian-sampler", "floating-point", "timing-leak"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-ED25519-MALLEABILITY-001",
            name: "Ed25519 Cofactor Signature Malleability & Non-Canonical Reduction (ZIP-215)",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:ed25519_verify_relaxed\b|zip215_disabled\b|allow_non_canonical_s\b|cofactorless_verification)"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Failure to enforce canonical scalar reduction (s < L) or cofactor-8 checking in Ed25519 verification allows valid signature malleability, creating consensus split vulnerabilities in distributed ledgers.",
            remediation: "Enforce strict ZIP-215 / RFC 8032 verification requiring canonical S scalar representation (s < L) and identical cofactor multiplication across all verifying nodes.",
            tags: &["ed25519", "malleability", "zip-215", "rfc-8032", "cofactor", "signatures"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-KECCAK-SCA-001",
            name: "ML-KEM / ML-DSA Unmasked Keccak Sponge Power/EM Side-Channel",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:unmasked_keccak\b|shake_sponge_unmasked\b|keccak_f1600_plain\b|raw_shake256_sponge)"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::Medium,
            description: "Unmasked Keccak-f[1600] / SHAKE-256 state permutations during lattice polynomial sampling and hashing leak seed and secret vectors via differential power/electromagnetic analysis.",
            remediation: "Apply Boolean or arithmetic masking (first-order or higher-order) to the Keccak-f[1600] non-linear Chi step when processing secret key material in hardware or embedded targets.",
            tags: &["keccak", "shake256", "ml-kem", "ml-dsa", "side-channel", "power-analysis", "masking"],
        },
        PatternDefinition {
            id: "CVE-ROCA-001",
            name: "ROCA Return of Coppersmith's Attack Infineon RSA Factorization (CVE-2017-15361)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(CVE-2017-15361|ROCA|Return\s+of\s+Coppersmith|infineon[_\s-]rsa|RSALib_FIPS|tpm-lcu)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "CVE-2017-15361 (ROCA): Infineon RSA library generates weak factorable RSA keys with structured primes k*M + (65537^a mod M), factorable via Coppersmith's algorithm.",
            remediation: "Audit and revoke all RSA keys generated on affected Infineon TPM firmware or smartcards. Migrate to NIST FIPS 203 (ML-KEM) or regenerate RSA keys using modern CSPRNG.",
            tags: &["cve-2017-15361", "roca", "rsa", "infineon", "factorization", "coppersmith"],
        },
        PatternDefinition {
            id: "CVE-POODLE-001",
            name: "POODLE SSLv3 / TLS CBC Padding Oracle Downgrade (CVE-2014-3566)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(CVE-2014-3566|POODLE|SSLv3_method|SSL_TXT_SSLV3|SSLv3_server_method|SSLv3_client_method)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "CVE-2014-3566 (POODLE): SSL 3.0 cipher-block chaining (CBC) padding oracle allows man-in-the-middle decryption of plaintext cookies and credentials.",
            remediation: "Completely disable SSL 3.0 and CBC-mode ciphersuites across all web servers and TLS termination proxies. Mandate TLS 1.3.",
            tags: &["cve-2014-3566", "tls", "poodle", "cbc", "padding-oracle", "sslv3"],
        },
        PatternDefinition {
            id: "CVE-LUCKY13-001",
            name: "Lucky Thirteen TLS CBC HMAC Timing Oracle (CVE-2013-0169)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(CVE-2013-0169|Lucky-13|LuckyThirteen|TLS_RSA_WITH_AES_\d+_CBC_SHA|TLS_ECDHE_RSA_WITH_AES_\d+_CBC_SHA)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "CVE-2013-0169 (Lucky Thirteen): Side-channel timing vulnerability in TLS CBC-mode decryption allowing plaintext recovery due to non-constant-time HMAC computation.",
            remediation: "Disable all CBC-mode TLS ciphersuites; mandate AEAD ciphersuites (AES-GCM, ChaCha20-Poly1305) and prepare for hybrid post-quantum TLS 1.3 (X25519MLKEM768).",
            tags: &["cve-2013-0169", "tls", "lucky13", "timing", "cbc", "hmac"],
        },
        PatternDefinition {
            id: "CVE-PUNYCODE-OPENSSL-001",
            name: "OpenSSL 3.0.x Punycode X.509 Email Address Buffer Overrun (CVE-2022-3602 / CVE-2022-3786)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(CVE-2022-3602|CVE-2022-3786|Spooky\s+SSL|ossl_a2ulabel|ossl_punycode_decode)\b"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "CVE-2022-3602 / CVE-2022-3786 (Spooky SSL): Buffer overrun in OpenSSL 3.0.0-3.0.6 X.509 certificate name constraint verification during Punycode email address decoding.",
            remediation: "Upgrade OpenSSL to >= 3.0.7 or modern OpenSSL 3.2+ / AWS-LC with built-in memory safety and post-quantum extensions.",
            tags: &["cve-2022-3602", "cve-2022-3786", "openssl", "punycode", "buffer-overflow", "x509"],
        },
        PatternDefinition {
            id: "CVE-BLEICHENBACHER-XML-001",
            name: "XML Encryption / SAML Bleichenbacher OAEP Timing Oracle (CVE-2012-0881)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(CVE-2012-0881|CVE-2011-1096|xmlenc[_\s-]rsa-1_5|rsa-oaep-mgf1p)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "XML Encryption 1.0 RSA PKCS#1 v1.5 and broken OAEP implementation timing oracles in SAML SSO authentication tokens allowing unauthorized identity spoofing.",
            remediation: "Disable RSA-1_5 in XML Encryption; enforce AES-GCM and migrate signature verification to ML-DSA or composite signatures.",
            tags: &["cve-2012-0881", "xml", "saml", "bleichenbacher", "padding-oracle", "sso"],
        },
        PatternDefinition {
            id: "PQC-BIKE-001",
            name: "BIKE Code-Based Key Encapsulation (NIST Round 4 Alternate)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(BIKE-L1|BIKE-L3|BIKE-L5|pqc_kem_bike|bike_round4)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST Round 4 Alternate post-quantum key encapsulation mechanism based on Quasi-Cyclic Moderate Density Parity-Check (QC-MDPC) codes.",
            remediation: "NIST Round 4 alternate code-based KEM. Valid non-lattice hedge against Module-LWE assumptions. Ensure constant-time decoder implementation.",
            tags: &["pqc", "bike", "code-based", "nist-round4", "kem"],
        },
        PatternDefinition {
            id: "PQC-HQC-001",
            name: "HQC Code-Based Key Encapsulation (NIST Round 4 Alternate)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(HQC-128|HQC-192|HQC-256|pqc_kem_hqc|hqc_round4)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST Round 4 Alternate post-quantum key encapsulation mechanism based on Hamming Quasi-Cyclic codes and tensor-product decoding.",
            remediation: "NIST Round 4 alternate code-based KEM with provable IND-CCA2 security reduction under standard decoding assumptions.",
            tags: &["pqc", "hqc", "code-based", "nist-round4", "kem"],
        },
        PatternDefinition {
            id: "PQC-MCELIECE-001",
            name: "Classic McEliece Code-Based Key Encapsulation (NIST Round 4 Alternate)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(mceliece348864|mceliece460896|mceliece6688128|mceliece6960119|mceliece8192128|ClassicMcEliece|classic_mceliece)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "NIST Round 4 Classic McEliece key encapsulation scheme based on binary Goppa codes. Has resisted all cryptanalytic breakthroughs for over 45 years.",
            remediation: "Ultra-conservative post-quantum KEM with compact ciphertexts (though large public keys). Highly recommended for high-assurance root certificates.",
            tags: &["pqc", "mceliece", "goppa", "code-based", "kem"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-LWE-ROWHAMMER-001",
            name: "Lattice-Fault Injection & Rowhammer on Module-LWE Coefficients",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)\b(lattice[_\s-]fault|rlwe[_\s-]rowhammer|mlkem[_\s-]fault[_\s-]injection|poly_eval_fault|fault_injection_kem)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "Post-quantum cryptanalysis research: Rowhammer DRAM disturbance or targeted laser/voltage fault injection flipping polynomial coefficients in ML-KEM / ML-DSA lattice vectors, reducing hardness from exponential to polynomial time.",
            remediation: "Implement spatial and temporal redundancy checks on secret polynomial vectors, verify decapsulation consistency c = Enc(pk, m'), and use ECC DRAM.",
            tags: &["pqc", "research", "rowhammer", "fault-injection", "lattice", "side-channel"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-FRODOKEM-001",
            name: "FrodoKEM Unstructured Plain LWE Key Encapsulation",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(FrodoKEM|FrodoKEM-640|FrodoKEM-976|FrodoKEM-1344|frodokem\d+|liboqs::KEM::FrodoKEM)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "FrodoKEM detected. A conservative lattice-based key encapsulation mechanism based on plain, unstructured Learning With Errors (LWE), standardized by ISO/IEC 14888-4 and recommended by BSI and ANSSI as an algebraic ring-independent safeguard.",
            remediation: "FrodoKEM provides strong algebraic-structure-free lattice security. Ensure adequate buffer allocations for larger ciphertext payloads.",
            tags: &["pqc", "frodokem", "plain-lwe", "iso-14888", "kem"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-NTRU-PRIME-001",
            name: "Streamlined NTRU Prime Key Encapsulation (sntrup761)",
            category: "Post-Quantum Cryptography",
            regex_pattern: r#"(?i)\b(sntrup761|sntrup761x25519|ntruprime|streamlined\s+ntru\s+prime)\b"#,
            severity: "INFO",
            quantum_risk: QuantumRisk::Safe,
            default_confidence: Confidence::High,
            description: "Streamlined NTRU Prime (sntrup761) detected. Deployed in OpenSSH 9.0+ as a hybrid post-quantum key exchange to minimize potential algebraic risk in cyclotomic rings.",
            remediation: "Conservative lattice KEM with established OpenSSH deployment. Plan transition to or hybrid pairing with NIST FIPS 203 (ML-KEM).",
            tags: &["pqc", "ntru-prime", "sntrup761", "openssh", "kem"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-KPKE-KEY-REUSE-001",
            name: "Ding-Peikert Chosen-Ciphertext Attack on Reused CPA-Secure Lattice Keys",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)\b(ind[-_]cpa[-_\s]*pke|k[-_]pke[-_\s]*encrypt|ind_cpa_encrypt|kyber.*static_key|ml[-_]?kem.*pke_encrypt|cpa_pke_encaps)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Insecure reuse of CPA-secure lattice public key encryption (K-PKE) without the Fujisaki-Okamoto (FO) transform. Using raw CPA-PKE with static or cached keys enables polynomial secret key recovery via adaptive chosen-ciphertext attacks in fewer than 200 queries (Ding et al. / Peikert).",
            remediation: "Never use raw K-PKE directly for message encryption or key exchange. Always use the full CCA-secure ML-KEM encapsulation/decapsulation scheme with Fujisaki-Okamoto transform (NIST FIPS 203 Section 7).",
            tags: &["pqc", "cpa-pke", "key-reuse", "chosen-ciphertext", "ding-peikert", "cwe-327"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-VM-ROLLBACK-001",
            name: "Stateful Hash Signature Hypervisor Snapshot & Rollback OTS Reuse",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)(?:snapshot_rollback|vm_clone|docker_commit|container_snapshot).*(?:lms|xmss|sp800-208)|(?:lms|xmss|sp800[-_]208).*(?:snapshot|clone|checkpoint)"#,
            severity: "CRITICAL",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Stateful Hash-Based Signatures (LMS/HSS RFC 8554, XMSS/XMSS-MT RFC 8391) detected in virtualized, containerized, or cloud environments without hardware monotonic counter enforcement. Hypervisor snapshot restoration or VM cloning causes one-time signature (OTS) state reuse, resulting in total private key compromise.",
            remediation: "Deploy stateful hash signatures only on dedicated hardware Security Modules (HSM) with tamper-proof monotonic hardware counters (NIST SP 800-208 Section 4). For general cloud/VM workloads, use stateless signatures like SLH-DSA (FIPS 205) or ML-DSA (FIPS 204).",
            tags: &["pqc", "lms", "xmss", "sp800-208", "vm-rollback", "state-reuse", "cwe-672"],
        },
        PatternDefinition {
            id: "CVE-OPENSSL-GENERAL-NAME-001",
            name: "OpenSSL GENERAL_NAME_cmp X.400 Type Confusion Arbitrary Read (CVE-2023-0286)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(GENERAL_NAME_cmp|X509_V_FLAG_CRL_CHECK|crl_distribution_points|OPENSSL_VERSION_NUMBER\s*<\s*0x30000080L)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "OpenSSL 3.0.x vulnerability where processing CRL distribution points or CRL issuer names causes a type confusion in GENERAL_NAME_cmp between EDIPartyName and otherName, allowing arbitrary memory read and potential denial of service or secret disclosure (CVE-2023-0286, High).",
            remediation: "Upgrade OpenSSL to version 3.0.8, 1.1.1t, or later to ensure strict type validation of X.509 GeneralName entries.",
            tags: &["cve", "cve-2023-0286", "openssl", "type-confusion", "x509", "crl"],
        },
        PatternDefinition {
            id: "CVE-OPENSSL-SESSION-CACHE-001",
            name: "OpenSSL TLS 1.3 Unbounded Session Cache Memory Exhaustion (CVE-2024-2511)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(SSL_CTX_set_session_cache_mode|SSL_SESS_CACHE_SERVER|tls13_generate_handshake_session_ticket)\b"#,
            severity: "MEDIUM",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "OpenSSL TLS 1.3 server session cache vulnerability ('Sly Slowloris') where unconstrained session ticket allocations allow remote unauthenticated attackers to exhaust server memory and trigger denial of service (CVE-2024-2511).",
            remediation: "Upgrade OpenSSL to 3.0.14+, 3.1.6+, 3.2.2+, or 3.3.1+. Bound session cache size with SSL_CTX_sess_set_cache_size.",
            tags: &["cve", "cve-2024-2511", "openssl", "tls13", "session-cache", "dos"],
        },
        PatternDefinition {
            id: "CVE-OPENSSL-RSA-MODEXP-001",
            name: "OpenSSL RSA Modular Exponentiation Cache-Timing Oracle (CVE-2022-4304)",
            category: "Real-World Cryptographic CVEs",
            regex_pattern: r#"(?i)\b(BN_mod_exp_mont_consttime|RSA_PKCS1_PADDING.*openssl|BN_mod_exp_mont\b)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Vulnerable,
            default_confidence: Confidence::High,
            description: "Timing side-channel oracle in OpenSSL's RSA decryption implementation (BN_mod_exp_mont_consttime) where branch execution and cache-timing differences in Montgomery modular exponentiation leak plaintext to network-adjacent attackers (CVE-2022-4304).",
            remediation: "Upgrade OpenSSL to 1.1.1t+, 3.0.8+, or migrate asymmetric key encapsulation to NIST FIPS 203 (ML-KEM-768).",
            tags: &["cve", "cve-2022-4304", "openssl", "rsa", "timing-attack", "side-channel"],
        },
        PatternDefinition {
            id: "PQC-RESEARCH-MLKEM-DECAP-FAILURE-001",
            name: "ML-KEM Chosen-Ciphertext Decapsulation Failure Rate Exploitation",
            category: "Bleeding-Edge Cryptographic Research",
            regex_pattern: r#"(?i)\b(poly_frommsg|poly_tomsg|check_norm|decaps.*failure_rate|kyber.*failure_boost)\b"#,
            severity: "HIGH",
            quantum_risk: QuantumRisk::Partial,
            default_confidence: Confidence::Medium,
            description: "ML-KEM / Kyber decapsulation failure boosting attack (D'Anvers et al.). If an implementation does not enforce strict coefficient bounds or constant-time polynomial reduction during error checking, an attacker can craft directional ciphertexts to artificially inflate the decapsulation failure probability and extract private key coefficients.",
            remediation: "Ensure strict compliance with NIST FIPS 203 Algorithm 17 (K-PKE.Decrypt) and enforce constant-time polynomial decoding without conditional branches.",
            tags: &["pqc", "ml-kem", "kyber", "decapsulation-failure", "chosen-ciphertext", "side-channel"],
        },
    ];

    raw_defs.into_iter().filter_map(|def| {
        match Regex::new(def.regex_pattern) {
            Ok(regex) => Some(CompiledPattern { def, regex }),
            Err(e) => {
                eprintln!("PQCanary warning: failed to compile pattern {}: {}", def.id, e);
                None
            }
        }
    }).collect()
});

/// Returns a cloned list of all enterprise pattern definitions in the catalog.
pub fn get_all_pattern_definitions() -> Vec<PatternDefinition> {
    ALL_PATTERNS.iter().map(|p| p.def.clone()).collect()
}

/// Inline suppression checker:
/// Detects `// pqcanary:ignore`, `/* pqcanary:ignore */`, `# pqcanary:ignore`, `// cryptoscan:ignore`, `// noscan`
pub struct SuppressionEngine;

impl SuppressionEngine {
    /// Checks if a finding on `line_number` is suppressed either by an inline directive on the same line,
    /// or by a `ignore-next-line` directive on the preceding line.
    pub fn is_suppressed(
        file_lines: &[&str],
        line_number: u32,
        rule_id: &str,
        category: &str,
    ) -> bool {
        if line_number == 0 || file_lines.is_empty() {
            return false;
        }

        let curr_idx = (line_number as usize).saturating_sub(1);

        // 1. Check current line for inline ignore: `const x = ...; // pqcanary:ignore`
        if curr_idx < file_lines.len()
            && Self::matches_ignore_directive(file_lines[curr_idx], rule_id, category, false) {
                return true;
            }

        // 2. Check preceding line for ignore directive placed above the target code:
        // e.g. `// pqcanary:ignore [RULE_ID]` or `// pqcanary:ignore-next-line [RULE_ID]`
        curr_idx > 0 && curr_idx - 1 < file_lines.len()
            && (Self::matches_ignore_directive(file_lines[curr_idx - 1], rule_id, category, false)
                || Self::matches_ignore_directive(file_lines[curr_idx - 1], rule_id, category, true))
    }

    fn matches_ignore_directive(line: &str, rule_id: &str, category: &str, next_line_mode: bool) -> bool {
        let lower = line.to_lowercase();

        let directives: &[&str] = if next_line_mode {
            &[
                "pqcanary:ignore-next-line", "pqc:ignore-next-line",
                "cryptoscan:ignore-next-line", "crypto-scan:ignore-next-line",
            ]
        } else {
            if lower.contains("ignore-next-line") {
                return false;
            }
            &[
                "pqcanary:ignore", "pqc:ignore",
                "cryptoscan:ignore", "crypto-scan:ignore", "noscan",
            ]
        };

        if !directives.iter().any(|d| lower.contains(d)) {
            return false;
        }

        for directive in directives {
            if let Some(pos) = lower.find(directive) {
                let rest = lower[pos + directive.len()..].trim();
                // If nothing follows or only whitespace / comment close / reason attribute
                if rest.is_empty() || rest.starts_with("*/") || rest.starts_with("-->") || rest.starts_with("reason=") {
                    return true;
                }

                // Check for specific rule ID or wildcard: e.g. "RSA-001", "RSA-*", "Category:Certificates"
                let tokens: Vec<&str> = rest.split_whitespace().collect();
                for token in tokens {
                    let clean = token.trim_matches(|c: char| c == '[' || c == ']' || c == ',' || c == ';' || c == '*' || c == '"' || c == '\'');
                    if clean.is_empty() {
                        return true; // was wildcard like "*"
                    }
                    if rule_id.to_lowercase().starts_with(clean)
                        || category.to_lowercase().contains(clean)
                    {
                        return true;
                    }
                }
            }
        }

        false
    }
}

static AWS_KEY_RE: std::sync::OnceLock<Option<Regex>> = std::sync::OnceLock::new();
static GITHUB_PAT_RE: std::sync::OnceLock<Option<Regex>> = std::sync::OnceLock::new();
static JWT_RE: std::sync::OnceLock<Option<Regex>> = std::sync::OnceLock::new();

/// Sanitizes sensitive cryptographic evidence (private keys, AWS keys, JWT tokens, GitHub PATs)
/// so raw credentials are never leaked into reports, logs, SARIF documents, or CBOMs.
pub fn sanitize_sensitive_evidence(text: &str) -> String {
    // 1. Redact AWS access keys
    let aws_re = AWS_KEY_RE.get_or_init(|| {
        Regex::new(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").ok()
    });
    let out1 = match aws_re {
        Some(re) => re.replace_all(text, "[MASKED_AWS_KEY]"),
        None => std::borrow::Cow::Borrowed(text),
    };

    // 2. Redact GitHub Personal Access Tokens
    let github_re = GITHUB_PAT_RE.get_or_init(|| {
        Regex::new(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b").ok()
    });
    let out2 = match github_re {
        Some(re) => re.replace_all(&out1, "[MASKED_GITHUB_TOKEN]"),
        None => out1,
    };

    // 3. Redact JWT tokens
    let jwt_re = JWT_RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").ok()
    });
    let mut out = match jwt_re {
        Some(re) => re.replace_all(&out2, "[MASKED_JWT_TOKEN]").into_owned(),
        None => out2.into_owned(),
    };

    // 4. Redact private key payload lines
    if out.contains("PRIVATE KEY") {
        let mut masked = String::with_capacity(out.len());
        let mut inside_key = false;

        for line in out.lines() {
            if line.contains("BEGIN") && line.contains("PRIVATE KEY") {
                inside_key = true;
                masked.push_str(line);
                masked.push_str("\n      | [MASKED_PRIVATE_KEY_MATERIAL]\n");
            } else if line.contains("END") && line.contains("PRIVATE KEY") {
                inside_key = false;
                masked.push_str(line);
                masked.push('\n');
            } else if inside_key {
                // omit the raw private key lines
                continue;
            } else {
                masked.push_str(line);
                masked.push('\n');
            }
        }
        out = masked;
    }

    out
}

/// Compute 3 lines of source context before and after
pub fn extract_code_snippet(lines: &[&str], line_number: u32, context_lines: usize) -> String {
    if lines.is_empty() || line_number == 0 {
        return String::new();
    }

    let target_idx = (line_number as usize).saturating_sub(1);
    let start_idx = target_idx.saturating_sub(context_lines);
    let end_idx = (target_idx + context_lines + 1).min(lines.len());

    let mut snippet = String::with_capacity((end_idx.saturating_sub(start_idx)).saturating_mul(80));
    use std::fmt::Write;
    for (idx, line) in lines.iter().enumerate().take(end_idx).skip(start_idx) {
        let line_num = idx + 1;
        let prefix = if idx == target_idx { ">" } else { " " };
        let _ = writeln!(&mut snippet, "{:>4} {} | {}", line_num, prefix, line);
    }
    sanitize_sensitive_evidence(&snippet)
}

/// Computes SHA-256 fingerprint for baseline comparison: sha256(relative_file + rule_id + normalized_match)
pub fn compute_finding_fingerprint(file_path: &str, rule_id: &str, line_content: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(file_path.trim().as_bytes());
    hasher.update(b":");
    hasher.update(rule_id.trim().as_bytes());
    hasher.update(b":");
    // Normalize line content by feeding whitespace-split tokens directly without intermediate String allocation
    for word in line_content.split_whitespace() {
        hasher.update(word.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}
