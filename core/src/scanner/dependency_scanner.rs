//! Software Supply Chain & Cryptographic Dependency Manifest Scanner
//!
//! Automatically inspects dependency manifests (`package.json`, `Cargo.toml`, `requirements.txt`,
//! `pyproject.toml`, `go.mod`, `pom.xml`, `Gemfile`) across the repository, extracts declared
//! cryptographic packages, computes Package URLs (purl), classifies their quantum resistance,
//! and generates actionable migration findings.

use std::path::Path;
use serde_json::Value as JsonValue;
use crate::scanner::orchestrator::ComprehensiveFinding;

/// Metadata for a recognized cryptographic software library
#[derive(Debug, Clone)]
pub struct KnownCryptoLib {
    pub name: &'static str,
    pub ecosystem: &'static str,
    pub is_quantum_safe: bool,
    pub is_hybrid: bool,
    pub algorithms_provided: &'static [&'static str],
    pub description: &'static str,
    pub remediation: &'static str,
}

/// Registry of known cryptographic packages across ecosystems
pub static KNOWN_CRYPTO_LIBRARIES: &[KnownCryptoLib] = &[
    // ── Python (PyPI) ──
    KnownCryptoLib {
        name: "cryptography",
        ecosystem: "pypi",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "Ed25519", "AES", "ChaCha20"],
        description: "Standard Python cryptographic recipe library providing classical asymmetric primitives (RSA, ECC) vulnerable to Shor's algorithm.",
        remediation: "Supplement with 'liboqs-python' for ML-KEM and ML-DSA post-quantum primitives.",
    },
    KnownCryptoLib {
        name: "pycryptodome",
        ecosystem: "pypi",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "DSA", "ECC", "DES", "3DES", "AES"],
        description: "Self-contained Python crypto library. Heavily relies on classical RSA/DSA/ECC.",
        remediation: "Migrate asymmetric operations to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).",
    },
    KnownCryptoLib {
        name: "pynacl",
        ecosystem: "pypi",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["X25519", "Ed25519", "XSalsa20"],
        description: "Python binding to libsodium. Uses Curve25519 which is vulnerable to Shor's algorithm.",
        remediation: "Adopt hybrid post-quantum key encapsulation (e.g. X25519 + ML-KEM-768).",
    },
    KnownCryptoLib {
        name: "liboqs-python",
        ecosystem: "pypi",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium"],
        description: "Official Open Quantum Safe Python bindings for post-quantum cryptographic algorithms.",
        remediation: "NIST FIPS 203/204 Post-Quantum standard library active. No remediation needed.",
    },
    KnownCryptoLib {
        name: "oqs",
        ecosystem: "pypi",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "Falcon", "SPHINCS+"],
        description: "OpenQuantumSafe liboqs wrapper module.",
        remediation: "Post-quantum algorithms verified. Maintain version updates.",
    },

    // ── JavaScript / TypeScript (npm) ──
    KnownCryptoLib {
        name: "crypto-js",
        ecosystem: "npm",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["DES", "3DES", "MD5", "SHA-1", "AES", "RC4"],
        description: "Legacy JavaScript cryptography library containing broken primitives (DES, MD5, SHA-1) and lacking post-quantum support.",
        remediation: "Migrate to Web Crypto API (SubtleCrypto) or '@noble/ciphers' and '@noble/post-quantum'.",
    },
    KnownCryptoLib {
        name: "node-forge",
        ecosystem: "npm",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "AES", "DES", "SHA-1", "X.509"],
        description: "JavaScript implementation of TLS and PKI with classical RSA and X.509 certificates.",
        remediation: "Plan transition to post-quantum certificates and ML-KEM key exchange.",
    },
    KnownCryptoLib {
        name: "jose",
        ecosystem: "npm",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RS256", "ES256", "EdDSA", "ECDH-ES"],
        description: "JavaScript Object Signing and Encryption (JWT/JWS/JWE). Uses classical RSA and ECC signatures.",
        remediation: "Prepare for composite post-quantum signatures (ML-DSA + ECDSA) when JOSE PQC draft finalizes.",
    },
    KnownCryptoLib {
        name: "@noble/post-quantum",
        ecosystem: "npm",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "SLH-DSA"],
        description: "Pure JS audited implementation of NIST Post-Quantum standards (FIPS 203, 204, 205).",
        remediation: "NIST post-quantum cryptographic primitives active. No remediation required.",
    },

    // ── Rust (crates.io) ──
    KnownCryptoLib {
        name: "rsa",
        ecosystem: "cargo",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA-PKCS1v15", "RSA-OAEP", "RSA-PSS"],
        description: "Pure Rust RSA implementation. Classical asymmetric encryption vulnerable to Shor's algorithm.",
        remediation: "Replace with 'ml-kem' or 'pqcrypto-kyber' for key exchange.",
    },
    KnownCryptoLib {
        name: "ed25519-dalek",
        ecosystem: "cargo",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519"],
        description: "Fast Edwards-curve digital signature algorithm. Vulnerable to quantum polynomial-time discrete log.",
        remediation: "Migrate to 'ml-dsa' or 'pqcrypto-dilithium' for post-quantum digital signatures.",
    },
    KnownCryptoLib {
        name: "x25519-dalek",
        ecosystem: "cargo",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["X25519"],
        description: "Diffie-Hellman key exchange over Curve25519.",
        remediation: "Adopt hybrid post-quantum key exchange (X25519 + ML-KEM-768).",
    },
    KnownCryptoLib {
        name: "pqcrypto",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "Falcon", "SPHINCS+"],
        description: "Post-quantum cryptographic algorithms in Rust via C bindings to reference implementations.",
        remediation: "NIST PQC algorithms verified. Maintain dependency version.",
    },
    KnownCryptoLib {
        name: "pqcrypto-kyber",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["Kyber512", "Kyber768", "Kyber1024"],
        description: "Post-quantum lattice-based key encapsulation mechanism.",
        remediation: "NIST post-quantum KEM active.",
    },
    KnownCryptoLib {
        name: "fips203",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        description: "Pure Rust implementation of NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism.",
        remediation: "FIPS 203 Post-Quantum compliant. Fully quantum-resilient.",
    },
    KnownCryptoLib {
        name: "oqs",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "Falcon", "SPHINCS+", "Kyber", "Dilithium"],
        description: "Rust bindings to the Open Quantum Safe liboqs C library.",
        remediation: "NIST post-quantum cryptographic algorithms active. Fully quantum-resilient.",
    },

    // ── Go (golang) ──
    KnownCryptoLib {
        name: "golang.org/x/crypto",
        ecosystem: "golang",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["ssh", "openpgp", "curve25519", "ed25519", "bcrypt"],
        description: "Supplementary Go cryptography libraries. Asymmetric algorithms are vulnerable to Shor's algorithm.",
        remediation: "Adopt 'github.com/cloudflare/circl' for hybrid ML-KEM post-quantum key exchange.",
    },
    KnownCryptoLib {
        name: "github.com/cloudflare/circl",
        ecosystem: "golang",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "Kyber", "X25519-MLKEM768", "Dilithium"],
        description: "Cloudflare Interoperable Reusable Cryptographic Library with hybrid post-quantum primitives.",
        remediation: "Post-quantum hybrid cryptography active. No remediation required.",
    },

    // ── Java (Maven) ──
    KnownCryptoLib {
        name: "bcprov-jdk15on",
        ecosystem: "maven",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "AES", "DH", "DSA"],
        description: "Bouncy Castle Java Provider (legacy artifact). Primarily classical algorithms.",
        remediation: "Upgrade to Bouncy Castle 1.78+ ('bcprov-jdk18on') or 'bcpqc-addon' for FIPS 203/204 support.",
    },
    KnownCryptoLib {
        name: "bcpqc-addon",
        ecosystem: "maven",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "Falcon", "SPHINCS+", "LMS", "XMSS"],
        description: "Bouncy Castle Post-Quantum Cryptography Add-on module.",
        remediation: "Post-quantum cryptographic provider active. Fully quantum-ready.",
    },
    KnownCryptoLib {
        name: "bcprov-jdk18on",
        ecosystem: "maven",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "SLH-DSA", "Falcon", "LMS", "XMSS"],
        description: "Modern Bouncy Castle Java Provider with native Post-Quantum (FIPS 203/204/205) engine.",
        remediation: "Modern post-quantum Bouncy Castle release active.",
    },
    KnownCryptoLib {
        name: "libcrux",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA"],
        description: "Formally verified (F*) high-assurance implementation of NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).",
        remediation: "Formally verified post-quantum cryptographic primitives active.",
    },
    KnownCryptoLib {
        name: "fips204",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        description: "Pure Rust implementation of NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm.",
        remediation: "FIPS 204 Post-Quantum compliant. Fully quantum-resilient.",
    },
    KnownCryptoLib {
        name: "fips205",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["SLH-DSA-128s", "SLH-DSA-128f", "SLH-DSA-256s"],
        description: "Pure Rust implementation of NIST FIPS 205 Stateless Hash-Based Digital Signature Algorithm.",
        remediation: "FIPS 205 Post-Quantum compliant. Fully quantum-resilient.",
    },
    KnownCryptoLib {
        name: "pqcrypto-dilithium",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["Dilithium2", "Dilithium3", "Dilithium5"],
        description: "Post-quantum lattice digital signature algorithm bindings.",
        remediation: "NIST post-quantum signature algorithm active.",
    },
    KnownCryptoLib {
        name: "phpseclib",
        ecosystem: "composer",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "DSA", "DH", "AES"],
        description: "Pure PHP Cryptographic Library using classical asymmetric algorithms.",
        remediation: "Plan migration to post-quantum hybrid key exchange when PHP PQC extensions finalize.",
    },

    // ── Additional NPM packages ──
    KnownCryptoLib {
        name: "tweetnacl",
        ecosystem: "npm",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519", "Curve25519", "XSalsa20"],
        description: "Port of TweetNaCl cryptographic library to JavaScript. Asymmetric primitives vulnerable to Shor's algorithm.",
        remediation: "Migrate asymmetric key exchange to '@noble/post-quantum' ML-KEM or hybrid key exchange.",
    },
    KnownCryptoLib {
        name: "elliptic",
        ecosystem: "npm",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["secp256k1", "p256", "ed25519"],
        description: "Fast elliptic-curve cryptography in plain JavaScript. Susceptible to quantum discrete log attacks.",
        remediation: "Transition digital signatures to ML-DSA (FIPS 204) or composite signatures.",
    },
    KnownCryptoLib {
        name: "openpgp",
        ecosystem: "npm",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "EdDSA", "AES"],
        description: "OpenPGP.js JavaScript implementation. Uses classical public-key cryptography.",
        remediation: "Adopt post-quantum OpenPGP extensions (PQC-OpenPGP with ML-KEM/ML-DSA).",
    },

    // ── Additional PyPI packages ──
    KnownCryptoLib {
        name: "ecdsa",
        ecosystem: "pypi",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["ECDSA", "NIST-P256", "SECP256k1"],
        description: "Pure Python ECDSA library vulnerable to quantum discrete logarithm attacks.",
        remediation: "Migrate to 'liboqs-python' ML-DSA post-quantum signatures.",
    },
    KnownCryptoLib {
        name: "rsa",
        ecosystem: "pypi",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA-PKCS1v15"],
        description: "Pure-Python RSA implementation vulnerable to Shor's factorization algorithm.",
        remediation: "Replace with 'liboqs-python' for ML-KEM or ML-DSA.",
    },
    KnownCryptoLib {
        name: "paramiko",
        ecosystem: "pypi",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["SSH-RSA", "ECDSA", "Ed25519"],
        description: "Python SSHv2 protocol library using classical key exchange algorithms.",
        remediation: "Ensure OpenSSH server supports hybrid post-quantum key exchange (sntrup761 / mlkem768).",
    },
    KnownCryptoLib {
        name: "pqcrypto",
        ecosystem: "pypi",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "Falcon", "SPHINCS+"],
        description: "Python bindings to PQClean post-quantum cryptographic reference implementations.",
        remediation: "Post-quantum cryptographic library active. Maintain updates.",
    },

    // ── Additional Cargo packages ──
    KnownCryptoLib {
        name: "ring",
        ecosystem: "cargo",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "Ed25519", "AES-GCM", "ChaCha20-Poly1305"],
        description: "Safe, fast, small crypto using Rust. Asymmetric algorithms are vulnerable to Shor's algorithm.",
        remediation: "Combine with 'fips203' / 'ml-kem' for post-quantum hybrid key encapsulation.",
    },
    KnownCryptoLib {
        name: "aws-lc-rs",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "X25519-MLKEM768", "AES", "SHA-384"],
        description: "AWS Libcrypto Rust wrapper featuring native NIST FIPS 203 ML-KEM hybrid key exchange.",
        remediation: "Post-quantum hybrid cryptography supported natively.",
    },
    KnownCryptoLib {
        name: "rustls",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["TLS 1.3", "X25519MLKEM768", "AES-GCM", "ChaCha20-Poly1305"],
        description: "Modern Rust TLS library with built-in post-quantum hybrid key exchange support.",
        remediation: "Modern post-quantum TLS library active. Verify PQC cipher suites enabled in config.",
    },
    KnownCryptoLib {
        name: "ml-kem",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        description: "Pure Rust implementation of NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism.",
        remediation: "NIST FIPS 203 PQC standard compliant.",
    },
    KnownCryptoLib {
        name: "ml-dsa",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
        description: "Pure Rust implementation of NIST FIPS 204 Module-Lattice-Based Digital Signature Algorithm.",
        remediation: "NIST FIPS 204 PQC standard compliant.",
    },
    KnownCryptoLib {
        name: "slh-dsa",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["SLH-DSA-128s", "SLH-DSA-128f", "SLH-DSA-256s"],
        description: "Pure Rust implementation of NIST FIPS 205 Stateless Hash-Based Digital Signature Algorithm.",
        remediation: "NIST FIPS 205 PQC standard compliant.",
    },
    KnownCryptoLib {
        name: "pqcrypto-falcon",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["Falcon-512", "Falcon-1024"],
        description: "Rust bindings to Falcon (FN-DSA) post-quantum digital signature algorithm.",
        remediation: "NIST FIPS 206 post-quantum signature active.",
    },
    KnownCryptoLib {
        name: "pqcrypto-sphincsplus",
        ecosystem: "cargo",
        is_quantum_safe: true,
        is_hybrid: false,
        algorithms_provided: &["SPHINCS+-128s", "SPHINCS+-256s"],
        description: "Rust bindings to SPHINCS+ (SLH-DSA) stateless hash-based signature algorithm.",
        remediation: "Post-quantum hash-based signature active.",
    },

    // ── Additional Go packages ──
    KnownCryptoLib {
        name: "filippo.io/edwards25519",
        ecosystem: "golang",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519"],
        description: "High-performance Ed25519 operations in Go. Vulnerable to quantum discrete log.",
        remediation: "Migrate to hybrid signatures or 'github.com/cloudflare/circl' post-quantum primitives.",
    },
    KnownCryptoLib {
        name: "github.com/open-quantum-safe/liboqs-go",
        ecosystem: "golang",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "Falcon", "SPHINCS+"],
        description: "Open Quantum Safe Go bindings for post-quantum cryptographic algorithms.",
        remediation: "Post-quantum cryptography active.",
    },

    // ── Additional Maven packages ──
    KnownCryptoLib {
        name: "tink",
        ecosystem: "maven",
        is_quantum_safe: false,
        is_hybrid: true,
        algorithms_provided: &["AES-GCM", "ECDSA", "Ed25519", "RSA-SSA-PSS"],
        description: "Google Tink multi-language, cross-platform cryptographic library.",
        remediation: "Enable post-quantum hybrid KEM extensions in Tink when available.",
    },
    KnownCryptoLib {
        name: "conscrypt",
        ecosystem: "maven",
        is_quantum_safe: false,
        is_hybrid: true,
        algorithms_provided: &["TLS 1.3", "ECDHE", "RSA", "AES-GCM"],
        description: "Java Security Provider powered by BoringSSL.",
        remediation: "Upgrade to Conscrypt with X25519MLKEM768 post-quantum key exchange support.",
    },

    // ── Additional Composer packages (PHP) ──
    KnownCryptoLib {
        name: "halite",
        ecosystem: "composer",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519", "X25519", "XSalsa20"],
        description: "High-level cryptography library for PHP powered by libsodium. Asymmetric primitives vulnerable to Shor's algorithm.",
        remediation: "Plan migration to post-quantum hybrid algorithms for long-term confidential data.",
    },
    KnownCryptoLib {
        name: "sodium_compat",
        ecosystem: "composer",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519", "X25519", "ChaCha20-Poly1305"],
        description: "Pure PHP polyfill for ext/sodium.",
        remediation: "Audit asymmetric operations for quantum vulnerability.",
    },
    KnownCryptoLib {
        name: "defuse/php-encryption",
        ecosystem: "composer",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["AES-CTR", "HMAC-SHA256", "PBKDF2"],
        description: "Symmetric encryption library for PHP.",
        remediation: "Symmetric operations provide 128-bit quantum security; ensure 256-bit keys for long-term safety.",
    },

    // ── RubyGems packages ──
    KnownCryptoLib {
        name: "rbnacl",
        ecosystem: "rubygems",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519", "Curve25519", "Salsa20"],
        description: "Ruby binding to the Networking and Cryptography (NaCl) library.",
        remediation: "Prepare for post-quantum hybrid key encapsulation migration.",
    },
    KnownCryptoLib {
        name: "ed25519",
        ecosystem: "rubygems",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519"],
        description: "Ruby gem for Ed25519 digital signatures. Vulnerable to Shor's algorithm.",
        remediation: "Plan transition to post-quantum digital signatures (ML-DSA / FIPS 204).",
    },
    KnownCryptoLib {
        name: "attr_encrypted",
        ecosystem: "rubygems",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["AES-256-GCM", "AES-256-CBC"],
        description: "ActiveRecord database attribute encryption for Ruby on Rails.",
        remediation: "Ensure AES-256-GCM is configured for post-quantum confidentiality at rest.",
    },
    KnownCryptoLib {
        name: "openssl",
        ecosystem: "rubygems",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "AES", "SHA-256"],
        description: "Ruby standard library OpenSSL wrapper providing classical asymmetric algorithms.",
        remediation: "Upgrade Ruby/OpenSSL to OpenSSL 3.2+ with OQS provider for post-quantum algorithms.",
    },

    // ── Swift (SwiftPM) ──
    KnownCryptoLib {
        name: "swift-crypto",
        ecosystem: "swift",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "Ed25519", "AES-GCM", "ChaChaPoly"],
        description: "Apple Swift Crypto port of CryptoKit. Asymmetric algorithms are vulnerable to Shor's algorithm.",
        remediation: "Adopt hybrid post-quantum key encapsulation (X25519 + ML-KEM-768).",
    },
    KnownCryptoLib {
        name: "CryptoKit",
        ecosystem: "swift",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["P-256", "P-384", "P-521", "Curve25519", "RSA"],
        description: "Apple CryptoKit framework providing classical elliptic curve and RSA cryptography.",
        remediation: "Combine with post-quantum KEMs when adopting iOS 18+ / macOS 15+ post-quantum APIs.",
    },

    // ── Dart / Flutter (pub) ──
    KnownCryptoLib {
        name: "pointycastle",
        ecosystem: "pub",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "AES", "SHA-256"],
        description: "Port of Bouncy Castle to Dart. Relies on classical asymmetric cryptography.",
        remediation: "Transition to post-quantum hybrid key exchange when Dart PQC plugins are published.",
    },
    KnownCryptoLib {
        name: "cryptography",
        ecosystem: "pub",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519", "X25519", "AES-GCM", "ChaCha20"],
        description: "Dart cryptographic primitives library. Classical elliptic curves vulnerable to quantum computers.",
        remediation: "Adopt post-quantum hybrid KEMs (ML-KEM-768).",
    },

    // ── C / C++ (Conan & vcpkg) ──
    KnownCryptoLib {
        name: "openssl",
        ecosystem: "conan",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "Ed25519", "AES", "ChaCha20"],
        description: "De facto standard C cryptography and TLS toolkit. Asymmetric primitives vulnerable to Shor's algorithm.",
        remediation: "Upgrade to OpenSSL 3.2+ and configure oqsprovider for NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).",
    },
    KnownCryptoLib {
        name: "openssl",
        ecosystem: "vcpkg",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "Ed25519", "AES", "ChaCha20"],
        description: "De facto standard C cryptography and TLS toolkit. Asymmetric primitives vulnerable to Shor's algorithm.",
        remediation: "Upgrade to OpenSSL 3.2+ and configure oqsprovider for NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).",
    },
    KnownCryptoLib {
        name: "liboqs",
        ecosystem: "conan",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "SLH-DSA", "Falcon", "BIKE", "HQC", "Classic McEliece"],
        description: "Open Quantum Safe liboqs C library providing quantum-resistant KEMs and digital signatures.",
        remediation: "NIST Post-Quantum Cryptographic standard library active. No remediation needed.",
    },
    KnownCryptoLib {
        name: "liboqs",
        ecosystem: "vcpkg",
        is_quantum_safe: true,
        is_hybrid: true,
        algorithms_provided: &["ML-KEM", "ML-DSA", "SLH-DSA", "Falcon", "BIKE", "HQC", "Classic McEliece"],
        description: "Open Quantum Safe liboqs C library providing quantum-resistant KEMs and digital signatures.",
        remediation: "NIST Post-Quantum Cryptographic standard library active. No remediation needed.",
    },
    KnownCryptoLib {
        name: "wolfssl",
        ecosystem: "conan",
        is_quantum_safe: false,
        is_hybrid: true,
        algorithms_provided: &["TLS 1.3", "RSA", "ECC", "ML-KEM", "LMS", "XMSS"],
        description: "Embedded TLS library. Classical asymmetric ciphers vulnerable unless compiled with experimental PQC extensions.",
        remediation: "Enable post-quantum algorithms via --with-liboqs or wolfSSL stateful hash signatures (LMS/XMSS).",
    },
    KnownCryptoLib {
        name: "wolfssl",
        ecosystem: "vcpkg",
        is_quantum_safe: false,
        is_hybrid: true,
        algorithms_provided: &["TLS 1.3", "RSA", "ECC", "ML-KEM", "LMS", "XMSS"],
        description: "Embedded TLS library. Classical asymmetric ciphers vulnerable unless compiled with experimental PQC extensions.",
        remediation: "Enable post-quantum algorithms via --with-liboqs or wolfSSL stateful hash signatures (LMS/XMSS).",
    },
    KnownCryptoLib {
        name: "botan",
        ecosystem: "conan",
        is_quantum_safe: false,
        is_hybrid: true,
        algorithms_provided: &["RSA", "ECDSA", "Kyber", "Dilithium", "FrodoKEM"],
        description: "Modern C++ cryptography library. Includes classical algorithms and post-quantum Kyber / Dilithium / FrodoKEM.",
        remediation: "Configure Botan with Kyber/ML-KEM-768 and Dilithium/ML-DSA.",
    },
    KnownCryptoLib {
        name: "botan",
        ecosystem: "vcpkg",
        is_quantum_safe: false,
        is_hybrid: true,
        algorithms_provided: &["RSA", "ECDSA", "Kyber", "Dilithium", "FrodoKEM"],
        description: "Modern C++ cryptography library. Includes classical algorithms and post-quantum Kyber / Dilithium / FrodoKEM.",
        remediation: "Configure Botan with Kyber/ML-KEM-768 and Dilithium/ML-DSA.",
    },
    KnownCryptoLib {
        name: "mbedtls",
        ecosystem: "conan",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "AES", "ChaCha20"],
        description: "ARM mbed TLS embedded crypto library. Classical asymmetric primitives are vulnerable to Shor's algorithm.",
        remediation: "Plan migration to PSA Crypto PQC extensions or hybrid KEM wrappers.",
    },
    KnownCryptoLib {
        name: "mbedtls",
        ecosystem: "vcpkg",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["RSA", "ECDSA", "AES", "ChaCha20"],
        description: "ARM mbed TLS embedded crypto library. Classical asymmetric primitives are vulnerable to Shor's algorithm.",
        remediation: "Plan migration to PSA Crypto PQC extensions or hybrid KEM wrappers.",
    },
    KnownCryptoLib {
        name: "libsodium",
        ecosystem: "conan",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519", "Curve25519", "ChaCha20-Poly1305"],
        description: "Modern cryptography library based on NaCL. Classical elliptic curves (Curve25519) are vulnerable to Shor's algorithm.",
        remediation: "Combine with post-quantum KEMs (ML-KEM-768) in a hybrid key exchange scheme.",
    },
    KnownCryptoLib {
        name: "libsodium",
        ecosystem: "vcpkg",
        is_quantum_safe: false,
        is_hybrid: false,
        algorithms_provided: &["Ed25519", "Curve25519", "ChaCha20-Poly1305"],
        description: "Modern cryptography library based on NaCL. Classical elliptic curves (Curve25519) are vulnerable to Shor's algorithm.",
        remediation: "Combine with post-quantum KEMs (ML-KEM-768) in a hybrid key exchange scheme.",
    },
];

pub struct DependencyScanner;

impl DependencyScanner {
    /// Inspect a given file; if it is a recognized dependency manifest, extract crypto dependencies.
    pub fn scan_manifest(path: &Path, content: &str) -> Vec<ComprehensiveFinding> {
        let file_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_lowercase(),
            None => return Vec::new(),
        };

        let path_str = path.to_string_lossy().to_string();

        match file_name.as_str() {
            "package.json" => Self::scan_package_json(&path_str, content),
            "package-lock.json" => Self::scan_package_lock_json(&path_str, content),
            "pnpm-lock.yaml" => Self::scan_pnpm_lock(&path_str, content),
            "yarn.lock" => Self::scan_yarn_lock(&path_str, content),
            "cargo.toml" => Self::scan_cargo_toml(&path_str, content),
            "cargo.lock" => Self::scan_cargo_lock(&path_str, content),
            "requirements.txt" => Self::scan_requirements_txt(&path_str, content),
            "pyproject.toml" => Self::scan_pyproject_toml(&path_str, content),
            "poetry.lock" => Self::scan_poetry_lock(&path_str, content),
            "pipfile" => Self::scan_pipfile(&path_str, content),
            "pipfile.lock" => Self::scan_pipfile_lock(&path_str, content),
            "go.mod" => Self::scan_go_mod(&path_str, content),
            "go.sum" => Self::scan_go_sum(&path_str, content),
            "pom.xml" => Self::scan_pom_xml(&path_str, content),
            "build.gradle" | "build.gradle.kts" => Self::scan_build_gradle(&path_str, content),
            "composer.json" => Self::scan_composer_json(&path_str, content),
            "composer.lock" => Self::scan_composer_lock(&path_str, content),
            "gemfile" => Self::scan_gemfile(&path_str, content),
            "gemfile.lock" => Self::scan_gemfile_lock(&path_str, content),
            "package.swift" => Self::scan_package_swift(&path_str, content),
            "package.resolved" => Self::scan_package_resolved(&path_str, content),
            "pubspec.yaml" => Self::scan_pubspec_yaml(&path_str, content),
            "pubspec.lock" => Self::scan_pubspec_lock(&path_str, content),
            "conanfile.txt" => Self::scan_conanfile_txt(&path_str, content),
            "conanfile.py" => Self::scan_conanfile_py(&path_str, content),
            "conan.lock" => Self::scan_conan_lock(&path_str, content),
            "vcpkg.json" => Self::scan_vcpkg_json(&path_str, content),
            _ => Vec::new(),
        }
    }

    fn scan_package_json(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let json: JsonValue = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let check_deps = |deps_val: Option<&JsonValue>, findings: &mut Vec<ComprehensiveFinding>| {
            if let Some(JsonValue::Object(map)) = deps_val {
                for (pkg, ver_val) in map {
                    let version = ver_val.as_str().unwrap_or("latest").trim_start_matches(['^', '~']);
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "npm") {
                        if pkg.eq_ignore_ascii_case(lib.name) {
                            findings.push(Self::build_dep_finding(
                                file_path,
                                pkg,
                                version,
                                "npm",
                                lib,
                                &format!("\"{}\": \"{}\"", pkg, ver_val.as_str().unwrap_or("")),
                            ));
                        }
                    }
                }
            }
        };

        check_deps(json.get("dependencies"), &mut findings);
        check_deps(json.get("devDependencies"), &mut findings);

        findings
    }

    fn scan_package_lock_json(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let json: JsonValue = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let mut seen = std::collections::HashSet::new();

        // 1. npm v7+ "packages" object
        if let Some(JsonValue::Object(packages)) = json.get("packages") {
            for (pkg_path, pkg_obj) in packages {
                let pkg_name = if let Some(last) = pkg_path.rsplit("node_modules/").next() {
                    last
                } else {
                    pkg_path.as_str()
                };
                let ver = pkg_obj.get("version").and_then(|v| v.as_str()).unwrap_or("locked");
                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "npm") {
                    if pkg_name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                        findings.push(Self::build_dep_finding(
                            file_path,
                            pkg_name,
                            ver,
                            "npm",
                            lib,
                            &format!("\"{}\": {{ \"version\": \"{}\" }}", pkg_name, ver),
                        ));
                    }
                }
            }
        }

        // 2. npm v1-v6 "dependencies" object
        if findings.is_empty() {
            if let Some(JsonValue::Object(deps)) = json.get("dependencies") {
                for (pkg_name, pkg_obj) in deps {
                    let ver = pkg_obj.get("version").and_then(|v| v.as_str()).unwrap_or("locked");
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "npm") {
                        if pkg_name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                            findings.push(Self::build_dep_finding(
                                file_path,
                                pkg_name,
                                ver,
                                "npm",
                                lib,
                                &format!("\"{}\": {{ \"version\": \"{}\" }}", pkg_name, ver),
                            ));
                        }
                    }
                }
            }
        }

        findings
    }

    fn scan_pnpm_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || (!trimmed.contains('@') && !trimmed.contains(':')) {
                continue;
            }
            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "npm") {
                let pkg_needle = lib.name;
                // Zero-allocation prefix check matching /{pkg}@, '/{pkg}@, "{pkg}":, {pkg}:, '{pkg}@
                let s = trimmed.strip_prefix('\'').unwrap_or(trimmed);
                let s = s.strip_prefix('/').unwrap_or(s);
                let s = s.strip_prefix('"').unwrap_or(s);
                let is_match = if let Some(rest) = s.strip_prefix(pkg_needle) {
                    rest.starts_with('@') || rest.starts_with(':') || rest.starts_with("\":") || rest.starts_with("':")
                } else {
                    false
                };

                if is_match && seen.insert(lib.name) {
                    let ver = trimmed.split('@').next_back()
                        .or_else(|| trimmed.split(':').next_back())
                        .unwrap_or("locked")
                        .trim_matches(|c: char| c == '\'' || c == '"' || c == ':' || c == '(' || c == ')' || c.is_whitespace());
                    let mut finding = Self::build_dep_finding(
                        file_path,
                        lib.name,
                        ver,
                        "npm",
                        lib,
                        trimmed,
                    );
                    finding.line_number = (idx + 1) as u32;
                    findings.push(finding);
                }
            }
        }
        findings
    }

    fn scan_yarn_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut current_pkg: Option<&'static KnownCryptoLib> = None;
        let mut pkg_line = 1;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.contains('@') && (trimmed.ends_with(':') || trimmed.contains(':')) {
                current_pkg = None;
                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "npm") {
                    if let Some(pos) = trimmed.find(lib.name) {
                        let before_ok = if pos == 0 {
                            true
                        } else {
                            let b = trimmed.as_bytes()[pos - 1];
                            b == b'"' || b == b'\'' || b == b'/' || b == b' '
                        };
                        let after = &trimmed[pos + lib.name.len()..];
                        if before_ok && after.starts_with('@') {
                            current_pkg = Some(lib);
                            pkg_line = idx + 1;
                            break;
                        }
                    }
                }
            } else if let Some(lib) = current_pkg {
                if trimmed.starts_with("version") {
                    let ver = trimmed.split(['"', ':', ' '])
                        .find(|s| !s.is_empty() && *s != "version")
                        .unwrap_or("locked");
                    if seen.insert(lib.name) {
                        let mut finding = Self::build_dep_finding(
                            file_path,
                            lib.name,
                            ver,
                            "npm",
                            lib,
                            trimmed,
                        );
                        finding.line_number = pkg_line as u32;
                        findings.push(finding);
                    }
                    current_pkg = None;
                }
            }
        }
        findings
    }

    fn scan_cargo_toml(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut in_deps = false;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let section = trimmed.trim_matches(|c| c == '[' || c == ']');
                in_deps = section == "dependencies" || section == "dev-dependencies" || section.ends_with(".dependencies");
                continue;
            }

            if in_deps && !trimmed.starts_with('#') && trimmed.contains('=') {
                if let Some((pkg, ver_part)) = trimmed.split_once('=') {
                    let pkg_name = pkg.trim();
                    let ver = ver_part.trim().trim_matches(|c| c == '"' || c == '\'' || c == '{' || c == '}');
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "cargo") {
                        if pkg_name.eq_ignore_ascii_case(lib.name) {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                pkg_name,
                                ver,
                                "cargo",
                                lib,
                                line,
                            );
                            finding.line_number = (idx + 1) as u32;
                            findings.push(finding);
                        }
                    }
                }
            }
        }

        findings
    }

    fn scan_cargo_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut current_pkg: Option<&str> = None;
        let mut current_ver: Option<&str> = None;
        let mut pkg_start_line = 1;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed == "[[package]]" {
                if let (Some(pkg), Some(ver)) = (current_pkg.take(), current_ver.take()) {
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "cargo") {
                        if pkg.eq_ignore_ascii_case(lib.name) {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                pkg,
                                ver,
                                "cargo",
                                lib,
                                &format!("name = \"{}\", version = \"{}\"", pkg, ver),
                            );
                            finding.line_number = pkg_start_line as u32;
                            findings.push(finding);
                        }
                    }
                }
                pkg_start_line = idx + 1;
            } else if let Some(rest) = trimmed.strip_prefix("name = \"") {
                current_pkg = rest.split('"').next();
            } else if let Some(rest) = trimmed.strip_prefix("version = \"") {
                current_ver = rest.split('"').next();
            }
        }

        if let (Some(pkg), Some(ver)) = (current_pkg, current_ver) {
            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "cargo") {
                if pkg.eq_ignore_ascii_case(lib.name) {
                    let mut finding = Self::build_dep_finding(
                        file_path,
                        pkg,
                        ver,
                        "cargo",
                        lib,
                        &format!("name = \"{}\", version = \"{}\"", pkg, ver),
                    );
                    finding.line_number = pkg_start_line as u32;
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn scan_requirements_txt(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let pkg_spec: Vec<&str> = trimmed.split(['=', '>', '<', '~']).collect();
            let pkg_name = pkg_spec[0].trim();
            let version = if pkg_spec.len() > 1 { pkg_spec[pkg_spec.len() - 1].trim() } else { "latest" };

            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pypi") {
                if pkg_name.eq_ignore_ascii_case(lib.name) {
                    let mut finding = Self::build_dep_finding(
                        file_path,
                        pkg_name,
                        version,
                        "pypi",
                        lib,
                        line,
                    );
                    finding.line_number = (idx + 1) as u32;
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn scan_pyproject_toml(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pypi") {
                if let Some(pos) = trimmed.find(lib.name) {
                    let before = trimmed[..pos].chars().last();
                    let after = trimmed[pos + lib.name.len()..].chars().next();
                    let quoted = (before == Some('"') || before == Some('\''))
                        && after.is_some_and(|c| c == '"' || c == '\'' || c == '>' || c == '<' || c == '=' || c == '~' || c == '[' || c == ';' || c == ' ' || c == ',');
                    let poetry_def = (before.is_none() || before.is_some_and(|c| c.is_whitespace()))
                        && after.is_some_and(|c| c.is_whitespace() || c == '=');
                    if quoted || poetry_def {
                        let mut finding = Self::build_dep_finding(
                            file_path,
                            lib.name,
                            "defined",
                            "pypi",
                            lib,
                            line,
                        );
                        finding.line_number = (idx + 1) as u32;
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    fn scan_poetry_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut current_pkg: Option<&str> = None;
        let mut current_ver: Option<&str> = None;
        let mut pkg_start_line = 1;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed == "[[package]]" {
                if let (Some(pkg), Some(ver)) = (current_pkg.take(), current_ver.take()) {
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pypi") {
                        if pkg.eq_ignore_ascii_case(lib.name) {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                pkg,
                                ver,
                                "pypi",
                                lib,
                                &format!("name = \"{}\", version = \"{}\"", pkg, ver),
                            );
                            finding.line_number = pkg_start_line as u32;
                            findings.push(finding);
                        }
                    }
                }
                pkg_start_line = idx + 1;
            } else if let Some(rest) = trimmed.strip_prefix("name = \"") {
                current_pkg = rest.split('"').next();
            } else if let Some(rest) = trimmed.strip_prefix("version = \"") {
                current_ver = rest.split('"').next();
            }
        }

        if let (Some(pkg), Some(ver)) = (current_pkg, current_ver) {
            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pypi") {
                if pkg.eq_ignore_ascii_case(lib.name) {
                    let mut finding = Self::build_dep_finding(
                        file_path,
                        pkg,
                        ver,
                        "pypi",
                        lib,
                        &format!("name = \"{}\", version = \"{}\"", pkg, ver),
                    );
                    finding.line_number = pkg_start_line as u32;
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn scan_pipfile(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut in_packages = false;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let section = trimmed.trim_matches(|c| c == '[' || c == ']');
                in_packages = section == "packages" || section == "dev-packages";
                continue;
            }

            if in_packages && !trimmed.starts_with('#') && trimmed.contains('=') {
                if let Some((pkg, ver_part)) = trimmed.split_once('=') {
                    let pkg_name = pkg.trim();
                    let ver = ver_part.trim().trim_matches(|c| c == '"' || c == '\'' || c == '*' || c == '{' || c == '}');
                    let clean_ver = if ver.is_empty() { "latest" } else { ver };
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pypi") {
                        if pkg_name.eq_ignore_ascii_case(lib.name) {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                pkg_name,
                                clean_ver,
                                "pypi",
                                lib,
                                line,
                            );
                            finding.line_number = (idx + 1) as u32;
                            findings.push(finding);
                        }
                    }
                }
            }
        }
        findings
    }

    fn scan_pipfile_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let json: JsonValue = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let mut seen = std::collections::HashSet::new();

        let mut check_section = |sec_val: Option<&JsonValue>, findings: &mut Vec<ComprehensiveFinding>| {
            if let Some(JsonValue::Object(map)) = sec_val {
                for (pkg, details) in map {
                    let ver = details.get("version").and_then(|v| v.as_str()).unwrap_or("locked").trim_start_matches(['=', '>', '<', '~']);
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pypi") {
                        if pkg.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                            findings.push(Self::build_dep_finding(
                                file_path,
                                pkg,
                                ver,
                                "pypi",
                                lib,
                                &format!("\"{}\": {{ \"version\": \"{}\" }}", pkg, ver),
                            ));
                        }
                    }
                }
            }
        };

        check_section(json.get("default"), &mut findings);
        check_section(json.get("develop"), &mut findings);
        findings
    }

    fn scan_go_mod(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "golang") {
                if trimmed.contains(lib.name) {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    let ver = if parts.first() == Some(&"require") && parts.len() >= 3 {
                        parts[2]
                    } else if parts.len() >= 2 {
                        parts[1]
                    } else {
                        "unknown"
                    };
                    let mut finding = Self::build_dep_finding(
                        file_path,
                        lib.name,
                        ver,
                        "golang",
                        lib,
                        line,
                    );
                    finding.line_number = (idx + 1) as u32;
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn scan_go_sum(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (idx, line) in content.lines().enumerate() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let pkg_name = parts[0];
                let ver = parts[1].trim_end_matches("/go.mod");
                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "golang") {
                    if pkg_name.contains(lib.name) && seen.insert(lib.name) {
                        let mut finding = Self::build_dep_finding(
                            file_path,
                            lib.name,
                            ver,
                            "golang",
                            lib,
                            line,
                        );
                        finding.line_number = (idx + 1) as u32;
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    fn scan_pom_xml(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();

        for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "maven") {
            if content.contains(&format!("<artifactId>{}</artifactId>", lib.name)) {
                let finding = Self::build_dep_finding(
                    file_path,
                    lib.name,
                    "maven-dependency",
                    "maven",
                    lib,
                    &format!("<artifactId>{}</artifactId>", lib.name),
                );
                findings.push(finding);
            }
        }

        findings
    }

    fn scan_build_gradle(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "maven") {
                if trimmed.contains(lib.name) {
                    let mut finding = Self::build_dep_finding(
                        file_path,
                        lib.name,
                        "gradle-dependency",
                        "maven",
                        lib,
                        trimmed,
                    );
                    finding.line_number = (idx + 1) as u32;
                    findings.push(finding);
                }
            }
        }
        findings
    }

    fn scan_composer_json(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let json: JsonValue = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let check_deps = |deps_val: Option<&JsonValue>, findings: &mut Vec<ComprehensiveFinding>| {
            if let Some(JsonValue::Object(map)) = deps_val {
                for (pkg, ver_val) in map {
                    let version = ver_val.as_str().unwrap_or("latest").trim_start_matches(['^', '~']);
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "composer") {
                        if pkg.eq_ignore_ascii_case(lib.name) || pkg.strip_suffix(lib.name).is_some_and(|p| p.ends_with('/')) {
                            findings.push(Self::build_dep_finding(
                                file_path,
                                pkg,
                                version,
                                "composer",
                                lib,
                                &format!("\"{}\": \"{}\"", pkg, ver_val.as_str().unwrap_or("")),
                            ));
                        }
                    }
                }
            }
        };

        check_deps(json.get("require"), &mut findings);
        check_deps(json.get("require-dev"), &mut findings);
        findings
    }

    fn scan_composer_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let json: JsonValue = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let mut seen = std::collections::HashSet::new();

        let mut check_packages = |pkg_array: Option<&JsonValue>, findings: &mut Vec<ComprehensiveFinding>| {
            if let Some(JsonValue::Array(packages)) = pkg_array {
                for pkg_obj in packages {
                    if let Some(name) = pkg_obj.get("name").and_then(|n| n.as_str()) {
                        let ver = pkg_obj.get("version").and_then(|v| v.as_str()).unwrap_or("locked");
                        for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "composer") {
                            if (name.eq_ignore_ascii_case(lib.name) || name.strip_suffix(lib.name).is_some_and(|p| p.ends_with('/'))) && seen.insert(lib.name) {
                                findings.push(Self::build_dep_finding(
                                    file_path,
                                    name,
                                    ver,
                                    "composer",
                                    lib,
                                    &format!("\"name\": \"{}\", \"version\": \"{}\"", name, ver),
                                ));
                            }
                        }
                    }
                }
            }
        };

        check_packages(json.get("packages"), &mut findings);
        check_packages(json.get("packages-dev"), &mut findings);
        findings
    }

    fn scan_gemfile(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("gem ") {
                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "rubygems") {
                    if let Some(pos) = trimmed.find(lib.name) {
                        let before = trimmed[..pos].chars().last();
                        let after = trimmed[pos + lib.name.len()..].chars().next();
                        let quoted = (before == Some('"') && after == Some('"'))
                            || (before == Some('\'') && after == Some('\''));
                        if quoted {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                lib.name,
                                "gem-specified",
                                "rubygems",
                                lib,
                                trimmed,
                            );
                            finding.line_number = (idx + 1) as u32;
                            findings.push(finding);
                        }
                    }
                }
            }
        }

        findings
    }

    fn scan_gemfile_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut in_specs = false;
        let mut seen = std::collections::HashSet::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed == "specs:" {
                in_specs = true;
                continue;
            } else if !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
                in_specs = false;
            }

            if in_specs && line.starts_with("    ") && !line.starts_with("      ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if !parts.is_empty() {
                    let pkg_name = parts[0];
                    let ver = if parts.len() > 1 {
                        parts[1].trim_matches(|c| c == '(' || c == ')')
                    } else {
                        "locked"
                    };
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "rubygems") {
                        if pkg_name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                pkg_name,
                                ver,
                                "rubygems",
                                lib,
                                trimmed,
                            );
                            finding.line_number = (idx + 1) as u32;
                            findings.push(finding);
                        }
                    }
                }
            }
        }
        findings
    }

    fn scan_package_swift(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (idx, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "swift") {
                if lower.contains(&lib.name.to_lowercase()) && seen.insert(lib.name) {
                    let mut finding = Self::build_dep_finding(
                        file_path,
                        lib.name,
                        "declared",
                        "swift",
                        lib,
                        line.trim(),
                    );
                    finding.line_number = (idx + 1) as u32;
                    findings.push(finding);
                }
            }
        }
        findings
    }

    fn scan_package_resolved(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let json: JsonValue = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let mut seen = std::collections::HashSet::new();

        let pins_opt = json.get("pins")
            .or_else(|| json.get("object").and_then(|o| o.get("pins")))
            .and_then(|p| p.as_array());

        if let Some(pins) = pins_opt {
            for pin in pins {
                let pkg_name = pin.get("identity")
                    .or_else(|| pin.get("package"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let version = pin.get("state")
                    .and_then(|s| s.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("locked");

                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "swift") {
                    if pkg_name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                        findings.push(Self::build_dep_finding(
                            file_path,
                            pkg_name,
                            version,
                            "swift",
                            lib,
                            &format!("{}: {}", pkg_name, version),
                        ));
                    }
                }
            }
        }
        findings
    }

    fn scan_pubspec_yaml(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut in_deps = false;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed == "dependencies:" || trimmed == "dev_dependencies:" {
                in_deps = true;
                continue;
            } else if !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
                in_deps = false;
            }

            if in_deps && trimmed.contains(':') {
                let parts: Vec<&str> = trimmed.split(':').collect();
                let pkg_name = parts[0].trim();
                let ver = parts.get(1).map(|v| v.trim().trim_start_matches(['^', '~', '>', '='])).unwrap_or("any");

                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pub") {
                    if pkg_name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                        let mut finding = Self::build_dep_finding(
                            file_path,
                            pkg_name,
                            ver,
                            "pub",
                            lib,
                            trimmed,
                        );
                        finding.line_number = (idx + 1) as u32;
                        findings.push(finding);
                    }
                }
            }
        }
        findings
    }

    fn scan_pubspec_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut current_pkg: Option<String> = None;
        let mut current_line = 1u32;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if line.starts_with("  ") && !line.starts_with("    ") && trimmed.ends_with(':') {
                let pkg = trimmed.trim_end_matches(':').trim();
                current_pkg = Some(pkg.to_string());
                current_line = (idx + 1) as u32;
            } else if let Some(ref pkg) = current_pkg {
                if trimmed.starts_with("version:") {
                    let ver = trimmed.trim_start_matches("version:").trim().trim_matches('"');
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "pub") {
                        if pkg.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                pkg,
                                ver,
                                "pub",
                                lib,
                                trimmed,
                            );
                            finding.line_number = current_line;
                            findings.push(finding);
                        }
                    }
                    current_pkg = None;
                }
            }
        }
        findings
    }

    fn scan_conanfile_txt(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut in_requires = false;
        let mut seen = std::collections::HashSet::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('[') {
                in_requires = trimmed == "[requires]";
                continue;
            }
            if in_requires {
                let pkg_part = trimmed.split('@').next().unwrap_or(trimmed);
                let mut parts = pkg_part.split('/');
                if let Some(pkg_name) = parts.next().map(|s| s.trim()) {
                    let version = parts.next().unwrap_or("latest").trim();
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "conan") {
                        if pkg_name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                            let mut finding = Self::build_dep_finding(
                                file_path,
                                pkg_name,
                                version,
                                "conan",
                                lib,
                                line,
                            );
                            finding.line_number = (idx + 1) as u32;
                            findings.push(finding);
                        }
                    }
                }
            }
        }
        findings
    }

    fn scan_conanfile_py(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("requires(") || trimmed.contains("requires.append(") || trimmed.contains("requires = ") {
                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "conan") {
                    if trimmed.to_lowercase().contains(lib.name) && seen.insert(lib.name) {
                        let version = if let Some(pos) = trimmed.find(lib.name) {
                            if trimmed[pos + lib.name.len()..].starts_with('/') {
                                let rest = &trimmed[pos + lib.name.len() + 1..];
                                rest.chars().take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_').collect::<String>()
                            } else {
                                "latest".to_string()
                            }
                        } else {
                            "latest".to_string()
                        };
                        let mut finding = Self::build_dep_finding(
                            file_path,
                            lib.name,
                            &version,
                            "conan",
                            lib,
                            line,
                        );
                        finding.line_number = (idx + 1) as u32;
                        findings.push(finding);
                    }
                }
            }
        }
        findings
    }

    fn scan_conan_lock(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if let Ok(json) = serde_json::from_str::<JsonValue>(content) {
            let mut refs = Vec::new();
            if let Some(nodes) = json.get("graph_lock").and_then(|g| g.get("nodes")).and_then(|n| n.as_object()) {
                for (_k, node) in nodes {
                    if let Some(r) = node.get("ref").and_then(|r| r.as_str()) {
                        refs.push(r.to_string());
                    }
                }
            } else if let Some(reqs) = json.get("requires").and_then(|r| r.as_array()) {
                for r in reqs {
                    if let Some(s) = r.as_str() {
                        refs.push(s.to_string());
                    }
                }
            }

            for r in refs {
                let pkg_part = r.split('#').next().unwrap_or(&r);
                let mut parts = pkg_part.split('/');
                if let Some(name) = parts.next().map(|s| s.trim()) {
                    let version = parts.next().unwrap_or("latest").trim();
                    for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "conan") {
                        if name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                            findings.push(Self::build_dep_finding(
                                file_path,
                                name,
                                version,
                                "conan",
                                lib,
                                &r,
                            ));
                        }
                    }
                }
            }
        } else {
            for (idx, line) in content.lines().enumerate() {
                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "conan") {
                    if line.to_lowercase().contains(lib.name) && seen.insert(lib.name) {
                        let mut finding = Self::build_dep_finding(
                            file_path,
                            lib.name,
                            "locked",
                            "conan",
                            lib,
                            line,
                        );
                        finding.line_number = (idx + 1) as u32;
                        findings.push(finding);
                    }
                }
            }
        }
        findings
    }

    fn scan_vcpkg_json(file_path: &str, content: &str) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let json: JsonValue = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_array()) {
            for dep in deps {
                let (name, ver) = if let Some(s) = dep.as_str() {
                    (s, "latest")
                } else if let Some(obj) = dep.as_object() {
                    let n = obj.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let v = obj.get("version>=").or_else(|| obj.get("version")).and_then(|v| v.as_str()).unwrap_or("latest");
                    (n, v)
                } else {
                    continue;
                };

                for lib in KNOWN_CRYPTO_LIBRARIES.iter().filter(|l| l.ecosystem == "vcpkg") {
                    if name.eq_ignore_ascii_case(lib.name) && seen.insert(lib.name) {
                        findings.push(Self::build_dep_finding(
                            file_path,
                            name,
                            ver,
                            "vcpkg",
                            lib,
                            &dep.to_string(),
                        ));
                    }
                }
            }
        }

        findings
    }

    fn build_dep_finding(
        file_path: &str,
        name: &str,
        version: &str,
        ecosystem: &str,
        lib: &KnownCryptoLib,
        snippet: &str,
    ) -> ComprehensiveFinding {
        let purl = format!("pkg:{}/{}@{}", ecosystem, name, version);
        let (severity, q_risk, rule_id) = if lib.is_quantum_safe {
            ("INFO", "SAFE", "PQC-DEP-SAFE")
        } else if lib.is_hybrid {
            ("LOW", "HYBRID", "PQC-DEP-HYBRID")
        } else {
            ("HIGH", "VULNERABLE", "PQC-DEP-VULNERABLE")
        };

        ComprehensiveFinding {
            file_path: file_path.to_string(),
            vulnerability_class: "Software Supply Chain Dependency".to_string(),
            description: format!(
                "Cryptographic package '{}' declared in manifest ({purl}). {desc} Provides algorithms: [{algos}].",
                name,
                purl = purl,
                desc = lib.description,
                algos = lib.algorithms_provided.join(", ")
            ),
            severity: severity.to_string(),
            line_number: 1,
            remediation: lib.remediation.to_string(),
            rule_id: Some(rule_id.to_string()),
            quantum_risk: Some(q_risk.to_string()),
            confidence: Some("HIGH".to_string()),
            snippet: Some(snippet.trim().to_string()),
            column_number: Some(1),
            fingerprint: Some(format!("pqc-dep:{}:{}", purl, rule_id)),
        }
    }
}
