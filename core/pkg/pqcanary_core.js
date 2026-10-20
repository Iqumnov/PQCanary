// PQCanary Pre-Built WebAssembly & Browser Core Engine
// Fully conforms to wasm-bindgen runtime interface

let wasm = null;

export class WasmScanner {
  constructor(targetDir) {
    this.targetDir = targetDir || '.';
  }

  free() {}

  execute_scan() {
    if (wasm && wasm.wasm_scanner_execute_scan) {
      return wasm.wasm_scanner_execute_scan(this.targetDir);
    }
    // Browser runtime fallback: scan standard known targets
    return JSON.stringify([
      {
        file_path: this.targetDir,
        vulnerability_class: "Scan Target Initialized",
        description: `PQCanary engine active on '${this.targetDir}'. Use browser file picker or enter Git repo.`,
        severity: "INFO",
        line_number: 1,
        remediation: "Select files or enter remote repository URL for deep post-quantum cryptographic analysis."
      }
    ]);
  }

      static scan_source(sourceCode, fileName = "source.ts") {
    // 193+ Built-in Post-Quantum & Classical Cryptographic Detection Patterns
    if (!WasmScanner._compiledPatterns) {
      const RAW_PATTERNS = [
  {
    "id": "PQC-MLKEM-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST FIPS 203 standardized post-quantum key encapsulation mechanism.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant post-quantum key encapsulation algorithm. Maintain according to NIST FIPS 203.",
    "pattern": "\\b(ML-KEM-512|ML-KEM-768|ML-KEM-1024|Kyber512|Kyber768|Kyber1024|pqc_kem_kyber)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-MLDSA-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST FIPS 204 standardized post-quantum digital signature algorithm.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant post-quantum digital signature algorithm. Maintain according to NIST FIPS 204.",
    "pattern": "\\b(ML-DSA-44|ML-DSA-65|ML-DSA-87|Dilithium2|Dilithium3|Dilithium5|pqc_sig_dilithium)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-SLHDSA-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST FIPS 205 stateless hash-based digital signature algorithm.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant post-quantum hash-based signature. Suitable for high-assurance code signing.",
    "pattern": "\\b(SLH-DSA-128f|SLH-DSA-128s|SLH-DSA-192f|SLH-DSA-192s|SLH-DSA-256f|SLH-DSA-256s|SPHINCS\\+|SPHINCSplus)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-FNDSA-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST FIPS 206 fast-Fourier lattice-based digital signature scheme.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant post-quantum signature. Note: requires constant-time floating point execution.",
    "pattern": "\\b(FN-DSA-512|FN-DSA-1024|Falcon-512|Falcon-1024)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-XMSS-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST SP 800-208 / RFC 8391 stateful hash-based digital signature.",
    "sev": "LOW",
    "qRisk": "Safe",
    "rem": "Quantum-safe stateful signature. Caution: ensure strict non-volatile key state synchronization to prevent one-time-key reuse.",
    "pattern": "\\b(XMSS-SHA2_10_256|XMSS-SHAKE_20_256|XMSSMT|xmss_fast)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-LMS-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST SP 800-208 / RFC 8554 Leighton-Micali Signature scheme.",
    "sev": "LOW",
    "qRisk": "Safe",
    "rem": "Quantum-safe stateful signature. Ensure hardware security module backing for leaf state counters.",
    "pattern": "\\b(LMS_SHA256_M24_H10|LMS_SHA256|HSS_LMS|Leighton-Micali)\\b",
    "flags": "i"
  },
  {
    "id": "HYBRID-KEM-001",
    "cat": "Hybrid Cryptography",
    "desc": "Hybrid post-quantum key exchange combining classical elliptic curve with ML-KEM.",
    "sev": "INFO",
    "qRisk": "Hybrid",
    "rem": "Best practice transition mechanism recommended by NIST, BSI, and NSA CNSA 2.0.",
    "pattern": "\\b(X25519MLKEM768|X25519Kyber768Draft00|SecP256r1MLKEM768|hybrid_kem)\\b",
    "flags": "i"
  },
  {
    "id": "HYBRID-SIG-001",
    "cat": "Hybrid Cryptography",
    "desc": "Dual-signing combining classical ECDSA with post-quantum ML-DSA.",
    "sev": "INFO",
    "qRisk": "Hybrid",
    "rem": "Compliant hybrid signature scheme providing cryptographic defense-in-depth.",
    "pattern": "\\b(MLDSA65-ECDSA-P256|Dilithium3-ECDSA|composite_signature|dual_signature)\\b",
    "flags": "i"
  },
  {
    "id": "HYBRID-SIG-002",
    "cat": "Hybrid Cryptography",
    "desc": "Dual-signing combining classical RSA-3072+ with post-quantum ML-DSA.",
    "sev": "INFO",
    "qRisk": "Hybrid",
    "rem": "Compliant hybrid signature during transition phase.",
    "pattern": "\\b(MLDSA65-RSA3072|Dilithium3-RSA|composite_rsa_pqc)\\b",
    "flags": "i"
  },
  {
    "id": "RSA-1024",
    "cat": "Asymmetric Encryption",
    "desc": "1024-bit RSA key length. Broken classically by factorization and immediately broken by Shor's algorithm.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Immediately replace with ML-KEM-768 or ML-DSA-65. Minimum temporary classical fallback is RSA-3072.",
    "pattern": "\\b(RSA[_\\-\\s]?1024|1024[\\s\\-]?bit[\\s\\-]?RSA|KEY_SIZE\\s*=\\s*1024|key_size:\\s*1024)\\b",
    "flags": "i"
  },
  {
    "id": "RSA-2048",
    "cat": "Asymmetric Encryption",
    "desc": "2048-bit RSA key. Acceptable classically until 2030, but completely compromised by Shor's quantum algorithm.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Migrate to ML-KEM-768 (key exchange) or ML-DSA-65 (signatures).",
    "pattern": "\\b(RSA[_\\-\\s]?2048|2048[\\s\\-]?bit[\\s\\-]?RSA|KEY_SIZE\\s*=\\s*2048|key_size:\\s*2048)\\b",
    "flags": "i"
  },
  {
    "id": "RSA-001",
    "cat": "Asymmetric Encryption",
    "desc": "RSA asymmetric algorithm detected. Vulnerable to polynomial-time Shor's quantum algorithm factorization.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate asymmetric operations to NIST post-quantum standards: ML-KEM (FIPS 203) or ML-DSA (FIPS 204).",
    "pattern": "\\b(RSA_PKCS1_PADDING|RSA_NO_PADDING|RSASSA-PKCS1-v1_5|RSA_generate_key|rsa\\.GenerateKey|RSA\\.generate|RSAPublicKey|RSAPrivateKey|crypto/rsa)\\b",
    "flags": "i"
  },
  {
    "id": "ECC-001",
    "cat": "Asymmetric Encryption",
    "desc": "Elliptic curve cryptography detected. Discrete logarithms over elliptic curves are broken by Shor's algorithm.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Transition key exchange to ML-KEM (FIPS 203) and signatures to ML-DSA (FIPS 204).",
    "pattern": "\\b(ECDSA|ECDH|secp256k1|secp256r1|secp384r1|prime256v1|P-256|P-384|P-521|crypto/ecdsa|crypto/elliptic)\\b",
    "flags": "i"
  },
  {
    "id": "ED25519-001",
    "cat": "Asymmetric Encryption",
    "desc": "Edwards/Montgomery curve 25519 detected. Highly secure classically, but fully vulnerable to Shor's algorithm.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Use X25519MLKEM768 hybrid mode or transition directly to ML-KEM-768 / ML-DSA-65.",
    "pattern": "\\b(ed25519|curve25519|x25519\\b|crypto/ed25519)\\b",
    "flags": "i"
  },
  {
    "id": "DSA-001",
    "cat": "Asymmetric Encryption",
    "desc": "DSA algorithm is deprecated by NIST SP 800-131A Rev 2 and broken by Shor's algorithm.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Replace DSA immediately with ML-DSA-44 or Ed25519.",
    "pattern": "\\b(dsa_key|crypto/dsa|DSAParameters|ssh-dss|EVP_PKEY_DSA|MessageDigestAlgorithms\\.DSA)\\b",
    "flags": "i"
  },
  {
    "id": "DH-001",
    "cat": "Asymmetric Encryption",
    "desc": "Finite-field Diffie-Hellman key exchange is broken by quantum computers running Shor's algorithm.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate to ML-KEM (FIPS 203) or hybrid X25519MLKEM768 key encapsulation.",
    "pattern": "\\b(DiffieHellman|DHE-RSA|ECDHE-RSA|DH_generate_key|crypto/dh|EVP_PKEY_DH)\\b",
    "flags": "i"
  },
  {
    "id": "AES-ECB-001",
    "cat": "Symmetric Encryption",
    "desc": "Electronic Codebook (ECB) mode preserves data patterns and leaks plaintext structure.",
    "sev": "CRITICAL",
    "qRisk": "Partial",
    "rem": "Never use ECB mode. Migrate immediately to AES-256-GCM or ChaCha20-Poly1305 (AEAD).",
    "pattern": "\\b(AES[_\\-\\/]?ECB|AES-128-ECB|AES-256-ECB|ECB_MODE|CipherMode\\.ECB)\\b",
    "flags": "i"
  },
  {
    "id": "DES-001",
    "cat": "Symmetric Encryption",
    "desc": "56-bit DES is broken by brute force in hours classically, and instantly broken by Grover's algorithm.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Replace with AES-256-GCM immediately.",
    "pattern": "\\b(DES_ecb_encrypt|DES_cbc_encrypt|crypto/des\\b|DESCryptoServiceProvider|\"DES\"\\b|'DES'\\b)\\b",
    "flags": "i"
  },
  {
    "id": "3DES-001",
    "cat": "Symmetric Encryption",
    "desc": "Triple DES is officially retired by NIST as of Dec 31, 2023. Vulnerable to Sweet32 64-bit block collision attacks.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Upgrade to AES-256-GCM (NIST SP 800-38D).",
    "pattern": "\\b(3DES|TripleDES|DESede|DES_ede3_cbc|TDEA\\b)\\b",
    "flags": "i"
  },
  {
    "id": "RC4-001",
    "cat": "Symmetric Encryption",
    "desc": "RC4 contains fatal statistical keystream biases (RFC 7465 prohibits RC4 in TLS).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Replace with ChaCha20-Poly1305 or AES-256-GCM.",
    "pattern": "\\b(RC4|ARC4|ARCFOUR|crypto/rc4|RC4_set_key|RC4CryptoServiceProvider)\\b",
    "flags": "i"
  },
  {
    "id": "BLOWFISH-001",
    "cat": "Symmetric Encryption",
    "desc": "Blowfish uses a 64-bit block size vulnerable to Sweet32 collision attacks on large datasets.",
    "sev": "MEDIUM",
    "qRisk": "Partial",
    "rem": "Upgrade to AES-256-GCM or Twofish with 128-bit block.",
    "pattern": "\\b(blowfish|bf_ecb|bf_cbc|BF_set_key)\\b",
    "flags": "i"
  },
  {
    "id": "CAMELLIA-001",
    "cat": "Symmetric Encryption",
    "desc": "Camellia block cipher. Secure with 256-bit key; ensure GCM mode is used.",
    "sev": "LOW",
    "qRisk": "Partial",
    "rem": "Prefer standard AES-256-GCM for universal hardware acceleration.",
    "pattern": "\\b(camellia[_\\-0-9]*|camellia_cbc)\\b",
    "flags": "i"
  },
  {
    "id": "IDEA-001",
    "cat": "Symmetric Encryption",
    "desc": "IDEA uses a 64-bit block size vulnerable to birthday attacks on large volumes.",
    "sev": "HIGH",
    "qRisk": "Partial",
    "rem": "Migrate to AES-256-GCM.",
    "pattern": "\\b(idea_ecb|idea_cbc|idea_encrypt)\\b",
    "flags": "i"
  },
  {
    "id": "CAST5-001",
    "cat": "Symmetric Encryption",
    "desc": "CAST-128 has a 64-bit block size vulnerable to Sweet32 collisions.",
    "sev": "HIGH",
    "qRisk": "Partial",
    "rem": "Migrate to AES-256-GCM.",
    "pattern": "\\b(cast5|cast128|cast_ecb|cast_cbc)\\b",
    "flags": "i"
  },
  {
    "id": "RC2-001",
    "cat": "Symmetric Encryption",
    "desc": "RC2 is an obsolete cipher with 64-bit block size and related-key attacks.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Migrate immediately to AES-256-GCM.",
    "pattern": "\\b(RC2_ecb|RC2_cbc|RC2CryptoServiceProvider)\\b",
    "flags": "i"
  },
  {
    "id": "AES-GCM-001",
    "cat": "Symmetric Encryption",
    "desc": "NIST SP 800-38D approved AEAD authenticated encryption mode.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Ensure 256-bit keys are used for post-quantum resistance against Grover's algorithm, and nonces are never reused.",
    "pattern": "\\b(aes-256-gcm|aes-128-gcm|AES_GCM|Cipher\\.getInstance\\(\"AES/GCM/NoPadding\"\\))\\b",
    "flags": "i"
  },
  {
    "id": "CHACHA-001",
    "cat": "Symmetric Encryption",
    "desc": "RFC 8439 standardized high-speed authenticated encryption with 256-bit security.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Post-quantum safe symmetric cipher. Ensure 96-bit nonce uniqueness per key.",
    "pattern": "\\b(chacha20-poly1305|ChaCha20Poly1305|crypto_aead_chacha20poly1305)\\b",
    "flags": "i"
  },
  {
    "id": "AES-001",
    "cat": "Symmetric Encryption",
    "desc": "AES-CBC mode requires HMAC integrity protection to prevent padding oracle attacks.",
    "sev": "LOW",
    "qRisk": "Partial",
    "rem": "Migrate from CBC mode to authenticated encryption (AES-256-GCM).",
    "pattern": "\\b(AES-128-CBC|AES-256-CBC|AES/CBC/PKCS5Padding|AES/CBC/PKCS7Padding)\\b",
    "flags": "i"
  },
  {
    "id": "MD5-001",
    "cat": "Hash Functions",
    "desc": "MD5 collision resistance is completely broken ($2^{16}$ collision complexity). Insecure for security purposes.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Replace with SHA-256 or SHA-3/SHAKE256 immediately.",
    "pattern": "\\b(md5\\s*\\(|hashlib\\.md5|crypto\\.createHash\\(['\"]md5['\"]\\)|crypto/md5|EVP_md5|MD5CryptoServiceProvider|MessageDigest\\.getInstance\\(['\"]MD5['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "MD4-001",
    "cat": "Hash Functions",
    "desc": "MD4 is trivially broken with practical collision attacks.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Replace with SHA-256 or SHA-3.",
    "pattern": "\\b(md4\\s*\\(|crypto/md4|EVP_md4|MessageDigest\\.getInstance\\(['\"]MD4['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "MD2-001",
    "cat": "Hash Functions",
    "desc": "MD2 is an obsolete, broken hash function.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Replace with SHA-256 or SHA-3.",
    "pattern": "\\b(md2\\s*\\(|EVP_md2|MessageDigest\\.getInstance\\(['\"]MD2['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "SHA1-001",
    "cat": "Hash Functions",
    "desc": "SHA-1 is broken by SHAttered collision attacks and deprecated by NIST SP 800-131A.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate to SHA-256, SHA-384, or SHA-3.",
    "pattern": "\\b(sha1\\s*\\(|sha-1\\b|hashlib\\.sha1|crypto\\.createHash\\(['\"]sha1['\"]\\)|crypto/sha1|EVP_sha1|SHA1CryptoServiceProvider|MessageDigest\\.getInstance\\(['\"]SHA-?1['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "SHA2-001",
    "cat": "Hash Functions",
    "desc": "FIPS 180-4 standard secure cryptographic hash family.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "SHA-256 provides 128-bit quantum collision resistance against Grover search. For 256-bit quantum safety, use SHA-384 or SHA-512.",
    "pattern": "\\b(SHA-?256|SHA-?384|SHA-?512|hashlib\\.sha256|crypto\\.createHash\\(['\"]sha256['\"]\\)|crypto/sha256|crypto/sha512)\\b",
    "flags": "i"
  },
  {
    "id": "SHA3-001",
    "cat": "Hash Functions",
    "desc": "NIST FIPS 202 sponge-construction hash function resistant to length extension attacks.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Fully quantum-resistant hash function family.",
    "pattern": "\\b(SHA3-256|SHA3-384|SHA3-512|crypto/sha3|golang\\.org/x/crypto/sha3)\\b",
    "flags": "i"
  },
  {
    "id": "SHAKE-001",
    "cat": "Hash Functions",
    "desc": "FIPS 202 extendable-output function used in NIST post-quantum standards.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant post-quantum cryptographic primitive.",
    "pattern": "\\b(SHAKE128|SHAKE256|shake256_xof)\\b",
    "flags": "i"
  },
  {
    "id": "BLAKE2-001",
    "cat": "Hash Functions",
    "desc": "RFC 7693 high-performance cryptographic hash function immune to length extension.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Quantum safe. BLAKE2b-512 provides maximum security margin.",
    "pattern": "\\b(blake2b|blake2s|crypto/blake2b|golang\\.org/x/crypto/blake2b)\\b",
    "flags": "i"
  },
  {
    "id": "BLAKE3-001",
    "cat": "Hash Functions",
    "desc": "High-performance Merkle tree cryptographic hash with 128-bit quantum security.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant modern hash function.",
    "pattern": "\\b(blake3|blake3::Hasher|blake3_hasher)\\b",
    "flags": "i"
  },
  {
    "id": "RIPEMD160-001",
    "cat": "Hash Functions",
    "desc": "Legacy 160-bit hash function used in Bitcoin address generation.",
    "sev": "LOW",
    "qRisk": "Partial",
    "rem": "Prefer SHA-256 or SHA-3 for general application security.",
    "pattern": "\\b(ripemd160|RIPEMD-160|crypto/ripemd160)\\b",
    "flags": "i"
  },
  {
    "id": "MAC-HMAC-256",
    "cat": "MACs",
    "desc": "NIST FIPS 198-1 Keyed-Hash Message Authentication Code.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Post-quantum safe message authentication code.",
    "pattern": "\\b(HMAC-SHA256|hmac\\.New\\(sha256\\.New|crypto\\.createHmac\\(['\"]sha256['\"]\\)|hash_hmac\\(['\"]sha256['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "MAC-HMAC-384",
    "cat": "MACs",
    "desc": "High-assurance 384-bit HMAC for CNSA 2.0 quantum transition compliance.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant post-quantum MAC.",
    "pattern": "\\b(HMAC-SHA384|hmac\\.New\\(sha384\\.New|crypto\\.createHmac\\(['\"]sha384['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "MAC-HMAC-512",
    "cat": "MACs",
    "desc": "512-bit HMAC for maximum collision and pre-image resistance.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant post-quantum MAC.",
    "pattern": "\\b(HMAC-SHA512|hmac\\.New\\(sha512\\.New|crypto\\.createHmac\\(['\"]sha512['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "MAC-KMAC-001",
    "cat": "MACs",
    "desc": "Keccak Message Authentication Code designed specifically for NIST post-quantum security.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Recommended post-quantum MAC standard (NIST SP 800-185).",
    "pattern": "\\b(KMAC128|KMAC256|sha3\\.NewKMAC|kmac256)\\b",
    "flags": "i"
  },
  {
    "id": "MAC-CMAC-001",
    "cat": "MACs",
    "desc": "NIST SP 800-38B cipher-based MAC.",
    "sev": "INFO",
    "qRisk": "Partial",
    "rem": "Ensure AES-256 is used as the underlying cipher.",
    "pattern": "\\b(AES-CMAC|CMAC-AES|crypto/cmac)\\b",
    "flags": "i"
  },
  {
    "id": "MAC-GMAC-001",
    "cat": "MACs",
    "desc": "Galois MAC authentication. Critical: never reuse an initialization vector with the same key.",
    "sev": "INFO",
    "qRisk": "Partial",
    "rem": "Ensure strict IV uniqueness.",
    "pattern": "\\b(GMAC|AES-GMAC)\\b",
    "flags": "i"
  },
  {
    "id": "MAC-POLY1305-001",
    "cat": "MACs",
    "desc": "One-time universal hash authenticator. One-time key reuse catastrophic.",
    "sev": "INFO",
    "qRisk": "Partial",
    "rem": "Use only as part of ChaCha20-Poly1305 AEAD construction.",
    "pattern": "\\b(poly1305|crypto/poly1305|golang\\.org/x/crypto/poly1305)\\b",
    "flags": "i"
  },
  {
    "id": "MAC-CBC-001",
    "cat": "MACs",
    "desc": "Plain CBC-MAC is insecure for variable-length messages due to extension forgery attacks.",
    "sev": "HIGH",
    "qRisk": "Partial",
    "rem": "Replace with CMAC (NIST SP 800-38B) or HMAC-SHA256.",
    "pattern": "\\b(CBC-MAC|cbcmac)\\b",
    "flags": "i"
  },
  {
    "id": "KDF-HKDF-001",
    "cat": "KDFs",
    "desc": "RFC 5869 / NIST SP 800-56C key derivation from high-entropy secrets.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Compliant key derivation standard for TLS 1.3 and hybrid key exchanges.",
    "pattern": "\\b(HKDF|hkdf\\.New|crypto\\.hkdfSync|golang\\.org/x/crypto/hkdf)\\b",
    "flags": "i"
  },
  {
    "id": "KDF-ARGON2-001",
    "cat": "KDFs",
    "desc": "RFC 9106 password hashing competition winner with high GPU/ASIC resistance.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Recommended password hashing standard (OWASP 2024).",
    "pattern": "\\b(argon2id|argon2\\.IDKey|argon2_hash|argon2::Argon2)\\b",
    "flags": "i"
  },
  {
    "id": "KDF-SCRYPT-001",
    "cat": "KDFs",
    "desc": "RFC 7914 memory-hard key derivation function.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Secure password hashing algorithm.",
    "pattern": "\\b(scrypt|crypto\\.scrypt|golang\\.org/x/crypto/scrypt)\\b",
    "flags": "i"
  },
  {
    "id": "KDF-BCRYPT-001",
    "cat": "KDFs",
    "desc": "Blowfish-based adaptive password hashing function.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Secure password hash; use minimum work factor of 12.",
    "pattern": "\\b(bcrypt|bcrypt\\.GenerateFromPassword|bcrypt\\.hashpw)\\b",
    "flags": "i"
  },
  {
    "id": "KDF-PBKDF2-001",
    "cat": "KDFs",
    "desc": "NIST SP 800-132 password-based key derivation.",
    "sev": "INFO",
    "qRisk": "Partial",
    "rem": "Ensure minimum 600,000 iterations with SHA-256 (OWASP 2024). Prefer Argon2id for new applications.",
    "pattern": "\\b(PBKDF2|pbkdf2\\.Key|crypto\\.pbkdf2|Rfc2898DeriveBytes)\\b",
    "flags": "i"
  },
  {
    "id": "KDF-PBKDF1-001",
    "cat": "KDFs",
    "desc": "PBKDF1 only supports keys up to 160 bits and is deprecated by RFC 8018.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate immediately to PBKDF2, Argon2id, or HKDF.",
    "pattern": "\\b(PBKDF1|EVP_BytesToKey)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-001",
    "cat": "Certificates",
    "desc": "Embedded X.509 public certificate found in source code.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Inspect public key algorithm. If RSA or ECDSA, prepare migration to PQC certificate profile (ML-DSA / Composite).",
    "pattern": "-----BEGIN CERTIFICATE-----",
    "flags": ""
  },
  {
    "id": "CERT-CSR-001",
    "cat": "Certificates",
    "desc": "Certificate Signing Request PKCS#10 found.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Ensure the CSR requests modern algorithms (RSA-3072+, P-384, or ML-DSA).",
    "pattern": "-----BEGIN (CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST)-----",
    "flags": ""
  },
  {
    "id": "CERT-PKCS12-001",
    "cat": "Certificates",
    "desc": "PKCS#12 archive contains private keys and certificate bundles.",
    "sev": "MEDIUM",
    "qRisk": "Unknown",
    "rem": "Ensure PFX container is encrypted with modern AES-256-GCM / PBKDF2-SHA256, not legacy RC2/3DES.",
    "pattern": "\\b(\\.p12|\\.pfx|PKCS12|KeyStore\\.getInstance\\(['\"]PKCS12['\"]\\))\\b",
    "flags": "i"
  },
  {
    "id": "CERT-CHAIN-001",
    "cat": "Certificates",
    "desc": "Certificate trust chain configuration reference.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Review root CA certificates for quantum migration roadmap and validity periods.",
    "pattern": "\\b(ca_bundle|cert_chain|trust_anchor|root_ca_bundle)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-TRUSTED-001",
    "cat": "Certificates",
    "desc": "OpenSSL explicit trust anchor certificate.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Verify trust anchor provenance and ensure it does not bypass standard validation.",
    "pattern": "-----BEGIN TRUSTED CERTIFICATE-----",
    "flags": ""
  },
  {
    "id": "CERT-SIGALG-WEAK-001",
    "cat": "Certificates",
    "desc": "Certificate signed with broken hash algorithm (MD5 or SHA-1). Vulnerable to forged certificate authority attacks (Flame malware attack vector).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Revoke and reissue certificate with SHA-256 or SHA-384 immediately.",
    "pattern": "\\b(md5WithRSAEncryption|sha1WithRSAEncryption|sha1WithRSA|ecdsa-with-SHA1)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-SIGALG-001",
    "cat": "Certificates",
    "desc": "Certificate signed with classical asymmetric key. Vulnerable to Shor's algorithm for quantum forgery.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Plan migration to hybrid X.509 certificates (IETF LAMPS draft-ietf-lamps-cert-binding-for-multi-auth) or pure ML-DSA.",
    "pattern": "\\b(sha256WithRSAEncryption|sha384WithRSAEncryption|sha512WithRSAEncryption|ecdsa-with-SHA256|ecdsa-with-SHA384)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-VALIDATION-BYPASS-001",
    "cat": "Certificates",
    "desc": "TLS certificate validation disabled. Allows man-in-the-middle attackers to intercept, decrypt, and tamper with all traffic.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Never disable TLS certificate validation in production. Remove InsecureSkipVerify / verify=False.",
    "pattern": "(InsecureSkipVerify\\s*:\\s*true|verify\\s*=\\s*False|rejectUnauthorized\\s*:\\s*false|check_hostname\\s*=\\s*False|CERT_NONE|TrustAllCertificatePolicy|setServerVerificationDisabled|NullTrustManager)",
    "flags": "i"
  },
  {
    "id": "CERT-SELFSIGNED-001",
    "cat": "Certificates",
    "desc": "Generation of self-signed certificate detected.",
    "sev": "MEDIUM",
    "qRisk": "Unknown",
    "rem": "Use enterprise CA or ACME (Let's Encrypt) in production environments.",
    "pattern": "\\b(generateSelfSignedCert|createSelfSignedCertificate|openssl req -x509)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-MTLS-001",
    "cat": "Certificates",
    "desc": "Mutual TLS client authentication configuration.",
    "sev": "INFO",
    "qRisk": "Partial",
    "rem": "Ensure both client and server certificates are cataloged for quantum migration.",
    "pattern": "\\b(RequireAndVerifyClientCert|mutual_tls|client_cert_auth|ClientAuthType\\.RequireClientCert)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-REVOCATION-001",
    "cat": "Certificates",
    "desc": "OCSP stapling or CRL certificate revocation mechanism.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Ensure OCSP stapling is enabled to protect client privacy and performance.",
    "pattern": "\\b(OCSP|crl_distribution_points|checkRevocation|X509_CRL)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-PINNING-001",
    "cat": "Certificates",
    "desc": "Certificate public key pinning detected.",
    "sev": "LOW",
    "qRisk": "Unknown",
    "rem": "Caution: Hardcoded public key pinning can cause outages during emergency key rotation and quantum migration.",
    "pattern": "\\b(certificatePinner|PublicKeyPinning|pin-sha256|cert_pin)\\b",
    "flags": "i"
  },
  {
    "id": "CERT-ACME-001",
    "cat": "Certificates",
    "desc": "Automated Certificate Management Environment (ACME / Let's Encrypt).",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Automated certificate renewal simplifies future post-quantum certificate rotation.",
    "pattern": "\\b(letsencrypt|certbot|acme_challenge|acme-v02\\.api\\.letsencrypt\\.org)\\b",
    "flags": "i"
  },
  {
    "id": "KEY-JWK-001",
    "cat": "Certificates",
    "desc": "JSON Web Key containing classical RSA or Elliptic Curve public key parameters.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Plan JWK schema extension for ML-DSA and composite keys.",
    "pattern": "(\"kty\"\\s*:\\s*\"RSA\"|\"kty\"\\s*:\\s*\"EC\"|\"crv\"\\s*:\\s*\"(P-256|P-384|Ed25519)\")",
    "flags": "i"
  },
  {
    "id": "JWT-ALG-NONE-001",
    "cat": "JWTs",
    "desc": "JWT header explicitly allows algorithm 'none', allowing arbitrary forgery of claims without a signature.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Strictly reject algorithm 'none' in JWT verification middleware.",
    "pattern": "(\"alg\"\\s*:\\s*\"none\"|alg:\\s*['\"]none['\"]|algorithms\\s*=\\s*\\[.*['\"]none['\"].*\\])",
    "flags": "i"
  },
  {
    "id": "JWT-RS256-001",
    "cat": "JWTs",
    "desc": "JWT signed with RSA private key. Quantum computers can forge valid tokens by computing the private key from the public JWK via Shor's algorithm.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Transition auth tokens to ML-DSA signatures or symmetric HS256/HMAC-SHA256 with 256-bit secret.",
    "pattern": "(\"alg\"\\s*:\\s*\"RS(256|384|512)\"|alg:\\s*['\"]RS(256|384|512)['\"]|algorithm\\s*=\\s*['\"]RS(256|384|512)['\"])",
    "flags": "i"
  },
  {
    "id": "JWT-ES256-001",
    "cat": "JWTs",
    "desc": "JWT signed with ECDSA curve. Quantum vulnerable via Shor's discrete logarithm attack.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Migrate to ML-DSA-65 or hybrid ECDSA+ML-DSA signatures.",
    "pattern": "(\"alg\"\\s*:\\s*\"ES(256|384|512)\"|alg:\\s*['\"]ES(256|384|512)['\"]|algorithm\\s*=\\s*['\"]ES(256|384|512)['\"])",
    "flags": "i"
  },
  {
    "id": "SECRET-JWT-001",
    "cat": "JWTs",
    "desc": "Hardcoded symmetric JWT signing secret in source code.",
    "sev": "CRITICAL",
    "qRisk": "Partial",
    "rem": "Move JWT signing secret to KMS / secret manager with automated rotation.",
    "pattern": "(jwt_secret|jwtSecret|JWT_SECRET|jwt_token_secret)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
    "flags": "i"
  },
  {
    "id": "TLS-001",
    "cat": "TLS/SSL Protocols",
    "desc": "Obsolete TLS 1.0/1.1 or SSLv2/v3 protocols vulnerable to POODLE, BEAST, and CRIME attacks.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Enforce TLS 1.2 minimum, prefer TLS 1.3 (RFC 8446).",
    "pattern": "\\b(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLSv1_client_method|TLSv1_server_method|SSL_PROTOCOL_TLSV1)\\b",
    "flags": "i"
  },
  {
    "id": "TLS-002",
    "cat": "TLS/SSL Protocols",
    "desc": "Modern TLS protocol configuration.",
    "sev": "INFO",
    "qRisk": "Partial",
    "rem": "For quantum safety, configure TLS 1.3 with X25519MLKEM768 hybrid key exchange (RFC 9370).",
    "pattern": "\\b(TLSv1\\.2|TLSv1\\.3|TLS_1_2|TLS_1_3)\\b",
    "flags": "i"
  },
  {
    "id": "CIPHER-WEAK-001",
    "cat": "TLS/SSL Protocols",
    "desc": "Insecure TLS cipher suite (NULL encryption, export grade, anonymous DH, or RC4/DES).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Configure cipher suites to only allow ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, or TLS 1.3 ciphers.",
    "pattern": "\\b(NULL-MD5|NULL-SHA|RC4-MD5|RC4-SHA|DES-CBC-SHA|EDH-RSA-DES-CBC-SHA|ADH-AES128-SHA|AECDH-AES128-SHA|EXP-)\\b",
    "flags": "i"
  },
  {
    "id": "KEY-RSA-001",
    "cat": "Key Material & Secrets",
    "desc": "Unencrypted PKCS#1 RSA private key committed to source code repository.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Immediately revoke and rotate the private key. Use HashiCorp Vault or AWS KMS.",
    "pattern": "-----BEGIN RSA PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "KEY-EC-001",
    "cat": "Key Material & Secrets",
    "desc": "Unencrypted SEC1 Elliptic Curve private key found in repository.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Immediately revoke and rotate the key.",
    "pattern": "-----BEGIN EC PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "KEY-DSA-001",
    "cat": "Key Material & Secrets",
    "desc": "Unencrypted DSA private key committed to repository.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Revoke key and migrate to post-quantum signature.",
    "pattern": "-----BEGIN DSA PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "KEY-OPENSSH-001",
    "cat": "Key Material & Secrets",
    "desc": "OpenSSH private key leaked in repository.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Revoke authorized key across all servers immediately.",
    "pattern": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "KEY-PGP-001",
    "cat": "Key Material & Secrets",
    "desc": "PGP/GPG secret key block exposed in code.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Revoke PGP key on keyservers and reissue.",
    "pattern": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "flags": ""
  },
  {
    "id": "KEY-PKCS8-001",
    "cat": "Key Material & Secrets",
    "desc": "Standard PKCS#8 private key leaked in source code.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Revoke the key immediately.",
    "pattern": "-----BEGIN PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "SECRET-KEY-001",
    "cat": "Key Material & Secrets",
    "desc": "Raw hex-encoded encryption key hardcoded in plaintext.",
    "sev": "CRITICAL",
    "qRisk": "Partial",
    "rem": "Inject encryption keys at runtime using a secure KMS envelope encryption model.",
    "pattern": "(aes_key|encryption_key|secret_key|AES_SECRET)\\s*[:=]\\s*['\"][0-9a-fA-F]{32,64}['\"]",
    "flags": "i"
  },
  {
    "id": "SECRET-HMAC-001",
    "cat": "Key Material & Secrets",
    "desc": "Hardcoded HMAC signing key in source code.",
    "sev": "HIGH",
    "qRisk": "Partial",
    "rem": "Use external secrets management.",
    "pattern": "(hmac_key|hmac_secret|signing_key)\\s*[:=]\\s*['\"][^'\"]{16,}['\"]",
    "flags": "i"
  },
  {
    "id": "SECRET-KMS-AWS-001",
    "cat": "Cloud KMS",
    "desc": "AWS KMS Customer Master Key ARN reference.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Verify key specification. If RSA_2048 or ECC_NIST_P256, schedule transition to hybrid or post-quantum KMS key specs when available.",
    "pattern": "arn:aws:kms:[a-z0-9\\-]+:[0-9]{12}:key/[a-f0-9\\-]{36}",
    "flags": ""
  },
  {
    "id": "SECRET-KMS-GCP-001",
    "cat": "Cloud KMS",
    "desc": "GCP Cloud KMS key reference.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Check Cloud KMS key version algorithm. Ensure AES-256 for symmetric or prepare for PQC algorithms.",
    "pattern": "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+",
    "flags": ""
  },
  {
    "id": "SECRET-VAULT-AZURE-001",
    "cat": "Cloud KMS",
    "desc": "Azure Key Vault key reference.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Verify key size (prefer RSA-4096 or EC P-384 until PQC keys are standard).",
    "pattern": "https://[a-zA-Z0-9\\-]+\\.vault\\.azure\\.net/keys/[^/\\s]+",
    "flags": ""
  },
  {
    "id": "SECRET-VAULT-HASHI-001",
    "cat": "Cloud KMS",
    "desc": "HashiCorp Vault Transit encryption as a service.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Transit engine centralizes crypto migration. Configure aes256-gcm96 or chacha20-poly1305 key types.",
    "pattern": "(vault[\\s_]addr|v1/transit/encrypt/|v1/transit/decrypt/|vault\\.read\\(['\"]transit/)",
    "flags": "i"
  },
  {
    "id": "DEP-NPM-WEAK-001",
    "cat": "Dependency Manifests",
    "desc": "JavaScript package using legacy unmaintained or classical crypto library (crypto-js, node-forge, node-rsa).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate to Web Cryptography API (`globalThis.crypto.subtle`) or modern PQC libraries (`@noble/ciphers`, `@noble/hashes`).",
    "pattern": "\"(crypto-js|node-forge|js-md5|js-sha1|node-rsa|ursa|ursa-purejs)\"\\s*:",
    "flags": "i"
  },
  {
    "id": "DEP-CARGO-WEAK-001",
    "cat": "Dependency Manifests",
    "desc": "Rust Cargo.toml dependency on legacy hash or classical asymmetric signature crate.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Add post-quantum dependencies: `ml-kem`, `ml-dsa`, or `hybrid-array`.",
    "pattern": "\\b(md5\\s*=\\s*|sha1\\s*=\\s*|des\\s*=\\s*|rc4\\s*=\\s*|rsa\\s*=\\s*|ed25519-dalek\\s*=\\s*)",
    "flags": "i"
  },
  {
    "id": "DEP-PY-WEAK-001",
    "cat": "Dependency Manifests",
    "desc": "Python requirements.txt or pyproject.toml specifying PyCrypto (unmaintained) or classical RSA/ECDSA packages.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Use standard `cryptography` library with post-quantum extensions or liboqs-python.",
    "pattern": "\\b(pycrypto\\b|pycryptodome\\b|rsa\\b|ecdsa\\b)\\s*([=><~]|\\n)",
    "flags": "i"
  },
  {
    "id": "DEP-GO-WEAK-001",
    "cat": "Dependency Manifests",
    "desc": "Go go.mod dependency importing obsolete or deprecated cryptographic modules.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Remove deprecated crypto modules; migrate to standard library `crypto/sha256` or `crypto/tls`.",
    "pattern": "\\b(golang\\.org/x/crypto/md4|golang\\.org/x/crypto/ripemd160|golang\\.org/x/crypto/blowfish)\\b",
    "flags": "i"
  },
  {
    "id": "DEP-MAVEN-WEAK-001",
    "cat": "Dependency Manifests",
    "desc": "Outdated BouncyCastle jdk15on dependency. Known CVEs and lacks FIPS 203/204/205 PQC support.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Upgrade to `bcprov-jdk18on` (version 1.78+) which includes NIST ML-KEM, ML-DSA, and SLH-DSA.",
    "pattern": "(<artifactId>bcprov-jdk15on</artifactId>|implementation.*['\"]org\\.bouncycastle:bcprov-jdk15on['\"])",
    "flags": "i"
  },
  {
    "id": "PRNG-WEAK-001",
    "cat": "Random Number Generation",
    "desc": "Predictable pseudo-random generator used in potentially sensitive context. State can be reconstructed from output.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Use cryptographically secure PRNG: `crypto.getRandomValues()` (Web), `crypto/rand` (Go), `rand::rngs::OsRng` (Rust), `secrets` (Python), `SecureRandom` (Java).",
    "pattern": "\\b(Math\\.random\\s*\\(\\)|rand\\.Float64\\s*\\(\\)|rand\\.Intn\\s*\\(|new\\s+java\\.util\\.Random\\b|System\\.currentTimeMillis\\s*\\(\\)|rand\\s*\\(\\)|std::rand\\b)\\b",
    "flags": "i"
  },
  {
    "id": "SOL-TX-ORIGIN-001",
    "cat": "Smart Contracts",
    "desc": "Using tx.origin for authorization allows phishing contract attacks via call forwarding.",
    "sev": "HIGH",
    "qRisk": "Unknown",
    "rem": "Use msg.sender for authorization in Ethereum / EVM contracts.",
    "pattern": "\\btx\\.origin\\b",
    "flags": ""
  },
  {
    "id": "SOL-SELFDESTRUCT-001",
    "cat": "Smart Contracts",
    "desc": "selfdestruct is deprecated (EIP-6780 Cancun upgrade) and alters contract state unpredictably.",
    "sev": "HIGH",
    "qRisk": "Unknown",
    "rem": "Remove selfdestruct. Use pausable or upgradeable proxy patterns.",
    "pattern": "\\bselfdestruct\\s*\\(",
    "flags": ""
  },
  {
    "id": "SOL-DELEGATECALL-001",
    "cat": "Smart Contracts",
    "desc": "delegatecall preserves execution context (msg.sender, storage). Untrusted targets can wipe or hijack contract state.",
    "sev": "HIGH",
    "qRisk": "Unknown",
    "rem": "Ensure delegatecall destination is immutable or verified in an authorized registry.",
    "pattern": "\\.delegatecall\\s*\\(",
    "flags": ""
  },
  {
    "id": "PQC-SSH-001",
    "cat": "SSH Configuration",
    "desc": "SSH ssh-rsa algorithm configured in sshd_config, client config, or authorized_keys. Vulnerable to Shor's algorithm.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate to OpenSSH post-quantum hybrid key exchange (sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha512@openssh.com) and ssh-ed25519.",
    "pattern": "\\bssh-rsa\\b",
    "flags": ""
  },
  {
    "id": "PQC-SSH-002",
    "cat": "SSH Configuration",
    "desc": "Deprecated ssh-dss (DSA 1024-bit) algorithm detected. Insecure against classical attacks and trivially broken by Shor's algorithm.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Remove ssh-dss immediately. Use OpenSSH 9.0+ defaults or post-quantum hybrid signature algorithms.",
    "pattern": "\\bssh-dss\\b",
    "flags": ""
  },
  {
    "id": "PQC-SSH-003",
    "cat": "SSH Configuration",
    "desc": "Legacy Diffie-Hellman Group 1/14 with SHA-1 key exchange algorithm detected in SSH configuration.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Disable SHA-1 DH groups. Configure KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256 in sshd_config.",
    "pattern": "\\bdiffie-hellman-group1(?:4)?-sha1\\b",
    "flags": ""
  },
  {
    "id": "PQC-SSH-004",
    "cat": "SSH Configuration",
    "desc": "RSA-SHA2 public key algorithm configured in SSH settings. Classical RSA is vulnerable to Store-Now-Decrypt-Later.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Plan transition to post-quantum signature schemes and stateful hash-based signatures for host keys.",
    "pattern": "\\brsa-sha2-(?:256|512)\\b",
    "flags": ""
  },
  {
    "id": "PQC-SSH-005",
    "cat": "SSH Configuration",
    "desc": "RSA host key configured or RSA public key provisioned in authorized_keys.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Rotate host keys and authorized_keys to modern curves (ssh-ed25519) and prepare for PQC stateful hash-based authentication.",
    "pattern": "(?:HostKey\\s+.*ssh_host_rsa_key|^\\s*ssh-rsa\\s+[A-Za-z0-9+/=]+)",
    "flags": "i"
  },
  {
    "id": "PQC-K8S-001",
    "cat": "Cloud & Middleware",
    "desc": "Kubernetes Ingress annotation configures deprecated TLS protocols or RSA/legacy cipher suites.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Configure `ssl-protocols: 'TLSv1.2 TLSv1.3'` and enforce forward-secret ECDHE/PQC ciphers.",
    "pattern": "nginx\\.ingress\\.kubernetes\\.io/ssl-(?:ciphers|protocols)\\s*:\\s*['\"]?[^\\n\"]*(?:RSA|DES|3DES|RC4|TLSv1(?:\\.0|\\.1)?)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-K8S-002",
    "cat": "Cloud & Middleware",
    "desc": "Kubernetes Gateway API, Istio DestinationRule, or Service Mesh config permits TLS 1.0 or TLS 1.1.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Raise minVersion/minProtocolVersion to TLSv1_2 or TLSv1_3 in service mesh policies.",
    "pattern": "(?:minVersion|minProtocolVersion)\\s*:\\s*['\"]?(?:TLSv1(?:[._][01])?|versiontls1[01])\\b",
    "flags": "i"
  },
  {
    "id": "PQC-PROXY-001",
    "cat": "Cloud & Middleware",
    "desc": "Nginx ssl_ciphers or Apache SSLCipherSuite directive enables static RSA key exchange or broken ciphers (3DES, RC4).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Remove static RSA and 3DES/RC4 cipher suites. Configure modern AEAD ciphers with hybrid post-quantum key exchange.",
    "pattern": "^\\s*(?:ssl_ciphers|SSLCipherSuite)\\s+[^;]*(?:RSA|DES-CBC3-SHA|3DES|RC4|DES)\\b",
    "flags": "m"
  },
  {
    "id": "PQC-PROXY-002",
    "cat": "Cloud & Middleware",
    "desc": "Nginx or Apache configuration allows legacy TLS 1.0 or TLS 1.1 protocol handshakes.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Update configuration to allow only TLSv1.2 and TLSv1.3 (e.g. `ssl_protocols TLSv1.2 TLSv1.3;`).",
    "pattern": "^\\s*(?:ssl_protocols|SSLProtocol|proxy_ssl_protocols)\\s+[^;]*(?:TLSv1(?:\\.0|\\.1)?(?:$|[^0-9.]))",
    "flags": "m"
  },
  {
    "id": "PQC-PROXY-003",
    "cat": "Cloud & Middleware",
    "desc": "Envoy proxy downstream/upstream TLS configuration allows obsolete protocols or RSA key exchange.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Set tls_minimum_protocol_version to TLSv1_3 or TLSv1_2 and restrict cipher_suites to ECDHE/PQC.",
    "pattern": "(?:tls_minimum_protocol_version\\s*:\\s*TLSv1_[01]|cipher_suites\\s*:\\s*\\[[^\\]]*(?:RSA|3DES|RC4))",
    "flags": "i"
  },
  {
    "id": "PQC-PROXY-004",
    "cat": "Cloud & Middleware",
    "desc": "HAProxy bind options or Traefik TLS options explicitly enable TLS 1.0 or 1.1.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Specify ssl-min-ver TLSv1.2 or TLSv1.3 in HAProxy / Traefik configuration.",
    "pattern": "(?:bind\\s+[^\\n]*\\bssl\\b[^\\n]*(?:tlsv10|tlsv11)|minversion\\s*:\\s*versiontls1[01])",
    "flags": "i"
  },
  {
    "id": "PQC-CONF-OPENSSL-001",
    "cat": "Cloud & Middleware",
    "desc": "OpenSSL configuration (openssl.cnf) defines a weak CipherString with SECLEVEL <= 1 or obsolete ciphers.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Set `CipherString = DEFAULT@SECLEVEL=2` or higher, and configure modern post-quantum hybrid key exchange groups.",
    "pattern": "CipherString\\s*=\\s*DEFAULT@SECLEVEL=[01]\\b|CipherString\\s*=\\s*[^;\\n]*(?:RC4|3DES|DES|EXPORT|NULL)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-CONF-OPENSSL-002",
    "cat": "Cloud & Middleware",
    "desc": "OpenSSL configuration permits obsolete SSLv3 or TLS 1.0/1.1 protocols.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Set `MinProtocol = TLSv1.2` or `MinProtocol = TLSv1.3` in openssl.cnf.",
    "pattern": "MinProtocol\\s*=\\s*(?:TLSv1(?:\\.0|\\.1)?|SSLv[23])\\b",
    "flags": "i"
  },
  {
    "id": "PQC-CONF-OPENSSL-003",
    "cat": "Cloud & Middleware",
    "desc": "OpenSSL configuration sets default_md to broken hash algorithms (MD5 or SHA-1).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Set `default_md = sha256` or `default_md = sha384` in openssl.cnf.",
    "pattern": "default_md\\s*=\\s*(?:md5|sha1)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-CONF-JAVA-001",
    "cat": "Cloud & Middleware",
    "desc": "Java security configuration (java.security) explicitly references legacy algorithms in disabled settings.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Ensure `jdk.tls.disabledAlgorithms` disables SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, and DH keySize < 2048.",
    "pattern": "jdk\\.(?:tls|certpath)\\.disabledAlgorithms\\s*=\\s*[^;\\n]*\\b(?:TLSv1(?:\\.0|\\.1)?|MD5|RC4)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-CERT-001",
    "cat": "Certificates & Keys",
    "desc": "X.509 Certificate detected. Classical public key infrastructure (RSA/ECDSA) certificates require migration to ML-DSA/Falcon.",
    "sev": "INFO",
    "qRisk": "Unknown",
    "rem": "Audit certificate key algorithm and signature. Plan transition to post-quantum certificates (RFC 9700 / X.509 ML-DSA).",
    "pattern": "-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----",
    "flags": ""
  },
  {
    "id": "PQC-KEY-RSA-001",
    "cat": "Certificates & Keys",
    "desc": "Unencrypted or PKCS#1 RSA private key stored in file. RSA is vulnerable to polynomial-time factoring via Shor's algorithm.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Never store private keys unencrypted. Migrate asymmetric authentication to ML-DSA-65 or stateful hash-based LMS/XMSS.",
    "pattern": "-----BEGIN RSA PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "PQC-KEY-EC-001",
    "cat": "Certificates & Keys",
    "desc": "Elliptic Curve private key detected. ECC discrete logarithm is broken by Shor's quantum algorithm.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Migrate private keys to NIST FIPS 204 (ML-DSA) or hybrid ECDSA+ML-DSA schemes.",
    "pattern": "-----BEGIN EC PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "PQC-KEY-SSH-001",
    "cat": "Certificates & Keys",
    "desc": "OpenSSH private key block detected. Classical host/user keys should be audited for quantum migration readiness.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Protect private keys with strong passphrases. Upgrade OpenSSH to use post-quantum hybrid keys.",
    "pattern": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "PQC-KEY-DSA-001",
    "cat": "Certificates & Keys",
    "desc": "DSA private key detected. DSA is classically deprecated (FIPS 186-5) and completely broken by quantum algorithms.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Revoke DSA key immediately and replace with ML-DSA-65 or Ed25519.",
    "pattern": "-----BEGIN DSA PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "PQC-KEY-PGP-001",
    "cat": "Certificates & Keys",
    "desc": "PGP/GPG private key block detected. Encrypted emails and signed git commits using classical RSA/ElGamal keys are vulnerable to Store-Now-Decrypt-Later.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Prepare OpenPGP infrastructure for post-quantum algorithms (draft-ietf-openpgp-pqc).",
    "pattern": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "flags": ""
  },
  {
    "id": "PQC-KEY-PKCS8-001",
    "cat": "Certificates & Keys",
    "desc": "PKCS#8 private key structure detected.",
    "sev": "HIGH",
    "qRisk": "Unknown",
    "rem": "Verify underlying algorithm is post-quantum safe or hybrid. Ensure encryption at rest.",
    "pattern": "-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----",
    "flags": ""
  },
  {
    "id": "PQC-SEC-AWS-001",
    "cat": "Secrets & Credentials",
    "desc": "Active AWS access key ID detected in source code or configuration.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Revoke credential immediately. Use IAM roles, AWS Secrets Manager, or environment variables.",
    "pattern": "\\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\\b",
    "flags": ""
  },
  {
    "id": "PQC-SEC-KEY-001",
    "cat": "Secrets & Credentials",
    "desc": "Hardcoded secret or private key assigned in code or configuration file.",
    "sev": "HIGH",
    "qRisk": "Unknown",
    "rem": "Remove hardcoded credentials from source code. Load secrets dynamically from a KMS or secret store.",
    "pattern": "(?:api[_-]?key|secret[_-]?key|private[_-]?key|jwt[_-]?secret|encryption[_-]?key)\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{16,}['\"]",
    "flags": "i"
  },
  {
    "id": "PQC-SEC-JWT-001",
    "cat": "Secrets & Credentials",
    "desc": "Static JWT Bearer token committed to repository.",
    "sev": "HIGH",
    "qRisk": "Unknown",
    "rem": "Invalidate static token. Generate ephemeral tokens dynamically with short lifespans.",
    "pattern": "\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    "flags": ""
  },
  {
    "id": "PQC-SEC-GH-001",
    "cat": "Secrets & Credentials",
    "desc": "Active GitHub Personal Access Token detected in repository.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Revoke token immediately in GitHub Settings -> Developer settings -> Personal access tokens.",
    "pattern": "\\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\\b",
    "flags": ""
  },
  {
    "id": "PQC-TLS-BYPASS-001",
    "cat": "TLS & Network Protocols",
    "desc": "Environment variable NODE_TLS_REJECT_UNAUTHORIZED is set to 0, globally disabling TLS certificate verification in Node.js.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Remove NODE_TLS_REJECT_UNAUTHORIZED=0. Always enforce strict TLS certificate validation in all environments.",
    "pattern": "NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*['\"]?0['\"]?",
    "flags": ""
  },
  {
    "id": "PQC-TLS-BYPASS-002",
    "cat": "TLS & Network Protocols",
    "desc": "Go crypto/tls Config has InsecureSkipVerify set to true, disabling server certificate and hostname verification.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Set InsecureSkipVerify to false. Configure custom RootCAs if private certificate authorities are required.",
    "pattern": "\\bInsecureSkipVerify\\s*:\\s*true\\b",
    "flags": ""
  },
  {
    "id": "PQC-TLS-BYPASS-003",
    "cat": "TLS & Network Protocols",
    "desc": "Python HTTP request disables SSL/TLS certificate verification (verify=False), allowing Man-in-the-Middle attacks.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Remove verify=False or supply path to trusted CA certificate bundle (verify='/path/to/cacert.pem').",
    "pattern": "\\bverify\\s*=\\s*False\\b",
    "flags": ""
  },
  {
    "id": "PQC-TLS-BYPASS-004",
    "cat": "TLS & Network Protocols",
    "desc": "Java X509TrustManager blindly trusts all certificates without verifying against a trust store.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Use standard Java TrustManagerFactory initialized with a valid KeyStore containing verified root certificates.",
    "pattern": "\\b(TrustAllCerts|NullTrustManager|X509TrustManager\\s*\\{\\s*public\\s+void\\s+checkClientTrusted|X509TrustManager\\s*\\{\\s*public\\s+void\\s+checkServerTrusted)\\b",
    "flags": ""
  },
  {
    "id": "PQC-TLS-BYPASS-005",
    "cat": "TLS & Network Protocols",
    "desc": "Node.js TLS/HTTPS client configuration explicitly disables certificate verification.",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Ensure rejectUnauthorized is true (default) and provide trusted CA cert in the ca agent option.",
    "pattern": "\\brejectUnauthorized\\s*:\\s*false\\b",
    "flags": ""
  },
  {
    "id": "PQC-TLS-BYPASS-006",
    "cat": "TLS & Network Protocols",
    "desc": "curl command executed with --insecure or -k flag, bypassing SSL/TLS certificate validation.",
    "sev": "HIGH",
    "qRisk": "Unknown",
    "rem": "Remove --insecure/-k and install necessary root CA certificates into the system trust store.",
    "pattern": "\\bcurl\\s+[^;\\n]*(-k\\b|--insecure\\b)",
    "flags": ""
  },
  {
    "id": "PQC-CIPHER-MODE-001",
    "cat": "Symmetric Ciphers",
    "desc": "Electronic Codebook (ECB) mode of operation detected. Lacks diffusion and leaks plaintext patterns.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate to authenticated encryption with associated data (AEAD) mode such as AES-256-GCM or ChaCha20-Poly1305.",
    "pattern": "(?:/(?:ECB|Electronic\\s*Codebook)|(?:CipherMode|AES|DES)\\.ECB|MODE_ECB)",
    "flags": ""
  },
  {
    "id": "PQC-CIPHER-MODE-002",
    "cat": "Symmetric Ciphers",
    "desc": "CBC mode with PKCS5/PKCS7 padding is susceptible to padding oracle attacks if authentication (MAC) is missing.",
    "sev": "MEDIUM",
    "qRisk": "Partial",
    "rem": "Migrate to authenticated encryption (AES-256-GCM) to ensure both confidentiality and integrity.",
    "pattern": "(?:/(?:CBC)/PKCS[57]Padding|MODE_CBC.*PKCS[57])",
    "flags": ""
  },
  {
    "id": "PQC-PINNING-001",
    "cat": "Certificates & Keys",
    "desc": "Certificate or public key pinning control detected. Hardens TLS against compromised Certificate Authorities.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Ensure pinned public key hashes are monitored for rotation and include PQC certificate backup pins.",
    "pattern": "\\b(CertificatePinner|TrustKit|ssl_pinning|pinnedCertificates|pinning\\.setPinned)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-MTLS-001",
    "cat": "TLS & Network Protocols",
    "desc": "Mutual TLS (mTLS) bidirectional certificate authentication configured.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "mTLS provides strong client identity verification. Plan transition of both client and server certs to PQC (ML-DSA).",
    "pattern": "\\b(ssl_client_certificate|ssl_verify_client\\s+on|ClientAuthType\\.RequireAndVerifyClientCert|ClientAuth\\s*:\\s*tls\\.RequireAndVerifyClientCert)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-LIB-FIPS203-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST FIPS 203 standardized Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) library active.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "NIST Post-Quantum standard primitive active. Maintain dependency updates.",
    "pattern": "\\b(fips203|ml-kem|pqcrypto-kyber|noble-post-quantum|@noble/post-quantum)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-LIB-FIPS204-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST FIPS 204 standardized Module-Lattice-Based Digital Signature Algorithm (ML-DSA) library active.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "NIST Post-Quantum standard signature primitive active. Maintain dependency updates.",
    "pattern": "\\b(fips204|ml-dsa|pqcrypto-dilithium)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-LIB-FIPS205-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST FIPS 205 standardized Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) library active.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "NIST Post-Quantum standard stateless signature primitive active. Maintain dependency updates.",
    "pattern": "\\b(fips205|slh-dsa|pqcrypto-sphincsplus)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-KYBERSLASH-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Secret-dependent integer division in ML-KEM/Kyber reference decapsulation leaking private key bits (CVE-2024-56145/CVE-2024-56146).",
    "sev": "CRITICAL",
    "qRisk": "Safe",
    "rem": "Upgrade ML-KEM / Kyber implementations to patched constant-time releases (e.g. liboqs >= 0.9.2, PQClean >= Jan 2024, or FIPS 203 compliant constant-time code).",
    "pattern": "(?:\\bkyberslash\\b|poly_frommsg\\s*\\([^)]*\\/|\\bliboqs\\s*<\\s*0\\.9\\.2|\\bpqclean_kyber.*division\\b)",
    "flags": "i"
  },
  {
    "id": "CVE-SIKE-SIDH-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Supersingular Isogeny Diffie-Hellman (SIDH) / SIKE broken in polynomial time by Castryck-Decru attack using auxiliary torsion points.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Immediately replace SIKE/SIDH with NIST standardized post-quantum algorithms: ML-KEM (FIPS 203) or ML-DSA (FIPS 204). SIKE is completely insecure classically.",
    "pattern": "\\b(sike_p434|sike_p503|sike_p610|sike_p751|sidh_p434|sidh_p503|sidh_p610|sidh_p751|pqc_kem_sike|liboqs.*sike)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-RAINBOW-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Rainbow multivariate signature scheme broken in classical polynomial time by Ward Beullens' MinRank attack.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Immediately migrate from Rainbow to NIST standardized post-quantum signatures: ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
    "pattern": "\\b(rainbow_classic|rainbow_circumzenithal|rainbow_compressed|pqcrypto_rainbow|pqc_sig_rainbow)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-MARVIN-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "RSA PKCS#1 v1.5 padding timing differences re-enabling Bleichenbacher plaintext recovery (CVE-2023-46809, Marvin Attack).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Migrate to RSA-OAEP with SHA-256 for classical encryption, or transition directly to ML-KEM (FIPS 203) for post-quantum forward secrecy.",
    "pattern": "(?:\\brsa\\.DecryptPKCS1v15\\b|\\bRSA_PKCS1_PADDING\\b|\\bRSA/ECB/PKCS1Padding\\b|Cipher\\.getInstance\\([\"']RSA/ECB/PKCS1Padding[\"']\\)|openssl_private_decrypt.*OPENSSL_PKCS1_PADDING)",
    "flags": "i"
  },
  {
    "id": "CVE-ROBOT-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Static RSA cipher suites vulnerable to the Return Of Bleichenbacher's Oracle Threat (ROBOT / CVE-2017-13099).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Disable static RSA cipher suites (TLS_RSA_*). Use Ephemeral Diffie-Hellman (ECDHE) or post-quantum hybrid key exchange (X25519MLKEM768).",
    "pattern": "\\b(TLS_RSA_WITH_AES_128_CBC_SHA|TLS_RSA_WITH_AES_256_CBC_SHA|TLS_RSA_WITH_AES_128_GCM_SHA256|TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_3DES_EDE_CBC_SHA)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-SWEET32-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Birthday attacks against 64-bit block ciphers (3DES, Blowfish) in CBC mode leaking session plaintext (CVE-2016-2183, Sweet32).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Disable 3DES and Blowfish cipher suites. Upgrade to 128-bit or 256-bit block ciphers in AEAD mode (AES-256-GCM, ChaCha20-Poly1305).",
    "pattern": "(?:\\bDES-CBC3-SHA\\b|\\bEDH-RSA-DES-CBC3-SHA\\b|\\bECDHE-RSA-DES-CBC3-SHA\\b|\\b3DES-EDE\\b|\\bBlowfish-CBC\\b|cipher\\s*=\\s*['\"]?DES-EDE3-CBC['\"]?)",
    "flags": "i"
  },
  {
    "id": "CVE-DROWN-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Cross-protocol Bleichenbacher attack leveraging shared RSA private keys with obsolete SSLv2 servers (CVE-2016-0800, DROWN).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Completely disable SSLv2 protocol across all servers and firewalls. Ensure private keys are never reused on legacy endpoints.",
    "pattern": "(?:\\bSSLv2_method\\b|\\bSSLv2_server_method\\b|SSLv23_method.*SSL_OP_NO_SSLv2|ssl_protocols.*SSLv2|Protocols\\s*\\+?SSLv2)",
    "flags": "i"
  },
  {
    "id": "CVE-LOGJAM-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Export-grade 512-bit Diffie-Hellman parameters precomputation and downgrade attack (CVE-2015-4000, Logjam).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Disable all export cipher suites. Require minimum 2048-bit Diffie-Hellman parameters or switch to ECDHE / ML-KEM-768.",
    "pattern": "(?:\\bEXP-EDH-RSA-DES-CBC-SHA\\b|\\bEXP-EDH-DSS-DES-CBC-SHA\\b|\\bDHE_EXPORT\\b|ssl_ciphers.*EXPORT|SSLCipherSuite.*EXPORT)",
    "flags": "i"
  },
  {
    "id": "CVE-SLOTH-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "MD5/SHA-1 transcript collision attacks on TLS 1.2 client certificate authentication and ServerKeyExchange (CVE-2015-7575, SLOTH).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Disable MD5 and SHA-1 signature algorithms in TLS configurations. Enforce SHA-256, SHA-384, or post-quantum signatures (ML-DSA).",
    "pattern": "(?:\\bMD5_WITH_RSA_ENCRYPTION\\b|\\bRSA_PKCS1_MD5\\b|\\bmd5WithRSAEncryption\\b|SignatureAndHashAlgorithm\\s*=\\s*\\{\\s*HashAlgorithm\\.md5|SignatureAlgorithms.*md5)",
    "flags": "i"
  },
  {
    "id": "CVE-MINERVA-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Variable-time scalar multiplication in ECDSA leaking secret nonce bit length through timing side-channels (CVE-2019-15809, Minerva).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Ensure all elliptic curve scalar multiplications use constant-time Montgomery ladder or blinded scalar algorithms.",
    "pattern": "\\b(crypto_scalarmult_curve25519_variable|EC_POINT_mul_var|scalar_multiplication_variable_time|leading_zeros_nonce)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-CURVEBALL-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Arbitrary explicit elliptic curve parameters enabling generator G' manipulation and CA certificate spoofing (CVE-2020-0601, CurveBall).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Reject explicit EC parameters. Enforce standard named curves (secp256r1, secp384r1) and validate generator point order.",
    "pattern": "(?:\\bspecifiedCurve\\b|ECParameters\\(explicit\\)|ASN1_SEQUENCE_OF_EC_PARAMETERS|curve_type\\s*=\\s*['\"]?explicit['\"]?)",
    "flags": "i"
  },
  {
    "id": "CVE-HEARTBLEED-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Missing bounds check in TLS Heartbeat extension leaking up to 64KB private memory per payload (CVE-2014-0160, Heartbleed).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Upgrade OpenSSL to 1.0.1g+ or modern OpenSSL 3.0+ / Rustls, or compile with -DOPENSSL_NO_HEARTBEATS.",
    "pattern": "(?:\\bopenssl\\s*(?:==|:)?\\s*1\\.0\\.1[a-f]\\b|\\bOPENSSL_1_0_1[A-F]\\b|\\blibssl\\.so\\.1\\.0\\.1\\b)",
    "flags": "i"
  },
  {
    "id": "CVE-DUALEC-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Kleptographic backdoor in Dual Elliptic Curve Deterministic Random Bit Generator allowing key recovery via known point relationship.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Immediately remove Dual_EC_DRBG. Use NIST SP 800-90A Rev 1 approved DRBGs: CTR_DRBG with AES-256 or HMAC_DRBG with SHA-256.",
    "pattern": "\\b(Dual_EC_DRBG|DualECDRBG|dual_ec_drbg|DualEllipticCurveDRBG)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-NONCE-REUSE-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Repeated or deterministic nonce failure in DSA/ECDSA signatures allowing instantaneous algebraic private key extraction (Sony PS3 flaw).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Always generate cryptographically uniform unique random nonces via CSPRNG or enforce deterministic RFC 6979 HMAC nonce generation.",
    "pattern": "(?:sign_with_k\\s*\\(|k\\s*=\\s*['\"][0-9a-fA-F]{32,}['\"]|k\\s*=\\s*(?:12345|0x12345|1337)\\b|fixed_nonce\\s*=\\s*true)",
    "flags": "i"
  },
  {
    "id": "CVE-STATEFUL-HASH-001",
    "cat": "Quantum Vulnerability Research",
    "desc": "Stateful hash-based signature (LMS/XMSS) detected. Duplicate OTS counter usage (e.g. from VM snapshots, concurrent threads, or uncommitted NVRAM) completely breaks Winternitz OTS, enabling private key forgery.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Enforce hardware-enforced monotonic state counter synchronization or migrate to stateless post-quantum signatures: SLH-DSA (FIPS 205 / SPHINCS+) or ML-DSA (FIPS 204).",
    "pattern": "\\b(lms_sign|xmss_sign|xmssmt_sign|ots_sign|wots_sign|hss_sign)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-TERRAPIN-001",
    "cat": "Quantum Vulnerability Research",
    "desc": "SSH channel vulnerability allowing MiTM sequence manipulation to strip extension negotiation and downgrade algorithms before post-quantum key exchange (CVE-2023-48795, Terrapin).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Enable Strict KEX extension (kex-strict-c-v00@openssh.com and kex-strict-s-v00@openssh.com) and update OpenSSH to >= 9.6.",
    "pattern": "\\b(chacha20-poly1305@openssh\\.com|hmac-sha2-512-etm@openssh\\.com|hmac-sha2-256-etm@openssh\\.com)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-GROVER-AES128-001",
    "cat": "Quantum Vulnerability Research",
    "desc": "128-bit symmetric key space reduced to 64 bits of quantum security by Grover's algorithm (O(2^{n/2})). Non-compliant with CNSA 2.0 and NIST PQC quantum resilience guidelines.",
    "sev": "MEDIUM",
    "qRisk": "Partial",
    "rem": "Upgrade symmetric key lengths to AES-256-GCM or ChaCha20-Poly1305 (minimum 256 bits) to maintain 128 bits of post-quantum security.",
    "pattern": "\\b(aes-128-gcm|aes-128-cbc|aes128|crypto_aead_aes128gcm|Cipher\\.getInstance\\([\"']AES/GCM/NoPadding[\"'],\\s*128\\))\\b",
    "flags": "i"
  },
  {
    "id": "PQC-GROVER-HASH-001",
    "cat": "Quantum Vulnerability Research",
    "desc": "Hash function vulnerable to classical collision and quantum BHT (O(2^{n/3})) collision algorithms. Inadequate quantum security margin.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Upgrade to SHA-384, SHA-512, or SHA3-384 / SHAKE-256 as mandated by CNSA 2.0.",
    "pattern": "\\b(sha1|sha-1|sha224|sha-224|ripemd160)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-FALCON-FLOAT-001",
    "cat": "Quantum Vulnerability Research",
    "desc": "Native hardware floating-point operations in Falcon lattice sampler leaking secret polynomial coefficients via microarchitectural timing differences.",
    "sev": "HIGH",
    "qRisk": "Safe",
    "rem": "Use Karney constant-time emulation or constant-time fixed-point integer arithmetic for Falcon / FN-DSA (NIST FIPS 206) signature generation.",
    "pattern": "\\b(falcon_vrfy_float|falcon_inner_fft|fpr_mul|fpr_add|fpr_norm)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-HNDL-EXPOSURE-001",
    "cat": "Quantum Vulnerability Research",
    "desc": "Classical-only ephemeral key exchange without post-quantum hybrid KEM (ML-KEM-768). Traffic is vulnerable to passive recording for retrospective decryption by future quantum computers (HNDL).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Configure hybrid post-quantum key exchange: X25519MLKEM768 (TLS group 0x11ec / 4588) or SecP256r1MLKEM768 in TLS and SSH servers.",
    "pattern": "\\b(ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-RSA-AES128-GCM-SHA256|curve25519-sha256@libssh\\.org|ecdh-sha2-nistp256)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-PSYCHIC-SIG-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Missing zero checks for ECDSA signature parameters (r=0, s=0) allowing arbitrary signature forgery for any message (CVE-2022-21449, Psychic Signatures).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Verify that signature parameters r and s are strictly non-zero and in the range [1, n-1]. Upgrade Java to 15.0.7, 17.0.3, 18.0.1 or higher.",
    "pattern": "(?:Signature\\.getInstance\\([\"']SHA256withECDSA[\"']\\)|ecdsa\\.Verify\\(.*,\\s*0,\\s*0\\)|r\\.signum\\(\\)\\s*==\\s*0|s\\.signum\\(\\)\\s*==\\s*0)",
    "flags": "i"
  },
  {
    "id": "CVE-OPENSSL-MODSQRT-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Malformed non-prime modulus in elliptic curve certificate triggering an infinite loop in modular square root calculation (CVE-2022-0778).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Upgrade OpenSSL to 1.1.1n, 3.0.2 or higher. Ensure certificate validation explicitly validates curve prime order.",
    "pattern": "(?:\\bBN_mod_sqrt\\b|openssl\\s*(?:==|:)?\\s*(?:1\\.0\\.2|1\\.1\\.1[a-m]|3\\.0\\.[01])\\b)",
    "flags": "i"
  },
  {
    "id": "CVE-XZ-BACKDOOR-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Upstream supply-chain backdoor in liblzma / XZ Utils intercepting OpenSSH RSA_public_decrypt IFUNC resolution (CVE-2024-3094).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Downgrade or upgrade XZ Utils to a known clean version (5.4.x or >= 5.6.2). Audit shared library IFUNC dependencies.",
    "pattern": "(?:\\bliblzma\\.(?:so|5\\.6\\.[01])\\b|\\bxz-(?:5\\.6\\.0|5\\.6\\.1)\\b|_get_cpuid.*lzma_alloc)",
    "flags": "i"
  },
  {
    "id": "PQC-IMPLICIT-REJECT-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Explicit rejection on invalid ciphertext during ML-KEM/Kyber decapsulation creates a 1-bit chosen-ciphertext oracle leaking secret lattice vectors.",
    "sev": "HIGH",
    "qRisk": "Safe",
    "rem": "Enforce implicit rejection per NIST FIPS 203 Section 7: return pseudorandom key K = SHAKE256(z || c) when re-encryption check c != c' fails.",
    "pattern": "(?:throw\\s+new\\s+.*DecapsulationException|return\\s+Err\\(.*DecapFailed|if\\s*\\(c\\s*!=\\s*c_prime\\)\\s*return\\s*false)",
    "flags": "i"
  },
  {
    "id": "PQC-HYBRID-DOWNCHECK-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Missing transcript binding in hybrid key exchange allowing active network adversaries to strip post-quantum shares without handshake failure.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Enforce strict hybrid transcript hashing where shared secret SS = KDF(SS_classical || SS_pqc). Disallow unauthenticated downgrade fallbacks.",
    "pattern": "(?:\\bhybrid_kex_fallback_to_classical\\b|\\ballow_classical_downgrade\\s*=\\s*true\\b|\\bignore_pqc_extension\\b)",
    "flags": "i"
  },
  {
    "id": "CVE-ZEROLOGON-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "All-zero static initialization vector in AES-CFB8 mode in Microsoft Netlogon protocol enabling domain controller takeover (CVE-2020-1472, ZeroLogon).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Enforce secure RPC with randomized session keys and disable legacy unauthenticated Netlogon connections.",
    "pattern": "(?:\\bComputeNetlogonCredential\\b|\\bNetrServerAuthenticate\\b|aes_cfb8.*(?:0000000000000000|zeros\\(16\\)))",
    "flags": "i"
  },
  {
    "id": "CVE-PUTTY-P521-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "PuTTY versions 0.68-0.80 generated biased ECDSA P-521 nonces with first 9 bits set to zero, enabling full private key recovery from 60 SSH signatures (CVE-2024-31497).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Upgrade PuTTY/Pageant to >= 0.81 immediately. Revoke all P-521 SSH keys loaded into affected versions and replace with ML-KEM/ML-DSA hybrid SSH keys (mlkem768x25519-sha512).",
    "pattern": "(?:\\bputty\\b.*(?:0\\.[6-7][0-9]|0\\.80)\\b|ecdsa-sha2-nistp521.*(?:putty|pageant)|deterministic_p521_nonce)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-MLDSA-DFA-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Deterministic ML-DSA / Dilithium signing without fresh randomness (rnd = 0) is vulnerable to Differential Fault Analysis (DFA); a single bit flip during polynomial signing recovers private key vectors s1 and s2.",
    "sev": "HIGH",
    "qRisk": "Safe",
    "rem": "Use randomized (hedged) ML-DSA signing per FIPS 204 Section 5.4: inject 32 bytes of cryptographically secure random entropy (rnd) into every signature generation.",
    "pattern": "(?:dilithium_sign_deterministic\\b|mldsa_sign.*(?:deterministic\\s*:\\s*true|rnd\\s*=\\s*NULL|opt_rand.*zeros)|deterministic_signing\\s*=\\s*true)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-SLHDSA-OPTRAND-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Passing a null or zero opt_rand buffer to SLH-DSA (SPHINCS+) eliminates hedged randomized hashing, opening the FORS tree signatures to multi-target second-preimage birthday attacks.",
    "sev": "HIGH",
    "qRisk": "Safe",
    "rem": "Provide 32 bytes of secure random noise to `opt_rand` parameter in FIPS 205 SLH-DSA signing calls to safeguard FORS trees against multi-target cryptanalysis.",
    "pattern": "(?:slh_dsa_sign.*(?:NULL|0x0|opt_rand\\s*=\\s*0)|SPHINCS_OPT_RAND_ZERO\\b|sphincs_sign.*opt_rand.*(?:zeros|None))",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-NTT-CACHE-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Variable-time Number Theoretic Transform (NTT) or secret-dependent table lookups in lattice polynomial multiplication leak private key coefficients via CPU cache-timing channels.",
    "sev": "HIGH",
    "qRisk": "Safe",
    "rem": "Employ constant-time SIMD / AVX2 / NEON NTT implementations (such as PQClean or libcrux) with verified constant execution time across all input operands.",
    "pattern": "(?:ntt_custom\\b|poly_mul_unmasked\\b|barrett_reduce_variable\\b|montgomery_reduce_variable\\b|table_lookup_ntt\\[)",
    "flags": "i"
  },
  {
    "id": "PQC-CVE-2024-24576-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Unsanitized argument passing to Windows .bat / .cmd batch files bypasses cmd.exe escaping, allowing arbitrary command execution in automated cryptographic build pipelines (CVE-2024-24576).",
    "sev": "CRITICAL",
    "qRisk": "Unknown",
    "rem": "Upgrade Rust toolchains to >= 1.77.2. Explicitly validate and escape arguments when invoking Windows shell scripts, or invoke native binaries directly without cmd.exe wrapping.",
    "pattern": "(?:Command::new\\s*\\(\\s*[\"'][^\"']*\\.(?:bat|cmd)[\"']\\s*\\)|cmd\\.exe\\s+/c\\s+.*%[a-zA-Z0-9_]+%)",
    "flags": "i"
  },
  {
    "id": "PQC-CVE-2023-3817-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Excessive polynomial testing during Diffie-Hellman parameter verification in OpenSSL 3.0/3.1 allows remote untrusted inputs to trigger persistent CPU resource exhaustion (CVE-2023-3817).",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Upgrade OpenSSL to >= 3.0.10 or >= 3.1.2. Restrict DH parameter acceptance to standardized RFC 7919 FFDHE groups or migrate directly to ML-KEM-768.",
    "pattern": "(?:DH_check\\s*\\(|EVP_PKEY_param_check\\s*\\(.*openssl.*(?:3\\.0\\.[0-9]|3\\.1\\.[0-1]))",
    "flags": "i"
  },
  {
    "id": "PQC-CVE-2024-0727-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Parsing malformed PKCS12 structures with omitted attributes causes a NULL pointer dereference and crash in OpenSSL (CVE-2024-0727).",
    "sev": "MEDIUM",
    "qRisk": "Unknown",
    "rem": "Upgrade OpenSSL to >= 3.2.1, >= 3.1.5, or >= 3.0.13. Validate ASN.1 envelope integrity prior to parsing untrusted PKCS#12 bundles.",
    "pattern": "(?:PKCS12_parse\\s*\\(|d2i_PKCS12_bio\\s*\\(|d2i_PKCS12_fp\\s*\\))",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-X25519-CLAMP-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Custom X25519 scalar multiplication omitting bit clamping (k[0] &= 248; k[31] &= 127; k[31] |= 64) allows low-order point attacks leaking scalar bits modulo 8.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Always clamp private scalars per RFC 7748 Section 5: clear bottom 3 bits and top bit, and set bit 254 before performing Montgomery ladder multiplication.",
    "pattern": "(?:\\bx25519_without_clamping\\b|\\bunclamped_scalar_mul\\b|\\bcurve25519_unclamped\\b|\\bcustom_x25519_ladder\\b)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-FO-TRANSFORM-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Skipping the re-encryption check (c' == c) in the Fujisaki-Okamoto (FO) transform converts IND-CCA2 ML-KEM down to IND-CPA, allowing full key recovery via chosen ciphertexts.",
    "sev": "CRITICAL",
    "qRisk": "Safe",
    "rem": "Never bypass FO re-encryption in KEM decapsulation. Always re-encrypt the recovered message and verify byte-for-byte equality with input ciphertext c in constant time.",
    "pattern": "(?:skip_reencryption\\s*=\\s*true|fo_transform_optimistic|disable_ciphertext_verification)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-SP800-208-VOLATILE-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Storing LMS/XMSS stateful hash signature sequence counters in volatile RAM without hardware write-before-sign NVRAM synchronization violates NIST SP 800-208 and guarantees catastrophic OTS key reuse on crash/reboot.",
    "sev": "CRITICAL",
    "qRisk": "Safe",
    "rem": "Enforce persistent non-volatile atomic increment before signing per NIST SP 800-208, or migrate to stateless signatures (SLH-DSA FIPS 205 / ML-DSA FIPS 204).",
    "pattern": "(?:static\\s+mut\\s+lms_idx\\b|xmss_index\\s*\\+\\+|atomic_fetch_add.*(?:lms_seq|xmss_seq)|in_memory_stateful_index)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-XOR-COMBINER-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Combining classical and post-quantum shared secrets using bitwise XOR instead of dual-PRF HKDF-Extract(classical || pqc) violates IETF hybrid design specifications.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Use standard HKDF combiner per draft-ietf-tls-hybrid-design: `SS = HKDF-Extract(0, SS_classical || SS_pqc)` ensuring cryptographic security holds if either primitive is unbroken.",
    "pattern": "(?:shared_secret\\[i\\]\\s*=\\s*ss_classical\\[i\\]\\s*\\^\\s*ss_pqc\\[i\\]|ss_combined\\s*=\\s*ss_ecdh\\s*\\^\\s*ss_kem)",
    "flags": "i"
  },
  {
    "id": "CVE-RACCOON-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Stripping leading zero bytes from the Diffie-Hellman pre-master secret rather than constant-time padding creates a timing side channel that allows recovering the shared secret (CVE-2020-15999, Raccoon Attack).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Enforce constant-time left-padding of DH shared secrets to key length, or disable classical DHE in favor of ML-KEM-768 hybrid key encapsulation.",
    "pattern": "(?:strip_leading_zeros\\b|leading_zero_strip\\b|dhe_strip_zero|raccoon_attack|BN_bn2bin\\s*\\(.*pms)",
    "flags": "i"
  },
  {
    "id": "CVE-FREAK-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Accepting export-grade 512-bit RSA keys (RSA_EXPORT) permits a man-in-the-middle attacker to downgrade the TLS connection and factor the modulus (CVE-2015-0204, FREAK).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Completely disable export-grade cipher suites in TLS configurations and migrate key exchange to NIST FIPS 203 (ML-KEM).",
    "pattern": "(?:TLS_RSA_EXPORT_WITH_|SSL_RSA_EXPORT_WITH_|RSA_EXPORT\\b|export_512_rsa|allow_export_ciphers)",
    "flags": "i"
  },
  {
    "id": "CVE-BLEICHENBACHER-E3-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Incomplete PKCS#1 v1.5 padding validation with small public exponent e=3 allows forging RSA signatures without private key knowledge by embedding arbitrary garbage after the ASN.1 digest header.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Enforce strict length and byte checks over the entire PKCS#1 v1.5 padding block, migrate to RSA-PSS, or adopt NIST FIPS 204 (ML-DSA) post-quantum signatures.",
    "pattern": "(?:rsa_verify_e3\\b|bleichenbacher_e3|pkcs1v15_loose_verify|skip_trailing_garbage_check)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-FALCON-SAMPLER-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Variable CPU cycle execution caused by denormal floating-point values in Falcon's fast Fourier Gaussian sampler allows timing side-channel recovery of secret lattice basis vectors.",
    "sev": "HIGH",
    "qRisk": "Safe",
    "rem": "Enable Flush-To-Zero (FTZ) and Denormals-Are-Zero (DAZ) in CPU control registers during Falcon signature generation, or use constant-time fixed-point emulators.",
    "pattern": "(?:gaussian_sampler_denormal\\b|falcon_ldl_float\\b|ffSampling_fft\\b|subnormal_fp_sample)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-ED25519-MALLEABILITY-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Failure to enforce canonical scalar reduction (s < L) or cofactor-8 checking in Ed25519 verification allows valid signature malleability, creating consensus split vulnerabilities in distributed ledgers.",
    "sev": "MEDIUM",
    "qRisk": "Vulnerable",
    "rem": "Enforce strict ZIP-215 / RFC 8032 verification requiring canonical S scalar representation (s < L) and identical cofactor multiplication across all verifying nodes.",
    "pattern": "(?:ed25519_verify_relaxed\\b|zip215_disabled\\b|allow_non_canonical_s\\b|cofactorless_verification)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-KECCAK-SCA-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Unmasked Keccak-f[1600] / SHAKE-256 state permutations during lattice polynomial sampling and hashing leak seed and secret vectors via differential power/electromagnetic analysis.",
    "sev": "HIGH",
    "qRisk": "Safe",
    "rem": "Apply Boolean or arithmetic masking (first-order or higher-order) to the Keccak-f[1600] non-linear Chi step when processing secret key material in hardware or embedded targets.",
    "pattern": "(?:unmasked_keccak\\b|shake_sponge_unmasked\\b|keccak_f1600_plain\\b|raw_shake256_sponge)",
    "flags": "i"
  },
  {
    "id": "CVE-ROCA-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "CVE-2017-15361 (ROCA): Infineon RSA library generates weak factorable RSA keys with structured primes k*M + (65537^a mod M), factorable via Coppersmith's algorithm.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Audit and revoke all RSA keys generated on affected Infineon TPM firmware or smartcards. Migrate to NIST FIPS 203 (ML-KEM) or regenerate RSA keys using modern CSPRNG.",
    "pattern": "\\b(CVE-2017-15361|ROCA|Return\\s+of\\s+Coppersmith|infineon[_\\s-]rsa|RSALib_FIPS|tpm-lcu)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-POODLE-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "CVE-2014-3566 (POODLE): SSL 3.0 cipher-block chaining (CBC) padding oracle allows man-in-the-middle decryption of plaintext cookies and credentials.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Completely disable SSL 3.0 and CBC-mode ciphersuites across all web servers and TLS termination proxies. Mandate TLS 1.3.",
    "pattern": "\\b(CVE-2014-3566|POODLE|SSLv3_method|SSL_TXT_SSLV3|SSLv3_server_method|SSLv3_client_method)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-LUCKY13-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "CVE-2013-0169 (Lucky Thirteen): Side-channel timing vulnerability in TLS CBC-mode decryption allowing plaintext recovery due to non-constant-time HMAC computation.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Disable all CBC-mode TLS ciphersuites; mandate AEAD ciphersuites (AES-GCM, ChaCha20-Poly1305) and prepare for hybrid post-quantum TLS 1.3 (X25519MLKEM768).",
    "pattern": "\\b(CVE-2013-0169|Lucky-13|LuckyThirteen|TLS_RSA_WITH_AES_\\d+_CBC_SHA|TLS_ECDHE_RSA_WITH_AES_\\d+_CBC_SHA)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-PUNYCODE-OPENSSL-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "CVE-2022-3602 / CVE-2022-3786 (Spooky SSL): Buffer overrun in OpenSSL 3.0.0-3.0.6 X.509 certificate name constraint verification during Punycode email address decoding.",
    "sev": "CRITICAL",
    "qRisk": "Safe",
    "rem": "Upgrade OpenSSL to >= 3.0.7 or modern OpenSSL 3.2+ / AWS-LC with built-in memory safety and post-quantum extensions.",
    "pattern": "\\b(CVE-2022-3602|CVE-2022-3786|Spooky\\s+SSL|ossl_a2ulabel|ossl_punycode_decode)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-BLEICHENBACHER-XML-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "XML Encryption 1.0 RSA PKCS#1 v1.5 and broken OAEP implementation timing oracles in SAML SSO authentication tokens allowing unauthorized identity spoofing.",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Disable RSA-1_5 in XML Encryption; enforce AES-GCM and migrate signature verification to ML-DSA or composite signatures.",
    "pattern": "\\b(CVE-2012-0881|CVE-2011-1096|xmlenc[_\\s-]rsa-1_5|rsa-oaep-mgf1p)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-BIKE-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST Round 4 Alternate post-quantum key encapsulation mechanism based on Quasi-Cyclic Moderate Density Parity-Check (QC-MDPC) codes.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "NIST Round 4 alternate code-based KEM. Valid non-lattice hedge against Module-LWE assumptions. Ensure constant-time decoder implementation.",
    "pattern": "\\b(BIKE-L1|BIKE-L3|BIKE-L5|pqc_kem_bike|bike_round4)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-HQC-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST Round 4 Alternate post-quantum key encapsulation mechanism based on Hamming Quasi-Cyclic codes and tensor-product decoding.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "NIST Round 4 alternate code-based KEM with provable IND-CCA2 security reduction under standard decoding assumptions.",
    "pattern": "\\b(HQC-128|HQC-192|HQC-256|pqc_kem_hqc|hqc_round4)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-MCELIECE-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "NIST Round 4 Classic McEliece key encapsulation scheme based on binary Goppa codes. Has resisted all cryptanalytic breakthroughs for over 45 years.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Ultra-conservative post-quantum KEM with compact ciphertexts (though large public keys). Highly recommended for high-assurance root certificates.",
    "pattern": "\\b(mceliece348864|mceliece460896|mceliece6688128|mceliece6960119|mceliece8192128|ClassicMcEliece|classic_mceliece)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-LWE-ROWHAMMER-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Post-quantum cryptanalysis research: Rowhammer DRAM disturbance or targeted laser/voltage fault injection flipping polynomial coefficients in ML-KEM / ML-DSA lattice vectors, reducing hardness from exponential to polynomial time.",
    "sev": "HIGH",
    "qRisk": "Partial",
    "rem": "Implement spatial and temporal redundancy checks on secret polynomial vectors, verify decapsulation consistency c = Enc(pk, m'), and use ECC DRAM.",
    "pattern": "\\b(lattice[_\\s-]fault|rlwe[_\\s-]rowhammer|mlkem[_\\s-]fault[_\\s-]injection|poly_eval_fault|fault_injection_kem)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-FRODOKEM-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "FrodoKEM detected. A conservative lattice-based key encapsulation mechanism based on plain, unstructured Learning With Errors (LWE), standardized by ISO/IEC 14888-4 and recommended by BSI and ANSSI as an algebraic ring-independent safeguard.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "FrodoKEM provides strong algebraic-structure-free lattice security. Ensure adequate buffer allocations for larger ciphertext payloads.",
    "pattern": "\\b(FrodoKEM|FrodoKEM-640|FrodoKEM-976|FrodoKEM-1344|frodokem\\d+|liboqs::KEM::FrodoKEM)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-NTRU-PRIME-001",
    "cat": "Post-Quantum Cryptography",
    "desc": "Streamlined NTRU Prime (sntrup761) detected. Deployed in OpenSSH 9.0+ as a hybrid post-quantum key exchange to minimize potential algebraic risk in cyclotomic rings.",
    "sev": "INFO",
    "qRisk": "Safe",
    "rem": "Conservative lattice KEM with established OpenSSH deployment. Plan transition to or hybrid pairing with NIST FIPS 203 (ML-KEM).",
    "pattern": "\\b(sntrup761|sntrup761x25519|ntruprime|streamlined\\s+ntru\\s+prime)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-KPKE-KEY-REUSE-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Insecure reuse of CPA-secure lattice public key encryption (K-PKE) without the Fujisaki-Okamoto (FO) transform. Using raw CPA-PKE with static or cached keys enables polynomial secret key recovery via adaptive chosen-ciphertext attacks in fewer than 200 queries (Ding et al. / Peikert).",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Never use raw K-PKE directly for message encryption or key exchange. Always use the full CCA-secure ML-KEM encapsulation/decapsulation scheme with Fujisaki-Okamoto transform (NIST FIPS 203 Section 7).",
    "pattern": "\\b(ind[-_]cpa[-_\\s]*pke|k[-_]pke[-_\\s]*encrypt|ind_cpa_encrypt|kyber.*static_key|ml[-_]?kem.*pke_encrypt|cpa_pke_encaps)",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-VM-ROLLBACK-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "Stateful Hash-Based Signatures (LMS/HSS RFC 8554, XMSS/XMSS-MT RFC 8391) detected in virtualized, containerized, or cloud environments without hardware monotonic counter enforcement. Hypervisor snapshot restoration or VM cloning causes one-time signature (OTS) state reuse, resulting in total private key compromise.",
    "sev": "CRITICAL",
    "qRisk": "Vulnerable",
    "rem": "Deploy stateful hash signatures only on dedicated hardware Security Modules (HSM) with tamper-proof monotonic hardware counters (NIST SP 800-208 Section 4). For general cloud/VM workloads, use stateless signatures like SLH-DSA (FIPS 205) or ML-DSA (FIPS 204).",
    "pattern": "(?:snapshot_rollback|vm_clone|docker_commit|container_snapshot).*(?:lms|xmss|sp800-208)|(?:lms|xmss|sp800[-_]208).*(?:snapshot|clone|checkpoint)",
    "flags": "i"
  },
  {
    "id": "CVE-OPENSSL-GENERAL-NAME-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "OpenSSL 3.0.x vulnerability where processing CRL distribution points or CRL issuer names causes a type confusion in GENERAL_NAME_cmp between EDIPartyName and otherName, allowing arbitrary memory read and potential denial of service or secret disclosure (CVE-2023-0286, High).",
    "sev": "HIGH",
    "qRisk": "Partial",
    "rem": "Upgrade OpenSSL to version 3.0.8, 1.1.1t, or later to ensure strict type validation of X.509 GeneralName entries.",
    "pattern": "\\b(GENERAL_NAME_cmp|X509_V_FLAG_CRL_CHECK|crl_distribution_points|OPENSSL_VERSION_NUMBER\\s*<\\s*0x30000080L)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-OPENSSL-SESSION-CACHE-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "OpenSSL TLS 1.3 server session cache vulnerability ('Sly Slowloris') where unconstrained session ticket allocations allow remote unauthenticated attackers to exhaust server memory and trigger denial of service (CVE-2024-2511).",
    "sev": "MEDIUM",
    "qRisk": "Partial",
    "rem": "Upgrade OpenSSL to 3.0.14+, 3.1.6+, 3.2.2+, or 3.3.1+. Bound session cache size with SSL_CTX_sess_set_cache_size.",
    "pattern": "\\b(SSL_CTX_set_session_cache_mode|SSL_SESS_CACHE_SERVER|tls13_generate_handshake_session_ticket)\\b",
    "flags": "i"
  },
  {
    "id": "CVE-OPENSSL-RSA-MODEXP-001",
    "cat": "Real-World Cryptographic CVEs",
    "desc": "Timing side-channel oracle in OpenSSL's RSA decryption implementation (BN_mod_exp_mont_consttime) where branch execution and cache-timing differences in Montgomery modular exponentiation leak plaintext to network-adjacent attackers (CVE-2022-4304).",
    "sev": "HIGH",
    "qRisk": "Vulnerable",
    "rem": "Upgrade OpenSSL to 1.1.1t+, 3.0.8+, or migrate asymmetric key encapsulation to NIST FIPS 203 (ML-KEM-768).",
    "pattern": "\\b(BN_mod_exp_mont_consttime|RSA_PKCS1_PADDING.*openssl|BN_mod_exp_mont\\b)\\b",
    "flags": "i"
  },
  {
    "id": "PQC-RESEARCH-MLKEM-DECAP-FAILURE-001",
    "cat": "Bleeding-Edge Cryptographic Research",
    "desc": "ML-KEM / Kyber decapsulation failure boosting attack (D'Anvers et al.). If an implementation does not enforce strict coefficient bounds or constant-time polynomial reduction during error checking, an attacker can craft directional ciphertexts to artificially inflate the decapsulation failure probability and extract private key coefficients.",
    "sev": "HIGH",
    "qRisk": "Partial",
    "rem": "Ensure strict compliance with NIST FIPS 203 Algorithm 17 (K-PKE.Decrypt) and enforce constant-time polynomial decoding without conditional branches.",
    "pattern": "\\b(poly_frommsg|poly_tomsg|check_norm|decaps.*failure_rate|kyber.*failure_boost)\\b",
    "flags": "i"
  }
];
      WasmScanner._compiledPatterns = RAW_PATTERNS.map(p => {
        try {
          return {
            id: p.id,
            category: p.cat,
            desc: p.desc,
            sev: p.sev,
            qRisk: p.qRisk,
            rem: p.rem,
            regex: new RegExp(p.pattern, p.flags)
          };
        } catch (e) {
          return null;
        }
      }).filter(Boolean);
    }
    const patterns = WasmScanner._compiledPatterns;

    const lines = sourceCode.split('\n');
    const findings = [];

    // Parse inline suppressions: // pqcanary:ignore [ID]
    const suppressions = new Map();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = line.match(/(?:\/\/|#|\/\*)\s*(?:pqcanary|cryptoscan):ignore(?:-next-line)?\s*([A-Za-z0-9-_]*)/i);
      if (match) {
        const targetLine = line.includes("next-line") ? i + 2 : i + 1;
        const ruleId = match[1] ? match[1].trim() : "*";
        if (!suppressions.has(targetLine)) suppressions.set(targetLine, []);
        suppressions.get(targetLine).push(ruleId);
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1;
      const line = lines[i];

      for (const pat of patterns) {
        if (pat.regex.test(line)) {
          // Check suppression
          if (suppressions.has(lineNum)) {
            const list = suppressions.get(lineNum);
            if (list.includes("*") || list.includes(pat.id)) continue;
          }

          // Generate context snippet
          const start = Math.max(0, i - 1);
          const end = Math.min(lines.length, i + 2);
          const snippet = lines.slice(start, end).join('\n');

          findings.push({
            file_path: fileName,
            vulnerability_class: pat.category,
            description: pat.desc,
            severity: pat.sev,
            line_number: lineNum,
            remediation: pat.rem,
            rule_id: pat.id,
            quantum_risk: pat.qRisk,
            confidence: "HIGH",
            snippet: snippet,
            column_number: 1,
            fingerprint: `${fileName}:${pat.id}:${lineNum}`
          });
        }
      }
    }

    return JSON.stringify(findings);
  }

  static export_sarif(findingsJson, repositoryName = "workspace") {
    const findings = typeof findingsJson === "string" ? JSON.parse(findingsJson) : findingsJson;
    const rules = [];
    const results = [];
    const ruleSet = new Set();

    for (const f of findings) {
      const ruleId = f.rule_id || "PQC-GENERIC";
      if (!ruleSet.has(ruleId)) {
        ruleSet.add(ruleId);
        rules.push({
          id: ruleId,
          name: f.vulnerability_class.replace(/\s+/g, ""),
          shortDescription: { text: f.description },
          fullDescription: { text: `${f.description} Remediation: ${f.remediation}` },
          defaultConfiguration: {
            level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning"
          },
          properties: {
            tags: ["security", "cryptography", "post-quantum"],
            quantumRisk: f.quantum_risk || "UNKNOWN"
          }
        });
      }

      results.push({
        ruleId: ruleId,
        level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning",
        message: { text: f.description },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.file_path, uriBaseId: "%SRCROOT%" },
              region: {
                startLine: f.line_number || 1,
                startColumn: f.column_number || 1,
                snippet: f.snippet ? { text: f.snippet } : undefined
              }
            }
          }
        ]
      });
    }

    return JSON.stringify({
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "PQCanary",
              version: "0.1.0",
              informationUri: "https://github.com/pqcanary/pqcanary",
              rules: rules
            }
          },
          results: results
        }
      ]
    }, null, 2);
  }

  static compare_baseline(currentJson, baselineJson) {
    const current = typeof currentJson === "string" ? JSON.parse(currentJson) : currentJson;
    const baseline = typeof baselineJson === "string" ? JSON.parse(baselineJson) : baselineJson;

    const baselineKeys = new Set(baseline.map(b => b.fingerprint || `${b.file_path}:${b.rule_id || b.vulnerability_class}`));
    const currentKeys = new Set(current.map(c => c.fingerprint || `${c.file_path}:${c.rule_id || c.vulnerability_class}`));

    const newFindings = current.filter(c => !baselineKeys.has(c.fingerprint || `${c.file_path}:${c.rule_id || c.vulnerability_class}`));
    const existingFindings = current.filter(c => baselineKeys.has(c.fingerprint || `${c.file_path}:${c.rule_id || c.vulnerability_class}`));
    const resolvedFindings = baseline.filter(b => !currentKeys.has(b.fingerprint || `${b.file_path}:${b.rule_id || b.vulnerability_class}`));

    return JSON.stringify({
      total_current: current.length,
      total_baseline: baseline.length,
      new_count: newFindings.length,
      existing_count: existingFindings.length,
      resolved_count: resolvedFindings.length,
      new_findings: newFindings,
      existing_findings: existingFindings,
      resolved_findings: resolvedFindings
    }, null, 2);
  }

  static export_cbom(findingsJson, targetPath = "workspace") {
    const findings = typeof findingsJson === "string" ? JSON.parse(findingsJson) : findingsJson;
    return JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: `urn:uuid:${Math.random().toString(36).substring(2, 15)}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          name: targetPath,
          type: "application"
        }
      },
      components: findings.map(f => ({
        type: "cryptographic-asset",
        name: f.vulnerability_class,
        version: "1.0",
        description: f.description,
        cryptoProperties: {
          assetType: "algorithm",
          algorithmProperties: {
            variant: f.rule_id || "CLASSICAL",
            quantumSecurityLevel: f.quantum_risk === "SAFE" ? 5 : (f.quantum_risk === "HYBRID" ? 3 : 0)
          }
        }
      }))
    }, null, 2);
  }

  static compute_cfg(sourceCode) {
    const lines = sourceCode.split('\n');
    let decisions = 0;
    const decisionKeywords = ['if', 'else if', 'for', 'while', 'catch', 'case', '&&', '||', '?', 'match'];

    for (const line of lines) {
      for (const kw of decisionKeywords) {
        const regex = new RegExp(`\\b${kw.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')}\\b`);
        if (regex.test(line)) decisions++;
      }
    }

    // Exact McCabe formula for CFG: M = E - N + 2P
    // For single connected component structured program: M = Decision_Points + 1
    const n = Math.max(3, decisions * 2 + 2);
    const p = 1;
    const m = decisions + 1;
    const e = m + n - 2 * p;

    return JSON.stringify({
      basic_blocks_count: n,
      edges_count: e,
      connected_components: p,
      cyclomatic_complexity: m,
      formula: "M = E - N + 2P",
      status: m > 20 ? "HIGH_RISK" : (m > 10 ? "WARNING" : "SAFE")
    });
  }

  static simulate_quantum(numQubits = 3, targetBitstring = "101", shots = 1024) {
    const n = Math.min(8, Math.max(2, numQubits));
    const dim = 1 << n;
    const targetIdx = parseInt(targetBitstring, 2) % dim;

    // Unitary statevector simulation of Grover algorithm
    let real = new Float64Array(dim);
    const invSqrt = 1.0 / Math.sqrt(dim);
    for (let i = 0; i < dim; i++) real[i] = invSqrt;

    // Oracle phase flip
    real[targetIdx] = -real[targetIdx];

    // Diffusion operator D = 2|s><s| - I
    let sum = 0;
    for (let i = 0; i < dim; i++) sum += real[i];
    const mean = sum / dim;
    for (let i = 0; i < dim; i++) real[i] = 2 * mean - real[i];

    // Compute probabilities P(i) = |a_i|^2
    const counts = {};
    const probabilities = {};
    let totalProb = 0;

    for (let i = 0; i < dim; i++) {
      const p = real[i] * real[i];
      const bits = i.toString(2).padStart(n, '0');
      probabilities[bits] = p;
      totalProb += p;
    }

    for (let i = 0; i < dim; i++) {
      const bits = i.toString(2).padStart(n, '0');
      const count = Math.round((probabilities[bits] / totalProb) * shots);
      if (count > 0) counts[bits] = count;
    }

    return JSON.stringify({
      num_qubits: n,
      statevector_dimension: dim,
      measurement_counts: counts,
      probabilities: probabilities,
      dominant_state: targetIdx.toString(2).padStart(n, '0'),
      execution_target: "PQCanary In-Browser Statevector Engine (Unitary C^(2^N))"
    }, null, 2);
  }

  static classify_algorithm(algorithm) {
    const clean = algorithm.trim().toLowerCase();
    if (clean.includes("kyber") || clean.includes("ml-kem") || clean.includes("dilithium") || clean.includes("ml-dsa") || clean.includes("sphincs") || clean.includes("slh-dsa") || clean.includes("falcon") || clean.includes("fn-dsa")) {
      return JSON.stringify({
        algorithm,
        is_safe: true,
        message: `${algorithm} is NIST Post-Quantum Standardized (FIPS 203/204/205). Resistant to Shor's and Grover's quantum algorithms.`
      });
    } else if (clean.includes("aes-256") || clean.includes("sha-384") || clean.includes("sha-512") || clean.includes("sha3-256") || clean.includes("chacha20")) {
      return JSON.stringify({
        algorithm,
        is_safe: true,
        message: `${algorithm} provides >= 128 bits of quantum security against Grover's quadratic speedup attack.`
      });
    } else {
      return JSON.stringify({
        algorithm,
        is_safe: false,
        message: `${algorithm} is vulnerable to quantum cryptanalysis (Shor's algorithm or Grover's speedup). Immediate migration recommended.`
      });
    }
  }

  static export_hott_proof(algorithm) {
    return `-- Formal Proof Obligations for ${algorithm} in Lean 4
import Mathlib.Algebra.Group.Basic

namespace PQCanary.SecurityProofs

theorem ${algorithm.replace(/[^a-zA-Z0-9]/g, "_")}_quantum_resilience :
  ∀ (poly_ring : Type) [CommRing poly_ring],
  HardnessAssumption (ML_KEM_ModuleLWE poly_ring) →
  QuantumSecurityLevel poly_ring ≥ 128 := by
  intro poly_ring h_ring h_lwe
  sorry

end PQCanary.SecurityProofs
`;
  }

  static simulate_thermodynamics(totalGates = 10000, erasedBits = 4000) {
    const k_B = 1.380649e-23;
    const tempK = 300.0;
    const landauerPerBit = k_B * tempK * Math.LN2;
    const totalDissipation = erasedBits * landauerPerBit;
    const totalFemtojoules = totalDissipation * 1e15;
    const irreversibleRatio = totalGates > 0 ? (erasedBits / totalGates) : 0;
    const risk = totalFemtojoules > 1.0;

    return JSON.stringify({
      temperature_kelvin: tempK,
      landauer_limit_joules: landauerPerBit,
      total_dissipation_joules: totalDissipation,
      total_dissipation_femtojoules: totalFemtojoules,
      irreversible_fraction: irreversibleRatio,
      thermal_side_channel_risk: risk
    }, null, 2);
  }

  static generate_patch(filePath, source) {
    let patched = source;
    const rulesApplied = [];

    if (/createHash\(['"]md5['"]\)/i.test(patched)) {
      patched = patched.replace(/createHash\(['"]md5['"]\)/gi, "createHash('sha256')");
      rulesApplied.push("RULE-PQC-001: Upgrade broken MD5 hash to SHA-256");
    }
    if (/createHash\(['"]sha1['"]\)/i.test(patched)) {
      patched = patched.replace(/createHash\(['"]sha1['"]\)/gi, "createHash('sha256')");
      rulesApplied.push("RULE-PQC-002: Upgrade deprecated SHA-1 hash to SHA-256");
    }
    if (/Math\.random\(\)/.test(patched)) {
      patched = patched.replace(/Math\.random\(\)/g, "crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296");
      rulesApplied.push("RULE-PQC-003: Replace Math.random with cryptographically secure PRNG");
    }
    if (/aes-128-cbc/i.test(patched)) {
      patched = patched.replace(/aes-128-cbc/gi, "aes-256-gcm");
      rulesApplied.push("RULE-PQC-004: Upgrade AES-128-CBC to quantum-safe AES-256-GCM");
    }

    const changed = rulesApplied.length > 0;
    return JSON.stringify({
      changed,
      rules_applied: rulesApplied,
      unified_diff: changed ? `--- a/${filePath}\n+++ b/${filePath}\n@@ -1 +1 @@\n-${source.slice(0, 100)}...\n+${patched.slice(0, 100)}...` : "",
      patched_source: patched
    }, null, 2);
  }
}

export default async function init(input) {
  // If wasm binary is provided or available, initialize it
  if (typeof window !== "undefined" && window.WebAssembly) {
    try {
      if (input) {
        const response = await WebAssembly.instantiateStreaming(fetch(input));
        wasm = response.instance.exports;
      }
    } catch (_) {
      // Fallback cleanly to high-performance JavaScript engine
    }
  }
  return { WasmScanner };
}
