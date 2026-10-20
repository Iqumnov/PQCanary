//! Post-Quantum Cryptographic Network MTU & Packet Fragmentation Risk Analyzer
//!
//! Models TCP/IP packet fragmentation, handshake latency, and middlebox drop risk
//! caused by large post-quantum public keys and signatures (FIPS 203 ML-KEM, FIPS 204 ML-DSA,
//! FIPS 205 SLH-DSA, and hybrid groups) exceeding standard 1,500-byte MTUs.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcAlgorithmSpec {
    pub name: String,
    pub standard: String,
    pub primitive_type: String, // "KEM", "Signature", "Hybrid"
    pub public_key_bytes: usize,
    pub ciphertext_or_signature_bytes: usize,
    pub classical_equivalent_bytes: usize,
    pub expansion_factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtuAnalysisResult {
    pub algorithm: String,
    pub mtu_bytes: usize,
    pub ip_version: String,
    pub max_segment_size_bytes: usize, // MTU minus IP & TCP headers
    pub key_exchange_bytes: usize,
    pub signature_bytes: usize,
    pub full_handshake_payload_bytes: usize,
    pub packets_required: usize,
    pub is_fragmented: bool,
    pub fragmentation_risk_level: String, // "LOW", "MODERATE", "HIGH", "CRITICAL"
    pub middlebox_drop_probability_percent: f64,
    pub latency_multiplier: f64,
    pub mitigations: Vec<String>,
}

pub struct PqcMtuAnalyzer;

impl PqcMtuAnalyzer {
    /// Catalog of Post-Quantum & Classical primitive sizes (in bytes)
    pub fn get_algorithm_spec(algo: &str) -> Option<PqcAlgorithmSpec> {
        let norm = algo.to_uppercase().replace(['-', '_', ' '], "");
        match norm.as_str() {
            // NIST FIPS 203 (ML-KEM / Kyber)
            "MLKEM512" | "KYBER512" => Some(PqcAlgorithmSpec {
                name: "ML-KEM-512".to_string(),
                standard: "NIST FIPS 203".to_string(),
                primitive_type: "KEM".to_string(),
                public_key_bytes: 800,
                ciphertext_or_signature_bytes: 768,
                classical_equivalent_bytes: 32, // X25519 is 32 bytes
                expansion_factor: 25.0,
            }),
            "MLKEM768" | "KYBER768" => Some(PqcAlgorithmSpec {
                name: "ML-KEM-768".to_string(),
                standard: "NIST FIPS 203".to_string(),
                primitive_type: "KEM".to_string(),
                public_key_bytes: 1184,
                ciphertext_or_signature_bytes: 1088,
                classical_equivalent_bytes: 32,
                expansion_factor: 37.0,
            }),
            "MLKEM1024" | "KYBER1024" => Some(PqcAlgorithmSpec {
                name: "ML-KEM-1024".to_string(),
                standard: "NIST FIPS 203".to_string(),
                primitive_type: "KEM".to_string(),
                public_key_bytes: 1568,
                ciphertext_or_signature_bytes: 1568,
                classical_equivalent_bytes: 32,
                expansion_factor: 49.0,
            }),

            // NIST FIPS 204 (ML-DSA / Dilithium)
            "MLDSA44" | "DILITHIUM2" => Some(PqcAlgorithmSpec {
                name: "ML-DSA-44".to_string(),
                standard: "NIST FIPS 204".to_string(),
                primitive_type: "Signature".to_string(),
                public_key_bytes: 1312,
                ciphertext_or_signature_bytes: 2420,
                classical_equivalent_bytes: 64, // ECDSA is 64 bytes
                expansion_factor: 37.8,
            }),
            "MLDSA65" | "DILITHIUM3" => Some(PqcAlgorithmSpec {
                name: "ML-DSA-65".to_string(),
                standard: "NIST FIPS 204".to_string(),
                primitive_type: "Signature".to_string(),
                public_key_bytes: 1952,
                ciphertext_or_signature_bytes: 3309,
                classical_equivalent_bytes: 64,
                expansion_factor: 51.7,
            }),
            "MLDSA87" | "DILITHIUM5" => Some(PqcAlgorithmSpec {
                name: "ML-DSA-87".to_string(),
                standard: "NIST FIPS 204".to_string(),
                primitive_type: "Signature".to_string(),
                public_key_bytes: 2592,
                ciphertext_or_signature_bytes: 4627,
                classical_equivalent_bytes: 96,
                expansion_factor: 48.2,
            }),

            // NIST FIPS 205 (SLH-DSA / SPHINCS+)
            "SLHDSA128S" | "SPHINCS128S" => Some(PqcAlgorithmSpec {
                name: "SLH-DSA-128s".to_string(),
                standard: "NIST FIPS 205".to_string(),
                primitive_type: "Signature".to_string(),
                public_key_bytes: 32,
                ciphertext_or_signature_bytes: 7856,
                classical_equivalent_bytes: 64,
                expansion_factor: 122.7,
            }),
            "SLHDSA128F" | "SPHINCS128F" => Some(PqcAlgorithmSpec {
                name: "SLH-DSA-128f".to_string(),
                standard: "NIST FIPS 205".to_string(),
                primitive_type: "Signature".to_string(),
                public_key_bytes: 32,
                ciphertext_or_signature_bytes: 17088,
                classical_equivalent_bytes: 64,
                expansion_factor: 267.0,
            }),

            // Hybrid Key Exchange Groups
            "X25519MLKEM768" | "HYBRIDKEM" => Some(PqcAlgorithmSpec {
                name: "X25519 + ML-KEM-768".to_string(),
                standard: "IETF Hybrid TLS 1.3".to_string(),
                primitive_type: "Hybrid".to_string(),
                public_key_bytes: 1216, // 32 + 1184
                ciphertext_or_signature_bytes: 1120, // 32 + 1088
                classical_equivalent_bytes: 32,
                expansion_factor: 38.0,
            }),

            // Classical Baselines
            "RSA2048" => Some(PqcAlgorithmSpec {
                name: "RSA-2048".to_string(),
                standard: "PKCS #1 v2.2".to_string(),
                primitive_type: "Classical".to_string(),
                public_key_bytes: 256,
                ciphertext_or_signature_bytes: 256,
                classical_equivalent_bytes: 256,
                expansion_factor: 1.0,
            }),
            "ECDSA256" | "P256" => Some(PqcAlgorithmSpec {
                name: "ECDSA secp256r1".to_string(),
                standard: "SEC 2".to_string(),
                primitive_type: "Classical".to_string(),
                public_key_bytes: 65,
                ciphertext_or_signature_bytes: 64,
                classical_equivalent_bytes: 64,
                expansion_factor: 1.0,
            }),
            _ => None,
        }
    }

    /// Evaluates fragmentation risk given an algorithm, MTU size, and IP version
    pub fn analyze(algo: &str, mtu: Option<usize>, is_ipv6: bool) -> MtuAnalysisResult {
        let spec = Self::get_algorithm_spec(algo).unwrap_or_else(|| PqcAlgorithmSpec {
            name: algo.to_string(),
            standard: "Custom Cryptographic Profile".to_string(),
            primitive_type: "Asymmetric".to_string(),
            public_key_bytes: 1184, // default to ML-KEM-768 dimensions
            ciphertext_or_signature_bytes: 1088,
            classical_equivalent_bytes: 32,
            expansion_factor: 37.0,
        });

        let mtu_bytes = mtu.unwrap_or(1500).max(576); // Standard Ethernet MTU (min RFC 791: 576)
        let ip_header_bytes = if is_ipv6 { 40 } else { 20 };
        let tcp_header_bytes = 32; // 20 standard + 12 options (timestamps/SACK)
        let tls_record_overhead = 5;

        let mss = mtu_bytes.saturating_sub(ip_header_bytes + tcp_header_bytes);
        let effective_mss = mss.saturating_sub(tls_record_overhead).max(512);

        // Approximate total TLS handshake security frame payload
        let key_exchange = spec.public_key_bytes;
        let sig = spec.ciphertext_or_signature_bytes;
        let cert_chain_estimate = 1200 + sig; // Base cert metadata + leaf signature
        let full_handshake_bytes = key_exchange + cert_chain_estimate;

        let packets_required = full_handshake_bytes.div_ceil(effective_mss);
        let is_fragmented = packets_required > 1;

        // Calculate middlebox drop probability & risk rating
        let (risk_level, drop_prob, latency_mult) = match packets_required {
            1 => ("LOW", 0.05, 1.0),
            2 => ("MODERATE", 1.80, 1.35),
            3..=5 => ("HIGH", 8.40, 2.10),
            _ => ("CRITICAL", 24.50, 4.20),
        };

        let mut mitigations = Vec::new();
        if is_fragmented {
            mitigations.push(format!("Payload ({} B) exceeds MSS ({} B). TCP segmentation into {} packets required.",
                full_handshake_bytes, effective_mss, packets_required));
        }
        if packets_required >= 3 {
            mitigations.push("Enable RFC 8879 TLS Certificate Compression (zlib/brotli/zstd) on edge reverse proxies to reduce certificate chain byte overhead.".to_string());
            mitigations.push("Configure TCP MSS Clamping on border firewalls and VPN concentrators to avoid MTU black-hole drops.".to_string());
        }
        if spec.name.contains("SLH-DSA") {
            mitigations.push("Avoid stateless hash-based SLH-DSA for interactive TLS handshakes; reserve for offline firmware and code signing due to severe MTU packet bloat.".to_string());
        }
        if mitigations.is_empty() {
            mitigations.push("Handshake payload fits inside a single standard Ethernet frame. Zero packet fragmentation risk.".to_string());
        }

        MtuAnalysisResult {
            algorithm: spec.name,
            mtu_bytes,
            ip_version: if is_ipv6 { "IPv6".to_string() } else { "IPv4".to_string() },
            max_segment_size_bytes: effective_mss,
            key_exchange_bytes: key_exchange,
            signature_bytes: sig,
            full_handshake_payload_bytes: full_handshake_bytes,
            packets_required,
            is_fragmented,
            fragmentation_risk_level: risk_level.to_string(),
            middlebox_drop_probability_percent: drop_prob,
            latency_multiplier: latency_mult,
            mitigations,
        }
    }

    /// Formats report as clean Markdown
    pub fn format_markdown(res: &MtuAnalysisResult) -> String {
        let mut out = String::new();
        out.push_str("# Post-Quantum Network MTU & Fragmentation Analysis\n\n");
        out.push_str(&format!("- **Algorithm**: `{}`\n", res.algorithm));
        out.push_str(&format!("- **Target MTU**: `{} bytes` ({})\n", res.mtu_bytes, res.ip_version));
        out.push_str(&format!("- **Effective MSS**: `{} bytes`\n", res.max_segment_size_bytes));
        out.push_str(&format!("- **Total Handshake Payload**: `{} bytes`\n", res.full_handshake_payload_bytes));
        out.push_str(&format!("- **Packets Required**: `{}` ({})\n", res.packets_required, if res.is_fragmented { "FRAGMENTED" } else { "SINGLE PACKET" }));
        out.push_str(&format!("- **Fragmentation Risk Level**: `{}`\n", res.fragmentation_risk_level));
        out.push_str(&format!("- **Middlebox Drop Probability**: `{:.1}%`\n", res.middlebox_drop_probability_percent));
        out.push_str(&format!("- **Estimated Latency Multiplier**: `{:.2}x`\n\n", res.latency_multiplier));

        out.push_str("### Mitigations & Best Practices\n");
        for m in &res.mitigations {
            out.push_str(&format!("- {}\n", m));
        }

        out
    }
}
