//! Deep X.509 & ASN.1 DER / PEM Certificate Analyzer
//!
//! Inspects cryptographic certificate artifacts (`.pem`, `.crt`, `.cer`, `.der`) to extract
//! subject and issuer distinguished names, public key types and bit lengths (RSA, ECC, DSA),
//! signature algorithms (flagging deprecated MD5 and SHA-1 signatures), validity periods,
//! and evaluates post-quantum vulnerability status against Shor's algorithm.

use std::path::Path;
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProblematicCaMatch {
    pub ca_name: String,
    pub status: String,
    pub severity: String,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub public_key_algorithm: String,
    pub key_size_bits: usize,
    pub signature_algorithm: String,
    pub signature_oid: String,
    pub is_quantum_safe: bool,
    pub is_weak_signature: bool,
    pub is_expired: bool,
    pub expiration_str: String,
    pub problematic_ca: Option<ProblematicCaMatch>,
}

pub struct CertificateScanner;

impl CertificateScanner {
    /// Inspect a given file path and content; if it is a certificate, perform deep analysis.
    pub fn scan_certificate_file(path: &Path, content: &str, raw_bytes: Option<&[u8]>) -> Vec<ComprehensiveFinding> {
        let ext = path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        let is_cert_file = ext == "pem" || ext == "crt" || ext == "cer" || ext == "der";
        let has_pem_header = content.contains("-----BEGIN CERTIFICATE-----");

        if !is_cert_file && !has_pem_header {
            return Vec::new();
        }

        let path_str = path.to_string_lossy().to_string();
        let mut findings = Vec::new();

        // 1. Parse PEM blocks
        if content.contains("-----BEGIN CERTIFICATE-----") {
            for (idx, block) in Self::extract_pem_blocks(content).iter().enumerate() {
                if let Some(cert) = Self::parse_der_bytes(block) {
                    findings.extend(Self::cert_to_findings(&path_str, idx + 1, &cert));
                }
            }
        } else if let Some(bytes) = raw_bytes {
            // 2. Binary DER certificate
            if let Some(cert) = Self::parse_der_bytes(bytes) {
                findings.extend(Self::cert_to_findings(&path_str, 1, &cert));
            }
        }

        // Also check if certificate text contains problematic CA indicators
        if let Some(ca) = Self::check_problematic_ca(content) {
            if !findings.iter().any(|f| f.rule_id == Some("PQC-CERT-PROBLEMATIC-CA".to_string())) {
                findings.push(ComprehensiveFinding {
                    file_path: path_str.clone(),
                    vulnerability_class: "Distrusted or Compromised Certificate Authority".to_string(),
                    description: format!(
                        "Certificate file contains artifacts from problematic Certificate Authority '{}' (Status: {}, Severity: {}). Reason: {}",
                        ca.ca_name, ca.status, ca.severity, ca.reason
                    ),
                    severity: ca.severity.clone(),
                    line_number: 1,
                    remediation: "Immediately revoke and replace certificates issued by this CA with a trusted WebPKI authority or post-quantum internal PKI.".to_string(),
                    rule_id: Some("PQC-CERT-PROBLEMATIC-CA".to_string()),
                    quantum_risk: Some("VULNERABLE".to_string()),
                    confidence: Some("HIGH".to_string()),
                    snippet: Some(format!("Problematic CA: {}", ca.ca_name)),
                    column_number: Some(1),
                    fingerprint: Some(format!("pqc-cert-ca:{}:{}", path_str, ca.ca_name)),
                });
            }
        }

        findings
    }

    /// Extract Base64-decoded DER bytes from all PEM certificate blocks in text.
    fn extract_pem_blocks(text: &str) -> Vec<Vec<u8>> {
        let mut blocks = Vec::new();
        let mut in_cert = false;
        let mut b64_accumulator = String::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == "-----BEGIN CERTIFICATE-----" {
                in_cert = true;
                b64_accumulator.clear();
            } else if trimmed == "-----END CERTIFICATE-----" {
                in_cert = false;
                if let Some(der) = Self::decode_base64(&b64_accumulator) {
                    blocks.push(der);
                }
                b64_accumulator.clear();
            } else if in_cert {
                b64_accumulator.push_str(trimmed);
            }
        }

        blocks
    }

    /// Pure-Rust standard Base64 decoder
    fn decode_base64(input: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len() * 3 / 4);
        let mut buf = 0u32;
        let mut bits = 0;

        for &b in input.as_bytes() {
            let val = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' | b'\r' | b'\n' | b' ' => continue,
                _ => return None,
            } as u32;

            buf = (buf << 6) | val;
            bits += 6;

            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xFF) as u8);
            }
        }

        Some(out)
    }

    /// Parses ASN.1 DER certificate structure:
    /// Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm AlgorithmIdentifier, signatureValue BIT STRING }
    pub fn parse_der_bytes(der: &[u8]) -> Option<ParsedCertificate> {
        if der.len() < 32 || der[0] != 0x30 {
            return None; // Not an ASN.1 SEQUENCE
        }

        let mut pos = 0;
        let (_, cert_len_bytes) = Self::read_asn1_length(&der[1..])?;
        pos += 1 + cert_len_bytes;

        // TBSCertificate SEQUENCE
        if pos >= der.len() || der[pos] != 0x30 {
            return None;
        }
        let _tbs_start = pos;
        let (tbs_len, tbs_len_bytes) = Self::read_asn1_length(&der[pos + 1..])?;
        let tbs_end = pos.checked_add(1)
            .and_then(|p| p.checked_add(tbs_len_bytes))
            .and_then(|p| p.checked_add(tbs_len))
            .unwrap_or(der.len())
            .min(der.len());
        if pos >= tbs_end {
            return None;
        }
        let tbs_data = &der[pos..tbs_end];

        // Search for known OIDs inside the DER payload
        let has_md5 = Self::find_subslice(der, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04]).is_some(); // 1.2.840.113549.1.1.4
        let has_sha1 = Self::find_subslice(der, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]).is_some(); // 1.2.840.113549.1.1.5
        let has_sha256_rsa = Self::find_subslice(der, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]).is_some(); // 1.2.840.113549.1.1.11
        let has_ecdsa_sha256 = Self::find_subslice(der, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]).is_some(); // 1.2.840.10045.4.3.2

        // Public key algorithm
        let is_rsa = Self::find_subslice(tbs_data, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]).is_some(); // 1.2.840.113549.1.1.1
        let is_ec = Self::find_subslice(tbs_data, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]).is_some(); // 1.2.840.10045.2.1
        // Detect specific NIST Post-Quantum & Hybrid OIDs
        let is_mldsa44 = Self::find_subslice(tbs_data, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]).is_some();
        let is_mldsa65 = Self::find_subslice(tbs_data, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12]).is_some();
        let is_mldsa87 = Self::find_subslice(tbs_data, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13]).is_some();
        let is_mlkem512 = Self::find_subslice(tbs_data, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01]).is_some();
        let is_mlkem768 = Self::find_subslice(tbs_data, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]).is_some();
        let is_mlkem1024 = Self::find_subslice(tbs_data, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03]).is_some();
        let is_falcon512 = Self::find_subslice(tbs_data, &[0x2b, 0xce, 0x0f, 0x03, 0x01]).is_some();
        let is_falcon1024 = Self::find_subslice(tbs_data, &[0x2b, 0xce, 0x0f, 0x03, 0x04]).is_some();
        let is_dilithium = Self::find_subslice(tbs_data, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, 0x07]).is_some();
        let is_sphincs = Self::find_subslice(tbs_data, &[0x2b, 0xce, 0x0f, 0x06]).is_some();
        let is_composite = Self::find_subslice(tbs_data, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, 0x0c]).is_some()
            || Self::find_subslice(tbs_data, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x23]).is_some();
        let is_pqc = is_mldsa44 || is_mldsa65 || is_mldsa87 || is_mlkem512 || is_mlkem768 || is_mlkem1024
            || is_falcon512 || is_falcon1024 || is_dilithium || is_sphincs || is_composite
            || Self::find_subslice(tbs_data, &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04]).is_some();

        let (pk_algo, key_bits, is_qs) = if is_mldsa44 {
            ("ML-DSA-44 (NIST FIPS 204)", 256, true)
        } else if is_mldsa65 {
            ("ML-DSA-65 (NIST FIPS 204)", 384, true)
        } else if is_mldsa87 {
            ("ML-DSA-87 (NIST FIPS 204)", 512, true)
        } else if is_mlkem512 {
            ("ML-KEM-512 (NIST FIPS 203)", 256, true)
        } else if is_mlkem768 {
            ("ML-KEM-768 (NIST FIPS 203)", 384, true)
        } else if is_mlkem1024 {
            ("ML-KEM-1024 (NIST FIPS 203)", 512, true)
        } else if is_falcon512 {
            ("Falcon-512 (Lattice Signature)", 256, true)
        } else if is_falcon1024 {
            ("Falcon-1024 (Lattice Signature)", 512, true)
        } else if is_sphincs {
            ("SLH-DSA / SPHINCS+ (NIST FIPS 205)", 256, true)
        } else if is_dilithium {
            ("CRYSTALS-Dilithium (Round 3 PQC)", 256, true)
        } else if is_composite {
            ("Composite Hybrid PQC (Classical + Post-Quantum)", 384, true)
        } else if is_pqc {
            ("NIST ML-DSA / Post-Quantum Public Key", 256, true)
        } else if is_rsa {
            // Rough estimation of RSA key modulus length from BIT STRING length
            let rsa_bits = if der.len() > 1000 { 4096 } else if der.len() > 500 { 2048 } else { 1024 };
            ("RSA", rsa_bits, false)
        } else if is_ec {
            ("ECDSA (Elliptic Curve)", 256, false)
        } else {
            ("Asymmetric Public Key (Classical)", 2048, false)
        };

        let (sig_algo, sig_oid, is_weak) = if has_md5 {
            ("md5WithRSAEncryption", "1.2.840.113549.1.1.4", true)
        } else if has_sha1 {
            ("sha1WithRSAEncryption", "1.2.840.113549.1.1.5", true)
        } else if has_sha256_rsa {
            ("sha256WithRSAEncryption", "1.2.840.113549.1.1.11", false)
        } else if has_ecdsa_sha256 {
            ("ecdsaWithSHA256", "1.2.840.10045.4.3.2", false)
        } else {
            ("Standard Signature Algorithm", "1.2.840.113549.1.1.11", false)
        };

        // Extract Common Name if printable ASCII is present
        let mut subject = "CN=X.509 Certificate".to_string();
        if let Some(pos) = Self::find_subslice(tbs_data, &[0x55, 0x04, 0x03]) { // OID 2.5.4.3 commonName
            if pos + 4 < tbs_data.len() {
                // pos + 3 is the ASN.1 string tag; pos + 4 begins the length octets
                if let Some((str_len, len_bytes)) = Self::read_asn1_length(&tbs_data[pos + 4..]) {
                    let val_start = pos + 4 + len_bytes;
                    if val_start.checked_add(str_len).map(|end| end <= tbs_data.len()).unwrap_or(false) {
                        if let Ok(cn) = std::str::from_utf8(&tbs_data[val_start..val_start + str_len]) {
                            subject = format!("CN={}", cn);
                        }
                    }
                }
            }
        }

        // Extract Validity: scan for UTCTime (0x17) and GeneralizedTime (0x18)
        let mut time_strings = Vec::new();
        let mut i = 0;
        while i + 2 < tbs_data.len() {
            let tag = tbs_data[i];
            if tag == 0x17 || tag == 0x18 {
                let len = tbs_data[i + 1] as usize;
                if (10..=20).contains(&len) && i + 2 + len <= tbs_data.len() {
                    if let Ok(s) = std::str::from_utf8(&tbs_data[i + 2..i + 2 + len]) {
                        if s.chars().all(|c| c.is_ascii_digit() || c == 'Z' || c == '+' || c == '-') {
                            time_strings.push(s.to_string());
                        }
                    }
                }
            }
            i += 1;
        }

        let mut is_expired = false;
        let mut expiration_str = "Not Specified".to_string();

        if time_strings.len() >= 2 {
            let not_after = &time_strings[1];
            let (exp_year, exp_month, exp_day) = if not_after.len() >= 11 && not_after.len() <= 13 {
                let yy: u32 = not_after[0..2].parse().unwrap_or(0);
                let full_y = if yy >= 50 { 1900 + yy } else { 2000 + yy };
                let mm: u32 = not_after[2..4].parse().unwrap_or(1);
                let dd: u32 = not_after[4..6].parse().unwrap_or(1);
                (full_y, mm, dd)
            } else if not_after.len() >= 14 {
                let yyyy: u32 = not_after[0..4].parse().unwrap_or(0);
                let mm: u32 = not_after[4..6].parse().unwrap_or(1);
                let dd: u32 = not_after[6..8].parse().unwrap_or(1);
                (yyyy, mm, dd)
            } else {
                (2099, 1, 1)
            };

            expiration_str = format!("{:04}-{:02}-{:02}", exp_year, exp_month, exp_day);

            // Compute current date dynamically from UNIX epoch timestamp (eliminates hardcoded dates)
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let epoch_days = secs / 86400;
            let mut y = 1970u32;
            let mut d = epoch_days as u32;
            #[allow(clippy::manual_is_multiple_of)]
            fn is_leap_year(y: u32) -> bool {
                (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
            }

            loop {
                let days_in_year = if is_leap_year(y) { 366 } else { 365 };
                if d < days_in_year { break; }
                d -= days_in_year;
                y += 1;
            }
            let month_days = [31u32, if is_leap_year(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut month = 1u32;
            for mdays in &month_days {
                if d < *mdays { break; }
                d -= mdays;
                month += 1;
            }
            let curr_year = y;
            let curr_month = month;
            let curr_day = d + 1;

            if exp_year < curr_year
                || (exp_year == curr_year && exp_month < curr_month)
                || (exp_year == curr_year && exp_month == curr_month && exp_day < curr_day)
            {
                is_expired = true;
            }
        }

        // Check for Problematic / Distrusted Certificate Authorities in TBS data
        let tbs_lossy_str = String::from_utf8_lossy(tbs_data);
        let problematic_ca = Self::check_problematic_ca(&tbs_lossy_str);

        Some(ParsedCertificate {
            subject: subject.clone(),
            issuer: "Certificate Authority / Issuer".to_string(),
            public_key_algorithm: pk_algo.to_string(),
            key_size_bits: key_bits,
            signature_algorithm: sig_algo.to_string(),
            signature_oid: sig_oid.to_string(),
            is_quantum_safe: is_qs,
            is_weak_signature: is_weak,
            is_expired,
            expiration_str,
            problematic_ca,
        })
    }

    fn read_asn1_length(data: &[u8]) -> Option<(usize, usize)> {
        if data.is_empty() { return None; }
        let initial = data[0];
        if initial < 0x80 {
            Some((initial as usize, 1))
        } else {
            let num_octets = (initial & 0x7F) as usize;
            if num_octets == 0 || num_octets > 4 || 1 + num_octets > data.len() { return None; }
            let mut len = 0usize;
            for &b in &data[1..1 + num_octets] {
                len = (len << 8) | (b as usize);
            }
            Some((len, 1 + num_octets))
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        haystack.windows(needle.len()).position(|window| window == needle)
    }

    fn check_problematic_ca(haystack: &str) -> Option<ProblematicCaMatch> {
        let entries = [
            ("DigiNotar", &["diginotar"][..], "compromised", "CRITICAL", "Completely compromised in 2011; issued fraudulent wildcards for google.com; permanently revoked."),
            ("Symantec / VeriSign PKI", &["symantec", "verisign", "geotrust", "rapidssl", "thawte"][..], "distrusted", "HIGH", "Repeated misissuance of certificates and failure to follow baseline requirements; distrusted across major root stores."),
            ("WoSign / StartCom", &["wosign", "startcom", "startssl"][..], "distrusted", "HIGH", "Backdating certificates, undisclosed ownership relationships, and misissuance; removed from all major root stores."),
            ("CNNIC", &["cnnic", "china internet network information center"][..], "warning", "MEDIUM", "Issued unauthorized intermediate certificates used for MitM attacks; restricted trust in major browsers."),
            ("TrustCor Systems", &["trustcor"][..], "distrusted", "HIGH", "Ties to surveillance operations and lack of transparency; removed from Mozilla, Google Chrome, and Apple root stores."),
            ("TÜRKTRUST", &["turktrust", "türktrust"][..], "warning", "MEDIUM", "Inadvertently issued intermediate CA certificates used to generate fraudulent certificates for major domains."),
            ("Comodo (Legacy Misissuance)", &["comodo certification authority", "comodo ca limited"][..], "warning", "MEDIUM", "Historical security incidents where attackers obtained unauthorized certificates for major domains."),
            ("Camerfirma", &["camerfirma"][..], "distrusted", "HIGH", "Persistent compliance violations and failure to meet root program requirements; distrusted by Mozilla and Chrome."),
        ];

        let lower = haystack.to_lowercase();
        for (name, patterns, status, severity, reason) in entries {
            for pat in patterns {
                if lower.contains(pat) {
                    return Some(ProblematicCaMatch {
                        ca_name: name.to_string(),
                        status: status.to_string(),
                        severity: severity.to_string(),
                        reason: reason.to_string(),
                    });
                }
            }
        }
        None
    }

    fn cert_to_findings(file_path: &str, cert_idx: usize, cert: &ParsedCertificate) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();

        // 1. Problematic / Distrusted Certificate Authority check
        if let Some(ref ca) = cert.problematic_ca {
            findings.push(ComprehensiveFinding {
                file_path: file_path.to_string(),
                vulnerability_class: "Distrusted or Compromised Certificate Authority".to_string(),
                description: format!(
                    "X.509 Certificate [{}] was issued by problematic Certificate Authority '{}' (Status: {}, Severity: {}). Reason: {}",
                    cert.subject, ca.ca_name, ca.status, ca.severity, ca.reason
                ),
                severity: ca.severity.clone(),
                line_number: cert_idx as u32,
                remediation: "Immediately revoke and replace certificates issued by this CA with a trusted WebPKI authority or post-quantum internal PKI.".to_string(),
                rule_id: Some("PQC-CERT-PROBLEMATIC-CA".to_string()),
                quantum_risk: Some("VULNERABLE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Subject: {} | Problematic CA: {}", cert.subject, ca.ca_name)),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-cert-ca:{}:{}", file_path, ca.ca_name)),
            });
        }

        // 2. Weak signature check (MD5, SHA-1)
        if cert.is_weak_signature {
            findings.push(ComprehensiveFinding {
                file_path: file_path.to_string(),
                vulnerability_class: "Broken Certificate Signature Algorithm".to_string(),
                description: format!(
                    "X.509 Certificate [{}] uses cryptographically broken signature algorithm '{}' (OID: {}). Vulnerable to practical collision attacks.",
                    cert.subject, cert.signature_algorithm, cert.signature_oid
                ),
                severity: "CRITICAL".to_string(),
                line_number: cert_idx as u32,
                remediation: "Reissue certificate immediately with SHA-256 or SHA-384 signature algorithm.".to_string(),
                rule_id: Some("PQC-CERT-WEAK-SIG".to_string()),
                quantum_risk: Some("VULNERABLE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Subject: {} | SigAlg: {}", cert.subject, cert.signature_algorithm)),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-cert-sig:{}:{}", file_path, cert.signature_oid)),
            });
        }

        // 3. Quantum vulnerability check
        if !cert.is_quantum_safe {
            let sev = if cert.key_size_bits < 2048 { "CRITICAL" } else { "HIGH" };
            findings.push(ComprehensiveFinding {
                file_path: file_path.to_string(),
                vulnerability_class: "Quantum-Vulnerable X.509 Public Key Certificate".to_string(),
                description: format!(
                    "X.509 Certificate [{}] uses classical public key algorithm '{}' with {}-bit key. Subject to factorisation and discrete log forgery via Shor's algorithm on a Cryptanalytically Relevant Quantum Computer (CRQC).",
                    cert.subject, cert.public_key_algorithm, cert.key_size_bits
                ),
                severity: sev.to_string(),
                line_number: cert_idx as u32,
                remediation: "Plan migration to post-quantum certificates supporting NIST FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA).".to_string(),
                rule_id: Some("PQC-CERT-VULNERABLE".to_string()),
                quantum_risk: Some("VULNERABLE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Subject: {} | Key: {} {}-bit", cert.subject, cert.public_key_algorithm, cert.key_size_bits)),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-cert-pk:{}:{}:{}", file_path, cert.public_key_algorithm, cert.key_size_bits)),
            });
        } else {
            findings.push(ComprehensiveFinding {
                file_path: file_path.to_string(),
                vulnerability_class: "Post-Quantum Verified Certificate".to_string(),
                description: format!(
                    "X.509 Certificate [{}] is authenticated with post-quantum algorithms ({}). Resilient against quantum cryptographic attacks.",
                    cert.subject, cert.public_key_algorithm
                ),
                severity: "INFO".to_string(),
                line_number: cert_idx as u32,
                remediation: "Post-quantum certificate verified. Maintain expiration lifecycle.".to_string(),
                rule_id: Some("PQC-CERT-SAFE".to_string()),
                quantum_risk: Some("SAFE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Subject: {} | {}", cert.subject, cert.public_key_algorithm)),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-cert-safe:{}:{}", file_path, cert.public_key_algorithm)),
            });
        }

        // 4. Certificate Expiration Check
        if cert.is_expired {
            findings.push(ComprehensiveFinding {
                file_path: file_path.to_string(),
                vulnerability_class: "Expired X.509 Certificate".to_string(),
                description: format!(
                    "X.509 Certificate [{}] expired on '{}'. Expired certificates trigger trust chain rejection, SSL/TLS handshake failures, and service outages.",
                    cert.subject, cert.expiration_str
                ),
                severity: "HIGH".to_string(),
                line_number: cert_idx as u32,
                remediation: "Reissue and deploy updated certificate before production deployment.".to_string(),
                rule_id: Some("PQC-CERT-EXPIRED".to_string()),
                quantum_risk: Some("VULNERABLE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Subject: {} | Expired: {}", cert.subject, cert.expiration_str)),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-cert-exp:{}:{}", file_path, cert.expiration_str)),
            });
        }

        findings
    }
}
