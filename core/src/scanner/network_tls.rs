//! Active Network TLS & Post-Quantum Cryptographic Handshake Probe
//!
//! Connects directly to remote endpoints over TCP, issuing a live TLS 1.3 ClientHello offering:
//! - IANA Standardized NIST FIPS 203 Hybrid Group: `0x11ec` (X25519MLKEM768)
//! - Cloudflare / Google Hybrid Group: `0x6399` (X25519Kyber768Draft00)
//! - Classical Curves: `0x001d` (X25519), `0x0017` (secp256r1), `0x0018` (secp384r1)
//!
//! Analyzes the live ServerHello response to verify whether the target endpoint has
//! achieved true Post-Quantum TLS Readiness or remains vulnerable to Store-Now-Decrypt-Later.

use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone)]
pub struct TlsProbeResult {
    pub host: String,
    pub port: u16,
    pub tls_version: String,
    pub cipher_suite: String,
    pub selected_group: String,
    pub is_post_quantum_safe: bool,
    pub is_hybrid: bool,
    pub rtt_ms: u128,
}

/// Rate limiter providing IDS/IPS-safe pacing with randomized timing jitter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    pub max_rate: f64,
    pub jitter_secs: f64,
    last_call: std::sync::Arc<tokio::sync::Mutex<Option<std::time::Instant>>>,
}

impl RateLimiter {
    pub fn new(max_rate: f64, jitter_secs: f64) -> Self {
        Self {
            max_rate,
            jitter_secs,
            last_call: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// IDS-Safe mode: 3 req/sec with 0.2s timing jitter to evade threshold-based IDS/IPS alert rules.
    pub fn ids_safe() -> Self {
        Self::new(3.0, 0.2)
    }

    /// Stealth mode: 0.5 req/sec (1 request every 2 seconds) with 1.0s randomized timing jitter.
    pub fn stealth() -> Self {
        Self::new(0.5, 1.0)
    }

    /// Paces the execution according to configured rate limit and timing jitter.
    pub async fn pace(&self) {
        if self.max_rate <= 0.0 || self.max_rate.is_nan() || self.jitter_secs.is_nan() {
            return;
        }
        let mut last_guard = self.last_call.lock().await;
        let now = std::time::Instant::now();
        let min_interval = Duration::from_secs_f64(1.0 / self.max_rate);
        
        let target_delay = if self.jitter_secs > 0.0 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            let jitter_ratio = ((nanos % 1000) as f64 / 500.0) - 1.0;
            let jitter = jitter_ratio * self.jitter_secs;
            let secs = (min_interval.as_secs_f64() + jitter).max(0.01);
            Duration::from_secs_f64(secs)
        } else {
            min_interval
        };

        if let Some(prev) = *last_guard {
            let elapsed = now.duration_since(prev);
            if elapsed < target_delay {
                tokio::time::sleep(target_delay - elapsed).await;
            }
        }
        *last_guard = Some(std::time::Instant::now());
    }
}

pub struct NetworkTlsProbe;

impl NetworkTlsProbe {
    /// Extracts host and port from a target URL or host string (e.g. `https://cloudflare.com` -> `("cloudflare.com", 443)`).
    /// Robustly supports bracketed IPv6 literals (e.g. `[::1]:8443`) and strips user credentials.
    pub fn parse_target(target: &str) -> (String, u16) {
        let clean = target
            .trim_start_matches("ssh://")
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(target);

        let clean = if let Some((_user, host_part)) = clean.split_once('@') {
            host_part
        } else {
            clean
        };

        if clean.starts_with('[') {
            if let Some(end_bracket) = clean.find(']') {
                let host = &clean[1..end_bracket];
                let rest = &clean[end_bracket + 1..];
                let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);
                return (host.to_string(), port);
            }
        }

        // If the entire clean string is a valid IPv6 address without brackets, do not split on colons
        if clean.parse::<std::net::Ipv6Addr>().is_ok() {
            return (clean.to_string(), 443);
        }

        if let Some((h, p)) = clean.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (clean.to_string(), 443)
        }
    }

    /// Performs live TLS 1.3 / PQC handshake probe against target host:port.
    pub async fn probe_endpoint(host: &str, port: u16) -> Result<TlsProbeResult, String> {
        crate::api::validate_network_target(host)
            .map_err(|e| format!("SSRF protection blocked probe to '{}': {}", host, e))?;

        let addr = if host.contains(':') && !host.starts_with('[') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };
        let start_time = std::time::Instant::now();

        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| format!("Connection timeout to {}", addr))?
        .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let client_hello = Self::build_pqc_client_hello(host);
        stream.write_all(&client_hello).await
            .map_err(|e| format!("Failed to send ClientHello to {}: {}", addr, e))?;

        let mut buffer = vec![0u8; 20480];
        let mut bytes_read = tokio::time::timeout(
            Duration::from_secs(5),
            stream.read(&mut buffer),
        )
        .await
        .map_err(|_| format!("Handshake read timeout from {}", addr))?
        .map_err(|e| format!("Failed to read ServerHello from {}: {}", addr, e))?;

        let rtt_ms = start_time.elapsed().as_millis();

        if bytes_read < 5 || (buffer[0] != 0x16 && buffer[0] != 0x15) {
            return Err(format!("Invalid TLS handshake response from {}", addr));
        }

        let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
        let expected_total = (5 + record_len).min(buffer.len());

        // Read remaining TCP segments if the TLS record was fragmented across packets
        while bytes_read < expected_total {
            let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer[bytes_read..expected_total])).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => break,
            };
            bytes_read += n;
        }

        Self::parse_server_hello(&buffer[..bytes_read], host, port, rtt_ms)
    }

    /// Converts a TLS probe result into standard PQCanary findings for reporting.
    pub fn to_findings(probe: &TlsProbeResult) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let target_str = if probe.host.contains(':') && !probe.host.starts_with('[') {
            format!("https://[{}]:{}", probe.host, probe.port)
        } else {
            format!("https://{}:{}", probe.host, probe.port)
        };

        if probe.is_post_quantum_safe {
            findings.push(ComprehensiveFinding {
                file_path: target_str.clone(),
                vulnerability_class: "Post-Quantum Cryptographic Transport (Verified)".to_string(),
                description: format!(
                    "Live TLS Handshake negotiated Post-Quantum Hybrid Group '{}' with Cipher Suite '{}' (TLS {}). Endpoint is resilient against quantum harvest-now-decrypt-later attacks.",
                    probe.selected_group, probe.cipher_suite, probe.tls_version
                ),
                severity: "INFO".to_string(),
                line_number: 1,
                remediation: "NIST Post-Quantum TLS standard active. Maintain current key exchange configuration.".to_string(),
                rule_id: Some("PQC-TLS-PROBE-SAFE".to_string()),
                quantum_risk: Some("SAFE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Negotiated: {} | {} | {}", probe.tls_version, probe.cipher_suite, probe.selected_group)),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-tls:{}:{}", probe.host, probe.selected_group)),
            });
        } else {
            findings.push(ComprehensiveFinding {
                file_path: target_str.clone(),
                vulnerability_class: "Quantum-Vulnerable Key Exchange (Store-Now-Decrypt-Later)".to_string(),
                description: format!(
                    "Live TLS Handshake negotiated classical Key Exchange Group '{}' with Cipher Suite '{}' (TLS {}). Traffic can be recorded today and decrypted by a cryptanalytically relevant quantum computer (CRQC).",
                    probe.selected_group, probe.cipher_suite, probe.tls_version
                ),
                severity: "HIGH".to_string(),
                line_number: 1,
                remediation: "Configure edge servers (Nginx, Cloudflare, Envoy) to enable X25519MLKEM768 (0x11ec) or SecP256r1MLKEM768 (0x11ed) hybrid key exchange.".to_string(),
                rule_id: Some("PQC-TLS-PROBE-VULNERABLE".to_string()),
                quantum_risk: Some("VULNERABLE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Negotiated: {} | {} | {}", probe.tls_version, probe.cipher_suite, probe.selected_group)),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-tls:{}:{}", probe.host, probe.selected_group)),
            });
        }

        findings
    }

    /// Constructs a binary TLS 1.3 ClientHello packet offering PQC hybrid groups.
    pub fn build_pqc_client_hello(host: &str) -> Vec<u8> {
        let mut extensions = Vec::new();

        // 1. SNI Extension (0x0000) - RFC 6066 forbids literal IP addresses in HostName SNI
        if host.parse::<std::net::IpAddr>().is_err() && !host.is_empty() {
            let host_bytes = host.as_bytes();
            let sni_list_len = host_bytes.len() + 3;
            let mut sni_ext = vec![0x00, 0x00]; // Extension Type: SNI
            sni_ext.extend_from_slice(&((sni_list_len + 2) as u16).to_be_bytes()); // Ext len
            sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes()); // List len
            sni_ext.push(0x00); // HostName type
            sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(host_bytes);
            extensions.extend_from_slice(&sni_ext);
        }

        // 2. Supported Versions Extension (0x002b): TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
        let mut supp_versions = vec![0x00, 0x2b];
        supp_versions.extend_from_slice(&[0x00, 0x05]); // Length: 5 bytes
        supp_versions.extend_from_slice(&[0x04]); // Versions length: 4 bytes
        supp_versions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        supp_versions.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        extensions.extend_from_slice(&supp_versions);

        // 3. Supported Groups Extension (0x000a) offering full PQC & Classical suite:
        //    0x11ec: X25519MLKEM768 (IANA Standard FIPS 203 Hybrid)
        //    0x11eb: SECP256R1MLKEM768 (NIST Hybrid)
        //    0x11ee: SECP384R1MLKEM1024 (NIST Hybrid)
        //    0x0201: MLKEM768 (Standalone FIPS 203)
        //    0x0202: MLKEM1024 (Standalone FIPS 203)
        //    0x0200: MLKEM512 (Standalone FIPS 203)
        //    0x6399: X25519Kyber768Draft00 (Draft Hybrid)
        //    0x0479: secp256r1Kyber768Draft00
        //    0x001d: X25519 (Classical)
        //    0x0017: secp256r1 (Classical)
        //    0x0018: secp384r1 (Classical)
        let mut groups_ext = vec![0x00, 0x0a];
        let groups = [
            0x11ecu16, 0x11ebu16, 0x11eeu16,
            0x0201u16, 0x0202u16, 0x0200u16,
            0x6399u16, 0x0479u16,
            0x001du16, 0x0017u16, 0x0018u16,
        ];
        let groups_len = groups.len() * 2;
        groups_ext.extend_from_slice(&((groups_len + 2) as u16).to_be_bytes());
        groups_ext.extend_from_slice(&(groups_len as u16).to_be_bytes());
        for g in groups {
            groups_ext.extend_from_slice(&g.to_be_bytes());
        }
        extensions.extend_from_slice(&groups_ext);

        // 4. Signature Algorithms Extension (0x000d)
        let mut sig_ext = vec![0x00, 0x0d];
        let sigs = [0x0403u16, 0x0804u16, 0x0401u16, 0x0501u16]; // ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
        let sigs_len = sigs.len() * 2;
        sig_ext.extend_from_slice(&((sigs_len + 2) as u16).to_be_bytes());
        sig_ext.extend_from_slice(&(sigs_len as u16).to_be_bytes());
        for s in sigs {
            sig_ext.extend_from_slice(&s.to_be_bytes());
        }
        extensions.extend_from_slice(&sig_ext);

        // 5. Key Share Extension (0x0033) offering client key share for X25519 (0x001d, 32-byte ephemeral curve point)
        let mut key_share = vec![0x00, 0x33];
        let probe_ephemeral_pubkey = [0x42u8; 32];
        let client_shares_len = 2 + 2 + probe_ephemeral_pubkey.len();
        key_share.extend_from_slice(&((client_shares_len + 2) as u16).to_be_bytes());
        key_share.extend_from_slice(&(client_shares_len as u16).to_be_bytes());
        key_share.extend_from_slice(&0x001du16.to_be_bytes()); // Group: X25519
        key_share.extend_from_slice(&(probe_ephemeral_pubkey.len() as u16).to_be_bytes());
        key_share.extend_from_slice(&probe_ephemeral_pubkey);
        extensions.extend_from_slice(&key_share);

        // Assemble ClientHello Handshake
        let mut hello_body = Vec::new();
        hello_body.extend_from_slice(&[0x03, 0x03]); // Legacy Client Version: TLS 1.2
        hello_body.extend_from_slice(&[0x01; 32]); // 32 bytes Random
        hello_body.push(0x20); // Session ID len: 32
        hello_body.extend_from_slice(&[0x02; 32]); // Session ID

        // Cipher suites (TLS 1.3 + TLS 1.2 modern)
        let cipher_suites = [
            0x1302u16, // TLS_AES_256_GCM_SHA384
            0x1301u16, // TLS_AES_128_GCM_SHA256
            0x1303u16, // TLS_CHACHA20_POLY1305_SHA256
            0xc02fu16, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030u16, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ];
        let cs_len = cipher_suites.len() * 2;
        hello_body.extend_from_slice(&(cs_len as u16).to_be_bytes());
        for cs in cipher_suites {
            hello_body.extend_from_slice(&cs.to_be_bytes());
        }

        hello_body.extend_from_slice(&[0x01, 0x00]); // Compression methods: null (1 byte)
        hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello_body.extend_from_slice(&extensions);

        // Record Layer Header
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 (Record Version)
        let handshake_len = hello_body.len() + 4;
        record.extend_from_slice(&(handshake_len as u16).to_be_bytes());

        record.push(0x01); // Handshake Type: ClientHello
        record.push(0x00);
        record.extend_from_slice(&(hello_body.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello_body);

        record
    }

    /// Parses ServerHello response bytes to extract negotiated parameters.
    pub fn parse_server_hello(buf: &[u8], host: &str, port: u16, rtt_ms: u128) -> Result<TlsProbeResult, String> {
        // Check for TLS Alert Record (0x15)
        if !buf.is_empty() && buf[0] == 0x15 {
            let level = if buf.len() > 5 { buf[5] } else { 0 };
            let code = if buf.len() > 6 { buf[6] } else { 0 };
            let level_str = match level {
                1 => "Warning",
                2 => "Fatal",
                _ => "Unknown",
            };
            let code_str = match code {
                0 => "close_notify (0)",
                10 => "unexpected_message (10)",
                20 => "bad_record_mac (20)",
                22 => "record_overflow (22)",
                40 => "handshake_failure (40)",
                42 => "bad_certificate (42)",
                43 => "unsupported_certificate (43)",
                44 => "certificate_revoked (44)",
                45 => "certificate_expired (45)",
                46 => "certificate_unknown (46)",
                47 => "illegal_parameter (47)",
                48 => "unknown_ca (48)",
                49 => "access_denied (49)",
                50 => "decode_error (50)",
                51 => "decrypt_error (51)",
                70 => "protocol_version (70)",
                71 => "insufficient_security (71)",
                80 => "internal_error (80)",
                86 => "inappropriate_fallback (86)",
                90 => "user_canceled (90)",
                109 => "missing_extension (109)",
                110 => "unsupported_extension (110)",
                112 => "unrecognized_name (112)",
                115 => "unknown_psk_identity (115)",
                116 => "certificate_required (116)",
                120 => "no_application_protocol (120)",
                _ => "unrecognized_alert",
            };
            return Ok(TlsProbeResult {
                host: host.to_string(),
                port,
                tls_version: "Handshake Rejected (Alert)".to_string(),
                cipher_suite: "None (Alert Terminated)".to_string(),
                selected_group: format!("Server Alert: {} - {}", level_str, code_str),
                is_post_quantum_safe: false,
                is_hybrid: false,
                rtt_ms,
            });
        }

        let mut pos = 5; // Skip record header
        if pos >= buf.len() || buf[pos] != 0x02 { // Handshake Type: ServerHello
            return Ok(TlsProbeResult {
                host: host.to_string(),
                port,
                tls_version: "TLS 1.2 or older".to_string(),
                cipher_suite: "Standard Cipher Suite".to_string(),
                selected_group: "Classical (Legacy Negotiation)".to_string(),
                is_post_quantum_safe: false,
                is_hybrid: false,
                rtt_ms,
            });
        }

        pos += 4; // Skip Handshake Type + 3-byte length
        pos += 2; // Skip server_version
        pos += 32; // Skip random

        if pos >= buf.len() {
            return Err("Truncated ServerHello response".to_string());
        }

        let session_id_len = buf[pos] as usize;
        pos = match pos.checked_add(1 + session_id_len) {
            Some(p) => p,
            None => return Err("Invalid session ID length in ServerHello".to_string()),
        };

        if pos.checked_add(2).map(|p| p > buf.len()).unwrap_or(true) {
            return Err("Missing cipher suite in ServerHello".to_string());
        }

        let cs_id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;
        pos += 1; // Skip compression method

        let cipher_name = match cs_id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            _ => "Unknown Cipher Suite",
        };

        let mut tls_ver = "TLS 1.2";
        let mut group_name = "Classical ECDHE";
        let mut is_pqc = false;
        let mut is_hybrid = false;

        // Parse extensions if present
        if pos + 2 <= buf.len() {
            let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
            let end = (pos + ext_total_len).min(buf.len());

            while pos + 4 <= end {
                let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
                let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
                pos += 4;

                if pos + ext_len > end { break; }
                let ext_data = &buf[pos..pos + ext_len];

                // Extension 0x002b: Supported Versions
                if ext_type == 0x002b && ext_data.len() >= 2 {
                    let ver = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                    if ver == 0x0304 {
                        tls_ver = "TLS 1.3";
                    }
                }

                // Extension 0x0033: Key Share
                if ext_type == 0x0033 && ext_data.len() >= 2 {
                    let group_id = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                    match group_id {
                        0x11ec => {
                            group_name = "X25519MLKEM768 (IANA Standard FIPS 203 Hybrid)";
                            is_pqc = true;
                            is_hybrid = true;
                        }
                        0x11eb | 0x11ed => {
                            group_name = "SECP256R1MLKEM768 (NIST Hybrid PQC)";
                            is_pqc = true;
                            is_hybrid = true;
                        }
                        0x11ee => {
                            group_name = "SECP384R1MLKEM1024 (NIST High-Security Hybrid)";
                            is_pqc = true;
                            is_hybrid = true;
                        }
                        0x0201 => {
                            group_name = "MLKEM768 (Standalone NIST FIPS 203)";
                            is_pqc = true;
                            is_hybrid = false;
                        }
                        0x0202 => {
                            group_name = "MLKEM1024 (Standalone NIST FIPS 203)";
                            is_pqc = true;
                            is_hybrid = false;
                        }
                        0x0200 => {
                            group_name = "MLKEM512 (Standalone NIST FIPS 203)";
                            is_pqc = true;
                            is_hybrid = false;
                        }
                        0x6399 => {
                            group_name = "X25519Kyber768Draft00 (Draft Hybrid PQC)";
                            is_pqc = true;
                            is_hybrid = true;
                        }
                        0x0479 => {
                            group_name = "secp256r1Kyber768Draft00 (Draft Hybrid PQC)";
                            is_pqc = true;
                            is_hybrid = true;
                        }
                        0x001d => {
                            group_name = "X25519 (Classical)";
                        }
                        0x0017 => {
                            group_name = "secp256r1 (Classical P-256)";
                        }
                        0x0018 => {
                            group_name = "secp384r1 (Classical P-384)";
                        }
                        _ => {
                            group_name = "Other Key Exchange Group";
                        }
                    }
                }

                pos += ext_len;
            }
        }

        Ok(TlsProbeResult {
            host: host.to_string(),
            port,
            tls_version: tls_ver.to_string(),
            cipher_suite: cipher_name.to_string(),
            selected_group: group_name.to_string(),
            is_post_quantum_safe: is_pqc,
            is_hybrid,
            rtt_ms,
        })
    }
}
