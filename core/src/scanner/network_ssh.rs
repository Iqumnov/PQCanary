//! Active Network SSH & Post-Quantum Cryptographic Handshake Probe
//!
//! Connects directly to remote SSH servers over TCP (default port 22), executing
//! the initial SSH 2.0 transport protocol handshake (RFC 4253):
//! 1. Exchanging client/server identification strings (e.g. `SSH-2.0-OpenSSH_9.6p1`).
//! 2. Parsing the binary `SSH_MSG_KEXINIT` packet (type 20).
//! 3. Extracting and analyzing offered Key Exchange (`kex_algorithms`) and host key algorithms.
//!
//! Evaluates whether the SSH endpoint supports Post-Quantum Hybrid KEX:
//! - `sntrup761x25519-sha512@openssh.com` (OpenSSH 9.0+ default hybrid)
//! - `mlkem768x25519-sha256` (NIST FIPS 203 hybrid draft)
//! - `mlkem768x25519-sha512`
//! - `frodo640aes-sha384`
//!
//! Or is restricted to classical algorithms vulnerable to Store-Now-Decrypt-Later
//! (`curve25519-sha256`, `ecdh-sha2-nistp256`, `diffie-hellman-group14-sha1`).

use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::scanner::orchestrator::ComprehensiveFinding;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshProbeResult {
    pub host: String,
    pub port: u16,
    pub server_banner: String,
    pub kex_algorithms: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub ciphers_c2s: Vec<String>,
    pub is_post_quantum_safe: bool,
    pub pqc_kex_supported: Vec<String>,
    pub weak_kex_detected: Vec<String>,
    pub rtt_ms: u128,
}

pub struct NetworkSshProbe;

impl NetworkSshProbe {
    /// Known Post-Quantum and Hybrid SSH Key Exchange algorithms.
    pub const PQC_KEX_ALGORITHMS: &'static [&'static str] = &[
        "sntrup761x25519-sha512@openssh.com",
        "mlkem768x25519-sha256",
        "mlkem768x25519-sha512",
        "sntrup761x25519-sha512",
        "frodo640aes-sha384",
        "frodo976aes-sha384",
        "kyber512-sha256",
        "kyber768-sha384",
        "kyber1024-sha512",
    ];

    /// Deprecated or broken classical SSH Key Exchange algorithms.
    pub const WEAK_KEX_ALGORITHMS: &'static [&'static str] = &[
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ];

    /// Extracts host and port from target string (e.g. `ssh://git.example.com:2222` -> `("git.example.com", 2222)`).
    /// Robustly supports bracketed IPv6 literals (e.g. `[::1]:2222`) and strips user credentials (e.g. `git@host`).
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
                let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(22);
                return (host.to_string(), port);
            }
        }

        // If the entire clean string is a valid IPv6 address without brackets, do not split on colons
        if clean.parse::<std::net::Ipv6Addr>().is_ok() {
            return (clean.to_string(), 22);
        }

        if let Some((h, p)) = clean.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(22))
        } else {
            (clean.to_string(), 22)
        }
    }

    /// Performs live SSH 2.0 handshake probe against target host:port.
    pub async fn probe_endpoint(host: &str, port: u16) -> Result<SshProbeResult, String> {
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
        .map_err(|_| format!("Connection timeout to SSH endpoint {}", addr))?
        .map_err(|e| format!("Failed to connect to SSH endpoint {}: {}", addr, e))?;

        // 1. Read Server Identification Banner (e.g. "SSH-2.0-OpenSSH_9.6p1 ... \r\n")
        // RFC 4253 Section 4.2 allows servers to send header lines before the "SSH-2.0-" identification line.
        let mut banner_buffer = [0u8; 1024];
        let mut banner_bytes_read = 0;
        let mut clean_banner = String::new();

        loop {
            let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut banner_buffer[banner_bytes_read..]))
                .await
                .map_err(|_| "SSH banner read timeout".to_string())?
                .map_err(|e| format!("Failed to read SSH banner: {}", e))?;

            if n == 0 {
                break;
            }
            banner_bytes_read += n;

            let text = String::from_utf8_lossy(&banner_buffer[..banner_bytes_read]);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("SSH-") {
                    clean_banner = trimmed.to_string();
                    break;
                }
            }

            if !clean_banner.is_empty() || banner_bytes_read >= banner_buffer.len() {
                break;
            }
        }

        if !clean_banner.starts_with("SSH-") {
            return Err(format!("Invalid SSH protocol banner from {}: '{}'", addr, clean_banner));
        }

        // 2. Send Client Identification Banner
        let client_banner = b"SSH-2.0-PQCanary_1.0.0\r\n";
        stream.write_all(client_banner).await
            .map_err(|e| format!("Failed to write SSH client banner: {}", e))?;

        // 3. Read Server SSH_MSG_KEXINIT packet
        let mut pkt_len_buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut pkt_len_buf))
            .await
            .map_err(|_| "SSH packet length read timeout".to_string())?
            .map_err(|e| format!("Failed to read SSH packet length: {}", e))?;

        let packet_length = u32::from_be_bytes(pkt_len_buf) as usize;
        if packet_length == 0 || packet_length > 35000 {
            return Err(format!("Unreasonable SSH packet length: {}", packet_length));
        }

        let mut payload_buf = vec![0u8; packet_length];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut payload_buf))
            .await
            .map_err(|_| "SSH packet payload read timeout".to_string())?
            .map_err(|e| format!("Failed to read SSH packet payload: {}", e))?;

        let rtt_ms = start_time.elapsed().as_millis();

        Self::parse_kexinit_payload(&payload_buf, host, port, &clean_banner, rtt_ms)
    }

    /// Parses the raw body of an SSH_MSG_KEXINIT packet (excluding the 4-byte packet length).
    pub fn parse_kexinit_payload(
        payload: &[u8],
        host: &str,
        port: u16,
        server_banner: &str,
        rtt_ms: u128,
    ) -> Result<SshProbeResult, String> {
        if payload.len() < 18 {
            return Err("SSH_MSG_KEXINIT packet too short".to_string());
        }

        let _padding_length = payload[0] as usize;
        let msg_type = payload[1];

        if msg_type != 20 {
            return Err(format!("Expected SSH_MSG_KEXINIT (20), received message type {}", msg_type));
        }

        // Skip 1 byte padding_len + 1 byte msg_type + 16 bytes cookie = 18 bytes
        let mut cursor = 18;

        let kex_algorithms = Self::read_name_list(payload, &mut cursor)?;
        let host_key_algorithms = Self::read_name_list(payload, &mut cursor)?;
        let ciphers_c2s = Self::read_name_list(payload, &mut cursor)?;

        let mut pqc_kex_supported = Vec::new();
        let mut weak_kex_detected = Vec::new();

        for algo in &kex_algorithms {
            let lower = algo.to_ascii_lowercase();
            if Self::PQC_KEX_ALGORITHMS.iter().any(|&pqc| lower == pqc) {
                pqc_kex_supported.push(algo.clone());
            }
            if Self::WEAK_KEX_ALGORITHMS.iter().any(|&weak| lower == weak) {
                weak_kex_detected.push(algo.clone());
            }
        }

        let is_post_quantum_safe = !pqc_kex_supported.is_empty();

        Ok(SshProbeResult {
            host: host.to_string(),
            port,
            server_banner: server_banner.to_string(),
            kex_algorithms,
            host_key_algorithms,
            ciphers_c2s,
            is_post_quantum_safe,
            pqc_kex_supported,
            weak_kex_detected,
            rtt_ms,
        })
    }

    /// Reads an SSH string/name-list: 4 bytes big-endian length followed by comma-separated ASCII string.
    fn read_name_list(data: &[u8], cursor: &mut usize) -> Result<Vec<String>, String> {
        let header_end = cursor.checked_add(4)
            .ok_or_else(|| "Integer overflow reading SSH name-list length".to_string())?;
        if header_end > data.len() {
            return Err("Unexpected end of SSH packet reading name-list length".to_string());
        }

        let len = u32::from_be_bytes([
            data[*cursor],
            data[*cursor + 1],
            data[*cursor + 2],
            data[*cursor + 3],
        ]) as usize;
        *cursor += 4;

        let content_end = cursor.checked_add(len)
            .ok_or_else(|| "Integer overflow reading SSH name-list contents".to_string())?;
        if content_end > data.len() {
            return Err("Unexpected end of SSH packet reading name-list contents".to_string());
        }

        let name_bytes = &data[*cursor..content_end];
        *cursor += len;

        let name_str = std::str::from_utf8(name_bytes)
            .map_err(|e| format!("Invalid UTF-8 in SSH name-list: {}", e))?;

        if name_str.trim().is_empty() {
            Ok(Vec::new())
        } else {
            Ok(name_str.split(',').map(|s| s.trim().to_string()).collect())
        }
    }

    /// Converts an SSH probe result into standard PQCanary findings for reporting.
    pub fn to_findings(probe: &SshProbeResult) -> Vec<ComprehensiveFinding> {
        let mut findings = Vec::new();
        let target_str = if probe.host.contains(':') && !probe.host.starts_with('[') {
            format!("ssh://[{}]:{}", probe.host, probe.port)
        } else {
            format!("ssh://{}:{}", probe.host, probe.port)
        };

        if probe.is_post_quantum_safe {
            findings.push(ComprehensiveFinding {
                file_path: target_str.clone(),
                vulnerability_class: "Post-Quantum Cryptographic SSH Transport (Verified)".to_string(),
                description: format!(
                    "Live SSH handshake with '{}' verified support for Post-Quantum Hybrid KEX: [{}]. Server is protected against quantum Store-Now-Decrypt-Later attacks.",
                    probe.server_banner, probe.pqc_kex_supported.join(", ")
                ),
                severity: "INFO".to_string(),
                line_number: 1,
                remediation: "OpenSSH Post-Quantum hybrid key exchange is active. Maintain modern OpenSSH 9.0+ configuration.".to_string(),
                rule_id: Some("PQC-SSH-PROBE-SAFE".to_string()),
                quantum_risk: Some("SAFE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Server: {} | PQC KEX: {}", probe.server_banner, probe.pqc_kex_supported.join(", "))),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-ssh-safe:{}:{}", probe.host, probe.pqc_kex_supported.first().unwrap_or(&"pqc".to_string()))),
            });
        } else {
            findings.push(ComprehensiveFinding {
                file_path: target_str.clone(),
                vulnerability_class: "Quantum-Vulnerable SSH Key Exchange (Store-Now-Decrypt-Later)".to_string(),
                description: format!(
                    "Live SSH handshake with '{}' revealed NO Post-Quantum Hybrid KEX algorithms. Server offers only classical key exchange (e.g. {}). Encrypted terminal sessions can be archived today and decrypted by a CRQC.",
                    probe.server_banner, probe.kex_algorithms.first().cloned().unwrap_or_else(|| "classical".to_string())
                ),
                severity: "HIGH".to_string(),
                line_number: 1,
                remediation: "Upgrade server to OpenSSH 9.0+ and ensure `KexAlgorithms sntrup761x25519-sha512@openssh.com` is enabled in /etc/ssh/sshd_config.".to_string(),
                rule_id: Some("PQC-SSH-PROBE-VULNERABLE".to_string()),
                quantum_risk: Some("VULNERABLE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Server: {} | Offered KEX: {}", probe.server_banner, probe.kex_algorithms.iter().take(4).cloned().collect::<Vec<_>>().join(", "))),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-ssh-vuln:{}:{}", probe.host, probe.port)),
            });
        }

        if !probe.weak_kex_detected.is_empty() {
            findings.push(ComprehensiveFinding {
                file_path: target_str,
                vulnerability_class: "Classically Broken SSH Key Exchange (SHA-1 / Small DH)".to_string(),
                description: format!(
                    "Server advertises obsolete, classically vulnerable SSH key exchange algorithms: [{}].",
                    probe.weak_kex_detected.join(", ")
                ),
                severity: "CRITICAL".to_string(),
                line_number: 1,
                remediation: "Immediately remove diffie-hellman-group1-sha1 and SHA-1 key exchange groups from sshd_config.".to_string(),
                rule_id: Some("PQC-SSH-WEAK-KEX".to_string()),
                quantum_risk: Some("VULNERABLE".to_string()),
                confidence: Some("HIGH".to_string()),
                snippet: Some(format!("Weak KEX: {}", probe.weak_kex_detected.join(", "))),
                column_number: Some(1),
                fingerprint: Some(format!("pqc-ssh-weak:{}:{}", probe.host, probe.weak_kex_detected.join("-"))),
            });
        }

        findings
    }
}
