//! Post-Quantum VPN & Secure Tunnel Configuration Auditor
//!
//! Evaluates WireGuard, strongSwan / IPSec, and OpenVPN configurations for
//! quantum-resilience. Detects classical Diffie-Hellman / ECDH key exchange proposals,
//! audits WireGuard Post-Quantum Pre-Shared Keys (RFC 9370 / Rosenpass daemon integration),
//! and checks IKEv2 / ESP proposals for RFC 9370 Multiple Key Exchanges in IKEv2.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VpnProtocolKind {
    WireGuard,
    IpsecStrongswan,
    OpenVpn,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnTunnelEndpointAudit {
    pub tunnel_identifier: String,
    pub protocol: VpnProtocolKind,
    pub key_exchange_mechanism: String,
    pub is_post_quantum_safe: bool,
    pub is_hybrid: bool,
    pub rosenpass_daemon_active: bool,
    pub psk_configured: bool,
    pub detected_ciphers: Vec<String>,
    pub vulnerability_rating: String,
    pub remediation_guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnAuditReport {
    pub target_file: String,
    pub overall_vpn_readiness: String,
    pub total_tunnels_audited: usize,
    pub quantum_safe_tunnels_count: usize,
    pub classical_vulnerable_count: usize,
    pub tunnels: Vec<VpnTunnelEndpointAudit>,
    pub recommendations: Vec<String>,
}

pub struct VpnScanner;

impl VpnScanner {
    /// Audits a VPN configuration file content (wg0.conf, ipsec.conf, swanctl.conf, or client.ovpn)
    pub fn audit_config(filename: &str, content: &str) -> VpnAuditReport {
        let mut tunnels = Vec::new();
        let mut recommendations = Vec::new();

        let filename_lower = filename.to_lowercase();
        let content_lower = content.to_lowercase();

        // 1. Detect VPN protocol type
        let is_wireguard = filename_lower.contains("wg") || content.contains("[Interface]") || content.contains("[Peer]");
        let is_ipsec = filename_lower.contains("ipsec") || filename_lower.contains("strongswan") || content.contains("conn ") || content.contains("ike=") || content.contains("esp=");
        let is_openvpn = filename_lower.contains(".ovpn") || content.contains("dev tun") || content.contains("proto udp") || content.contains("tls-cipher");

        if is_wireguard {
            // Real parser for WireGuard INI config
            let mut current_peer = String::new();
            let mut has_psk = false;
            let mut psk_entropy_valid = false;
            let mut peer_count = 0;

            for line in content.lines() {
                let line_trim = line.trim();
                if line_trim.starts_with('#') || line_trim.is_empty() {
                    continue;
                }
                if line_trim.eq_ignore_ascii_case("[Peer]") {
                    if !current_peer.is_empty() {
                        tunnels.push(Self::build_wireguard_audit(&current_peer, has_psk, psk_entropy_valid, &content_lower));
                    }
                    peer_count += 1;
                    current_peer = format!("WireGuard-Peer-{}", peer_count);
                    has_psk = false;
                    psk_entropy_valid = false;
                } else if line_trim.starts_with("Endpoint") {
                    let parts: Vec<&str> = line_trim.split('=').collect();
                    if parts.len() >= 2 {
                        current_peer = format!("Peer-{}", parts[1].trim());
                    }
                } else if line_trim.starts_with("PresharedKey") {
                    has_psk = true;
                    let parts: Vec<&str> = line_trim.split('=').collect();
                    if parts.len() >= 2 {
                        let key_val = parts[1].trim();
                        // 256-bit base64 key is 44 characters (including padding)
                        if key_val.len() == 44 {
                            psk_entropy_valid = true;
                        }
                    }
                }
            }

            if !current_peer.is_empty() {
                tunnels.push(Self::build_wireguard_audit(&current_peer, has_psk, psk_entropy_valid, &content_lower));
            } else {
                // Single interface representation
                tunnels.push(Self::build_wireguard_audit("WireGuard-Interface", has_psk, psk_entropy_valid, &content_lower));
            }

            let has_rosenpass = content_lower.contains("rosenpass") || content_lower.contains("rp_");
            if !has_rosenpass {
                recommendations.push("Deploy Rosenpass post-quantum key exchange daemon alongside WireGuard to inject rotated ML-KEM/McEliece PSKs.".to_string());
            }
            if !has_psk {
                recommendations.push("Generate and inject 256-bit post-quantum PresharedKey into all WireGuard [Peer] sections.".to_string());
            }
        } else if is_ipsec {
            // Real parser for strongSwan ipsec.conf / swanctl.conf
            let mut conn_name = "default-ipsec-connection".to_string();
            let mut ike_proposals = Vec::new();
            let mut esp_proposals = Vec::new();

            for line in content.lines() {
                let line_trim = line.trim();
                if line_trim.starts_with("conn ") {
                    conn_name = line_trim.replace("conn ", "").trim().to_string();
                } else if line_trim.starts_with("ike=") || line_trim.starts_with("ike =") {
                    let parts: Vec<&str> = line_trim.split('=').collect();
                    if parts.len() >= 2 {
                        ike_proposals.extend(parts[1].trim().split(',').map(|s| s.trim().to_string()));
                    }
                } else if line_trim.starts_with("esp=") || line_trim.starts_with("esp =") {
                    let parts: Vec<&str> = line_trim.split('=').collect();
                    if parts.len() >= 2 {
                        esp_proposals.extend(parts[1].trim().split(',').map(|s| s.trim().to_string()));
                    }
                }
            }

            let mut all_ciphers = Vec::new();
            all_ciphers.extend(ike_proposals.clone());
            all_ciphers.extend(esp_proposals.clone());

            let has_pqc_transform = ike_proposals.iter().any(|p| {
                let p_low = p.to_lowercase();
                p_low.contains("mlkem") || p_low.contains("kyber") || p_low.contains("frodo") || p_low.contains("mceliece")
            });

            let is_classical_dh = ike_proposals.iter().any(|p| {
                let p_low = p.to_lowercase();
                p_low.contains("modp1024") || p_low.contains("modp1536") || p_low.contains("modp2048") || p_low.contains("ecp256") || p_low.contains("curve25519")
            });

            tunnels.push(VpnTunnelEndpointAudit {
                tunnel_identifier: conn_name,
                protocol: VpnProtocolKind::IpsecStrongswan,
                key_exchange_mechanism: if has_pqc_transform { "RFC 9370 Hybrid IKEv2 (ML-KEM + ECDH)".to_string() } else { "Classical IKEv2 (Diffie-Hellman / ECDH)".to_string() },
                is_post_quantum_safe: has_pqc_transform,
                is_hybrid: has_pqc_transform && is_classical_dh,
                rosenpass_daemon_active: false,
                psk_configured: content_lower.contains("authby=secret") || content_lower.contains("psk"),
                detected_ciphers: all_ciphers,
                vulnerability_rating: if has_pqc_transform { "LOW_QUANTUM_RESILIENT".to_string() } else { "CRITICAL_HARVEST_NOW_DECRYPT_LATER".to_string() },
                remediation_guidance: if has_pqc_transform {
                    "IPSec configuration conforms to RFC 9370 Multiple Key Exchanges in IKEv2.".to_string()
                } else {
                    "Update ike proposal in ipsec.conf to negotiate RFC 9370 hybrid ML-KEM transforms (e.g. ike=aes256gcm16-prfsha384-curve25519-mlkem768).".to_string()
                },
            });

            if !has_pqc_transform {
                recommendations.push("Upgrade strongSwan to v5.9.14+ with liboqs plugin enabled for RFC 9370 post-quantum KEX.".to_string());
                recommendations.push("Deprecate legacy Diffie-Hellman Group 2 (modp1024) and Group 14 (modp2048).".to_string());
            }
        } else if is_openvpn {
            // Real parser for OpenVPN configuration
            let has_pqc_tls = content_lower.contains("x25519mlkem768") || content_lower.contains("mlkem");
            let mut ciphers = Vec::new();
            for line in content.lines() {
                let line_trim = line.trim();
                if line_trim.starts_with("data-ciphers ") || line_trim.starts_with("cipher ") || line_trim.starts_with("tls-cipher ") {
                    ciphers.push(line_trim.to_string());
                }
            }

            tunnels.push(VpnTunnelEndpointAudit {
                tunnel_identifier: "OpenVPN-Client-Profile".to_string(),
                protocol: VpnProtocolKind::OpenVpn,
                key_exchange_mechanism: if has_pqc_tls { "TLS 1.3 Hybrid Post-Quantum KEM".to_string() } else { "TLS 1.2/1.3 Classical ECDHE".to_string() },
                is_post_quantum_safe: has_pqc_tls,
                is_hybrid: has_pqc_tls,
                rosenpass_daemon_active: false,
                psk_configured: content_lower.contains("tls-auth") || content_lower.contains("tls-crypt"),
                detected_ciphers: ciphers,
                vulnerability_rating: if has_pqc_tls { "SAFE".to_string() } else { "HIGH_QUANTUM_VULNERABLE".to_string() },
                remediation_guidance: if has_pqc_tls {
                    "OpenVPN tunnel utilizes quantum-safe TLS 1.3 hybrid key exchange.".to_string()
                } else {
                    "Configure tls-groups X25519MLKEM768 in OpenVPN 2.6+ with OpenSSL 3.3+ backend.".to_string()
                },
            });

            if !has_pqc_tls {
                recommendations.push("Inject 'tls-groups X25519MLKEM768:X25519' into OpenVPN client/server profiles.".to_string());
            }
        } else {
            // Generic network configuration fallback
            tunnels.push(VpnTunnelEndpointAudit {
                tunnel_identifier: filename.to_string(),
                protocol: VpnProtocolKind::Unknown,
                key_exchange_mechanism: "Unrecognized VPN Profile".to_string(),
                is_post_quantum_safe: false,
                is_hybrid: false,
                rosenpass_daemon_active: false,
                psk_configured: false,
                detected_ciphers: vec![],
                vulnerability_rating: "INDETERMINATE".to_string(),
                remediation_guidance: "Provide WireGuard (wg0.conf), strongSwan (ipsec.conf), or OpenVPN (.ovpn) configuration file.".to_string(),
            });
        }

        let pq_safe = tunnels.iter().filter(|t| t.is_post_quantum_safe).count();
        let classical = tunnels.len() - pq_safe;
        let overall = if tunnels.iter().any(|t| t.protocol == VpnProtocolKind::Unknown) {
            "UNRECOGNIZED_VPN_CONFIGURATION".to_string()
        } else if classical == 0 && !tunnels.is_empty() {
            "POST_QUANTUM_RESILIENT_SECURE_TUNNEL".to_string()
        } else {
            "VULNERABLE_HARVEST_NOW_DECRYPT_LATER_VPN".to_string()
        };

        VpnAuditReport {
            target_file: filename.to_string(),
            overall_vpn_readiness: overall,
            total_tunnels_audited: tunnels.len(),
            quantum_safe_tunnels_count: pq_safe,
            classical_vulnerable_count: classical,
            tunnels,
            recommendations,
        }
    }

    fn build_wireguard_audit(peer_id: &str, has_psk: bool, psk_entropy_valid: bool, content_lower: &str) -> VpnTunnelEndpointAudit {
        let has_rosenpass = content_lower.contains("rosenpass") || content_lower.contains("rp_");
        let is_safe = has_rosenpass || (has_psk && psk_entropy_valid);

        VpnTunnelEndpointAudit {
            tunnel_identifier: peer_id.to_string(),
            protocol: VpnProtocolKind::WireGuard,
            key_exchange_mechanism: if has_rosenpass {
                "Rosenpass Protocol (Classic McEliece + ML-KEM-768)"
            } else if has_psk {
                "WireGuard + Post-Quantum 256-bit PSK (RFC-Adjacent)"
            } else {
                "Classical Curve25519 Noise_IKpsk2 (No PSK Attached)"
            }.to_string(),
            is_post_quantum_safe: is_safe,
            is_hybrid: is_safe,
            rosenpass_daemon_active: has_rosenpass,
            psk_configured: has_psk,
            detected_ciphers: vec!["ChaCha20-Poly1305 (Payload)".to_string(), "Curve25519 (Noise IK)".to_string(), "BLAKE2s (MAC)".to_string()],
            vulnerability_rating: if is_safe { "RESILIENT".to_string() } else { "CRITICAL_STORE_NOW_DECRYPT_LATER".to_string() },
            remediation_guidance: if is_safe {
                "Peer possesses quantum-resistant symmetric entropy barrier.".to_string()
            } else {
                "Execute 'wg genpsk' to generate a 256-bit pre-shared key or run 'rosenpass' daemon.".to_string()
            },
        }
    }

    /// Formats the VPN audit report as readable Markdown
    pub fn format_markdown(report: &VpnAuditReport) -> String {
        let mut md = String::new();
        md.push_str("# Post-Quantum VPN & Secure Tunnel Audit Report\n\n");
        md.push_str(&format!("* **Configuration Target:** `{}`\n", report.target_file));
        md.push_str(&format!("* **Overall Readiness:** `{}`\n", report.overall_vpn_readiness));
        md.push_str(&format!("* **Tunnels Inspected:** {} (Quantum-Safe: {}, Vulnerable: {})\n\n",
            report.total_tunnels_audited, report.quantum_safe_tunnels_count, report.classical_vulnerable_count));

        md.push_str("| Tunnel ID | Protocol | Key Exchange Mechanism | PSK / Rosenpass | Risk Rating |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
        for t in &report.tunnels {
            let prot_str = match t.protocol {
                VpnProtocolKind::WireGuard => "WireGuard",
                VpnProtocolKind::IpsecStrongswan => "IPSec strongSwan",
                VpnProtocolKind::OpenVpn => "OpenVPN",
                VpnProtocolKind::Unknown => "Unknown",
            };
            let psk_str = if t.rosenpass_daemon_active {
                "ROSENPASS (ACTIVE)"
            } else if t.psk_configured {
                "STATIC 256-BIT PSK"
            } else {
                "NONE (CLASSICAL ONLY)"
            };
            md.push_str(&format!("| `{}` | {} | {} | {} | `{}` |\n",
                t.tunnel_identifier, prot_str, t.key_exchange_mechanism, psk_str, t.vulnerability_rating
            ));
        }

        if !report.recommendations.is_empty() {
            md.push_str("\n### Migration & Remediation Recommendations\n\n");
            for r in &report.recommendations {
                md.push_str(&format!("* {}\n", r));
            }
        }

        md
    }
}
