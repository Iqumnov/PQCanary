//! Native Host & Container OS Cryptographic Environment Auditor
//!
//! Inspects the host operating system's installed cryptographic runtimes, dynamic libraries,
//! OpenSSL / LibreSSL engines, and system trust stores to evaluate whether the host environment
//! possesses native Post-Quantum Cryptography (PQC) capabilities or remains bound to legacy classical cryptography.

use std::process::Command;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCryptoLibrary {
    pub name: String,
    pub path: String,
    pub detected: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCryptoAuditReport {
    pub os_name: String,
    pub os_family: String,
    pub arch: String,
    pub openssl_detected: bool,
    pub openssl_version: Option<String>,
    pub openssl_pqc_ready: bool,
    pub system_crypto_libraries: Vec<SystemCryptoLibrary>,
    pub trust_store_path: Option<String>,
    pub quantum_readiness_posture: String, // "QUANTUM_RESILIENT", "TRANSITIONING", "LEGACY_AT_RISK"
    pub recommendations: Vec<String>,
}

pub struct OsCryptoAuditor;

impl OsCryptoAuditor {
    /// Perform a deep cryptographic inspection of the local host system environment.
    pub fn audit_host() -> HostCryptoAuditReport {
        let os_family = std::env::consts::FAMILY.to_string();
        let os_name = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let mut libraries = Vec::new();
        let mut recommendations = Vec::new();

        // 1. Probe for OpenSSL binary and version
        let (openssl_detected, openssl_version, openssl_pqc_ready) = Self::probe_openssl(&mut libraries);

        // 2. Probe platform-specific cryptographic system libraries
        Self::probe_platform_libraries(&os_name, &mut libraries);

        // 3. Locate system root trust store
        let trust_store_path = Self::locate_system_trust_store(&os_name);

        // 4. Formulate recommendations and calculate quantum posture
        let posture = if openssl_pqc_ready {
            "QUANTUM_RESILIENT".to_string()
        } else if openssl_detected {
            recommendations.push("Host OpenSSL does not support native NIST FIPS 203 ML-KEM or OQS provider. Install `oqs-provider` or upgrade to OpenSSL with PQC extensions.".to_string());
            "TRANSITIONING".to_string()
        } else {
            recommendations.push("No standard OpenSSL runtime detected in PATH. Ensure TLS termination proxies support hybrid post-quantum key exchange.".to_string());
            "LEGACY_AT_RISK".to_string()
        };

        if os_name == "windows" {
            recommendations.push("Ensure Windows CNG (Cryptography Next Generation) and Schannel are updated for post-quantum TLS 1.3 curve support.".to_string());
        }

        HostCryptoAuditReport {
            os_name,
            os_family,
            arch,
            openssl_detected,
            openssl_version,
            openssl_pqc_ready,
            system_crypto_libraries: libraries,
            trust_store_path,
            quantum_readiness_posture: posture,
            recommendations,
        }
    }

    fn probe_openssl(libraries: &mut Vec<SystemCryptoLibrary>) -> (bool, Option<String>, bool) {
        let output = Command::new("openssl")
            .arg("version")
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let ver_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let lower = ver_str.to_lowercase();
                let is_pqc = lower.contains("oqs") || lower.contains("mlkem") || lower.contains("kyber") || lower.contains("pqc");

                libraries.push(SystemCryptoLibrary {
                    name: "OpenSSL CLI Runtime".to_string(),
                    path: "PATH/openssl".to_string(),
                    detected: true,
                    details: ver_str.clone(),
                });

                (true, Some(ver_str), is_pqc)
            }
            _ => {
                libraries.push(SystemCryptoLibrary {
                    name: "OpenSSL CLI Runtime".to_string(),
                    path: "PATH/openssl".to_string(),
                    detected: false,
                    details: "Not found in system PATH".to_string(),
                });
                (false, None, false)
            }
        }
    }

    fn probe_platform_libraries(os: &str, libraries: &mut Vec<SystemCryptoLibrary>) {
        if os == "windows" {
            let win_dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
            let bcrypt_path = format!("{}\\System32\\bcrypt.dll", win_dir);
            let schannel_path = format!("{}\\System32\\schannel.dll", win_dir);
            let ncrypt_path = format!("{}\\System32\\ncrypt.dll", win_dir);

            libraries.push(SystemCryptoLibrary {
                name: "Windows CNG Core (bcrypt.dll)".to_string(),
                path: bcrypt_path.clone(),
                detected: std::path::Path::new(&bcrypt_path).exists(),
                details: "Windows Cryptography Next Generation Kernel Primitive Provider".to_string(),
            });

            libraries.push(SystemCryptoLibrary {
                name: "Windows Secure Channel (schannel.dll)".to_string(),
                path: schannel_path.clone(),
                detected: std::path::Path::new(&schannel_path).exists(),
                details: "Windows Security Support Provider (SSP) for TLS/SSL Handshakes".to_string(),
            });

            libraries.push(SystemCryptoLibrary {
                name: "Windows Key Storage Provider (ncrypt.dll)".to_string(),
                path: ncrypt_path.clone(),
                detected: std::path::Path::new(&ncrypt_path).exists(),
                details: "Windows Cryptographic Hardware and Software Key Storage Provider".to_string(),
            });
        } else {
            let candidates = [
                ("libcrypto.so", "/usr/lib/libcrypto.so"),
                ("libssl.so", "/usr/lib/libssl.so"),
                ("libgnutls.so", "/usr/lib/libgnutls.so"),
                ("libsodium.so", "/usr/lib/libsodium.so"),
                ("libgcrypt.so", "/usr/lib/libgcrypt.so"),
                ("libnss3.so", "/usr/lib/libnss3.so"),
            ];

            for (name, path) in candidates {
                let exists = std::path::Path::new(path).exists()
                    || std::path::Path::new(&format!("/usr/lib/x86_64-linux-gnu/{}", name)).exists()
                    || std::path::Path::new(&format!("/usr/lib64/{}", name)).exists();

                libraries.push(SystemCryptoLibrary {
                    name: name.to_string(),
                    path: path.to_string(),
                    detected: exists,
                    details: if exists { "Installed system shared library".to_string() } else { "Not found in standard paths".to_string() },
                });
            }
        }
    }

    fn locate_system_trust_store(os: &str) -> Option<String> {
        if os == "windows" {
            Some("Windows CryptoAPI System Certificate Store (Cert:\\LocalMachine\\Root)".to_string())
        } else {
            let paths = [
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                "/etc/ssl/cert.pem",
            ];
            for p in paths {
                if std::path::Path::new(p).exists() {
                    return Some(p.to_string());
                }
            }
            None
        }
    }

    /// Formats the audit report as a clean terminal / markdown summary card.
    pub fn format_markdown(report: &HostCryptoAuditReport) -> String {
        let mut out = String::new();
        out.push_str("# PQCanary Host Cryptographic Environment Audit\n\n");
        out.push_str(&format!("- **Operating System**: {} ({}) [{}]\n", report.os_name, report.os_family, report.arch));
        out.push_str(&format!("- **Quantum Posture**: `{}`\n", report.quantum_readiness_posture));
        if let Some(ref ver) = report.openssl_version {
            out.push_str(&format!("- **OpenSSL Version**: `{}` (PQC Capable: {})\n", ver, report.openssl_pqc_ready));
        } else {
            out.push_str("- **OpenSSL CLI**: Not detected in system PATH\n");
        }
        if let Some(ref ts) = report.trust_store_path {
            out.push_str(&format!("- **System Trust Store**: `{}`\n", ts));
        }

        out.push_str("\n### Discovered Cryptographic Runtimes & Providers\n\n");
        out.push_str("| Provider / Runtime | Path | Status | Details |\n");
        out.push_str("|---|---|---|---|\n");
        for lib in &report.system_crypto_libraries {
            let status = if lib.detected { "Detected" } else { "Missing" };
            out.push_str(&format!("| {} | `{}` | {} | {} |\n", lib.name, lib.path, status, lib.details));
        }

        if !report.recommendations.is_empty() {
            out.push_str("\n### Quantum Migration Recommendations\n\n");
            for rec in &report.recommendations {
                out.push_str(&format!("- Warning: {}\n", rec));
            }
        }

        out
    }
}
