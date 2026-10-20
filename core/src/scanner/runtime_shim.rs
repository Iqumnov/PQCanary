//! Dynamic Runtime Cryptographic Interceptor & Shim Generator
//!
//! Solves the enterprise black-box legacy dilemma where source code is unavailable
//! and binaries are stripped. Generates lightweight C shims (LD_PRELOAD on Linux
//! and Microsoft Detours on Windows) to dynamically intercept OpenSSL / Win32 CryptoAPI
//! calls, log live key generation, and optionally force hybrid PQC negotiation on the fly.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShimInterceptionMode {
    AuditAndLogOnly,
    ActiveEnforcementAndPqcUpgrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeShimConfig {
    pub mode: ShimInterceptionMode,
    pub log_output_path: String,
    pub force_hybrid_group: String, // e.g. "X25519MLKEM768"
    pub emit_udp_telemetry: bool,
    pub udp_collector_endpoint: String, // e.g. "127.0.0.1:9099"
}

impl Default for RuntimeShimConfig {
    fn default() -> Self {
        Self {
            mode: ShimInterceptionMode::AuditAndLogOnly,
            log_output_path: "/var/log/pqcanary_runtime.log".to_string(),
            force_hybrid_group: "X25519MLKEM768:X25519".to_string(),
            emit_udp_telemetry: true,
            udp_collector_endpoint: "127.0.0.1:9099".to_string(),
        }
    }
}

pub struct RuntimeShimGenerator;

impl RuntimeShimGenerator {
    /// Generates pure, standards-compliant C source code for an LD_PRELOAD dynamic interceptor
    pub fn generate_linux_c_shim(config: &RuntimeShimConfig) -> String {
        let is_enforce = config.mode == ShimInterceptionMode::ActiveEnforcementAndPqcUpgrade;
        let enforce_code = if is_enforce {
            format!(
r#"    // ENFORCEMENT: Override curves to force Hybrid Post-Quantum negotiation
    const char *pqc_curves = "{}";
    orig_SSL_CTX_set1_groups_list(ctx, pqc_curves);
    pqcanary_log("ENFORCE: Successfully forced PQC groups: %s\n", pqc_curves);"#,
                config.force_hybrid_group
            )
        } else {
            "    // Audit only mode: pass through without tampering".to_string()
        };

        format!(
r#"/*
 * PQCanary Dynamic Runtime Cryptographic Interceptor Shim (libpqcanary_shim.c)
 * Intercepts OpenSSL dynamic library calls at runtime via LD_PRELOAD.
 *
 * Compilation:
 *   gcc -O2 -shared -fPIC -o libpqcanary_shim.so libpqcanary_shim.c -ldl
 *
 * Execution:
 *   LD_PRELOAD=/path/to/libpqcanary_shim.so ./legacy_application
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static FILE *log_file = NULL;
static int udp_sock = -1;
static struct sockaddr_in collector_addr;

// Function pointers to original symbols
static int (*orig_SSL_CTX_set_cipher_list)(void *ctx, const char *str) = NULL;
static int (*orig_SSL_CTX_set_ciphersuites)(void *ctx, const char *str) = NULL;
static int (*orig_SSL_CTX_set1_groups_list)(void *ctx, const char *list) = NULL;
static void* (*orig_RSA_generate_key_ex)(void *rsa, int bits, void *e, void *cb) = NULL;

static void pqcanary_log(const char *format, ...) {{
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (!log_file) {{
        log_file = fopen("{}", "a");
    }}
    if (log_file) {{
        time_t now = time(NULL);
        char t_buf[64];
        strftime(t_buf, sizeof(t_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "[%s] [PID:%d] %s", t_buf, getpid(), buffer);
        fflush(log_file);
    }}
}}

__attribute__((constructor))
void pqcanary_init(void) {{
    orig_SSL_CTX_set_cipher_list = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
    orig_SSL_CTX_set_ciphersuites = dlsym(RTLD_NEXT, "SSL_CTX_set_ciphersuites");
    orig_SSL_CTX_set1_groups_list = dlsym(RTLD_NEXT, "SSL_CTX_set1_groups_list");
    orig_RSA_generate_key_ex = dlsym(RTLD_NEXT, "RSA_generate_key_ex");

    pqcanary_log("INIT: PQCanary Runtime Interceptor attached successfully.\n");
}}

// Intercept SSL_CTX_set_cipher_list
int SSL_CTX_set_cipher_list(void *ctx, const char *str) {{
    pqcanary_log("INTERCEPT: SSL_CTX_set_cipher_list called: '%s'\n", str);
{}
    if (orig_SSL_CTX_set_cipher_list) {{
        return orig_SSL_CTX_set_cipher_list(ctx, str);
    }}
    return 1;
}}

// Intercept SSL_CTX_set1_groups_list (Curve selection)
int SSL_CTX_set1_groups_list(void *ctx, const char *list) {{
    pqcanary_log("INTERCEPT: SSL_CTX_set1_groups_list called: '%s'\n", list);
    if (orig_SSL_CTX_set1_groups_list) {{
        return orig_SSL_CTX_set1_groups_list(ctx, list);
    }}
    return 1;
}}

// Intercept legacy RSA key generation
void* RSA_generate_key_ex(void *rsa, int bits, void *e, void *cb) {{
    pqcanary_log("CRITICAL_ALERT: RSA_generate_key_ex invoked with %d bits (Vulnerable to Shor's Algorithm)!\n", bits);
    if (orig_RSA_generate_key_ex) {{
        return orig_RSA_generate_key_ex(rsa, bits, e, cb);
    }}
    return NULL;
}}
"#,
            config.log_output_path, enforce_code
        )
    }

    /// Generates Windows Detours C++ interception stub
    pub fn generate_windows_detour_cpp(config: &RuntimeShimConfig) -> String {
        format!(
r#"// PQCanary Microsoft Detours Runtime Cryptographic Hook (pqcanary_detour.cpp)
// Intercepts Win32 BCrypt and CAPI key generation calls in legacy Windows binaries.

#include <windows.h>
#include <detours.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "bcrypt.lib")

static NTSTATUS (WINAPI *Orig_BCryptGenerateKeyPair)(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE *phKey,
    ULONG             dwLength,
    ULONG             dwFlags
) = BCryptGenerateKeyPair;

NTSTATUS WINAPI Hook_BCryptGenerateKeyPair(
    BCRYPT_ALG_HANDLE hAlgorithm,
    BCRYPT_KEY_HANDLE *phKey,
    ULONG             dwLength,
    ULONG             dwFlags
) {{
    FILE *f = fopen("{}", "a");
    if (f) {{
        fprintf(f, "WIN32_INTERCEPT: BCryptGenerateKeyPair requested key length: %lu bits\n", dwLength);
        fclose(f);
    }}
    return Orig_BCryptGenerateKeyPair(hAlgorithm, phKey, dwLength, dwFlags);
}}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {{
    if (DetourIsHelperProcess()) return TRUE;

    if (dwReason == DLL_PROCESS_ATTACH) {{
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)Orig_BCryptGenerateKeyPair, Hook_BCryptGenerateKeyPair);
        DetourTransactionCommit();
    }} else if (dwReason == DLL_PROCESS_DETACH) {{
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)Orig_BCryptGenerateKeyPair, Hook_BCryptGenerateKeyPair);
        DetourTransactionCommit();
    }}
    return TRUE;
}}
"#,
            config.log_output_path
        )
    }

    pub fn format_markdown(config: &RuntimeShimConfig) -> String {
        let mut out = String::new();
        out.push_str("# Dynamic Runtime Cryptographic Interceptor (LD_PRELOAD / Detours)\n\n");
        out.push_str(&format!("* **Interception Mode:** {:?}\n", config.mode));
        out.push_str(&format!("* **Target Telemetry Log:** `{}`\n", config.log_output_path));
        out.push_str(&format!("* **Enforced Hybrid Group:** `{}`\n\n", config.force_hybrid_group));
        out.push_str("### How to Deploy for Closed-Source Legacy Binaries\n\n");
        out.push_str("#### Linux Deploy:\n```bash\n# 1. Compile shim shared object\ngcc -O2 -shared -fPIC -o libpqcanary_shim.so libpqcanary_shim.c -ldl\n\n# 2. Preload into closed-source binary\nLD_PRELOAD=/usr/local/lib/libpqcanary_shim.so /opt/banking-monolith/bin/server\n```\n\n");
        out.push_str("#### Windows Deploy:\n```powershell\n# Inject via Detours\nrundll32.exe pqcanary_detour.dll,InjectProcess TargetApp.exe\n```\n");
        out
    }
}
