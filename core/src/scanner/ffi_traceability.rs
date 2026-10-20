use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::alloc::Layout;

// ============================================================
// Cross-Language Memory Layout Model
// ============================================================

/// The programming language a memory region was declared in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceLanguage {
    TypeScript,
    JavaScript,
    Rust,
    C,
    Cpp,
    Python,
    Go,
    Java,
}

impl SourceLanguage {
    /// The native buffer type name in this language.
    pub fn buffer_type(&self) -> &'static str {
        match self {
            Self::TypeScript | Self::JavaScript => "Buffer / Uint8Array",
            Self::Rust => "&[u8] / Vec<u8>",
            Self::C => "*char / unsigned char*",
            Self::Cpp => "std::vector<uint8_t> / std::string",
            Self::Python => "bytes / bytearray",
            Self::Go => "[]byte / C.CBytes",
            Self::Java => "byte[] / ByteBuffer / JNIEnv",
        }
    }

    /// The secure zeroing function for this language.
    pub fn zero_function(&self) -> &'static str {
        match self {
            Self::TypeScript | Self::JavaScript => "buffer.fill(0) or crypto.getRandomValues()",
            Self::Rust => "zeroize::Zeroize::zeroize(&mut buf)",
            Self::C | Self::Cpp => "OQS_MEM_cleanse(ptr, len) or explicit_bzero(ptr, len) or SecureZeroMemory()",
            Self::Python => "ctypes.memset(id(buf), 0, sys.getsizeof(buf))",
            Self::Go => "subtle.ConstantTimeCopy or explicit memory wipe",
            Self::Java => "java.util.Arrays.fill(buf, (byte)0)",
        }
    }
}

/// A tainted (sensitive) memory region crossing an FFI boundary.
#[derive(Debug, Clone)]
pub struct FfiAllocation {
    pub base_address: usize,
    pub layout: Layout,
    pub is_zeroized: bool,
    pub source_language: SourceLanguage,
    pub destination_language: SourceLanguage,
    /// Human-readable source location where the allocation was made
    pub allocation_trace: String,
    /// Whether the allocation contains cryptographic key material (high priority)
    pub is_key_material: bool,
    /// Chain of languages this buffer has passed through (for multi-hop tracing)
    pub language_path: Vec<SourceLanguage>,
    /// Number of times this buffer has crossed an FFI boundary
    pub ffi_hop_count: u32,
}

impl FfiAllocation {
    /// Generate a human-readable security report for this allocation.
    pub fn security_report(&self) -> String {
        let priority = if self.is_key_material { "CRITICAL: KEY MATERIAL" } else { "MEDIUM: SENSITIVE DATA" };
        let zeroized = if self.is_zeroized { "OK: ZEROIZED" } else { "FAIL: NOT ZEROIZED — LEAK RISK" };
        let path: Vec<&str> = self.language_path.iter().map(|l| match l {
            SourceLanguage::TypeScript => "TS",
            SourceLanguage::JavaScript => "JS",
            SourceLanguage::Rust => "Rust",
            SourceLanguage::C => "C",
            SourceLanguage::Cpp => "C++",
            SourceLanguage::Python => "Py",
            SourceLanguage::Go => "Go",
            SourceLanguage::Java => "Java",
        }).collect();

        format!(
            "FFI ALLOCATION: {}\n\
             Address: 0x{:016X} | Size: {} bytes | FFI Hops: {}\n\
             Language Path: {} → {}\n\
             Zeroization: {}\n\
             Allocated at: {}\n\
             Fix: Use {} in {:?}",
            priority,
            self.base_address,
            self.layout.size(),
            self.ffi_hop_count,
            path.join(" → "),
            self.destination_language.buffer_type(),
            zeroized,
            self.allocation_trace,
            self.destination_language.zero_function(),
            self.destination_language,
        )
    }
}

// ============================================================
// N-API & Cross-Language FFI Pattern Detector
// ============================================================

/// Detected N-API / FFI boundary crossing pattern from AST analysis.
#[derive(Debug, Clone)]
pub struct NApiPattern {
    pub pattern_type: NApiPatternType,
    pub variable_name: String,
    pub file_path: String,
    pub line_number: u32,
    pub source_language: SourceLanguage,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NApiPatternType {
    /// TypeScript Buffer passed to native addon: Buffer.from() / nativeAddon.fn(buffer)
    TypeScriptBufferToNative,
    /// Rust slice returned from N-API: &[u8] from napi_get_buffer_info
    RustSliceFromNapi,
    /// C pointer received from Rust via FFI: *const u8 / *mut u8
    CPointerFromRust,
    /// Rust Vec<u8> cast to C pointer: buf.as_ptr()
    RustVecToCPtr,
    /// Python bytes object passed through CFFI
    PythonBytesToCffi,
    /// Go byte slice passed across Cgo boundary
    GoCgoBytesToC,
    /// Java byte array passed across JNI boundary
    JavaJniBytesToC,
    /// Open Quantum Safe (liboqs) KEM native context allocated across FFI
    OqsNativeKemCall,
    /// Open Quantum Safe (liboqs) Signature native context allocated across FFI
    OqsNativeSigCall,
    /// Missing zeroize call before buffer drop/free
    MissingZeroizeBeforeFree,
    /// OpenSSL EVP_PKEY or EVP_MD_CTX not freed with secure destroy
    UnsecureOpenSslContext,
}

/// Known N-API & FFI code patterns that constitute dangerous or sensitive FFI crossings.
const NAPI_DANGEROUS_PATTERNS: &[(&str, NApiPatternType)] = &[
    ("napi_get_buffer_info",      NApiPatternType::RustSliceFromNapi),
    ("napi_create_buffer",        NApiPatternType::RustSliceFromNapi),
    ("napi_get_arraybuffer_info", NApiPatternType::RustSliceFromNapi),
    ("as_ptr()",                  NApiPatternType::RustVecToCPtr),
    ("as_mut_ptr()",              NApiPatternType::RustVecToCPtr),
    ("Buffer.from(",              NApiPatternType::TypeScriptBufferToNative),
    ("cffi.cast(",                NApiPatternType::PythonBytesToCffi),
    ("C.CBytes(",                 NApiPatternType::GoCgoBytesToC),
    ("GetByteArrayElements(",     NApiPatternType::JavaJniBytesToC),
    ("OQS_KEM_new",               NApiPatternType::OqsNativeKemCall),
    ("OQS_SIG_new",               NApiPatternType::OqsNativeSigCall),
    ("EVP_PKEY_free",             NApiPatternType::UnsecureOpenSslContext),
];

/// Known safe zeroization patterns (these cancel out a missing-zeroize finding).
const SAFE_ZEROIZE_PATTERNS: &[&str] = &[
    "zeroize()",
    "explicit_bzero(",
    "SecureZeroMemory(",
    ".fill(0)",
    "OPENSSL_cleanse(",
    "EVP_MD_CTX_free(",
    "EVP_PKEY_free(",
    "sodium_memzero(",
    "OQS_MEM_cleanse(",
    "OQS_MEM_secure_free(",
    "memset_s(",
    "Arrays.fill(",
];

// ============================================================
// Multi-Hop Cross-Language Taint Tracker
// ============================================================

/// A taint fact: a specific variable at a specific location is tainted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintFact {
    pub variable: String,
    pub file_path: String,
    pub line: u32,
    pub language: String,
}

/// A taint propagation edge: how taint flows from source to sink.
#[derive(Debug, Clone)]
pub struct TaintEdge {
    pub from: TaintFact,
    pub to: TaintFact,
    pub edge_type: TaintEdgeType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaintEdgeType {
    DirectAssignment,       // x = y where y is tainted
    FfiPassthrough,         // taint crosses a language boundary
    ReturnValue,            // function returning tainted value
    ArrayElement,           // tainted element written to array
    StructField,            // tainted data stored in struct field
}

/// The full cross-language FFI taint graph.
pub struct FfiTaintGraph {
    /// Set of all currently tainted facts
    tainted: HashSet<TaintFact>,
    /// The propagation edges (taint flow graph)
    edges: Vec<TaintEdge>,
    /// Sinks that must never receive taint (e.g., log output, network output)
    dangerous_sinks: HashSet<String>,
}

impl Default for FfiTaintGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl FfiTaintGraph {
    pub fn new() -> Self {
        let mut sinks = HashSet::new();
        // These patterns should never receive secret material
        sinks.insert("console.log".to_string());
        sinks.insert("console.error".to_string());
        sinks.insert("fs.writeFile".to_string());
        sinks.insert("println!".to_string());
        sinks.insert("eprintln!".to_string());
        sinks.insert("log::info".to_string());
        sinks.insert("log::error".to_string());
        sinks.insert("send(".to_string());
        sinks.insert("write_all(".to_string());
        Self { tainted: HashSet::new(), edges: Vec::new(), dangerous_sinks: sinks }
    }

    /// Mark a variable as a taint source (e.g., user-provided key material).
    pub fn taint_source(&mut self, var: &str, file: &str, line: u32, lang: &str) {
        self.tainted.insert(TaintFact {
            variable: var.to_string(),
            file_path: file.to_string(),
            line,
            language: lang.to_string(),
        });
    }

    /// Propagate taint from `from_var` to `to_var` if `from_var` is tainted.
    /// Returns true if taint was actually propagated.
    #[allow(clippy::too_many_arguments)]
    pub fn propagate(
        &mut self,
        from_var: &str, from_file: &str, from_line: u32, from_lang: &str,
        to_var: &str, to_file: &str, to_line: u32, to_lang: &str,
        edge_type: TaintEdgeType,
    ) -> bool {
        let from_fact = TaintFact {
            variable: from_var.to_string(),
            file_path: from_file.to_string(),
            line: from_line,
            language: from_lang.to_string(),
        };

        if self.tainted.contains(&from_fact) {
            let to_fact = TaintFact {
                variable: to_var.to_string(),
                file_path: to_file.to_string(),
                line: to_line,
                language: to_lang.to_string(),
            };
            self.edges.push(TaintEdge {
                from: from_fact,
                to: to_fact.clone(),
                edge_type,
            });
            self.tainted.insert(to_fact);
            true
        } else {
            false
        }
    }

    /// Sanitize a variable (e.g., it was zeroized). Removes it from the taint set.
    pub fn sanitize(&mut self, var: &str, file: &str, _line: u32, lang: &str) {
        self.tainted.retain(|f| {
            !(f.variable == var && f.file_path == file && f.language == lang)
        });
    }

    /// Check if any tainted variable reaches a dangerous sink.
    pub fn find_sink_violations(&self) -> Vec<TaintFact> {
        self.tainted.iter().filter(|f| {
            self.dangerous_sinks.iter().any(|sink| f.variable.contains(sink.as_str()))
        }).cloned().collect()
    }

    /// Return all tainted facts that cross a language boundary (FFI leaks).
    pub fn find_ffi_leaks(&self) -> Vec<&TaintEdge> {
        self.edges.iter().filter(|e| {
            e.edge_type == TaintEdgeType::FfiPassthrough
                && e.from.language != e.to.language
        }).collect()
    }
}

// ============================================================
// The Full FFI Traceability Scanner
// ============================================================

/// Shadow memory registry (runtime tracking of live FFI pointers).
pub struct FfiTracker {
    shadow_registry: Arc<Mutex<HashMap<usize, FfiAllocation>>>,
    /// Taint graph tracking cross-language data flows
    pub taint_graph: FfiTaintGraph,
}

impl Default for FfiTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FfiTracker {
    pub fn new() -> Self {
        Self {
            shadow_registry: Arc::new(Mutex::new(HashMap::new())),
            taint_graph: FfiTaintGraph::new(),
        }
    }

    /// Register a raw pointer allocation crossing the FFI boundary.
    pub fn register_allocation(
        &self,
        ptr: *mut u8,
        layout: Layout,
        trace: &str,
        src_lang: SourceLanguage,
        dst_lang: SourceLanguage,
        is_key_material: bool,
    ) {
        let addr = ptr as usize;
        let mut registry = self.shadow_registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.insert(addr, FfiAllocation {
            base_address: addr,
            layout,
            is_zeroized: false,
            source_language: src_lang.clone(),
            destination_language: dst_lang,
            allocation_trace: trace.to_string(),
            is_key_material,
            language_path: vec![src_lang],
            ffi_hop_count: 1,
        });
    }

    /// Record that an existing FFI allocation has crossed another language boundary.
    pub fn record_ffi_hop(&self, ptr: *mut u8, next_language: SourceLanguage) {
        let addr = ptr as usize;
        let mut registry = self.shadow_registry.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(alloc) = registry.get_mut(&addr) {
            alloc.language_path.push(next_language.clone());
            alloc.destination_language = next_language;
            alloc.ffi_hop_count += 1;
        }
    }

    /// Mark an FFI memory region as securely wiped.
    pub fn mark_zeroized(&self, ptr: *mut u8) -> Result<(), &'static str> {
        let addr = ptr as usize;
        let mut registry = self.shadow_registry.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(alloc) = registry.get_mut(&addr) {
            alloc.is_zeroized = true;
            Ok(())
        } else {
            Err("Attempted to zeroize an untracked FFI pointer — potential wild pointer")
        }
    }

    /// Verify that a pointer is safe to free (has been zeroized).
    pub fn verify_safe_to_free(&self, ptr: *mut u8) -> Result<(), String> {
        let addr = ptr as usize;
        let mut registry = self.shadow_registry.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(alloc) = registry.remove(&addr) {
            if alloc.is_zeroized {
                Ok(())
            } else {
                Err(alloc.security_report())
            }
        } else {
            Err(format!("CRITICAL: Untracked FFI free attempt at 0x{:016X}", addr))
        }
    }

    /// Scan source code text for dangerous N-API patterns.
    /// Returns a list of detected FFI crossing patterns.
    pub fn scan_source_for_napi_patterns(&self, source: &str, file_path: &str, language: SourceLanguage) -> Vec<NApiPattern> {
        let mut patterns = Vec::new();
        let mut has_zeroize = false;

        // Check for safe zeroization patterns
        for safe_pattern in SAFE_ZEROIZE_PATTERNS {
            if source.contains(safe_pattern) {
                has_zeroize = true;
                break;
            }
        }

        for (line_num, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with('#') {
                continue;
            }

            for (pattern_str, pattern_type) in NAPI_DANGEROUS_PATTERNS {
                if line.contains(pattern_str) {
                    // Infer the variable name from the line (simplified: take word before the pattern)
                    let var_name = line.split_whitespace()
                        .find(|w| !w.contains(pattern_str))
                        .unwrap_or("unknown")
                        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                        .to_string();

                    patterns.push(NApiPattern {
                        pattern_type: pattern_type.clone(),
                        variable_name: var_name,
                        file_path: file_path.to_string(),
                        line_number: line_num as u32 + 1,
                        source_language: language.clone(),
                    });
                }
            }

            // Detect missing zeroize: if there are dangerous patterns but no safe zeroize
            if !has_zeroize && (line.contains("drop(") || line.contains("free(") || line.contains("dealloc(")) {
                patterns.push(NApiPattern {
                    pattern_type: NApiPatternType::MissingZeroizeBeforeFree,
                    variable_name: "heap_allocation".to_string(),
                    file_path: file_path.to_string(),
                    line_number: line_num as u32 + 1,
                    source_language: language.clone(),
                });
            }
        }
        patterns
    }

    /// Audit all live FFI allocations for memory leaks and zeroization failures.
    pub fn audit_leaks(&self) -> Vec<FfiAllocation> {
        let registry = self.shadow_registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.values().cloned().collect()
    }

    /// Generate a full human-readable audit report.
    pub fn generate_audit_report(&self) -> String {
        let allocations = self.audit_leaks();
        let ffi_leaks = self.taint_graph.find_ffi_leaks();
        let sink_violations = self.taint_graph.find_sink_violations();

        let mut report = String::from(
            "═══════════════════════════════════════════════════════\n\
             PQCanary FFI Traceability Audit Report\n\
             ═══════════════════════════════════════════════════════\n\n"
        );

        report.push_str(&format!("Live FFI Allocations: {}\n\n", allocations.len()));
        for alloc in &allocations {
            report.push_str(&alloc.security_report());
            report.push_str("\n\n");
        }

        report.push_str(&format!("Cross-Language Taint Leaks: {}\n", ffi_leaks.len()));
        for leak in &ffi_leaks {
            report.push_str(&format!(
                "  {} ({}) → {} ({}): {:?} propagation\n",
                leak.from.variable, leak.from.language,
                leak.to.variable, leak.to.language,
                leak.edge_type
            ));
        }

        report.push_str(&format!("\nDangerous Sink Violations: {}\n", sink_violations.len()));
        for sink in &sink_violations {
            report.push_str(&format!(
                "  CRITICAL: '{}' in {} (lang: {}) reaches a logging/network sink!\n",
                sink.variable, sink.file_path, sink.language
            ));
        }

        report
    }
}
