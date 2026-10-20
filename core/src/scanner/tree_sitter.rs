use tree_sitter::{Language, Parser, Query, QueryCursor};
use rayon::prelude::*;
use std::path::Path;
use std::collections::HashSet;
use crate::scanner::patterns::{ALL_PATTERNS, SuppressionEngine, extract_code_snippet, compute_finding_fingerprint};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityFinding {
    pub file_path: String,
    pub pattern_name: String,
    pub line_number: u32,
    pub column_number: u32,
    pub severity: String,
    pub rule_id: String,
    pub category: String,
    pub quantum_risk: String,
    pub confidence: String,
    pub description: String,
    pub remediation: String,
    pub snippet: String,
    pub fingerprint: String,
}

/// Compute Shannon entropy of a string (bits per character).
/// High-entropy strings (> 4.5) are likely secrets, tokens, or private keys.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

/// Detects if a line looks like logging statements, CLI help/usage text, or docstring notes
/// that frequently mention crypto algorithms without being functional crypto usage.
pub fn is_log_or_help_text(line: &str) -> bool {
    let lower = line.to_lowercase();
    let trimmed = lower.trim();
    if trimmed.starts_with("log.")
        || trimmed.starts_with("logger.")
        || trimmed.starts_with("console.log")
        || trimmed.starts_with("console.info")
        || trimmed.starts_with("println!")
        || trimmed.starts_with("eprintln!")
        || trimmed.starts_with("print(")
        || trimmed.starts_with("logging.")
        || trimmed.starts_with("info!(")
        || trimmed.starts_with("debug!(")
    {
        return true;
    }
    let help_patterns = [
        "usage:", "options:", "flags:", "--help", "-help", "synopsis:",
        "supported algorithms", "available algorithms", "choose from:",
        "@param", "@return", "@deprecated", "@see", "todo:", "note:"
    ];
    help_patterns.iter().any(|p| trimmed.contains(p))
}

/// The enterprise multi-layer AST and pattern scanning engine.
pub struct CoreAstEngine {}

impl Default for CoreAstEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreAstEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// Recursively scans a list of files using Rayon for parallel execution.
    /// Combines 95+ detection patterns, Tree-sitter AST validation, inline suppression,
    /// and Shannon entropy secret extraction.
    pub fn scan_monorepo(&self, files: Vec<(&Path, &str)>) -> Vec<SecurityFinding> {
        files.into_par_iter()
            .flat_map(|(path, content)| {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                let path_str = path.to_string_lossy().to_string();
                let is_test_file = path_str.contains("test") || path_str.contains("spec") || path_str.contains("_test.");
                let is_doc_file = ext == "md" || ext == "txt" || ext == "rst" || path_str.contains("docs/");

                if is_doc_file {
                    // Skip documentation files from reporting false positive findings
                    return vec![];
                }

                let lines: Vec<&str> = content.lines().collect();
                let mut extracted = Vec::new();
                let mut deduplication_set: HashSet<(u32, &'static str)> = HashSet::new();

                // ── 1. 95+ Pattern Catalog Multi-Line & Line-by-Line Scanner ───────
                for (line_idx, line) in lines.iter().enumerate() {
                    let line_trim = line.trim();
                    if line_trim.is_empty() {
                        continue;
                    }
                    let line_num = line_idx as u32 + 1;
                    let is_comment = line_trim.starts_with("//")
                        || line_trim.starts_with('#')
                        || line_trim.starts_with("/*")
                        || line_trim.starts_with('*')
                        || line_trim.starts_with("<!--");

                    let is_log_or_help = is_log_or_help_text(line);

                    for pat in ALL_PATTERNS.iter() {
                        if pat.regex.is_match(line) {
                            // Check inline suppression (// pqcanary:ignore)
                            if SuppressionEngine::is_suppressed(&lines, line_num, pat.def.id, pat.def.category) {
                                continue;
                            }

                            let key = (line_num, pat.def.id);
                            if deduplication_set.contains(&key) {
                                continue;
                            }
                            deduplication_set.insert(key);

                            let col = line.find(pat.def.name)
                                .or_else(|| line.find(line_trim))
                                .unwrap_or(0) as u32 + 1;

                            let confidence = if is_comment || is_log_or_help {
                                "LOW"
                            } else if is_test_file {
                                "MEDIUM"
                            } else {
                                pat.def.default_confidence.as_str()
                            };

                            let snippet = extract_code_snippet(&lines, line_num, 2);
                            let fingerprint = compute_finding_fingerprint(&path_str, pat.def.id, line);

                            extracted.push(SecurityFinding {
                                file_path: path_str.clone(),
                                pattern_name: pat.def.name.to_string(),
                                line_number: line_num,
                                column_number: col,
                                severity: pat.def.severity.to_string(),
                                rule_id: pat.def.id.to_string(),
                                category: pat.def.category.to_string(),
                                quantum_risk: pat.def.quantum_risk.as_str().to_string(),
                                confidence: confidence.to_string(),
                                description: pat.def.description.to_string(),
                                remediation: pat.def.remediation.to_string(),
                                snippet,
                                fingerprint,
                            });
                        }
                    }

                    // ── 2. Shannon High-Entropy Token Detection (Hardcoded Secrets) ─
                    if !is_comment {
                        for word in line.split_whitespace() {
                            let clean = word.trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == '=' || c == ';' || c == ',');
                            if clean.len() >= 24
                                && !clean.contains('/') && !clean.contains('\\')
                                && !clean.starts_with("http") && !clean.starts_with("file:")
                            {
                                let entropy = shannon_entropy(clean);
                                if entropy > 4.65 {
                                    if SuppressionEngine::is_suppressed(&lines, line_num, "SECRET-ENTROPY-001", "Secrets") {
                                        continue;
                                    }

                                    let key = (line_num, "SECRET-ENTROPY-001");
                                    if !deduplication_set.contains(&key) {
                                        deduplication_set.insert(key);
                                        let snippet = extract_code_snippet(&lines, line_num, 2);
                                        let fingerprint = compute_finding_fingerprint(&path_str, "SECRET-ENTROPY-001", clean);

                                        extracted.push(SecurityFinding {
                                            file_path: path_str.clone(),
                                            pattern_name: format!("High-Entropy Hardcoded Secret: '{:.12}...' (entropy={:.2} bits/char)", clean, entropy),
                                            line_number: line_num,
                                            column_number: 1,
                                            severity: "CRITICAL".to_string(),
                                            rule_id: "SECRET-ENTROPY-001".to_string(),
                                            category: "Key Material & Secrets".to_string(),
                                            quantum_risk: "PARTIAL".to_string(),
                                            confidence: "HIGH".to_string(),
                                            description: "Detected token with high Shannon entropy (> 4.65 bits/char), indicating an unencrypted secret or key.".to_string(),
                                            remediation: "Move credentials into environment variables or a secrets manager like HashiCorp Vault or AWS Secrets Manager.".to_string(),
                                            snippet,
                                            fingerprint,
                                        });
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                // ── 3. Tree-sitter Semantic AST Queries ────────────────────────────
                let language_opt: Option<Language> = match ext {
                    "ts" | "tsx" => Some(tree_sitter_typescript::language_typescript()),
                    "js" | "jsx" => Some(tree_sitter_javascript::language()),
                    "rs"         => Some(tree_sitter_rust::language()),
                    "py"         => Some(tree_sitter_python::language()),
                    _            => None,
                };

                if let Some(language) = language_opt {
                    let mut parser = Parser::new();
                    if parser.set_language(&language).is_ok() {
                        if let Some(tree) = parser.parse(content, None) {
                            let call_query_str = match ext {
                                "ts" | "tsx" | "js" | "jsx" => {
                                    r#"
                                    (call_expression
                                      function: [
                                        (member_expression property: (property_identifier) @fn_name)
                                        (identifier) @fn_name
                                      ]
                                      arguments: (arguments (string (string_fragment) @algo_arg))
                                    )
                                    "#
                                }
                                "py" => {
                                    r#"
                                    (call
                                      function: [
                                        (attribute attribute: (identifier) @fn_name)
                                        (identifier) @fn_name
                                      ]
                                      arguments: (argument_list (string) @algo_arg)
                                    )
                                    "#
                                }
                                _ => ""
                            };

                            static TS_QUERY: std::sync::OnceLock<Option<Query>> = std::sync::OnceLock::new();
                            static JS_QUERY: std::sync::OnceLock<Option<Query>> = std::sync::OnceLock::new();
                            static PY_QUERY: std::sync::OnceLock<Option<Query>> = std::sync::OnceLock::new();

                            let query_opt = match ext {
                                "ts" | "tsx" => TS_QUERY.get_or_init(|| Query::new(&tree_sitter_typescript::language_typescript(), call_query_str).ok()),
                                "js" | "jsx" => JS_QUERY.get_or_init(|| Query::new(&tree_sitter_javascript::language(), call_query_str).ok()),
                                "py" => PY_QUERY.get_or_init(|| Query::new(&tree_sitter_python::language(), call_query_str).ok()),
                                _ => &None,
                            };

                            if let Some(query) = query_opt.as_ref() {
                                let mut cursor = QueryCursor::new();
                                let matches = cursor.matches(query, tree.root_node(), content.as_bytes());

                                static DANGEROUS_CALL_RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
                                let dangerous_call_patterns = DANGEROUS_CALL_RE.get_or_init(|| {
                                    regex::Regex::new(r"(?i)(createhash|createcipher|createcipheriv|createdecipher|md5|sha1|sha-1|des|rc4)").ok()
                                });

                                    for m in matches {
                                        let fn_name = m.captures.iter()
                                            .find(|c| query.capture_names().get(c.index as usize).copied() == Some("fn_name"))
                                            .and_then(|c| {
                                                let s = c.node.start_byte();
                                                let e = c.node.end_byte();
                                                content.get(s..e)
                                            });
                                        let algo_arg = m.captures.iter()
                                            .find(|c| query.capture_names().get(c.index as usize).copied() == Some("algo_arg"))
                                            .and_then(|c| {
                                                let s = c.node.start_byte();
                                                let e = c.node.end_byte();
                                                content.get(s..e)
                                            });

                                        if let (Some(fn_name), Some(algo)) = (fn_name, algo_arg) {
                                            let algo_clean = algo.trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
                                            let is_dangerous = dangerous_call_patterns.as_ref()
                                                .map(|re| re.is_match(fn_name) || re.is_match(algo_clean))
                                                .unwrap_or(false);
                                            if is_dangerous {
                                                let first_node = match m.captures.first() {
                                                    Some(c) => c.node,
                                                    None => continue,
                                                };
                                                let line_num = first_node.start_position().row as u32 + 1;
                                                let col = first_node.start_position().column as u32 + 1;

                                                if SuppressionEngine::is_suppressed(&lines, line_num, "AST-CRYPTO-CALL-001", "AST Calls") {
                                                    continue;
                                                }

                                                let key = (line_num, "AST-CRYPTO-CALL-001");
                                                if !deduplication_set.contains(&key) {
                                                    deduplication_set.insert(key);
                                                    let snippet = extract_code_snippet(&lines, line_num, 2);
                                                    let fingerprint = compute_finding_fingerprint(&path_str, "AST-CRYPTO-CALL-001", &format!("{}({})", fn_name, algo_clean));

                                                    extracted.push(SecurityFinding {
                                                        file_path: path_str.clone(),
                                                        pattern_name: format!("Semantic AST Crypto Call: {}('{}')", fn_name, algo_clean),
                                                        line_number: line_num,
                                                        column_number: col,
                                                        severity: "HIGH".to_string(),
                                                        rule_id: "AST-CRYPTO-CALL-001".to_string(),
                                                        category: "Semantic AST".to_string(),
                                                        quantum_risk: "VULNERABLE".to_string(),
                                                        confidence: "HIGH".to_string(),
                                                        description: format!("Tree-sitter AST verified invocation of cryptographic function {}('{}').", fn_name, algo_clean),
                                                        remediation: "Replace deprecated cryptographic primitive with NIST Post-Quantum standard or AES-256-GCM.".to_string(),
                                                        snippet,
                                                        fingerprint,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                extracted
            })
            .collect()
    }
}
