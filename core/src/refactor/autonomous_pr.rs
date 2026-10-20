// ============================================================
// LCS-based Unified Diff Engine
// ============================================================

/// A single line-level edit operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOp {
    /// Keep this line unchanged (it exists in both old and new)
    Keep(String),
    /// Delete this line (it exists only in the old version)
    Delete(String),
    /// Insert this line (it exists only in the new version)
    Insert(String),
}

/// A unified diff hunk — a contiguous region of changes with surrounding context lines.
#[derive(Debug, Clone)]
pub struct DiffHunk {
    pub old_start: usize,
    pub old_count: usize,
    pub new_start: usize,
    pub new_count: usize,
    pub ops: Vec<EditOp>,
}

impl DiffHunk {
    pub fn to_unified_string(&self) -> String {
        let old_start_display = if self.old_count == 0 { self.old_start } else { self.old_start + 1 };
        let new_start_display = if self.new_count == 0 { self.new_start } else { self.new_start + 1 };
        let mut out = format!(
            "@@ -{},{} +{},{} @@\n",
            old_start_display, self.old_count,
            new_start_display, self.new_count
        );
        for op in &self.ops {
            match op {
                EditOp::Keep(line)   => out.push_str(&format!(" {}\n", line)),
                EditOp::Delete(line) => out.push_str(&format!("-{}\n", line)),
                EditOp::Insert(line) => out.push_str(&format!("+{}\n", line)),
            }
        }
        out
    }
}

/// Compute the LCS (Longest Common Subsequence) dynamic programming matrix.
/// O(m × n) time and space using a contiguous 1D vector to minimize heap allocations and maximize CPU cache locality.
fn compute_lcs_table(a: &[&str], b: &[&str]) -> (Vec<usize>, usize) {
    let m = a.len();
    let n = b.len();
    let stride = n + 1;
    let mut dp = vec![0usize; (m + 1) * stride];
    for i in 1..=m {
        for j in 1..=n {
            dp[i * stride + j] = if a[i - 1] == b[j - 1] {
                dp[(i - 1) * stride + (j - 1)] + 1
            } else {
                dp[(i - 1) * stride + j].max(dp[i * stride + (j - 1)])
            };
        }
    }
    (dp, stride)
}

/// Backtrack the flat LCS table to produce the minimal edit sequence.
fn backtrack_edits(dp: &[usize], stride: usize, a: &[&str], b: &[&str], mut i: usize, mut j: usize) -> Vec<EditOp> {
    let mut ops = Vec::new();
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && a[i - 1] == b[j - 1] {
            ops.push(EditOp::Keep(a[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i * stride + (j - 1)] >= dp[(i - 1) * stride + j]) {
            ops.push(EditOp::Insert(b[j - 1].to_string()));
            j -= 1;
        } else {
            ops.push(EditOp::Delete(a[i - 1].to_string()));
            i -= 1;
        }
    }
    ops.reverse();
    ops
}

/// Split a flat edit sequence into context-wrapped hunks (standard unified diff format).
/// `context` lines: number of unchanged lines to include before/after each change region.
fn split_into_hunks(ops: &[EditOp], context: usize) -> Vec<DiffHunk> {
    // Find indices of all change operations
    let change_indices: Vec<usize> = ops.iter().enumerate()
        .filter(|(_, op)| !matches!(op, EditOp::Keep(_)))
        .map(|(i, _)| i)
        .collect();

    if change_indices.is_empty() {
        return Vec::new();
    }

    // Group change indices into contiguous hunk regions (separated by >2*context keep lines)
    let mut hunk_regions: Vec<(usize, usize)> = Vec::new();
    let mut hunk_start = change_indices[0].saturating_sub(context);
    let mut hunk_end = (change_indices[0] + context).min(ops.len() - 1);

    for &idx in change_indices.iter().skip(1) {
        let gap_start = hunk_end;
        let new_start = idx.saturating_sub(context);
        if new_start <= gap_start + 1 {
            // Merge into current hunk
            hunk_end = (idx + context).min(ops.len() - 1);
        } else {
            hunk_regions.push((hunk_start, hunk_end));
            hunk_start = new_start;
            hunk_end = (idx + context).min(ops.len() - 1);
        }
    }
    hunk_regions.push((hunk_start, hunk_end));

    // Build DiffHunk structs from each region
    let mut hunks = Vec::new();

    // First pass: compute line offsets
    let mut old_offsets = Vec::new();
    let mut new_offsets = Vec::new();
    let mut o = 0;
    let mut n = 0;
    for op in ops {
        old_offsets.push(o);
        new_offsets.push(n);
        match op {
            EditOp::Keep(_)   => { o += 1; n += 1; }
            EditOp::Delete(_) => { o += 1; }
            EditOp::Insert(_) => { n += 1; }
        }
    }

    for (start, end) in hunk_regions {
        let region = &ops[start..=end];
        let old_count = region.iter().filter(|op| !matches!(op, EditOp::Insert(_))).count();
        let new_count = region.iter().filter(|op| !matches!(op, EditOp::Delete(_))).count();

        hunks.push(DiffHunk {
            old_start: old_offsets[start],
            old_count,
            new_start: new_offsets[start],
            new_count,
            ops: region.to_vec(),
        });
    }

    hunks
}

// ============================================================
// GitHub REST API Payload Builder
// ============================================================

/// A structured GitHub Pull Request payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GithubPrPayload {
    pub title: String,
    pub body: String,
    #[serde(rename = "head")]
    pub head_branch: String,
    #[serde(rename = "base")]
    pub base_branch: String,
    pub labels: Vec<String>,
    pub draft: bool,
}

impl GithubPrPayload {
    /// Serialize to a valid GitHub REST API JSON payload (POST /repos/{owner}/{repo}/pulls).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// ============================================================
// Vulnerability Remediation Patch Generator
// ============================================================

/// A known cryptographic vulnerability pattern and its automated fix.
#[derive(Debug, Clone)]
pub struct RemediationRule {
    pub id: &'static str,
    pub description: &'static str,
    /// Line-level pattern to detect (exact line match after trimming)
    pub detect_pattern: &'static str,
    /// The replacement line(s) to substitute
    pub replacement: &'static str,
}

/// The built-in remediation rules for known cryptographic vulnerabilities.
/// These rules are applied by the SemanticAstPatcher.
pub fn builtin_remediation_rules() -> Vec<RemediationRule> {
    vec![
        // ── JavaScript / TypeScript ──
        RemediationRule {
            id: "CWE-327-MD5-JS",
            description: "Broken cryptographic hash function MD5. Replace with SHA-256.",
            detect_pattern: "createHash('md5')",
            replacement: "createHash('sha256')",
        },
        RemediationRule {
            id: "CWE-327-SHA1-JS",
            description: "Broken cryptographic hash function SHA-1. Replace with SHA-256.",
            detect_pattern: "createHash('sha1')",
            replacement: "createHash('sha256')",
        },
        RemediationRule {
            id: "CWE-327-DES-JS",
            description: "Broken symmetric cipher DES. Replace with AES-256-GCM.",
            detect_pattern: "createCipheriv('des'",
            replacement: "createCipheriv('aes-256-gcm'",
        },
        RemediationRule {
            id: "CWE-327-RC4-JS",
            description: "Broken stream cipher RC4. Replace with ChaCha20-Poly1305.",
            detect_pattern: "createCipheriv('rc4'",
            replacement: "createCipheriv('chacha20-poly1305'",
        },
        RemediationRule {
            id: "CWE-327-AES-ECB-JS",
            description: "AES in ECB mode leaks block patterns. Replace with AES-256-GCM.",
            detect_pattern: "createCipheriv('aes-256-ecb'",
            replacement: "createCipheriv('aes-256-gcm'",
        },
        RemediationRule {
            id: "CWE-330-MATH-RANDOM-JS",
            description: "Math.random() is not cryptographically secure. Replace with crypto.getRandomValues().",
            detect_pattern: "Math.random()",
            replacement: "crypto.getRandomValues(new Uint8Array(1))[0] / 255",
        },
        RemediationRule {
            id: "CWE-261-PLAINTEXT-JWT",
            description: "JWT algorithm set to 'none' allows signature bypass. Enforce RS256 or ES256.",
            detect_pattern: "algorithm: 'none'",
            replacement: "algorithm: 'ES256'",
        },

        // ── Python ──
        RemediationRule {
            id: "CWE-327-MD5-PY",
            description: "Python hashlib.md5() is broken. Replace with hashlib.sha256().",
            detect_pattern: "hashlib.md5(",
            replacement: "hashlib.sha256(",
        },
        RemediationRule {
            id: "CWE-327-SHA1-PY",
            description: "Python hashlib.sha1() is vulnerable to collision attacks. Replace with hashlib.sha256().",
            detect_pattern: "hashlib.sha1(",
            replacement: "hashlib.sha256(",
        },
        RemediationRule {
            id: "CWE-330-RANDOM-PY",
            description: "Python random.random() is predictable Mersenne Twister. Replace with secrets.randbelow().",
            detect_pattern: "random.random()",
            replacement: "secrets.randbelow(1_000_000) / 1_000_000",
        },

        // ── Java ──
        RemediationRule {
            id: "CWE-327-MD5-JAVA",
            description: "Java MessageDigest MD5 is broken. Replace with MessageDigest.getInstance(\"SHA-256\").",
            detect_pattern: "MessageDigest.getInstance(\"MD5\")",
            replacement: "MessageDigest.getInstance(\"SHA-256\")",
        },
        RemediationRule {
            id: "CWE-327-DES-JAVA",
            description: "Java Cipher DES is insecure. Replace with AES/GCM/NoPadding.",
            detect_pattern: "Cipher.getInstance(\"DES\")",
            replacement: "Cipher.getInstance(\"AES/GCM/NoPadding\")",
        },
        RemediationRule {
            id: "CWE-330-RANDOM-JAVA",
            description: "Java java.util.Random is non-secure PRNG. Replace with java.security.SecureRandom.",
            detect_pattern: "new Random()",
            replacement: "new SecureRandom()",
        },

        // ── C / C++ ──
        RemediationRule {
            id: "CWE-330-RAND-C",
            description: "C standard rand() is weak non-cryptographic PRNG. Replace with arc4random().",
            detect_pattern: "rand()",
            replacement: "arc4random()",
        },

        // ── Post-Quantum Cryptography Migrations ──
        RemediationRule {
            id: "PQC-MIGRATE-RSA-PY",
            description: "Python RSA key generation is vulnerable to Shor's algorithm. Migrate to Open Quantum Safe (liboqs-python) ML-KEM.",
            detect_pattern: "RSA.generate(",
            replacement: "oqs.KeyEncapsulation('ML-KEM-768').generate_keypair()  # Migrated from RSA.generate(",
        },
        RemediationRule {
            id: "PQC-MIGRATE-RSA-GO",
            description: "Go rsa.GenerateKey is vulnerable to Shor's algorithm. Migrate to Cloudflare Circl ML-KEM-768.",
            detect_pattern: "rsa.GenerateKey(rand.Reader",
            replacement: "mlkem768.GenerateKeyPair()  // Migrated from rsa.GenerateKey(",
        },
        RemediationRule {
            id: "PQC-MIGRATE-RSA-RS",
            description: "Rust Rsa::generate is vulnerable to Shor's algorithm. Migrate to pqcrypto_kyber::kyber768 or fips203.",
            detect_pattern: "Rsa::generate(2048)",
            replacement: "pqcrypto_kyber::kyber768::keypair()  // Migrated to NIST FIPS 203 ML-KEM",
        },
        RemediationRule {
            id: "PQC-MIGRATE-RSA-NODE",
            description: "Node.js generateKeyPairSync for RSA is vulnerable. Migrate to ML-KEM or @noble/post-quantum.",
            detect_pattern: "generateKeyPairSync('rsa'",
            replacement: "mlkem768.keygen()  // Migrated from generateKeyPairSync('rsa'",
        },
    ]
}

// ============================================================
// Semantic Line-Level AST Patcher
// ============================================================

/// Result of applying a remediation patch.
#[derive(Debug, Clone)]
pub struct PatchResult {
    pub file_path: String,
    pub rules_applied: Vec<String>,
    pub original_source: String,
    pub patched_source: String,
    pub unified_diff: String,
}

impl PatchResult {
    pub fn is_changed(&self) -> bool {
        self.original_source != self.patched_source
    }
}

/// The semantic patch engine.
///
/// Applies known remediation rules on a line-by-line basis, then generates
/// the full unified diff and GitHub PR payload for review.
pub struct SemanticPatcher {
    rules: Vec<RemediationRule>,
    context_lines: usize,
}

impl Default for SemanticPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticPatcher {
    pub fn new() -> Self {
        Self {
            rules: builtin_remediation_rules(),
            context_lines: 3,
        }
    }

    pub fn with_context_lines(mut self, n: usize) -> Self {
        self.context_lines = n;
        self
    }

    /// Apply all remediation rules to the given source file.
    /// Returns a full PatchResult describing all changes made.
    pub fn patch_file(&self, file_path: &str, source: &str) -> PatchResult {
        // Fast-path: check if any remediation rule pattern exists before line-splitting & allocation
        if !self.rules.iter().any(|r| source.contains(r.detect_pattern)) {
            return PatchResult {
                file_path: file_path.to_string(),
                rules_applied: Vec::new(),
                original_source: source.to_string(),
                patched_source: source.to_string(),
                unified_diff: String::from("(no changes)"),
            };
        }

        let mut patched_lines: Vec<String> = source.lines().map(str::to_string).collect();
        let mut rules_applied = Vec::new();

        for rule in &self.rules {
            for line in patched_lines.iter_mut() {
                if line.contains(rule.detect_pattern) {
                    let original_line = line.clone();
                    *line = line.replace(rule.detect_pattern, rule.replacement);
                    if *line != original_line {
                        rules_applied.push(format!("[{}] {}", rule.id, rule.description));
                    }
                }
            }
        }

        let patched_source = if rules_applied.is_empty() {
            source.to_string()
        } else {
            patched_lines.join("\n")
        };
        let unified_diff = if rules_applied.is_empty() || source == patched_source {
            String::from("(no changes)")
        } else {
            self.generate_unified_diff(source, &patched_source, file_path)
        };

        PatchResult {
            file_path: file_path.to_string(),
            rules_applied,
            original_source: source.to_string(),
            patched_source,
            unified_diff,
        }
    }

    /// Generate a complete unified diff between original and patched source.
    pub fn generate_unified_diff(&self, original: &str, patched: &str, filename: &str) -> String {
        if original == patched {
            return String::from("(no changes)");
        }
        let old_lines: Vec<&str> = original.lines().collect();
        let new_lines: Vec<&str> = patched.lines().collect();

        // Guard against quadratic memory explosion on massive files (>10M cell matrix)
        if old_lines.len().saturating_mul(new_lines.len()) > 10_000_000 {
            return format!("--- a/{filename}\n+++ b/{filename}\n@@ -1,{} +1,{} @@\n(diff omitted: file size exceeds dynamic programming memory threshold)\n", old_lines.len(), new_lines.len());
        }

        let (dp, stride) = compute_lcs_table(&old_lines, &new_lines);
        let ops = backtrack_edits(&dp, stride, &old_lines, &new_lines, old_lines.len(), new_lines.len());
        let hunks = split_into_hunks(&ops, self.context_lines);

        if hunks.is_empty() {
            return String::from("(no changes)");
        }

        let mut diff = format!("--- a/{filename}\n+++ b/{filename}\n");
        for hunk in &hunks {
            diff.push_str(&hunk.to_unified_string());
        }
        diff
    }

    /// Build the GitHub PR body from a set of patch results.
    pub fn build_pr_payload(
        &self,
        patch_results: &[PatchResult],
        head_branch: &str,
        base_branch: &str,
    ) -> GithubPrPayload {
        let changed_files: Vec<&PatchResult> = patch_results.iter().filter(|r| r.is_changed()).collect();

        let file_list = changed_files.iter()
            .map(|r| format!("- `{}`", r.file_path))
            .collect::<Vec<_>>()
            .join("\n");

        let rule_list: Vec<String> = changed_files.iter()
            .flat_map(|r| r.rules_applied.iter().cloned())
            .collect::<std::collections::HashSet<String>>()
            .into_iter()
            .collect();

        let findings_block = rule_list.iter()
            .map(|r| format!("- {}", r))
            .collect::<Vec<_>>()
            .join("\n");

        let diff_block = changed_files.iter()
            .map(|r| format!("```diff\n# {}\n{}\n```", r.file_path, r.unified_diff))
            .collect::<Vec<_>>()
            .join("\n\n");

        let body = format!(
"## PQCanary Autonomous Cryptographic Remediation

This Pull Request was generated automatically by the PQCanary engine after detecting \
post-quantum unsafe cryptographic patterns in the following files:

{}

### Vulnerabilities Remediated

{}

### Unified Diff

{}

---
*This PR was generated by PQCanary. Please review the changes and verify CI/CD passes before merging.*",
            file_list, findings_block, diff_block
        );

        GithubPrPayload {
            title: format!("SECURITY: PQCanary: Remediate {} cryptographic vulnerability findings", rule_list.len()),
            body,
            head_branch: head_branch.to_string(),
            base_branch: base_branch.to_string(),
            labels: vec!["security".to_string(), "automated".to_string(), "pqcanary".to_string()],
            draft: false,
        }
    }
}

// ============================================================
// The Autonomous PR Generator Entry Point
// ============================================================

/// Full autonomous PR generator.
/// Takes raw source files, applies semantic patches, generates unified diffs,
/// and serializes the complete GitHub PR payload.
pub struct AutonomousPrGenerator {
    patcher: SemanticPatcher,
}

impl Default for AutonomousPrGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AutonomousPrGenerator {
    pub fn new() -> Self {
        Self { patcher: SemanticPatcher::new() }
    }

    /// Analyze and patch multiple source files, then generate the PR payload.
    pub fn generate_pr(
        &self,
        files: &[(&str, &str)],  // (file_path, source_code)
        head_branch: &str,
        base_branch: &str,
    ) -> Option<GithubPrPayload> {
        let results: Vec<PatchResult> = files.iter()
            .map(|(path, source)| self.patcher.patch_file(path, source))
            .collect();

        let has_changes = results.iter().any(|r| r.is_changed());
        if !has_changes {
            return None;
        }

        Some(self.patcher.build_pr_payload(&results, head_branch, base_branch))
    }

    /// Generate a unified diff string between two source strings (direct access).
    pub fn generate_unified_diff(&self, original: &str, modified: &str, filename: &str) -> String {
        self.patcher.generate_unified_diff(original, modified, filename)
    }

    /// Serialize the GitHub PR payload to JSON.
    pub fn generate_github_pr_payload(
        &self,
        title: &str,
        diff_body: &str,
        branch: &str,
        base: &str,
    ) -> String {
        GithubPrPayload {
            title: title.to_string(),
            body: diff_body.to_string(),
            head_branch: branch.to_string(),
            base_branch: base.to_string(),
            labels: vec!["security".to_string(), "pqcanary".to_string()],
            draft: false,
        }.to_json()
    }

    /// Physically execute the POST request to the GitHub REST API using reqwest.
    /// Requires a valid GitHub Personal Access Token (PAT).
    pub async fn execute_github_pr(
        &self,
        repo_owner: &str,
        repo_name: &str,
        payload: &GithubPrPayload,
        github_token: &str,
    ) -> Result<String, String> {
        let owner = repo_owner.trim();
        let repo = repo_name.trim();
        if owner.is_empty() || owner.contains('/') || owner.contains('\\') || owner.contains("..")
            || repo.is_empty() || repo.contains('/') || repo.contains('\\') || repo.contains("..")
        {
            return Err("Invalid repo_owner or repo_name: must be valid repository identifiers without path traversal characters".to_string());
        }
        let url = format!("https://api.github.com/repos/{}/{}/pulls", owner, repo);
        
        let client = reqwest::Client::new();
        let json_body = payload.to_json();

        let response = client
            .post(&url)
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "PQCanary-Autonomous-Agent")
            .header("Authorization", format!("token {}", github_token))
            .header("Content-Type", "application/json")
            .body(json_body)
            .send()
            .await
            .map_err(|e| format!("Reqwest network error: {}", e))?;

        if response.status().is_success() {
            let response_text = response.text().await.unwrap_or_default();
            Ok(format!("Successfully created PR. API Response: {}", response_text))
        } else {
            let status = response.status();
            let err_text = response.text().await.unwrap_or_default();
            Err(format!("GitHub API Error {}: {}", status, err_text))
        }
    }
}
