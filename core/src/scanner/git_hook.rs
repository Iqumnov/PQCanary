//! Git Pre-Commit Hook & Shift-Left Incremental Staged Scanner
//!
//! Installs and manages a sub-15ms pre-commit hook in `.git/hooks/pre-commit`
//! that inspects staged files (`git diff --cached --name-only`), preventing
//! quantum-broken cryptography and hardcoded private keys from entering git history.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::scanner::orchestrator::ComprehensiveFinding;
use crate::scanner::patterns::{ALL_PATTERNS, SuppressionEngine, extract_code_snippet, compute_finding_fingerprint};

pub struct GitHookManager;

impl GitHookManager {
    /// Discovers the .git directory starting from the given path
    pub fn find_git_dir(start_path: &Path) -> Option<PathBuf> {
        let mut curr = start_path.to_path_buf();
        loop {
            let git_candidate = curr.join(".git");
            if git_candidate.exists() {
                if git_candidate.is_dir() {
                    return Some(git_candidate);
                } else if git_candidate.is_file() {
                    // Git worktree: read file to find gitdir
                    if let Ok(content) = fs::read_to_string(&git_candidate) {
                        for line in content.lines() {
                            if let Some(rest) = line.strip_prefix("gitdir:") {
                                let target = PathBuf::from(rest.trim());
                                if target.is_absolute() {
                                    return Some(target);
                                } else {
                                    return Some(curr.join(target));
                                }
                            }
                        }
                    }
                }
            }
            if !curr.pop() {
                break;
            }
        }
        None
    }

    /// Generates the cross-platform pre-commit hook script content
    pub fn generate_hook_script() -> &'static str {
        r#"#!/bin/sh
# PQCanary Pre-Commit Cryptographic Security Guardrail
# Prevents post-quantum vulnerable algorithms and hardcoded keys from entering git history.

# Check if pqcanary binary is available on PATH
if command -v pqcanary >/dev/null 2>&1; then
    pqcanary hooks run
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        echo ""
        echo "PQCanary: Commit rejected due to critical cryptographic vulnerabilities."
        echo "PQCanary: Run 'pqcanary patch <file>' or remediate findings before committing."
        exit $EXIT_CODE
    fi
else
    # Fallback to cargo run if inside the PQCanary repository
    if [ -f "Cargo.toml" ] && grep -q "pqcanary" Cargo.toml 2>/dev/null; then
        cargo run -q -p pqcanary-cli -- hooks run
        EXIT_CODE=$?
        if [ $EXIT_CODE -ne 0 ]; then
            exit $EXIT_CODE
        fi
    fi
fi

exit 0
"#
    }

    /// Installs the pre-commit hook into the repository's `.git/hooks/`
    pub fn install_hook(repo_root: &Path) -> Result<PathBuf, String> {
        let git_dir = Self::find_git_dir(repo_root)
            .ok_or_else(|| "Not a git repository: could not locate '.git' directory.".to_string())?;

        let hooks_dir = git_dir.join("hooks");
        if !hooks_dir.exists() {
            fs::create_dir_all(&hooks_dir)
                .map_err(|e| format!("Failed to create hooks directory: {}", e))?;
        }

        let hook_path = hooks_dir.join("pre-commit");
        fs::write(&hook_path, Self::generate_hook_script())
            .map_err(|e| format!("Failed to write pre-commit hook: {}", e))?;

        // On Unix, ensure executable bit is set
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&hook_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(&hook_path, perms);
            }
        }

        Ok(hook_path)
    }

    /// Uninstalls the pre-commit hook
    pub fn uninstall_hook(repo_root: &Path) -> Result<(), String> {
        let git_dir = Self::find_git_dir(repo_root)
            .ok_or_else(|| "Not a git repository: could not locate '.git' directory.".to_string())?;

        let hook_path = git_dir.join("hooks").join("pre-commit");
        if hook_path.exists() {
            fs::remove_file(&hook_path)
                .map_err(|e| format!("Failed to remove pre-commit hook: {}", e))?;
        }
        Ok(())
    }

    /// Retrieves list of staged file paths from git
    pub fn get_staged_files(repo_root: &Path) -> Result<Vec<PathBuf>, String> {
        let output = Command::new("git")
            .current_dir(repo_root)
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
            .output()
            .map_err(|e| format!("Failed to execute 'git diff': {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut paths = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                paths.push(repo_root.join(trimmed));
            }
        }
        Ok(paths)
    }

    /// Scans staged files incrementally in sub-15ms
    pub fn scan_staged_files(repo_root: &Path) -> Result<Vec<ComprehensiveFinding>, String> {
        let files = Self::get_staged_files(repo_root)?;
        let mut findings = Vec::new();

        for file_path in files {
            if !file_path.exists() || !file_path.is_file() {
                continue;
            }

            let path_str = file_path.to_string_lossy().to_string();
            let content = match fs::read_to_string(&file_path) {
                Ok(c) => c,
                Err(_) => continue, // Skip binary files or unreadable text
            };

            let lines: Vec<&str> = content.lines().collect();
            for pat in ALL_PATTERNS.iter() {
                for mat in pat.regex.find_iter(&content) {
                    let line_number = (content[..mat.start()].bytes().filter(|&b| b == b'\n').count() + 1) as u32;

                    if SuppressionEngine::is_suppressed(&lines, line_number, pat.def.id, pat.def.category) {
                        continue;
                    }

                    let line_start = content[..mat.start()].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
                    let col = (mat.start() - line_start + 1) as u32;
                    let snippet = extract_code_snippet(&lines, line_number, 2);
                    let line_content = lines.get((line_number as usize).saturating_sub(1)).copied().unwrap_or(pat.def.description);
                    let fingerprint = compute_finding_fingerprint(&path_str, pat.def.id, line_content);

                    findings.push(ComprehensiveFinding {
                        file_path: path_str.clone(),
                        vulnerability_class: pat.def.category.to_string(),
                        description: pat.def.description.to_string(),
                        severity: pat.def.severity.to_string(),
                        line_number,
                        remediation: pat.def.remediation.to_string(),
                        rule_id: Some(pat.def.id.to_string()),
                        quantum_risk: Some(pat.def.quantum_risk.as_str().to_string()),
                        confidence: Some("HIGH".to_string()),
                        snippet: Some(snippet),
                        column_number: Some(col),
                        fingerprint: Some(fingerprint),
                    });
                }
            }
        }

        Ok(findings)
    }
}
