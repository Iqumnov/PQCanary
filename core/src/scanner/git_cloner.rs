use std::fs;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── RAII Temp Directory Guard ────────────────────────────────────────────────

/// A guard that automatically deletes a temp directory when dropped.
/// Prevents accumulation of temp dirs if the caller panics or early-returns.
pub struct TempDirGuard {
    pub path: PathBuf,
    pub disarmed: bool,
}

impl TempDirGuard {
    pub fn new(path: PathBuf) -> Self {
        Self { path, disarmed: false }
    }

    /// Disarm the guard so the directory is NOT deleted on drop.
    /// Call this when you want to hand the path to the caller for further processing.
    pub fn disarm(mut self) -> PathBuf {
        self.disarmed = true;
        self.path.clone()
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if !self.disarmed && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

// ─── Git Repository Fetcher ───────────────────────────────────────────────────

/// Git / GitHub Repository Fetcher & Cloner
/// Automatically detects remote repository URLs and fetches the codebase
/// to a temporary directory so `MasterOrchestrator` can scan the actual source files.
pub struct GitRepositoryFetcher {
    temp_base_dir: PathBuf,
}

impl Default for GitRepositoryFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl GitRepositoryFetcher {
    pub fn new() -> Self {
        let base = if let Ok(custom) = std::env::var("PQCANARY_TEMP_DIR") {
            PathBuf::from(custom)
        } else {
            std::env::temp_dir().join("pqcanary_git_scans")
        };
        Self { temp_base_dir: base }
    }

    /// Normalize raw target input URL (prepends https:// if missing, strips trailing slashes).
    pub fn normalize_git_url(target: &str) -> String {
        let mut t = target.trim().to_string();
        if !t.starts_with("http://") && !t.starts_with("https://") && !t.starts_with("git@")
            && (t.starts_with("github.com") || t.starts_with("gitlab.com") || t.starts_with("bitbucket.org") || t.starts_with("www.")) {
                t = format!("https://{}", t);
            }
        t
    }

    /// Check if a target path string is a Git, GitHub, GitLab, or Bitbucket repository URL.
    pub fn is_git_repository_url(target: &str) -> bool {
        let raw = target.trim();
        let t = Self::normalize_git_url(raw);

        t.contains("github.com")
            || t.contains("gitlab.com")
            || t.contains("bitbucket.org")
            || t.ends_with(".git")
    }

    /// Convert a Git repository URL (GitHub, GitLab, Bitbucket) into a zip download URL.
    pub fn get_git_zip_url(target: &str, branch: &str) -> Option<String> {
        let normalized = Self::normalize_git_url(target);
        let t = normalized.trim_end_matches(".git").trim_end_matches('/');

        if t.contains("github.com/") {
            let parts: Vec<&str> = t.split("github.com/").collect();
            if parts.len() == 2 {
                let repo_path = parts[1].trim_matches('/');
                let segments: Vec<&str> = repo_path.split('/').collect();
                if segments.len() >= 2 {
                    return Some(format!("https://github.com/{}/{}/archive/refs/heads/{}.zip", segments[0], segments[1], branch));
                }
            }
        } else if t.contains("gitlab.com/") {
            let parts: Vec<&str> = t.split("gitlab.com/").collect();
            if parts.len() == 2 {
                let repo_path = parts[1].trim_matches('/');
                let segments: Vec<&str> = repo_path.split('/').collect();
                if segments.len() >= 2 {
                    let repo = segments[1];
                    return Some(format!("https://gitlab.com/{}/{}/-/archive/{}/{}-{}.zip", segments[0], repo, branch, repo, branch));
                }
            }
        } else if t.contains("bitbucket.org/") {
            let parts: Vec<&str> = t.split("bitbucket.org/").collect();
            if parts.len() == 2 {
                let repo_path = parts[1].trim_matches('/');
                let segments: Vec<&str> = repo_path.split('/').collect();
                if segments.len() >= 2 {
                    return Some(format!("https://bitbucket.org/{}/{}/get/{}.zip", segments[0], segments[1], branch));
                }
            }
        }
        None
    }

    /// Get primary "main" branch zip URL.
    pub fn get_github_zip_url(target: &str) -> Option<String> {
        Self::get_git_zip_url(target, "main")
    }

    /// Get fallback "master" branch zip URL for older repositories.
    pub fn get_github_zip_url_master(target: &str) -> Option<String> {
        Self::get_git_zip_url(target, "master")
    }


    /// Prepare a unique temporary folder for cloning with collision-proof timestamp, PID, and atomic counter.
    fn create_temp_folder(&self, repo_name: &str) -> Result<TempDirGuard, String> {
        static TEMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = TEMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let clean_name: String = repo_name.chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();

        let target_dir = self.temp_base_dir.join(format!("{}_{}_{}_{}", clean_name, pid, timestamp, seq));
        fs::create_dir_all(&target_dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;
        Ok(TempDirGuard::new(target_dir))
    }

    /// Maximum files allowed when extracting remote repository zip archives (Zip Bomb defense).
    pub const MAX_ZIP_FILES: usize = 10_000;
    /// Maximum total uncompressed bytes allowed (250 MB) to prevent disk space exhaustion.
    pub const MAX_ZIP_TOTAL_BYTES: u64 = 250 * 1024 * 1024;
    /// Maximum compressed zip download bytes allowed (100 MB) to prevent network and memory exhaustion.
    pub const MAX_ZIP_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;

    /// Unpack a zip archive into a target directory with strict resource limits.
    async fn unpack_zip(bytes: bytes::Bytes, dest: &Path) -> Result<(), String> {
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| format!("Invalid zip archive: {}", e))?;

        if archive.len() > Self::MAX_ZIP_FILES {
            return Err(format!(
                "Zip archive rejected: contains {} files, exceeding maximum allowed limit of {}.",
                archive.len(), Self::MAX_ZIP_FILES
            ));
        }

        let mut total_decompressed: u64 = 0;

        for i in 0..archive.len() {
            if let Ok(mut file) = archive.by_index(i) {
                let outpath = match file.enclosed_name() {
                    Some(path) => dest.join(path),
                    None => continue,
                };
                if file.is_dir() {
                    let _ = fs::create_dir_all(&outpath);
                } else {
                    if let Some(p) = outpath.parent() {
                        let _ = fs::create_dir_all(p);
                    }
                    if let Ok(mut outfile) = fs::File::create(&outpath) {
                        use std::io::Read;
                        // Limit copy to remaining byte quota
                        let remaining_quota = Self::MAX_ZIP_TOTAL_BYTES.saturating_sub(total_decompressed);
                        if remaining_quota == 0 {
                            return Err("Zip archive exceeds 250 MB maximum uncompressed limit (Zip Bomb detected).".to_string());
                        }
                        let mut limited_reader = (&mut file).take(remaining_quota + 1);
                        let copied = std::io::copy(&mut limited_reader, &mut outfile)
                            .map_err(|e| format!("Failed to extract file: {}", e))?;
                        if copied > remaining_quota {
                            return Err("Zip archive exceeds 250 MB maximum uncompressed limit (Zip Bomb detected).".to_string());
                        }
                        total_decompressed += copied;
                    }
                }
            }
        }
        Ok(())
    }

    /// Fetch a remote repository to a local temporary directory for scanning.
    ///
    /// Strategy 1: `git clone --depth 1` (non-blocking via tokio::process)
    /// Strategy 2: HTTP download of GitHub zip archive (main branch)
    /// Strategy 3: HTTP download of GitHub zip archive (master branch fallback)
    ///
    /// Returns a `PathBuf` to the temp directory. Caller must call `cleanup_temp_dir` after use.
    pub async fn fetch_repository(&self, target_url: &str) -> Result<PathBuf, String> {
        let trimmed = target_url.trim();
        if trimmed.starts_with('-') {
            return Err("Target repository URL cannot start with '-' (flag injection rejected)".to_string());
        }

        let normalized = Self::normalize_git_url(trimmed);
        let clean_target = normalized.as_str();
        if clean_target.starts_with('-') {
            return Err("Target repository URL cannot start with '-' (flag injection rejected)".to_string());
        }

        if clean_target.contains('\0') || clean_target.contains('\n') || clean_target.contains('\r') || clean_target.contains(' ') {
            return Err("Target repository URL contains invalid whitespace or control characters.".to_string());
        }
        if clean_target.starts_with("ext::") || clean_target.starts_with("fd::") {
            return Err("Prohibited git protocol helper rejected.".to_string());
        }

        // Validate network target for SSRF protection
        if let Err(e) = crate::api::validate_network_target(clean_target) {
            return Err(format!("Network target validation failed: {}", e));
        }

        let guard = self.create_temp_folder("repo")?;
        let temp_path = guard.path.clone();

        // Strategy 1: Non-blocking git clone via tokio::process::Command with explicit '--' argument boundary and 60s timeout
        let mut cmd = Command::new("git");
        cmd.kill_on_drop(true)
            .env("GIT_ALLOW_PROTOCOL", "https:http:git:ssh")
            .args(["-c", "protocol.ext.allow=never", "clone", "--depth", "1", "--single-branch", "--", clean_target,
                    temp_path.to_str().unwrap_or(".")]);

        let git_result = tokio::time::timeout(std::time::Duration::from_secs(60), cmd.output()).await;

        if let Ok(Ok(output)) = git_result {
            if output.status.success() {
                // Disarm guard — caller takes ownership; cleanup_temp_dir handles deletion
                let _ = guard.disarm();
                return Ok(temp_path);
            }
        }

        // Strategy 2: GitHub zip archive download (main branch)
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("PQCanary-Security-Scanner/0.1.0")
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    attempt.error("Too many redirects (max 5)")
                } else if let Err(e) = crate::api::validate_network_target(attempt.url().as_str()) {
                    attempt.error(e)
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let zip_urls: Vec<Option<String>> = vec![
            Self::get_github_zip_url(clean_target),
            Self::get_github_zip_url_master(clean_target),
        ];

        for zip_url_opt in zip_urls {
            let Some(zip_url) = zip_url_opt else { continue };
            let response = client.get(&zip_url).send().await;
            if let Ok(mut resp) = response {
                if resp.status().is_success() {
                    if let Some(cl) = resp.content_length() {
                        if cl > Self::MAX_ZIP_DOWNLOAD_BYTES {
                            continue;
                        }
                    }
                    let mut downloaded = if let Some(cl) = resp.content_length() {
                        Vec::with_capacity(cl as usize)
                    } else {
                        Vec::new()
                    };
                    let mut exceeded = false;
                    while let Ok(Some(chunk)) = resp.chunk().await {
                        if (downloaded.len() + chunk.len()) as u64 > Self::MAX_ZIP_DOWNLOAD_BYTES {
                            exceeded = true;
                            break;
                        }
                        downloaded.extend_from_slice(&chunk);
                    }
                    if !exceeded && !downloaded.is_empty() {
                        let bytes = bytes::Bytes::from(downloaded);
                        if Self::unpack_zip(bytes, &temp_path).await.is_ok() {
                            let _ = guard.disarm();
                            return Ok(temp_path);
                        }
                    }
                }
            }
        }

        // Guard drops here and cleans up temp_path on failure
        Err(format!(
            "Failed to fetch repository '{}'. Ensure git is installed and the repository is public.",
            clean_target
        ))
    }

    /// Clean up a temporary directory post-scan.
    pub fn cleanup_temp_dir(dir: &Path) {
        if dir.exists() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}
