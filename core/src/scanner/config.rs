//! Configuration File Engine for PQCanary (.pqcanary.yaml, pqcanary.toml)
//!
//! Enables zero-CLI-flag operation via structured configuration files.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PqCanaryConfig {
    pub target: Option<String>,
    pub severity: Option<String>,
    pub format: Option<String>,
    pub output: Option<String>,
    pub baseline: Option<String>,
    #[serde(rename = "fail_on", alias = "fail-on")]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub ignore: IgnoreConfig,
    #[serde(default)]
    pub engines: EnginesConfig,
    #[serde(default)]
    pub qpu: QpuConfig,
    #[serde(default, alias = "custom-rules")]
    pub custom_rules: Vec<CustomRuleConfig>,
    #[serde(default, alias = "webhook-url")]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomRuleConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(alias = "pattern")]
    pub regex: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnginesConfig {
    #[serde(default = "default_true")]
    pub ast: bool,
    #[serde(default = "default_true")]
    pub concolic: bool,
    #[serde(default = "default_true")]
    pub ffi: bool,
    #[serde(default = "default_true")]
    pub dpa: bool,
    #[serde(default = "default_true")]
    pub thermo: bool,
    #[serde(default = "default_true")]
    pub hott: bool,
    #[serde(default = "default_true")]
    pub snn: bool,
}

impl Default for EnginesConfig {
    fn default() -> Self {
        Self {
            ast: true,
            concolic: true,
            ffi: true,
            dpa: true,
            thermo: true,
            hott: true,
            snn: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QpuConfig {
    pub token: Option<String>,
    pub backend: Option<String>,
    pub shots: Option<u32>,
}

fn default_true() -> bool { true }

impl PqCanaryConfig {
    /// Attempts to auto-discover configuration file in the target directory or current directory.
    pub fn discover(dir: &Path) -> Option<(Self, PathBuf)> {
        let candidate_names = [
            ".pqcanary.yaml", ".pqcanary.yml", "pqcanary.yaml", "pqcanary.yml",
            ".pqcanary.toml", "pqcanary.toml"
        ];

        for name in candidate_names {
            let candidate = dir.join(name);
            if candidate.exists() && candidate.is_file() {
                if let Ok(cfg) = Self::load_from_file(&candidate) {
                    return Some((cfg, candidate));
                }
            }
        }
        None
    }

    /// Loads configuration from an explicit file path (YAML or TOML).
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file '{}': {}", path.display(), e))?;

        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext == "yaml" || ext == "yml" {
            serde_yaml::from_str(&content)
                .map_err(|e| format!("Invalid YAML syntax in '{}': {}", path.display(), e))
        } else if ext == "toml" {
            toml::from_str(&content)
                .map_err(|e| format!("Invalid TOML syntax in '{}': {}", path.display(), e))
        } else {
            Self::from_str_auto(&content)
        }
    }

    /// Parse configuration from a string, automatically detecting YAML or TOML syntax.
    pub fn from_str_auto(content: &str) -> Result<Self, String> {
        if let Ok(cfg) = serde_yaml::from_str(content) {
            Ok(cfg)
        } else {
            toml::from_str(content)
                .map_err(|e| format!("Failed to parse config as YAML or TOML: {}", e))
        }
    }
}
