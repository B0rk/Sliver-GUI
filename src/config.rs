//! Loading of Sliver operator configuration files.
//!
//! These are the same JSON `.cfg` files the official `sliver-client` consumes,
//! normally found under `~/.sliver-client/configs/`. Field names mirror the Go
//! `assets.ClientConfig` struct so existing operator configs load unchanged.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct OperatorConfig {
    #[serde(default)]
    pub operator: String,
    pub lhost: String,
    pub lport: u16,
    #[serde(default)]
    pub token: String,
    pub ca_certificate: String,
    pub private_key: String,
    pub certificate: String,

    /// The on-disk path we loaded this from (not part of the JSON).
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
}

impl OperatorConfig {
    pub fn load_file(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let mut cfg: OperatorConfig = serde_json::from_str(&raw)?;
        cfg.source_path = Some(path.to_path_buf());
        Ok(cfg)
    }

    /// Short human label, e.g. `operator@host:port`.
    pub fn label(&self) -> String {
        let who = if self.operator.is_empty() {
            "operator"
        } else {
            &self.operator
        };
        format!("{who}@{}:{}", self.lhost, self.lport)
    }

    #[allow(dead_code)]
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.lhost, self.lport)
    }
}

/// Default config directory: `~/.sliver-client/configs`.
pub fn default_config_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sliver-client").join("configs"))
}

/// Discover operator configs in the default directory.
pub fn discover_configs() -> Vec<OperatorConfig> {
    let Some(dir) = default_config_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(cfg) = OperatorConfig::load_file(&path) {
                out.push(cfg);
            }
        }
    }
    out.sort_by(|a, b| a.label().cmp(&b.label()));
    out
}
