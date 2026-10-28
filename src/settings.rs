//! Persistent GUI settings: theme, notifications, dock layout, graph node
//! positions, listener presets, host notes and the screenshot gallery index.
//!
//! Stored as JSON at `<config dir>/sliver-gui/settings.json`. Loading never
//! fails — a missing or unreadable file yields defaults.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ListenerPreset {
    pub name: String,
    /// 0 mtls, 1 http(s), 2 dns, 3 stage (tcp), 4 wireguard
    pub kind: usize,
    pub host: String,
    pub port: u32,
    pub domain: String,
    pub secure: bool,
    pub website: String,
    pub stage_c2: String,
    pub wg_nport: u32,
    pub wg_key_port: u32,
    /// HTTPS certificate: 0 Sliver's self-signed, 1 PEM files below, 2 Let's Encrypt.
    pub tls: u8,
    pub cert: String,
    pub key: String,
}

/// One saved screenshot in the gallery.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Shot {
    pub file: String,
    pub host: String,
    pub implant: String,
    pub time: i64,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub light_theme: bool,
    /// Toast + window attention when a new session/beacon checks in.
    pub notify_callbacks: bool,
    pub notify_attention: bool,
    /// Hide credential secrets until hovered/copied.
    pub mask_secrets: bool,
    /// Append the event log to a daily file in the data dir.
    pub log_events: bool,
    /// Log command lines entered in the Sliver Console / Local Terminal to a daily file.
    pub log_terminal: bool,
    /// Log operator actions (on implants and the server) to a daily file.
    pub log_activity: bool,
    /// Send GUI errors to this operator's client log on the server.
    pub server_client_log: bool,
    /// Serialized dock layout (permanent tabs only).
    pub dock: Option<serde_json::Value>,
    /// Session-graph node positions keyed by `hostname|name`.
    pub graph_pos: HashMap<String, (f32, f32)>,
    pub listener_presets: Vec<ListenerPreset>,
    /// Settings of listeners this GUI started, keyed by `server/kind/port`
    /// (job IDs change when the server restarts), for the Edit dialog.
    pub listener_specs: HashMap<String, ListenerPreset>,
    /// sliver-client for the Sliver Console tab; empty = look on PATH.
    pub sliver_client_path: String,
    pub msfvenom_path: String,
    /// Local Terminal shell; empty = the login shell (`$SHELL`) / PowerShell on Windows.
    pub local_shell: String,
    /// Operator notes per host UUID.
    pub host_notes: HashMap<String, String>,
    pub shots: Vec<Shot>,
    /// Sliver-console command history (most recent last).
    pub server_history: Vec<String>,
    /// Folder the last implant was saved to (start of the next Save dialog).
    pub build_dir: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            light_theme: false,
            notify_callbacks: true,
            notify_attention: true,
            mask_secrets: true,
            log_events: true,
            server_client_log: true,
            log_terminal: true,
            log_activity: true,
            dock: None,
            graph_pos: HashMap::new(),
            listener_presets: Vec::new(),
            listener_specs: HashMap::new(),
            sliver_client_path: String::new(),
            msfvenom_path: String::new(),
            local_shell: String::new(),
            host_notes: HashMap::new(),
            shots: Vec::new(),
            server_history: Vec::new(),
            build_dir: String::new(),
        }
    }
}

/// `<config dir>/sliver-gui`, overridable with `SLIVER_GUI_HOME` (tests).
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SLIVER_GUI_HOME") {
        return Some(PathBuf::from(p));
    }
    dirs::config_dir().map(|d| d.join("sliver-gui"))
}

/// `<data dir>/sliver-gui` — screenshots and event logs.
pub fn data_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SLIVER_GUI_HOME") {
        return Some(PathBuf::from(p).join("data"));
    }
    dirs::data_dir().map(|d| d.join("sliver-gui"))
}

impl Settings {
    pub fn load() -> Self {
        config_dir()
            .map(|d| d.join("settings.json"))
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let dir = config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join("settings.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, dir.join("settings.json"))?;
        Ok(())
    }
}
