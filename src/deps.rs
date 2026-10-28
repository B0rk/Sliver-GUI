//! Runtime checks for the external tools the GUI shells out to — `sliver-client` (the
//! embedded Sliver Console) and `msfvenom` (staged-payload stubs). Each tool is resolved
//! on the `PATH` or at an operator-set path, so a tool run from a repo pull or a portable
//! copy (rather than a system install) still works: point the override at the binary, or
//! at the directory holding it. Version probing is best-effort and belongs off the UI
//! thread (msfvenom's first run is slow).

use std::path::Path;

/// One external tool the GUI can use.
pub struct Tool {
    pub key: &'static str,
    pub label: &'static str,
    /// Bare binary name (no extension; `.exe` is appended on Windows).
    pub exe: &'static str,
    pub why: &'static str,
    pub install_hint: &'static str,
    pub version_args: &'static [&'static str],
}

/// The tools the GUI depends on at runtime, in display order.
pub const TOOLS: &[Tool] = &[
    Tool {
        key: "sliver-client",
        label: "sliver-client",
        exe: "sliver-client",
        why: "the Sliver Console tab (embedded operator client)",
        install_hint: "Copy the sliver-client binary matching your server version onto PATH, or Browse to it.",
        version_args: &["version"],
    },
    Tool {
        key: "msfvenom",
        label: "msfvenom",
        exe: "msfvenom",
        why: "staged payloads (building the stager stub)",
        install_hint: "Install metasploit-framework, or Browse to the msfvenom binary.",
        version_args: &["--version"],
    },
];

/// The platform binary name for `exe` (adds `.exe` on Windows).
fn exe_name(exe: &str) -> String {
    if cfg!(windows) && !exe.ends_with(".exe") { format!("{exe}.exe") } else { exe.to_string() }
}

/// Resolve a tool to a concrete binary path: the operator's `configured` override when it
/// is a file (or a directory containing the binary), otherwise the first match on `PATH`.
pub fn resolve(exe: &str, configured: &str) -> Option<String> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let p = Path::new(configured);
        if p.is_file() {
            return Some(configured.to_string());
        }
        if p.is_dir() {
            let candidate = p.join(exe_name(exe));
            if candidate.is_file() {
                return Some(candidate.display().to_string());
            }
        }
    }
    let name = exe_name(exe);
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).map(|d| d.join(&name)).find(|p| p.is_file()).map(|p| p.display().to_string())
    })
}

/// Run `<path> <args>` and return its first non-empty output line (the version banner).
/// Best-effort: returns `None` if the tool can't be run. Call off the UI thread.
pub fn probe_version(path: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(path)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let bytes = if out.stdout.is_empty() { out.stderr } else { out.stdout };
    String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.chars().take(80).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_an_override_file_or_directory() {
        let dir = std::env::temp_dir().join(format!("sliver-gui-deps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join(exe_name("toolx"));
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        // An explicit file path is used as-is.
        assert_eq!(resolve("toolx", &bin.display().to_string()), Some(bin.display().to_string()));
        // A directory override resolves to the binary inside it.
        assert_eq!(resolve("toolx", &dir.display().to_string()), Some(bin.display().to_string()));
        // An override that is neither a file nor a dir with the binary falls through to PATH,
        // where this made-up name won't exist.
        assert!(resolve("sliver-gui-nonexistent-tool-zzz", "/no/such/path").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
