//! Sliver armory client: fetch the signed package index, install extensions,
//! and enumerate what is already installed.
//!
//! This mirrors the official client: the default armory is the GitHub releases
//! of `sliverarmory/armory`, whose latest release carries `armory.json` (the
//! index) and `armory.minisig` (its minisign signature). Each listed package in
//! turn has its own GitHub releases with `<command_name>.tar.gz` + `.minisig`.
//! Signatures are verified against the official (or a configured) public key.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;

/// Official armory signing key (same value the stock client ships with).
pub const OFFICIAL_PUBLIC_KEY: &str = "RWSBpxpRWDrD7Fe+VvRE3c2VEDC2NK80rlNCj+BX0gz44Xw07r6KQD9L";
/// Default armory index location (GitHub releases API).
pub const DEFAULT_REPO_URL: &str = "https://api.github.com/repos/sliverarmory/armory/releases";

const USER_AGENT: &str = "sliver-gui";

/// A package entry from the armory index (alias or extension).
#[derive(Clone, Debug, Deserialize)]
pub struct Package {
    pub name: String,
    pub command_name: String,
    pub repo_url: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
struct ArmoryIndexJson {
    #[serde(default)]
    aliases: Vec<Package>,
    #[serde(default)]
    extensions: Vec<Package>,
}

/// Parsed armory index.
#[derive(Clone, Debug, Default)]
pub struct ArmoryIndex {
    pub aliases: Vec<Package>,
    pub extensions: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

/// Metadata about an installed extension on disk.
#[derive(Clone, Debug)]
pub struct Installed {
    pub name: String,
    pub command_name: String,
    pub version: String,
    pub root: PathBuf,
    pub files: Vec<ExtFile>,
    pub init: String,
    pub is_bof: bool,
}

#[derive(Clone, Debug)]
pub struct ExtFile {
    pub os: String,
    pub arch: String,
    pub path: String,
}

impl Installed {
    /// Pick the binary file matching the given target, falling back to any entry
    /// whose OS matches.
    pub fn file_for(&self, os: &str, arch: &str) -> Option<&ExtFile> {
        self.files
            .iter()
            .find(|f| f.os.eq_ignore_ascii_case(os) && f.arch.eq_ignore_ascii_case(arch))
            .or_else(|| self.files.iter().find(|f| f.os.eq_ignore_ascii_case(os)))
            .or_else(|| self.files.first())
    }
}

/// `~/.sliver-client/extensions`.
pub fn extensions_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sliver-client")
        .join("extensions")
}

fn gh_json(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call();
    read_body(resp)
}

fn gh_asset(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/octet-stream")
        .call();
    read_body(resp)
}

fn read_body(resp: std::result::Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>> {
    match resp {
        Ok(r) => {
            let mut buf = Vec::new();
            r.into_reader()
                .take(256 * 1024 * 1024)
                .read_to_end(&mut buf)
                .context("reading response body")?;
            Ok(buf)
        }
        Err(ureq::Error::Status(403, _)) => {
            bail!("GitHub API rate limit hit (60 req/hr unauthenticated) — try again later")
        }
        Err(ureq::Error::Status(code, _)) => bail!("armory request failed (HTTP {code})"),
        Err(e) => Err(anyhow!("armory request failed: {e}")),
    }
}

fn verify(public_key_b64: &str, data: &[u8], sig_text: &[u8]) -> Result<()> {
    let pk = PublicKey::from_base64(public_key_b64.trim())
        .map_err(|e| anyhow!("invalid public key: {e}"))?;
    let sig_str = std::str::from_utf8(sig_text).context("signature not UTF-8")?;
    let sig = Signature::decode(sig_str).map_err(|e| anyhow!("invalid signature: {e}"))?;
    pk.verify(data, &sig, true)
        .map_err(|e| anyhow!("signature verification failed: {e}"))
}

fn latest_release(repo_url: &str) -> Result<GithubRelease> {
    let body = gh_json(repo_url)?;
    let releases: Vec<GithubRelease> =
        serde_json::from_slice(&body).context("parsing GitHub releases")?;
    releases
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no releases found at {repo_url}"))
}

/// Fetch and verify the armory index.
pub fn fetch_index(repo_url: &str, public_key_b64: &str) -> Result<ArmoryIndex> {
    let release = latest_release(repo_url)?;
    let mut index_data = None;
    let mut sig_data = None;
    for asset in &release.assets {
        match asset.name.as_str() {
            "armory.json" => index_data = Some(gh_asset(&asset.url)?),
            "armory.minisig" => sig_data = Some(gh_asset(&asset.url)?),
            _ => {}
        }
    }
    let index_data = index_data.ok_or_else(|| anyhow!("armory.json not found in release"))?;
    let sig_data = sig_data.ok_or_else(|| anyhow!("armory.minisig not found in release"))?;
    verify(public_key_b64, &index_data, &sig_data).context("verifying index signature")?;

    let parsed: ArmoryIndexJson =
        serde_json::from_slice(&index_data).context("parsing armory index")?;
    Ok(ArmoryIndex {
        aliases: parsed.aliases,
        extensions: parsed.extensions,
    })
}

/// Resolve a github.com `/releases/latest` redirect to its tag.
fn github_latest_tag(repo_url: &str) -> Result<String> {
    let agent = ureq::builder().redirects(0).build();
    let url = format!("{}/releases/latest", repo_url.trim_end_matches('/'));
    let resp = agent
        .get(&url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| anyhow!("resolving latest release: {e}"))?;
    let location = resp
        .header("location")
        .ok_or_else(|| anyhow!("no redirect to a release tag for {repo_url}"))?;
    // Location looks like .../releases/tag/<tag>
    let segs: Vec<&str> = location.split('/').collect();
    for (i, s) in segs.iter().enumerate() {
        if *s == "tag" && i + 1 < segs.len() {
            return Ok(segs[i + 1].to_string());
        }
    }
    bail!("could not determine latest tag for {repo_url}")
}

fn download_direct(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url).set("User-Agent", USER_AGENT).call();
    read_body(resp)
}

/// Fetch a package's `.tar.gz` and `.minisig`, handling both the github.com
/// (direct download) and api.github.com (releases API) layouts.
fn package_assets(pkg: &Package) -> Result<(Vec<u8>, Vec<u8>)> {
    let tar_name = format!("{}.tar.gz", pkg.command_name);
    let sig_name = format!("{}.minisig", pkg.command_name);

    if pkg.repo_url.contains("api.github.com") {
        let release = latest_release(&pkg.repo_url)?;
        let mut tar_gz = None;
        let mut sig = None;
        for asset in &release.assets {
            if asset.name == tar_name {
                tar_gz = Some(gh_asset(&asset.url)?);
            } else if asset.name == sig_name {
                sig = Some(gh_asset(&asset.url)?);
            }
        }
        Ok((
            tar_gz.ok_or_else(|| anyhow!("{tar_name} not found in package release"))?,
            sig.ok_or_else(|| anyhow!("{sig_name} not found in package release"))?,
        ))
    } else {
        let tag = github_latest_tag(&pkg.repo_url)?;
        let base = format!("{}/releases/download/{tag}", pkg.repo_url.trim_end_matches('/'));
        let tar_gz = download_direct(&format!("{base}/{tar_name}"))?;
        let sig = download_direct(&format!("{base}/{sig_name}"))?;
        Ok((tar_gz, sig))
    }
}

/// Download, verify, and extract an extension package to the extensions dir.
/// Returns the installed extension metadata.
pub fn install_extension(pkg: &Package) -> Result<Installed> {
    let (tar_gz, sig) = package_assets(pkg)?;
    verify(&pkg.public_key, &tar_gz, &sig).context("verifying package signature")?;

    let dest = extensions_dir().join(sanitize_component(&pkg.command_name));
    if dest.exists() {
        let _ = std::fs::remove_dir_all(&dest);
    }
    std::fs::create_dir_all(&dest).context("creating extension dir")?;
    extract_tar_gz(&tar_gz, &dest).context("extracting package")?;

    let manifest_path = dest.join("extension.json");
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("package has no extension.json at {}", manifest_path.display()))?;
    parse_manifest(&dest, &manifest_bytes)
}

/// Enumerate installed extensions by scanning the extensions directory.
pub fn installed_extensions() -> Vec<Installed> {
    let dir = extensions_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let manifest = entry.path().join("extension.json");
        if let Ok(bytes) = std::fs::read(&manifest) {
            if let Ok(inst) = parse_manifest(&entry.path(), &bytes) {
                out.push(inst);
            }
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// Parse either a v1 (flat) or v2 (`commands[]`) extension manifest.
fn parse_manifest(root: &Path, bytes: &[u8]) -> Result<Installed> {
    let v: serde_json::Value = serde_json::from_slice(bytes).context("parsing extension.json")?;
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let version = v.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string();

    // v1 keeps files/init/entrypoint at the top level; v2 nests them under commands[0].
    let (command_name, files_val, init, depends_on) = if v.get("commands").is_some() {
        let cmd = v
            .get("commands")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        (
            v.get("command_name").and_then(|x| x.as_str())
                .or_else(|| cmd.get("command_name").and_then(|x| x.as_str()))
                .unwrap_or(&name).to_string(),
            cmd.get("files").cloned(),
            cmd.get("init").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            cmd.get("depends_on").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        )
    } else {
        (
            v.get("command_name").and_then(|x| x.as_str()).unwrap_or(&name).to_string(),
            v.get("files").cloned(),
            v.get("init").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            v.get("depends_on").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        )
    };

    let mut files = Vec::new();
    if let Some(arr) = files_val.and_then(|f| f.as_array().cloned()) {
        for f in arr {
            files.push(ExtFile {
                os: f.get("os").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                arch: f.get("arch").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                path: f.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            });
        }
    }
    let is_bof = depends_on.to_lowercase().contains("coff")
        || files.iter().any(|f| f.path.to_lowercase().ends_with(".o"));

    Ok(Installed {
        name: if name.is_empty() { command_name.clone() } else { name },
        command_name,
        version,
        root: root.to_path_buf(),
        files,
        init,
        is_bof,
    })
}

fn extract_tar_gz(data: &[u8], dest: &Path) -> Result<()> {
    let gz = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz);
    for entry in archive.entries().context("reading tar")? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        // Guard against path traversal and absolute paths.
        let safe: PathBuf = path
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .collect();
        if safe.as_os_str().is_empty() {
            continue;
        }
        let out = dest.join(&safe);
        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&out)?;
        }
    }
    Ok(())
}

fn sanitize_component(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}
