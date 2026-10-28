//! State and update handling for the extended views (processes, registry,
//! services, builds, hosts, pivots, C2 profiles, gallery), plus shared
//! modals: confirmations, beacon reconfigure, settings and the cred editor.

use std::collections::{HashMap, HashSet};

use super::{kit, SliverApp};
use crate::client::{BuildInfo, Command, GrepHit, Op, OpUpdate, ServerInfo, Target};
use crate::proto::{clientpb, commonpb, sliverpb};
use crate::theme::Palette;

#[derive(Default)]
pub(super) struct ProcView {
    pub procs: Vec<commonpb::Process>,
    pub filter: String,
    pub tree: bool,
    pub loading: bool,
    pub selected: Option<i32>,
}

pub(super) struct RegView {
    pub hive: String,
    pub path: String,
    pub path_edit: String,
    pub subkeys: Vec<String>,
    pub values: Vec<String>,
    pub value: Option<(String, String)>,
    pub loading: bool,
    pub edit_key: String,
    pub edit_value: String,
    pub edit_dword: bool,
    pub new_key: String,
}

impl Default for RegView {
    fn default() -> Self {
        Self {
            hive: "HKLM".into(),
            path: "SOFTWARE".into(),
            path_edit: "SOFTWARE".into(),
            subkeys: Vec::new(),
            values: Vec::new(),
            value: None,
            loading: false,
            edit_key: String::new(),
            edit_value: String::new(),
            edit_dword: false,
            new_key: String::new(),
        }
    }
}

#[derive(Default)]
pub(super) struct SvcView {
    pub services: Vec<sliverpb::ServiceDetails>,
    pub filter: String,
    pub loading: bool,
    pub running_only: bool,
    /// Full record for one service (right-click → Details).
    pub detail: Option<sliverpb::ServiceDetails>,
}

#[derive(Default)]
pub(super) struct GrepView {
    pub pattern: String,
    pub recursive: bool,
    pub root: String,
    pub hits: Vec<GrepHit>,
    pub running: bool,
}

/// A pending destructive action awaiting operator confirmation.
pub(super) struct Confirm {
    pub title: String,
    pub body: String,
    pub cmds: Vec<Command>,
}

#[derive(Clone, Default)]
pub(super) struct CredForm {
    pub id: Option<String>,
    pub username: String,
    pub plaintext: String,
    pub hash: String,
    pub hash_type: i32,
    pub collection: String,
    pub is_cracked: bool,
    pub origin: String,
}

pub(super) struct ReconfigForm {
    pub target: Target,
    pub label: String,
    pub interval: i64,
    pub jitter: i64,
}

#[derive(Default)]
pub(super) struct ExtState {
    /// Sliver Console tab: the embedded sliver-client, whether it was auto-started, last start error.
    pub cli: Option<super::term::LocalTerm>,
    pub cli_tried: bool,
    pub cli_err: String,
    /// Local Terminal tab: a shell on this machine, whether it was auto-started, last
    /// start error, the shell it's running, and the shells found on this host.
    pub local: Option<super::term::LocalTerm>,
    pub local_tried: bool,
    pub local_err: String,
    pub local_running: String,
    pub local_shells: Vec<String>,
    /// Terminal command lines entered this client session: (unix time, source, line).
    pub term_log: Vec<(i64, String, String)>,
    /// Operator activity this client session: (unix time, target, what). Written from
    /// `send`, which only borrows the app, hence the RefCell.
    pub activity: std::cell::RefCell<Vec<(i64, String, String)>>,
    /// A `generate stager` command queued for the embedded Sliver Console, flushed once
    /// the console reaches a prompt (staged-payload builds).
    pub staged_stager_cmd: Option<String>,
    /// Dependency check (Settings → Environment): cached version banner per resolved tool
    /// path, filled off the UI thread (msfvenom's first run is slow).
    pub dep_versions: std::sync::Arc<std::sync::Mutex<HashMap<String, Option<String>>>>,
    /// Tool paths whose version probe is in flight, so it isn't re-spawned every frame.
    pub dep_probing: HashSet<String>,

    pub procs: HashMap<String, ProcView>,
    pub reg: HashMap<String, RegView>,
    pub svcs: HashMap<String, SvcView>,
    pub grep: HashMap<String, GrepView>,
    pub mounts: HashMap<String, Vec<sliverpb::MountInfo>>,
    pub previews: HashMap<String, (String, Vec<u8>)>,

    pub profiles: Vec<clientpb::ImplantProfile>,
    pub builds: Vec<BuildInfo>,
    pub canaries: Vec<clientpb::DnsCanary>,
    pub builds_view: u8,
    pub save_profile_name: String,
    /// Pivot listeners were requested for the generator's listener picker.
    pub gen_pivots_fetched: bool,

    pub hosts: Vec<clientpb::Host>,
    pub host_sel: Option<String>,

    pub pivot_listeners: HashMap<String, Vec<sliverpb::PivotListener>>,
    pub wg: HashMap<String, (Vec<sliverpb::WgSocksServer>, Vec<sliverpb::WgtcpForwarder>)>,

    pub c2_profiles: Vec<String>,
    pub c2_detail: Option<Box<clientpb::Httpc2Config>>,
    pub c2_overwrite: bool,

    pub operators: Vec<clientpb::Operator>,

    /// Server tab: certificates, compiler targets, builders, AI providers.
    pub server: Option<Box<ServerInfo>>,
    pub server_loading: bool,
    pub cert_filter: String,
    pub ai_convs: Vec<clientpb::AiConversation>,
    pub ai_sel: Option<Box<clientpb::AiConversation>>,

    /// Implant-side reverse port-forwards as the server reports them, per target.
    pub rportfwds: HashMap<String, Vec<sliverpb::RportFwdListener>>,
    /// WASM extensions registered on each implant.
    pub wasm: HashMap<String, Vec<String>>,

    pub loot_preview: Option<(String, String, Vec<u8>)>,
    pub loot_search: String,
    pub cred_search: String,
    pub cred_form: Option<CredForm>,
    pub cred_sel: HashSet<String>,
    /// Creds tab hash-type filter (server-side): the chosen type and, once fetched, its IDs.
    pub cred_type: Option<i32>,
    pub cred_type_ids: Option<(i32, HashSet<String>)>,
    /// Loot being renamed: (id, new name).
    pub loot_rename: Option<(String, String)>,
    /// Hosted file whose Content-Type is being edited: (website, path, type).
    pub hosted_ct: Option<(String, String, String)>,

    pub confirm: Option<Confirm>,
    pub reconfig: Option<ReconfigForm>,
    pub show_settings: bool,

    pub shot_sel: Option<usize>,
    pub shot_tex: HashMap<String, egui::TextureHandle>,
    /// Textures of deleted captures, held one extra frame: freeing a texture
    /// in the frame that still draws it panics the wgpu renderer.
    pub shot_tex_retired: Vec<egui::TextureHandle>,
    pub shot_zoom: f32,
    pub shot_filter: String,

    /// Beacon task ids whose results were already printed to the console.
    pub seen_tasks: HashMap<String, HashSet<String>>,
    /// When each beacon console was opened (unix secs): tasks created after
    /// this print automatically when they complete.
    pub beacon_console_since: HashMap<String, i64>,
    /// Targets whose next directory listing was requested from a console.
    pub console_ls: HashSet<String>,
    pub beacon_poll_at: f64,
    /// Last periodic session/beacon list refresh (keeps live/dead status current).
    pub list_poll_at: f64,
    /// Requests to sessions still waiting on a reply: (id, target key, label, started).
    pub running: Vec<(u64, String, String, std::time::Instant)>,
}

impl SliverApp {
    /// Queue a destructive action behind a confirmation dialog.
    pub(super) fn confirm(&mut self, title: &str, body: impl Into<String>, cmds: Vec<Command>) {
        self.ext.confirm = Some(Confirm { title: title.into(), body: body.into(), cmds });
    }

    pub(super) fn op(&self, op: Op) {
        self.send(Command::Op(op));
    }

    pub(super) fn apply_op(&mut self, u: OpUpdate) {
        match u {
            OpUpdate::Processes { target, procs } => {
                let v = self.ext.procs.entry(target).or_default();
                v.procs = procs;
                v.loading = false;
            }
            OpUpdate::Cwd { target, path } => {
                let c = self.consoles.entry(target.clone()).or_default();
                c.lines.push(super::ConsoleLine::stamped("[*] working directory", Palette::accent()));
                c.push_line(path.clone(), Palette::text());
                let fb = self.files.entry(target.clone()).or_default();
                fb.cwd = path.clone();
                self.send(Command::Ls { target: self.target_from_key(&target), path });
            }
            OpUpdate::Grep { target, pattern, root, hits } => {
                let g = self.ext.grep.entry(target).or_default();
                g.running = false;
                g.root = root;
                g.hits = hits;
                let n = g.hits.len();
                self.set_toast(true, &format!("search '{pattern}': {n} match(es)"));
            }
            OpUpdate::Mounts { target, mounts } => { self.ext.mounts.insert(target, mounts); }
            OpUpdate::Preview { target, path, data } => { self.ext.previews.insert(target, (path, data)); }
            OpUpdate::Profiles(p) => self.ext.profiles = p,
            OpUpdate::Builds(b) => self.ext.builds = b,
            OpUpdate::Canaries(c) => self.ext.canaries = c,
            OpUpdate::LootContent { id, name, data } => self.ext.loot_preview = Some((id, name, data)),
            OpUpdate::Hosts(h) => self.ext.hosts = h,
            OpUpdate::PivotListeners { target, listeners } => { self.ext.pivot_listeners.insert(target, listeners); }
            OpUpdate::WgList { target, socks, fwds } => { self.ext.wg.insert(target, (socks, fwds)); }
            OpUpdate::C2Profiles(names) => self.ext.c2_profiles = names,
            OpUpdate::C2Profile(p) => self.ext.c2_detail = Some(p),
            OpUpdate::Registry { target, hive, path, subkeys, values } => {
                let r = self.ext.reg.entry(target).or_default();
                r.hive = hive;
                r.path_edit = path.clone();
                r.path = path;
                r.subkeys = subkeys;
                r.values = values;
                r.loading = false;
            }
            OpUpdate::RegValue { target, key, value } => {
                self.ext.reg.entry(target).or_default().value = Some((key, value));
            }
            OpUpdate::Services { target, services } => {
                let s = self.ext.svcs.entry(target).or_default();
                s.services = services;
                s.loading = false;
            }
            OpUpdate::ServiceDetail { target, detail } => {
                self.ext.svcs.entry(target).or_default().detail = Some(detail);
            }
            OpUpdate::Operators(ops) => self.ext.operators = ops,
            OpUpdate::ServerInfo(info) => {
                for e in &info.errors { self.push_event("error", &format!("server info — {e}")); }
                self.ext.server = Some(info);
                self.ext.server_loading = false;
            }
            OpUpdate::AiConversations(list) => self.ext.ai_convs = list,
            OpUpdate::AiConversation(conv) => self.ext.ai_sel = Some(conv),
            OpUpdate::Beacon(b) => {
                self.names.insert(b.id.clone(), b.name.clone());
                match self.beacons.iter_mut().find(|x| x.id == b.id) {
                    Some(x) => *x = *b,
                    None => self.beacons.push(*b),
                }
            }
            OpUpdate::RportFwds { target, listeners } => { self.ext.rportfwds.insert(target, listeners); }
            OpUpdate::WasmExtensions { target, names } => { self.ext.wasm.insert(target, names); }
            OpUpdate::CredDetail(c) => {
                if let Some(f) = self.ext.cred_form.as_mut().filter(|f| f.id.as_deref() == Some(c.id.as_str())) {
                    f.username = c.username;
                    f.plaintext = c.plaintext;
                    f.hash_type = if c.hash.is_empty() && !f.plaintext.is_empty() { -1 } else { c.hash_type };
                    f.hash = c.hash;
                    f.collection = c.collection;
                    f.is_cracked = c.is_cracked;
                }
            }
            OpUpdate::CredsOfType { hash_type, ids } => {
                self.ext.cred_type_ids = Some((hash_type, ids.into_iter().collect()));
            }
            OpUpdate::SniffedHashType { hash, hash_type } => {
                if hash_type == clientpb::HashType::Invalid as i32 {
                    // The server only names unambiguous formats ($6$, $2y$-style crypt strings…);
                    // bare hex such as NTLM / MD5 / SHA1 could be several types.
                    self.set_toast(false, "the server couldn't identify this hash — bare hex (NTLM, MD5, SHA1…) is ambiguous; pick the type by hand");
                } else if let Some(f) = self.ext.cred_form.as_mut().filter(|f| f.hash.trim() == hash) {
                    f.hash_type = hash_type;
                    let name = super::collect::hash_type_name(hash_type);
                    self.set_toast(true, &format!("hash looks like {name}"));
                }
            }
        }
    }

    /// Shared modal windows for the extended views.
    pub(super) fn ext_modals(&mut self, ctx: &egui::Context) {
        // ---- Confirmation ----
        if self.ext.confirm.is_some() {
            let mut decided: Option<bool> = None;
            let (title, body) = self.ext.confirm.as_ref().map(|c| (c.title.clone(), c.body.clone())).unwrap_or_default();
            egui::Window::new(egui::RichText::new(format!("⚠ {title}")).color(Palette::yellow()))
                .id(egui::Id::new("confirm-modal"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, -40.0))
                .show(ctx, |ui| {
                    ui.set_max_width(420.0);
                    ui.label(body);
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(egui::RichText::new("Confirm").strong().color(Palette::red()))).clicked() {
                            decided = Some(true);
                        }
                        if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            decided = Some(false);
                        }
                    });
                });
            if let Some(yes) = decided {
                if let Some(c) = self.ext.confirm.take() {
                    if yes {
                        for cmd in c.cmds { self.send(cmd); }
                    }
                }
            }
        }

        // ---- Beacon reconfigure ----
        if self.ext.reconfig.is_some() {
            let mut open = true;
            let mut apply = false;
            egui::Window::new("Reconfigure beacon")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    if let Some(f) = &mut self.ext.reconfig {
                        ui.colored_label(Palette::muted(), &f.label);
                        egui::Grid::new("reconf").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                            ui.label("Check-in interval");
                            ui.add(egui::DragValue::new(&mut f.interval).range(1..=86_400).suffix(" s"));
                            ui.end_row();
                            ui.label("Jitter");
                            ui.add(egui::DragValue::new(&mut f.jitter).range(0..=3_600).suffix(" s"));
                            ui.end_row();
                        });
                        ui.colored_label(Palette::muted(), "Queued as a beacon task — takes effect after the next check-in.");
                        ui.add_space(6.0);
                        if ui.button(egui::RichText::new("Apply").strong()).clicked() { apply = true; }
                    }
                });
            if apply {
                if let Some(f) = self.ext.reconfig.take() {
                    self.op(Op::Reconfigure { target: f.target, interval_s: f.interval, jitter_s: f.jitter });
                }
            } else if !open {
                self.ext.reconfig = None;
            }
        }

        // ---- Settings ----
        if self.ext.show_settings {
            let mut open = true;
            let mut theme_changed = false;
            let mut changed = false;
            egui::Window::new("⚙ Settings")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    kit::section(ui, "Appearance");
                    ui.horizontal(|ui| {
                        ui.label("Theme");
                        theme_changed |= ui.selectable_value(&mut self.settings.light_theme, false, "☾ Dark").changed();
                        theme_changed |= ui.selectable_value(&mut self.settings.light_theme, true, "☀ Light").changed();
                    });
                    kit::section(ui, "Notifications");
                    changed |= ui.checkbox(&mut self.settings.notify_callbacks, "Toast when a new session or beacon checks in").changed();
                    changed |= ui.checkbox(&mut self.settings.notify_attention, "Flash the window / taskbar on new callbacks").changed();
                    kit::section(ui, "Data");
                    changed |= ui.checkbox(&mut self.settings.mask_secrets, "Mask credential secrets (hover to reveal)").changed();
                    changed |= ui.checkbox(&mut self.settings.log_events, "Write the event log to a daily file").changed();
                    changed |= ui.checkbox(&mut self.settings.log_activity, "Log operator actions (commands on implants, listeners, builds …) to a daily file")
                        .on_hover_text("Every action you send to an implant or the server, and each implant reply, timestamped with its UTC offset. Secrets are left out.").changed();
                    changed |= ui.checkbox(&mut self.settings.log_terminal, "Log commands entered in the Sliver Console / Local Terminal to a daily file")
                        .on_hover_text("Each line you submit, as shown on screen (prompt + command). Input the program doesn't show, such as a password prompt, is never logged.").changed();
                    changed |= ui.checkbox(&mut self.settings.server_client_log, "Send GUI errors to my client log on the server").changed();
                    if let Some(d) = crate::settings::data_dir() {
                        ui.colored_label(Palette::muted(), egui::RichText::new(format!("data: {}", d.display())).small());
                    }
                    kit::section(ui, "Environment");
                    changed |= self.environment_section(ui, ctx);
                    kit::section(ui, "Layout");
                    ui.horizontal(|ui| {
                        if ui.button("Reset dock layout").clicked() {
                            self.dock = super::default_dock(None);
                            changed = true;
                        }
                        if ui.button("Reset graph positions").clicked() {
                            self.graph_pos.clear();
                            changed = true;
                        }
                    });
                });
            if theme_changed {
                crate::theme::apply(ctx, self.settings.light_theme);
                changed = true;
            }
            if changed { self.settings_dirty = true; }
            if !open { self.ext.show_settings = false; }
        }

        // ---- Credential editor ----
        if self.ext.cred_form.is_some() {
            let mut open = true;
            let mut save = false;
            let mut sniff: Option<String> = None;
            egui::Window::new(if self.ext.cred_form.as_ref().is_some_and(|f| f.id.is_some()) { "Edit credential" } else { "Add credential" })
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    if let Some(f) = &mut self.ext.cred_form {
                        egui::Grid::new("credform").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                            ui.label("Username");
                            ui.text_edit_singleline(&mut f.username);
                            ui.end_row();
                            ui.label("Plaintext");
                            ui.text_edit_singleline(&mut f.plaintext);
                            ui.end_row();
                            ui.label("Hash");
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut f.hash);
                                if ui.add_enabled(!f.hash.trim().is_empty(), egui::Button::new("Detect"))
                                    .on_hover_text("Ask the server to identify the hash type").clicked() {
                                    sniff = Some(f.hash.trim().to_string());
                                }
                            });
                            ui.end_row();
                            ui.label("Hash type");
                            egui::ComboBox::from_id_salt("cred-hashtype")
                                .selected_text(super::collect::hash_type_name(f.hash_type))
                                .show_ui(ui, |ui| {
                                    for (v, n) in super::collect::COMMON_HASH_TYPES {
                                        ui.selectable_value(&mut f.hash_type, *v, *n);
                                    }
                                });
                            ui.end_row();
                            ui.label("Collection / tag");
                            ui.text_edit_singleline(&mut f.collection);
                            ui.end_row();
                            ui.label("Cracked");
                            ui.checkbox(&mut f.is_cracked, "plaintext recovered");
                            ui.end_row();
                        });
                        ui.add_space(6.0);
                        let valid = !f.username.trim().is_empty() && (!f.plaintext.is_empty() || !f.hash.is_empty());
                        if ui.add_enabled(valid, egui::Button::new(egui::RichText::new("Save").strong())).clicked() { save = true; }
                    }
                });
            if let Some(hash) = sniff { self.op(Op::SniffHashType { hash }); }
            if save {
                if let Some(f) = self.ext.cred_form.take() {
                    self.save_cred(f);
                }
            } else if !open {
                self.ext.cred_form = None;
            }
        }
    }

    /// Settings → Environment: the runtime dependency check. Lists each external tool the
    /// GUI shells out to with its resolved path + version (or a "not found" hint), and a
    /// Browse… control so a tool kept outside the system PATH — a repo pull or a portable
    /// copy — can be pointed at directly (a binary, or the directory holding it). Version
    /// banners are probed off-thread and cached. Returns true if a setting changed.
    fn environment_section(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> bool {
        let mut changed = false;
        let mut browse_set: Option<(&'static str, String)> = None;
        for tool in crate::deps::TOOLS {
            let configured = self.tool_override(tool.key).to_string();
            let resolved = crate::deps::resolve(tool.exe, &configured);
            ui.horizontal(|ui| {
                match &resolved {
                    Some(path) => {
                        let cached = self.ext.dep_versions.lock().ok().and_then(|m| m.get(path).cloned());
                        let ver: String = match cached {
                            Some(Some(v)) => v,
                            Some(None) => "version n/a".into(),
                            None => {
                                if self.ext.dep_probing.insert(path.clone()) {
                                    let cache = self.ext.dep_versions.clone();
                                    let (ctx2, p) = (ctx.clone(), path.clone());
                                    let args: Vec<String> = tool.version_args.iter().map(|s| s.to_string()).collect();
                                    std::thread::spawn(move || {
                                        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                                        let v = crate::deps::probe_version(&p, &refs);
                                        if let Ok(mut m) = cache.lock() { m.insert(p, v); }
                                        ctx2.request_repaint();
                                    });
                                }
                                "checking…".into()
                            }
                        };
                        ui.colored_label(Palette::green(), format!("✓ {}", tool.label));
                        ui.colored_label(Palette::muted(), ver).on_hover_text(path);
                    }
                    None => { ui.colored_label(Palette::yellow(), format!("⚠ {} — not found", tool.label)); }
                }
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        browse_set = Some((tool.key, p.display().to_string()));
                    }
                }
                if !configured.trim().is_empty() && ui.small_button("✕").on_hover_text("Clear the override and use PATH").clicked() {
                    browse_set = Some((tool.key, String::new()));
                }
            });
            ui.colored_label(Palette::muted(), egui::RichText::new(format!("for {}", tool.why)).small());
            if resolved.is_none() {
                ui.colored_label(Palette::muted(), egui::RichText::new(tool.install_hint).small());
            }
        }
        if ui.button("Re-check").clicked() {
            if let Ok(mut m) = self.ext.dep_versions.lock() { m.clear(); }
            self.ext.dep_probing.clear();
        }
        if let Some((key, path)) = browse_set {
            self.set_tool_override(key, path);
            changed = true;
        }
        changed
    }

    /// The operator-set path override for a dependency (empty = search PATH).
    fn tool_override(&self, key: &str) -> &str {
        match key {
            "sliver-client" => &self.settings.sliver_client_path,
            "msfvenom" => &self.settings.msfvenom_path,
            _ => "",
        }
    }

    /// Set (or clear, with an empty string) a dependency's path override.
    fn set_tool_override(&mut self, key: &str, path: String) {
        match key {
            "sliver-client" => self.settings.sliver_client_path = path,
            "msfvenom" => self.settings.msfvenom_path = path,
            _ => {}
        }
        self.settings_dirty = true;
    }
}
