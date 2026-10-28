//! Implant generator dialog. Laid out top-down: target, listener type, the
//! listener itself (picked from what the server is running, or typed), then
//! only the options that apply to that transport, mode and format.

use super::{build_generate_request, kit, short, GenerateForm, SliverApp};
use crate::client::{Command, Op, Target};
use crate::proto::clientpb;
use crate::theme::Palette;
use std::collections::HashMap;

/// The C2 transport an implant calls back over.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) enum Transport {
    #[default]
    Mtls,
    Http,
    Dns,
    Wg,
    TcpPivot,
    NamedPipe,
}

impl Transport {
    pub const ALL: [Transport; 6] = [Self::Mtls, Self::Http, Self::Dns, Self::Wg, Self::TcpPivot, Self::NamedPipe];

    pub fn label(self) -> &'static str {
        match self {
            Self::Mtls => "mTLS",
            Self::Http => "HTTP(S)",
            Self::Dns => "DNS",
            Self::Wg => "WireGuard",
            Self::TcpPivot => "TCP pivot (chain through a session)",
            Self::NamedPipe => "Named pipe (chain through a Windows session)",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Mtls => "host:port, e.g. 198.51.100.5:8888",
            Self::Http => "https://host[:port] or host",
            Self::Dns => "parent domain, e.g. c2.example.com",
            Self::Wg => "host:port of the WireGuard listener (UDP)",
            Self::TcpPivot => "pivot session's address:port, e.g. 198.51.100.7:9898",
            Self::NamedPipe => "host/pipe/name, e.g. 198.51.100.7/pipe/msupd",
        }
    }

    pub fn is_pivot(self) -> bool {
        matches!(self, Self::TcpPivot | Self::NamedPipe)
    }
}

impl GenerateForm {
    /// The address list (comma-separated) for one transport.
    pub(super) fn addr(&self, t: Transport) -> &String {
        match t {
            Transport::Mtls => &self.mtls,
            Transport::Http => &self.http,
            Transport::Dns => &self.dns,
            Transport::Wg => &self.wg,
            Transport::TcpPivot => &self.tcp_pivot,
            Transport::NamedPipe => &self.named_pipe,
        }
    }

    pub(super) fn addr_mut(&mut self, t: Transport) -> &mut String {
        match t {
            Transport::Mtls => &mut self.mtls,
            Transport::Http => &mut self.http,
            Transport::Dns => &mut self.dns,
            Transport::Wg => &mut self.wg,
            Transport::TcpPivot => &mut self.tcp_pivot,
            Transport::NamedPipe => &mut self.named_pipe,
        }
    }
}

/// Architectures offered per OS.
fn arches(os: &str) -> &'static [&'static str] {
    match os {
        "windows" => &["amd64", "386"],
        "darwin" => &["amd64", "arm64"],
        _ => &["amd64", "386", "arm64"],
    }
}

/// Output formats offered per OS, as (OutputFormat value, label).
fn formats(os: &str) -> &'static [(i32, &'static str)] {
    match os {
        "windows" => &[(2, "Executable (.exe)"), (0, "Shared library (.dll)"), (1, "Shellcode"), (3, "Service (.exe)")],
        "darwin" => &[(2, "Executable"), (0, "Shared library (.dylib)")],
        _ => &[(2, "Executable"), (0, "Shared library (.so)")],
    }
}

/// Why the server can't build `os/arch` in `format`, or None if its compiler lists it.
fn unsupported_target(targets: &[clientpb::CompilerTarget], os: &str, arch: &str, format: i32) -> Option<String> {
    if targets.iter().any(|t| t.goos == os && t.goarch == arch && t.format == format) { return None; }
    let what = super::server::format_name(format);
    Some(if targets.iter().any(|t| t.goos == os && t.goarch == arch) {
        format!("this server can't build {os}/{arch} as {what} (see Server → Compile targets)")
    } else {
        format!("this server has no compiler for {os}/{arch} (see Server → Compile targets)")
    })
}

/// Host part of `host:port` (IPv6 brackets kept).
/// The port of a `host:port` / `wg://host:port` address (the first, if several).
fn udp_port(addr: &str) -> Option<u32> {
    addr.split(',').next()?.trim().rsplit_once(':')?.1.parse().ok()
}

/// Port of the first address if it's an https:// URL (443 when not given).
fn https_port(addr: &str) -> Option<u32> {
    let rest = addr.split(',').next()?.trim().strip_prefix("https://")?;
    let hostport = rest.split('/').next()?;
    Some(hostport.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(443))
}

fn host_of(addr: &str) -> &str {
    addr.rsplit_once(':').map_or(addr, |(h, _)| h)
}

/// Server-side listener jobs that fit a transport, as (label, address).
/// Listeners bind on the server, so the address uses `server` (the host this
/// client connects to) unless an HTTP listener is tied to a domain.
pub(super) fn server_listener_choices(t: Transport, jobs: &[clientpb::Job], server: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for j in jobs {
        let name = j.name.as_str();
        match (t, name) {
            (Transport::Mtls, "mtls") | (Transport::Wg, "wg") => {
                out.push((format!("job {} · {} {}:{}", j.id, name, server, j.port), format!("{server}:{}", j.port)));
            }
            (Transport::Http, "http" | "https") => {
                let host = j.domains.iter().find(|d| !d.is_empty()).map_or(server, |d| d.as_str());
                let default_port = if name == "https" { 443 } else { 80 };
                let url = if j.port == default_port { format!("{name}://{host}") } else { format!("{name}://{host}:{}", j.port) };
                out.push((format!("job {} · {url}", j.id), url));
            }
            (Transport::Dns, "dns") => {
                for d in j.domains.iter().map(|d| d.trim_end_matches('.')).filter(|d| !d.is_empty()) {
                    out.push((format!("job {} · dns {d}", j.id), d.to_string()));
                }
            }
            _ => {}
        }
    }
    out
}

impl SliverApp {
    /// Running listeners that fit a transport, as (label, address to use).
    /// Server listeners are addressed by the host this client connects to.
    pub(super) fn listener_choices(&self, t: Transport) -> Vec<(String, String)> {
        let server = self.configs.get(self.selected_cfg).map(|c| c.lhost.clone()).unwrap_or_default();
        let mut out = Vec::new();
        match t {
            Transport::Mtls | Transport::Wg | Transport::Http | Transport::Dns => out = server_listener_choices(t, &self.jobs, &server),
            Transport::TcpPivot | Transport::NamedPipe => {
                for s in &self.sessions {
                    let Some(ls) = self.ext.pivot_listeners.get(&Target::session(&s.id).key()) else { continue };
                    let host = host_of(&s.remote_address);
                    for l in ls {
                        let value = match (t, l.r#type) {
                            (Transport::TcpPivot, 0) => format!("{host}:{}", l.bind_address.rsplit(':').next().unwrap_or("9898")),
                            (Transport::NamedPipe, 2) => {
                                let pipe = l.bind_address.rsplit(['\\', '/']).next().unwrap_or(&l.bind_address);
                                format!("{host}/pipe/{pipe}")
                            }
                            _ => continue,
                        };
                        out.push((format!("{} ({}) · {} → {value}", s.name, short(&s.id), l.bind_address), value));
                    }
                }
            }
        }
        out
    }

    pub(super) fn generate_ui(&mut self, ui: &mut egui::Ui) {
        let t = self.generate_form.transport;
        let choices = self.listener_choices(t);
        // Pivot listeners live on sessions; fetch them once when a pivot type is picked.
        if t.is_pivot() && !self.ext.gen_pivots_fetched {
            self.ext.gen_pivots_fetched = true;
            let ids: Vec<String> = self.sessions.iter().map(|s| s.id.clone()).collect();
            for id in ids { self.op(Op::PivotListeners { target: Target::session(&id) }); }
        }
        let mut refresh_pivots = false;
        let profiles = self.ext.c2_profiles.clone();
        // Running WireGuard listeners by UDP port, with the tunnel ports this GUI
        // recorded when it started them (Sliver doesn't report those).
        let wg_listeners: HashMap<u32, Option<(u32, u32)>> = if t == Transport::Wg {
            let key = self.server_key();
            self.jobs.iter().filter(|j| j.name == "wg").map(|j| {
                let rec = self.settings.listener_specs.get(&super::listener_key(&key, 4, j.port)).map(|p| (p.wg_key_port, p.wg_nport));
                (j.port, rec)
            }).collect()
        } else { HashMap::new() };
        // HTTPS listeners started from this GUI with a certificate file, by port.
        let https_certs: HashMap<u32, String> = if t == Transport::Http {
            let key = self.server_key();
            self.jobs.iter().filter(|j| j.name == "https").filter_map(|j| {
                let p = self.settings.listener_specs.get(&super::listener_key(&key, 1, j.port))?;
                let desc = match p.tls {
                    1 => {
                        let file = std::path::Path::new(&p.cert).file_name().map_or(p.cert.clone(), |n| n.to_string_lossy().to_string());
                        let fp = super::certs::fingerprint(&p.cert).map_or("file unreadable".into(), |fp| format!("SHA-256 {}…", &fp[..23]));
                        format!("Listener presents {file} ({fp}).")
                    }
                    2 => "Listener uses a Let's Encrypt certificate for its domain.".into(),
                    _ => "Listener uses Sliver's self-signed certificate.".into(),
                };
                Some((j.port, desc))
            }).collect()
        } else { HashMap::new() };
        // What the server says it can compile (Server tab → Compile targets).
        let targets = self.ext.server.as_ref().and_then(|s| s.compiler.as_ref()).map(|c| c.targets.clone());
        let f = &mut self.generate_form;

        egui::Grid::new("gen").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
            ui.label("Name (optional)");
            ui.add(egui::TextEdit::singleline(&mut f.name).hint_text("random if empty"));
            ui.end_row();

            ui.label("Target OS");
            egui::ComboBox::from_id_salt("os").selected_text(&f.os).show_ui(ui, |ui| {
                for os in ["windows", "linux", "darwin"] {
                    ui.selectable_value(&mut f.os, os.to_string(), os);
                }
            });
            ui.end_row();
            // Keep arch and format valid for the chosen OS.
            if !arches(&f.os).contains(&f.arch.as_str()) { f.arch = "amd64".into(); }
            if !formats(&f.os).iter().any(|(v, _)| *v == f.format) { f.format = 2; }

            ui.label("Arch");
            egui::ComboBox::from_id_salt("arch").selected_text(&f.arch).show_ui(ui, |ui| {
                for a in arches(&f.os) {
                    ui.selectable_value(&mut f.arch, a.to_string(), *a);
                }
            });
            ui.end_row();

            ui.label("Payload");
            ui.horizontal(|ui| {
                ui.radio_value(&mut f.staged, false, "Stageless")
                    .on_hover_text("One self-contained implant binary");
                ui.radio_value(&mut f.staged, true, "Staged")
                    .on_hover_text("A small msfvenom stub that pulls the full implant (hosted on the server) and runs it in memory");
            });
            ui.end_row();

            if f.staged {
                ui.label("Stage protocol");
                egui::ComboBox::from_id_salt("stageproto").selected_text(["TCP", "HTTP", "HTTPS"][f.stage_protocol as usize]).show_ui(ui, |ui| {
                    for (i, l) in ["TCP", "HTTP", "HTTPS"].iter().enumerate() {
                        ui.selectable_value(&mut f.stage_protocol, i as u8, *l);
                    }
                });
                ui.end_row();
                ui.label("Stage port");
                ui.add(egui::DragValue::new(&mut f.stage_bind_port).range(1..=65535))
                    .on_hover_text("Port the stage listener binds on the server; the stub calls back here");
                ui.end_row();
                ui.label("Stager format");
                egui::ComboBox::from_id_salt("stagerfmt").selected_text(&f.stager_format).show_ui(ui, |ui| {
                    for fmt in ["exe", "dll", "raw", "elf", "powershell", "python", "csharp", "vbscript"] {
                        ui.selectable_value(&mut f.stager_format, fmt.to_string(), fmt);
                    }
                });
                ui.end_row();
            } else {
                ui.label("Format");
                let fmt_label = formats(&f.os).iter().find(|(v, _)| *v == f.format).map_or("Executable", |(_, l)| l);
                egui::ComboBox::from_id_salt("fmt").selected_text(fmt_label).show_ui(ui, |ui| {
                    for (v, l) in formats(&f.os) {
                        ui.selectable_value(&mut f.format, *v, *l);
                    }
                });
                ui.end_row();
            }
            // The stage of a staged build is shellcode.
            let fmt = if f.staged { 1 } else { f.format };
            if let Some(why) = targets.as_deref().and_then(|t| unsupported_target(t, &f.os, &f.arch, fmt)) {
                ui.label("");
                ui.colored_label(Palette::yellow(), format!("⚠ {why}"));
                ui.end_row();
            }

            ui.label("Listener type");
            egui::ComboBox::from_id_salt("transport").selected_text(f.transport.label()).width(260.0).show_ui(ui, |ui| {
                for tr in Transport::ALL {
                    ui.selectable_value(&mut f.transport, tr, tr.label());
                }
            });
            ui.end_row();

            ui.label("Listener");
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let current = f.addr(t).clone();
                    let picked = choices.iter().find(|(_, v)| *v == current).map(|(l, _)| l.clone());
                    let text = match (&picked, choices.is_empty()) {
                        (Some(l), _) => l.clone(),
                        (None, true) => format!("no running {} listeners", if t.is_pivot() { "pivot" } else { f.transport.label() }),
                        (None, false) => format!("select a running listener ({})…", choices.len()),
                    };
                    ui.add_enabled_ui(!choices.is_empty(), |ui| {
                        egui::ComboBox::from_id_salt(("gen-listener", t as u8)).selected_text(text).width(330.0).show_ui(ui, |ui| {
                            for (label, value) in &choices {
                                if ui.selectable_label(current == *value, label).clicked() {
                                    *f.addr_mut(t) = value.clone();
                                    if let Some(Some((key, comms))) = udp_port(value).and_then(|p| wg_listeners.get(&p)) {
                                        (f.wg_key_port, f.wg_comms_port) = (*key, *comms);
                                    }
                                }
                            }
                        });
                    });
                    if t.is_pivot() && ui.small_button("⟳").on_hover_text("Re-read pivot listeners from all sessions").clicked() {
                        refresh_pivots = true;
                    }
                });
                ui.add(egui::TextEdit::singleline(f.addr_mut(t)).desired_width(360.0).hint_text(t.hint()))
                    .on_hover_text("Or type the address the implant should call back to. Several, comma-separated, are tried in order.");
            });
            ui.end_row();

            // Transport-specific settings.
            match t {
                Transport::Http => {
                    ui.label("HTTP C2 profile");
                    egui::ComboBox::from_id_salt("gen-c2prof").selected_text(&f.c2_profile).show_ui(ui, |ui| {
                        let mut names = profiles.clone();
                        if names.is_empty() { names.push("default".into()); }
                        for n in names { ui.selectable_value(&mut f.c2_profile, n.clone(), n); }
                    });
                    ui.end_row();
                    if let Some(desc) = https_port(f.addr(t)).and_then(|p| https_certs.get(&p)) {
                        ui.label("Certificate");
                        ui.colored_label(Palette::muted(), desc).on_hover_text(
                            "Sliver implants accept the listener's certificate without pinning it; C2 traffic is also encrypted by Sliver itself.");
                        ui.end_row();
                    }
                }
                Transport::Wg => {
                    ui.label("Tunnel ports");
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.add(egui::DragValue::new(&mut f.wg_key_port).range(1..=65535).prefix("key exchange "));
                            ui.add(egui::DragValue::new(&mut f.wg_comms_port).range(1..=65535).prefix("comms "));
                        }).response.on_hover_text("Ports inside the WireGuard tunnel, not firewall ports. They must equal the listener's \
                            key-exchange and tunnel comms ports (defaults 1337 / 8888) or the implant never connects.");
                        let ports = (f.wg_key_port, f.wg_comms_port);
                        match udp_port(f.addr(t)).map(|p| (p, wg_listeners.get(&p))) {
                            None => {}
                            Some((p, None)) => { ui.colored_label(Palette::yellow(), format!("No WireGuard listener running on UDP {p}.")); }
                            Some((p, Some(Some(rec)))) if *rec == ports => {
                                ui.colored_label(Palette::green(), format!("✓ Match the listener on UDP {p}."));
                            }
                            Some((p, Some(Some((key, comms))))) => {
                                ui.horizontal_wrapped(|ui| {
                                    ui.colored_label(Palette::red(), format!("The listener on UDP {p} uses key exchange {key} / comms {comms}; this implant won't connect."));
                                    if ui.small_button("Use listener's ports").clicked() { (f.wg_key_port, f.wg_comms_port) = (*key, *comms); }
                                });
                            }
                            Some((p, Some(None))) => {
                                ui.colored_label(Palette::muted(), format!("The listener on UDP {p} wasn't started from this GUI, so its tunnel ports are unknown. Check them under Listeners → Edit."));
                            }
                        }
                    });
                    ui.end_row();
                }
                Transport::NamedPipe if f.os != "windows" => {
                    ui.label("");
                    ui.colored_label(Palette::yellow(), "Named-pipe pivots are Windows-only.");
                    ui.end_row();
                }
                _ => {}
            }

            ui.label("Mode");
            ui.horizontal(|ui| {
                ui.radio_value(&mut f.is_beacon, false, "Session (interactive)");
                ui.radio_value(&mut f.is_beacon, true, "Beacon (asynchronous)");
            });
            ui.end_row();
            if f.is_beacon {
                ui.label("Interval / jitter (s)");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut f.beacon_interval).range(1..=86400).prefix("every "));
                    ui.add(egui::DragValue::new(&mut f.beacon_jitter).range(0..=3600).prefix("± "));
                });
                ui.end_row();
            }

            // Donut options apply to shellcode output only.
            if f.format == 1 {
                ui.label("Shellcode");
                ui.vertical(|ui| {
                    egui::ComboBox::from_id_salt("sc_entropy")
                        .selected_text(match f.sc_entropy {
                            1 => "No entropy",
                            2 => "Random names",
                            _ => "Random names + encryption (varies each build)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut f.sc_entropy, 3, "Random names + encryption (varies each build)");
                            ui.selectable_value(&mut f.sc_entropy, 2, "Random names");
                            ui.selectable_value(&mut f.sc_entropy, 1, "No entropy");
                        });
                    let mut aplib = f.sc_compress == 2;
                    if ui.checkbox(&mut aplib, "aPLib compression").changed() {
                        f.sc_compress = if aplib { 2 } else { 1 };
                    }
                });
                ui.end_row();
            }

            ui.label("Build options");
            ui.horizontal(|ui| {
                if f.transport == Transport::Wg {
                    // Symbol obfuscation breaks WireGuard implants on every OS (upstream
                    // garble bug: the WG key exchange never completes), so force it off.
                    f.obfuscate_symbols = false;
                    let mut disabled = false;
                    ui.add_enabled(false, egui::Checkbox::new(&mut disabled, "obfuscate symbols"))
                        .on_hover_text("Disabled for WireGuard — symbol obfuscation breaks WG implants (they never finish the key exchange). Upstream Sliver/garble bug.");
                } else {
                    ui.checkbox(&mut f.obfuscate_symbols, "obfuscate symbols")
                        .on_hover_text("Randomise Go symbol names — unique per build (larger file)");
                }
                ui.checkbox(&mut f.debug, "debug");
                if f.os == "windows" { ui.checkbox(&mut f.evasion, "evasion"); }
            });
            ui.end_row();
        });

        // Everything optional lives under Advanced.
        let advanced_used = Transport::ALL.iter().any(|o| *o != t && !f.addr(*o).trim().is_empty())
            || !f.canary.trim().is_empty() || !f.limit_hostname.is_empty() || !f.limit_username.is_empty()
            || !f.limit_datetime.is_empty() || f.limit_domain_joined;
        ui.add_space(4.0);
        egui::CollapsingHeader::new(if advanced_used { "Advanced (in use)" } else { "Advanced" })
            .id_salt("gen-advanced")
            .default_open(advanced_used)
            .show(ui, |ui| {
                egui::Grid::new("gen-adv").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                    kit::th(ui, "Fallback C2");
                    ui.colored_label(Palette::muted(), egui::RichText::new("tried after the listener above, in this order").small());
                    ui.end_row();
                    for o in Transport::ALL.into_iter().filter(|o| *o != t) {
                        ui.label(o.label().split(" (").next().unwrap_or(""));
                        ui.add(egui::TextEdit::singleline(f.addr_mut(o)).desired_width(300.0).hint_text(o.hint()));
                        ui.end_row();
                    }
                    ui.label("Canary domains");
                    ui.add(egui::TextEdit::singleline(&mut f.canary).desired_width(300.0).hint_text("comma-separated"))
                        .on_hover_text("Needs a DNS listener with canaries enabled — alerts if the binary is resolved/inspected");
                    ui.end_row();
                    ui.label("Execution limits");
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut f.limit_hostname).desired_width(145.0).hint_text("hostname"));
                            ui.add(egui::TextEdit::singleline(&mut f.limit_username).desired_width(145.0).hint_text("username"));
                        });
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut f.limit_datetime).desired_width(200.0).hint_text("kill date (RFC 3339)"));
                            ui.checkbox(&mut f.limit_domain_joined, "domain-joined only");
                        });
                    }).response.on_hover_text("Scope guardrails: the implant exits on hosts/users outside these limits, or after the kill date");
                    ui.end_row();
                });
            });

        ui.add_space(10.0);
        let has_primary = !f.addr(t).trim().is_empty();
        if !has_primary {
            ui.colored_label(Palette::yellow(), "Pick a running listener or type its address.");
        }
        let mut save_profile = false;
        let mut build = false;
        let staged = self.generate_form.staged;
        let profile_name = &mut self.ext.save_profile_name;
        ui.horizontal(|ui| {
            let build_label = if staged { "▶ Build staged payload" } else { "▶ Build implant" };
            if ui.add_enabled(has_primary, egui::Button::new(egui::RichText::new(build_label).strong())).clicked() {
                build = true;
            }
            ui.separator();
            ui.add(egui::TextEdit::singleline(profile_name).desired_width(140.0).hint_text("profile name"));
            if ui.add_enabled(has_primary && !profile_name.trim().is_empty(), egui::Button::new("◈ Save as profile"))
                .on_hover_text("Store this configuration on the server as a reusable implant profile").clicked()
            {
                save_profile = true;
            }
        });
        if refresh_pivots {
            self.ext.gen_pivots_fetched = false;
        }
        if build {
            if staged {
                self.build_staged();
            } else {
                let (config, name, _) = build_generate_request(&self.generate_form);
                self.send(Command::Generate { config, name, save_dir: None });
                self.set_toast(true, "build requested — compiling on server; you'll be asked where to save it");
            }
            self.show_generate = false;
        }
        if save_profile {
            let (config, _, _) = build_generate_request(&self.generate_form);
            let name = self.ext.save_profile_name.trim().to_string();
            self.op(Op::SaveProfile { name, config });
        }
    }

    /// Kick off a staged build: compile the implant as shellcode (the stage), host it on a
    /// stager listener, then (via `Update::StagedReady`) run `generate stager` in the
    /// embedded Sliver Console to produce the matching stub.
    fn build_staged(&mut self) {
        let (mut config, name, _) = build_generate_request(&self.generate_form);
        // The stage is always shellcode, regardless of the Format control.
        config.format = 1; // SHELLCODE
        config.is_shellcode = true;
        config.is_shared_lib = false;
        config.is_service = false;
        if config.shellcode_config.is_none() {
            config.shellcode_config = Some(clientpb::ShellcodeConfig { entropy: 3, compress: 1, ..Default::default() });
        }
        let f = &self.generate_form;
        let (protocol, bind_port) = (f.stage_protocol as i32, f.stage_bind_port as u32);
        let (stager_format, stager_arch) = (f.stager_format.clone(), f.arch.clone());
        // The stub calls back to the server, where the stage listener binds.
        let server_lhost = self.configs.get(self.selected_cfg).map(|c| c.lhost.clone()).unwrap_or_default();
        // The embedded sliver-client shares this GUI's host, so a local temp dir is reachable.
        let save_dir = std::env::temp_dir().join("sliver-stagers");
        let _ = std::fs::create_dir_all(&save_dir);
        let save_dir = save_dir.to_string_lossy().into_owned();
        self.send(Command::GenerateStaged {
            config, name, bind_host: "0.0.0.0".into(), bind_port, protocol,
            server_lhost, stager_format, stager_arch, save_dir,
        });
        self.set_toast(true, "staging: compiling the stage and starting its listener…");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: u32, name: &str, port: u32, domains: &[&str]) -> clientpb::Job {
        clientpb::Job { id, name: name.into(), port, domains: domains.iter().map(|d| d.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn listener_picker_matches_jobs_to_transports() {
        // Running listeners: mTLS :8888, WireGuard udp/8889, HTTP :44, plus a DNS one.
        let jobs = [job(1, "mtls", 8888, &[]), job(32, "wg", 8889, &[]), job(33, "http", 44, &[""]), job(40, "dns", 53, &["c2.example.com.", "alt.example.com."])];
        let pick = |t| server_listener_choices(t, &jobs, "192.0.2.10").into_iter().map(|(_, v)| v).collect::<Vec<_>>();
        assert_eq!(pick(Transport::Mtls), vec!["192.0.2.10:8888"]);
        assert_eq!(pick(Transport::Wg), vec!["192.0.2.10:8889"]);
        assert_eq!(pick(Transport::Http), vec!["http://192.0.2.10:44"]);
        assert_eq!(pick(Transport::Dns), vec!["c2.example.com", "alt.example.com"]);
        assert!(pick(Transport::TcpPivot).is_empty(), "pivots come from sessions, not server jobs");
        let https = [job(5, "https", 443, &["c2.example.com"])];
        assert_eq!(server_listener_choices(Transport::Http, &https, "x").remove(0).1, "https://c2.example.com");
    }

    #[test]
    fn https_port_reads_urls() {
        assert_eq!(super::https_port("https://c2.example.com:9643"), Some(9643));
        assert_eq!(super::https_port("https://c2.example.com"), Some(443));
        assert_eq!(super::https_port("http://c2.example.com:80"), None);
    }

    #[test]
    fn udp_port_reads_the_first_address() {
        assert_eq!(super::udp_port("192.0.2.10:8890"), Some(8890));
        assert_eq!(super::udp_port("wg://c2.example.com:51820, 198.51.100.1:1"), Some(51820));
        assert_eq!(super::udp_port("c2.example.com"), None);
    }

    #[test]
    fn compile_target_check() {
        let t = |os: &str, arch: &str, f: i32| clientpb::CompilerTarget { goos: os.into(), goarch: arch.into(), format: f };
        let targets = [t("windows", "amd64", 2), t("windows", "amd64", 1), t("linux", "amd64", 2)];
        assert_eq!(unsupported_target(&targets, "windows", "amd64", 1), None);
        assert!(unsupported_target(&targets, "linux", "amd64", 0).unwrap().contains("as shared lib"));
        assert!(unsupported_target(&targets, "darwin", "arm64", 2).unwrap().contains("no compiler"));
    }

    #[test]
    fn os_limits_arch_and_format() {
        assert!(formats("windows").iter().any(|(v, _)| *v == 1), "Windows offers shellcode");
        assert!(!formats("linux").iter().any(|(v, _)| *v == 1 || *v == 3), "no shellcode/service off Windows");
        assert!(!arches("darwin").contains(&"386"));
    }
}
