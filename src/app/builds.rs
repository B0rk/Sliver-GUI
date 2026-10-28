//! Builds: saved implant profiles (one-click generate / load into the
//! generator), the server's build history (re-download, delete), DNS
//! canary status and HTTP C2 profiles.

use super::generator::Transport;
use super::{kit, GenerateForm, SliverApp};
use crate::client::{Command, Op};
use crate::proto::clientpb;
use crate::theme::Palette;

pub(super) fn format_name(f: i32) -> &'static str {
    match f { 0 => "shared lib", 1 => "shellcode", 3 => "service", 5 => "go archive", _ => "executable" }
}

/// Rebuild generator form fields from a saved implant config.
pub(super) fn form_from_config(cfg: &clientpb::ImplantConfig, save_dir: String) -> GenerateForm {
    const NS: i64 = 1_000_000_000;
    let mut f = GenerateForm { save_dir, ..Default::default() };
    f.os = cfg.goos.clone();
    f.arch = cfg.goarch.clone();
    f.format = cfg.format;
    f.is_beacon = cfg.is_beacon;
    if cfg.beacon_interval > 0 { f.beacon_interval = cfg.beacon_interval / NS; }
    f.beacon_jitter = cfg.beacon_jitter / NS;
    f.debug = cfg.debug;
    f.evasion = cfg.evasion;
    f.obfuscate_symbols = cfg.obfuscate_symbols;
    if let Some(sc) = &cfg.shellcode_config {
        f.sc_entropy = sc.entropy.max(1);
        f.sc_compress = sc.compress.max(1);
    }
    let by = |scheme: &str| -> String {
        cfg.c2.iter().filter_map(|c| c.url.strip_prefix(scheme)).map(|s| s.trim_end_matches('.').to_string()).collect::<Vec<_>>().join(", ")
    };
    f.mtls = by("mtls://");
    f.wg = by("wg://");
    f.dns = by("dns://");
    f.tcp_pivot = by("tcppivot://");
    f.named_pipe = by("namedpipe://");
    f.http = cfg.c2.iter().filter(|c| c.url.starts_with("http")).map(|c| c.url.clone()).collect::<Vec<_>>().join(", ");
    // The highest-priority C2 decides the listener type shown in the generator.
    let mut first: Vec<&clientpb::ImplantC2> = cfg.c2.iter().collect();
    first.sort_by_key(|c| c.priority);
    f.transport = match first.first().map(|c| c.url.split("://").next().unwrap_or("")) {
        Some("http" | "https") => Transport::Http,
        Some("dns") => Transport::Dns,
        Some("wg") => Transport::Wg,
        Some("tcppivot") => Transport::TcpPivot,
        Some("namedpipe") => Transport::NamedPipe,
        _ => Transport::Mtls,
    };
    if cfg.wg_key_exchange_port > 0 { f.wg_key_port = cfg.wg_key_exchange_port; }
    if cfg.wg_tcp_comms_port > 0 { f.wg_comms_port = cfg.wg_tcp_comms_port; }
    f.c2_profile = if cfg.httpc2_config_name.is_empty() { "default".into() } else { cfg.httpc2_config_name.clone() };
    f.canary = cfg.canary_domains.join(", ");
    f.limit_hostname = cfg.limit_hostname.clone();
    f.limit_username = cfg.limit_username.clone();
    f.limit_domain_joined = cfg.limit_domain_joined;
    f.limit_datetime = cfg.limit_datetime.clone();
    f
}

impl SliverApp {
    /// Ask where to save a finished build (starting in the last folder used)
    /// and write it there.
    pub(super) fn save_build(&mut self, name: &str, file_name: &str, data: &[u8]) {
        let start = Some(self.settings.build_dir.clone())
            .filter(|d| !d.is_empty() && std::path::Path::new(d).is_dir())
            .unwrap_or_else(|| self.generate_form.save_dir.clone());
        let picked = rfd::FileDialog::new()
            .set_title(format!("Save implant {name}"))
            .set_directory(&start)
            .set_file_name(file_name)
            .save_file();
        let Some(path) = picked else {
            self.set_toast(false, &format!("{name} not saved — it stays on the server (Builds → Build history → Download)"));
            return;
        };
        match std::fs::write(&path, data) {
            Ok(_) => {
                if let Some(dir) = path.parent() {
                    self.settings.build_dir = dir.display().to_string();
                    self.settings_dirty = true;
                }
                self.set_toast(true, &format!("saved {name} → {} ({} bytes)", path.display(), data.len()));
                self.push_event("info", &format!("implant built: {}", path.display()));
            }
            Err(e) => self.set_toast(false, &format!("saving {name} failed: {e}")),
        }
    }

    pub(super) fn builds_tab(&mut self, ui: &mut egui::Ui) {
        kit::toolbar(ui, |ui| {
            ui.selectable_value(&mut self.ext.builds_view, 0, format!("◈ Profiles ({})", self.ext.profiles.len()));
            ui.selectable_value(&mut self.ext.builds_view, 1, format!("▤ Build history ({})", self.ext.builds.len()));
            ui.selectable_value(&mut self.ext.builds_view, 2, format!("⚑ Canaries ({})", self.ext.canaries.len()));
            ui.selectable_value(&mut self.ext.builds_view, 3, format!("⌘ HTTP C2 profiles ({})", self.ext.c2_profiles.len()));
            ui.separator();
            if ui.button("⟳ Refresh").clicked() {
                self.op(Op::RefreshProfiles);
                self.op(Op::RefreshBuilds);
                self.op(Op::RefreshCanaries);
                self.op(Op::RefreshC2Profiles);
            }
            if ui.button("✦ New implant…").clicked() { self.show_generate = true; }
        });
        match self.ext.builds_view {
            0 => self.profiles_view(ui),
            1 => self.history_view(ui),
            2 => self.canaries_view(ui),
            _ => self.c2_profiles_tab(ui),
        }
    }

    fn profiles_view(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        if self.ext.profiles.is_empty() {
            kit::empty(ui, "◈", "No implant profiles", "Open the generator and use \"Save as profile\" to keep a reusable build recipe");
            return;
        }
        let profiles = self.ext.profiles.clone();
        let mut acts: Vec<(&'static str, clientpb::ImplantProfile)> = Vec::new();
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(150.0))
            .column(Column::auto().at_least(110.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::auto().at_least(230.0))
            .header(22.0, |mut h| {
                for t in ["Profile", "Target", "Format", "Mode", "C2", ""] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|body| {
                body.rows(26.0, profiles.len(), |mut row| {
                    let p = &profiles[row.index()];
                    let cfg = p.config.clone().unwrap_or_default();
                    row.col(|ui| { ui.label(egui::RichText::new(&p.name).strong()); });
                    row.col(|ui| kit::os_badge(ui, &cfg.goos, &cfg.goarch));
                    row.col(|ui| { ui.colored_label(Palette::muted(), format_name(cfg.format)); });
                    row.col(|ui| {
                        if cfg.is_beacon { kit::badge(ui, format!("beacon {}s", cfg.beacon_interval / 1_000_000_000), Palette::accent()); }
                        else { kit::badge(ui, "session", Palette::green()); }
                    });
                    row.col(|ui| {
                        let c2: Vec<String> = cfg.c2.iter().map(|c| c.url.clone()).collect();
                        ui.add(egui::Label::new(egui::RichText::new(c2.join(", ")).monospace().small()).truncate());
                    });
                    row.col(|ui| {
                        if ui.small_button("▶ Generate").on_hover_text("Build this profile now").clicked() { acts.push(("gen", p.clone())); }
                        if ui.small_button("✎ Load in generator").clicked() { acts.push(("load", p.clone())); }
                        if ui.small_button(egui::RichText::new("✕").color(Palette::red())).on_hover_text("Delete profile").clicked() { acts.push(("rm", p.clone())); }
                    });
                });
            });
        for (a, p) in acts {
            match a {
                "gen" => {
                    let config = p.config.unwrap_or_default();
                    self.send(Command::Generate { config, name: String::new(), save_dir: None });
                    self.set_toast(true, &format!("building from profile '{}' — compiling on server; you'll be asked where to save it", p.name));
                }
                "load" => {
                    self.generate_form = form_from_config(&p.config.unwrap_or_default(), self.generate_form.save_dir.clone());
                    self.ext.save_profile_name = p.name.clone();
                    self.show_generate = true;
                }
                "rm" => self.confirm("Delete profile", format!("Delete implant profile '{}'?", p.name), vec![Command::Op(Op::DeleteProfile { name: p.name })]),
                _ => {}
            }
        }
    }

    fn history_view(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        if self.ext.builds.is_empty() {
            kit::empty(ui, "▤", "No builds on the server", "Every implant you generate is recorded here");
            return;
        }
        let builds = self.ext.builds.clone();
        let mut acts: Vec<(&'static str, String)> = Vec::new();
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(170.0))
            .column(Column::auto().at_least(110.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::auto().at_least(150.0))
            .header(22.0, |mut h| {
                for t in ["Implant", "Target", "Format", "Mode", "C2", ""] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|body| {
                body.rows(26.0, builds.len(), |mut row| {
                    let b = &builds[row.index()];
                    row.col(|ui| {
                        ui.label(egui::RichText::new(&b.name).strong());
                        if b.staged { kit::badge(ui, "staged", Palette::purple()); }
                    });
                    row.col(|ui| kit::os_badge(ui, &b.os, &b.arch));
                    row.col(|ui| { ui.colored_label(Palette::muted(), format_name(b.format)); });
                    row.col(|ui| {
                        if b.beacon { kit::badge(ui, "beacon", Palette::accent()); } else { kit::badge(ui, "session", Palette::green()); }
                    });
                    row.col(|ui| { ui.add(egui::Label::new(egui::RichText::new(b.c2.join(", ")).monospace().small()).truncate()); });
                    row.col(|ui| {
                        if ui.small_button("⬇ Download").on_hover_text("Regenerate (re-download) this build").clicked() { acts.push(("regen", b.name.clone())); }
                        if ui.small_button(egui::RichText::new("✕").color(Palette::red())).on_hover_text("Delete build").clicked() { acts.push(("rm", b.name.clone())); }
                    });
                });
            });
        for (a, name) in acts {
            match a {
                "regen" => {
                    self.op(Op::Regenerate { name: name.clone(), save_dir: None });
                    self.set_toast(true, &format!("fetching build {name}…"));
                }
                "rm" => self.confirm("Delete build", format!("Delete implant build '{name}' from the server? Implants already deployed from it will no longer be able to check in."),
                    vec![Command::Op(Op::DeleteBuild { name })]),
                _ => {}
            }
        }
    }

    fn canaries_view(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        ui.colored_label(Palette::muted(), "DNS canaries are embedded in implants built with canary domains; a lookup means the binary was inspected or detonated somewhere unexpected.");
        if self.ext.canaries.is_empty() {
            kit::empty(ui, "⚑", "No canaries", "Add canary domains in the generator (requires a DNS listener with canaries enabled)");
            return;
        }
        let canaries = self.ext.canaries.clone();
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(150.0))
            .column(Column::remainder().at_least(220.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(140.0))
            .column(Column::auto().at_least(140.0))
            .column(Column::auto().at_least(60.0))
            .header(22.0, |mut h| {
                for t in ["Implant", "Domain", "Status", "First", "Latest", "Hits"] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|body| {
                body.rows(24.0, canaries.len(), |mut row| {
                    let c = &canaries[row.index()];
                    row.col(|ui| { ui.label(&c.implant_name); });
                    row.col(|ui| { ui.monospace(&c.domain); });
                    row.col(|ui| {
                        if c.triggered { kit::badge(ui, "⚠ TRIGGERED", Palette::red()); } else { kit::badge(ui, "quiet", Palette::green()); }
                    });
                    row.col(|ui| { ui.colored_label(Palette::muted(), &c.first_triggered); });
                    row.col(|ui| { ui.colored_label(Palette::muted(), &c.latest_trigger); });
                    row.col(|ui| { ui.label(c.count.to_string()); });
                });
            });
    }
}
