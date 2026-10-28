//! HTTP C2 profiles: list the profiles stored on the server, inspect one,
//! export / import it as JSON, and pick it for the implant generator.

use super::{kit, SliverApp};
use crate::client::Op;
use crate::proto::clientpb;
use crate::theme::Palette;

impl SliverApp {
    /// The HTTP C2 profiles view (inside the Builds tab).
    pub(super) fn c2_profiles_tab(&mut self, ui: &mut egui::Ui) {
        let mut import = false;
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() { self.op(Op::RefreshC2Profiles); }
            if ui.button("⬆ Import JSON…").on_hover_text("Import a profile previously exported from this GUI").clicked() { import = true; }
            ui.checkbox(&mut self.ext.c2_overwrite, "overwrite existing");
            ui.colored_label(Palette::muted(), format!("{} profiles", self.ext.c2_profiles.len()));
        });
        if import {
            if let Some(p) = rfd::FileDialog::new().add_filter("JSON", &["json"]).pick_file() {
                match std::fs::read_to_string(&p).map_err(|e| e.to_string())
                    .and_then(|raw| serde_json::from_str::<clientpb::Httpc2Config>(&raw).map_err(|e| e.to_string()))
                {
                    Ok(cfg) if !cfg.name.is_empty() => self.op(Op::ImportC2Profile { config: cfg, overwrite: self.ext.c2_overwrite }),
                    Ok(_) => self.set_toast(false, "profile JSON has no name"),
                    Err(e) => self.set_toast(false, &format!("import failed: {e}")),
                }
            }
        }
        if self.ext.c2_profiles.is_empty() {
            kit::empty(ui, "⌘", "No HTTP C2 profiles loaded", "Press Refresh to list the server's profiles");
            return;
        }
        let names = self.ext.c2_profiles.clone();
        let sel = self.ext.c2_detail.as_ref().map(|d| d.name.clone());
        let mut pick: Option<String> = None;
        ui.horizontal_top(|ui| {
            ui.allocate_ui(egui::vec2(200.0, ui.available_height()), |ui| {
                egui::ScrollArea::vertical().id_salt("c2-names").auto_shrink([false, false]).show(ui, |ui| {
                    for n in &names {
                        let in_use = self.generate_form.c2_profile == *n;
                        let label = if in_use { format!("● {n}") } else { format!("  {n}") };
                        if ui.selectable_label(sel.as_deref() == Some(n.as_str()), label).clicked() { pick = Some(n.clone()); }
                    }
                });
            });
            ui.separator();
            ui.vertical(|ui| self.c2_detail_ui(ui));
        });
        if let Some(n) = pick { self.op(Op::C2ProfileDetail { name: n }); }
    }

    fn c2_detail_ui(&mut self, ui: &mut egui::Ui) {
        let Some(p) = self.ext.c2_detail.clone() else {
            kit::empty(ui, "⌘", "Select a profile", "");
            return;
        };
        let mut export = false;
        ui.horizontal(|ui| {
            ui.heading(&p.name);
            if self.generate_form.c2_profile == p.name {
                kit::badge(ui, "selected in generator", Palette::green());
            } else if ui.button("✦ Use in generator").clicked() {
                self.generate_form.c2_profile = p.name.clone();
                self.set_toast(true, &format!("generator will use C2 profile '{}'", p.name));
            }
            if ui.button("⬇ Export JSON…").clicked() { export = true; }
        });
        if export {
            if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{}.json", p.name)).save_file() {
                match serde_json::to_vec_pretty(&*p).map_err(|e| e.to_string()).and_then(|b| std::fs::write(&path, b).map_err(|e| e.to_string())) {
                    Ok(_) => self.set_toast(true, &format!("exported → {}", path.display())),
                    Err(e) => self.set_toast(false, &format!("export failed: {e}")),
                }
            }
        }
        egui::ScrollArea::vertical().id_salt("c2-detail").auto_shrink([false, false]).show(ui, |ui| {
            if let Some(ic) = &p.implant_config {
                kit::section(ui, "Implant requests");
                egui::Grid::new("c2-implant").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
                    ui.colored_label(Palette::muted(), "User-Agent");
                    ui.label(egui::RichText::new(if ic.user_agent.is_empty() { "(generated)" } else { &ic.user_agent }).monospace());
                    ui.end_row();
                    ui.colored_label(Palette::muted(), "Chrome base version");
                    ui.label(ic.chrome_base_version.to_string());
                    ui.end_row();
                    ui.colored_label(Palette::muted(), "File extensions");
                    ui.label(egui::RichText::new(ic.extensions.join(" ")).monospace());
                    ui.end_row();
                    ui.colored_label(Palette::muted(), "Path segments");
                    ui.label(format!("{} ({}–{} per URL, {}–{} chars)", ic.path_segments.len(), ic.min_path_gen, ic.max_path_gen, ic.min_path_length, ic.max_path_length));
                    ui.end_row();
                    ui.colored_label(Palette::muted(), "Nonce");
                    ui.label(format!("{} · {} chars of '{}'", if ic.nonce_mode.is_empty() { "default" } else { &ic.nonce_mode }, ic.nonce_query_length, ic.nonce_query_arg_chars));
                    ui.end_row();
                });
                if !ic.headers.is_empty() {
                    ui.label(egui::RichText::new("Headers").strong());
                    for h in &ic.headers {
                        ui.label(egui::RichText::new(format!("{} {}: {}  ({}%)", h.method, h.name, h.value, h.probability)).monospace().small());
                    }
                }
                if !ic.extra_url_parameters.is_empty() {
                    ui.label(egui::RichText::new("URL parameters").strong());
                    for q in &ic.extra_url_parameters {
                        ui.label(egui::RichText::new(format!("{} {}={}  ({}%)", q.method, q.name, q.value, q.probability)).monospace().small());
                    }
                }
                if !ic.path_segments.is_empty() {
                    ui.label(egui::RichText::new("Path segment values").strong());
                    let segs: Vec<String> = ic.path_segments.iter().take(40).map(|s| if s.is_file { format!("{}·file", s.value) } else { s.value.clone() }).collect();
                    ui.label(egui::RichText::new(segs.join("  ")).monospace().small().color(Palette::muted()));
                }
            }
            if let Some(sc) = &p.server_config {
                kit::section(ui, "Server responses");
                ui.label(format!("Random version headers: {}", if sc.random_version_headers { "yes" } else { "no" }));
                for h in &sc.headers {
                    ui.label(egui::RichText::new(format!("{} {}: {}  ({}%)", h.method, h.name, h.value, h.probability)).monospace().small());
                }
                if !sc.cookies.is_empty() {
                    let c: Vec<&str> = sc.cookies.iter().map(|c| c.name.as_str()).collect();
                    ui.label(egui::RichText::new(format!("Cookies: {}", c.join(", "))).monospace().small());
                }
            }
        });
    }
}
