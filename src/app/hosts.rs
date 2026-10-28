//! Hosts: the server's per-host inventory (independent of live implants),
//! the implants on each host, operator notes, and an IOC / cleanup checklist
//! built from Sliver's host IOC records (e.g. uploads tracked as IOCs).

use super::{fmt_time, kit, short, SliverApp, Tab};
use crate::client::{Command, Op, Target};
use crate::theme::Palette;

impl SliverApp {
    pub(super) fn hosts_tab(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() { self.op(Op::RefreshHosts); }
            ui.colored_label(Palette::muted(), format!("{} hosts · {} open IOCs", self.ext.hosts.len(),
                self.ext.hosts.iter().map(|h| h.io_cs.len()).sum::<usize>()));
        });
        if self.ext.hosts.is_empty() {
            kit::empty(ui, "🖧", "No hosts recorded", "Hosts appear once an implant checks in");
            return;
        }
        let hosts = self.ext.hosts.clone();
        // Host records can come back with an empty ID; the host UUID is the stable key.
        if self.ext.host_sel.as_ref().map_or(true, |u| !hosts.iter().any(|h| &h.host_uuid == u)) {
            self.ext.host_sel = hosts.first().map(|h| h.host_uuid.clone());
        }
        let sel = self.ext.host_sel.clone();
        let implants = |uuid: &str| -> (usize, usize) {
            (self.sessions.iter().filter(|s| s.uuid == uuid).count(), self.beacons.iter().filter(|b| b.uuid == uuid).count())
        };
        let counts: Vec<(usize, usize)> = hosts.iter().map(|h| implants(&h.host_uuid)).collect();

        let mut pick: Option<String> = None;
        let list_h = (ui.available_height() * 0.45).max(120.0);
        ui.push_id("hosts-table", |ui| {
            kit::table(ui)
                .striped(true)
                .sense(egui::Sense::click())
                .max_scroll_height(list_h)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(160.0))
                .column(Column::remainder().at_least(220.0).clip(true))
                .column(Column::auto().at_least(70.0))
                .column(Column::auto().at_least(130.0))
                .column(Column::auto().at_least(90.0))
                .column(Column::auto().at_least(60.0))
                .header(22.0, |mut h| {
                    for t in ["Hostname", "OS version", "Locale", "First contact", "Implants", "IOCs"] { h.col(|ui| kit::th(ui, t)); }
                })
                .body(|body| {
                    body.rows(24.0, hosts.len(), |mut row| {
                        let i = row.index();
                        let h = &hosts[i];
                        // Selection shown with a marker: egui's selected-row tint washes out the badges.
                        let selected = sel.as_deref() == Some(h.host_uuid.as_str());
                        row.col(|ui| {
                            ui.label(egui::RichText::new(if selected { "▶" } else { " " }).color(Palette::accent()));
                            let name = egui::RichText::new(&h.hostname).strong();
                            ui.label(if selected { name.color(Palette::accent()) } else { name });
                        });
                        row.col(|ui| { ui.colored_label(Palette::muted(), &h.os_version); });
                        row.col(|ui| { ui.colored_label(Palette::muted(), &h.locale); });
                        row.col(|ui| { ui.colored_label(Palette::muted(), fmt_time(h.first_contact)); });
                        row.col(|ui| {
                            let (s, b) = counts[i];
                            if s + b == 0 { ui.colored_label(Palette::muted(), "none live"); }
                            if s > 0 { kit::badge(ui, format!("{s} session{}", if s == 1 { "" } else { "s" }), Palette::green()); }
                            if b > 0 { kit::badge(ui, format!("{b} beacon{}", if b == 1 { "" } else { "s" }), Palette::accent()); }
                        });
                        row.col(|ui| {
                            let n = h.io_cs.len();
                            if n == 0 { ui.colored_label(Palette::muted(), "0"); } else { kit::badge(ui, n.to_string(), Palette::yellow()); }
                        });
                        if row.response().clicked() { pick = Some(h.host_uuid.clone()); }
                    });
                });
        });
        if let Some(id) = pick { self.ext.host_sel = Some(id); }

        // ---- detail of the selected host ----
        let Some(h) = hosts.iter().find(|h| Some(&h.host_uuid) == self.ext.host_sel.as_ref()).cloned() else { return };
        ui.separator();
        let mut open: Option<Target> = None;
        let mut rm_ioc: Option<crate::proto::clientpb::Ioc> = None;
        let mut rm_host = false;
        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            ui.horizontal(|ui| {
                ui.heading(&h.hostname);
                ui.colored_label(Palette::muted(), egui::RichText::new(short(&h.host_uuid)).monospace().small());
            });
            kit::section(ui, "Implants on this host");
            let mut any = false;
            for s in self.sessions.iter().filter(|s| s.uuid == h.host_uuid) {
                any = true;
                ui.horizontal(|ui| {
                    kit::badge(ui, "session", Palette::green());
                    if ui.link(format!("{} {}", short(&s.id), s.name)).clicked() { open = Some(Target::session(&s.id)); }
                    ui.colored_label(Palette::muted(), format!("{} · {} · {}", s.username, s.transport, s.remote_address));
                });
            }
            for b in self.beacons.iter().filter(|b| b.uuid == h.host_uuid) {
                any = true;
                ui.horizontal(|ui| {
                    kit::badge(ui, "beacon", Palette::accent());
                    if ui.link(format!("{} {}", short(&b.id), b.name)).clicked() { open = Some(Target::beacon(&b.id)); }
                    ui.colored_label(Palette::muted(), format!("{} · {}", b.username, b.remote_address));
                });
            }
            if !any { ui.colored_label(Palette::muted(), "no live implants"); }
            kit::section(ui, "Notes");
            let note = self.settings.host_notes.entry(h.host_uuid.clone()).or_default();
            if ui.add(egui::TextEdit::multiline(note).desired_rows(4).desired_width(f32::INFINITY).hint_text("operator notes for this host (saved locally)")).changed() {
                self.settings_dirty = true;
            }
            ui.add_space(6.0);
            if kit::danger(ui, "✕ Remove host record") { rm_host = true; }

            let ui = &mut cols[1];
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("IOC / cleanup checklist").strong());
                kit::badge(ui, format!("{} open", h.io_cs.len()), if h.io_cs.is_empty() { Palette::green() } else { Palette::yellow() });
            });
            ui.colored_label(Palette::muted(), egui::RichText::new("Artifacts left on the host. Mark each cleaned once removed.").small());
            if h.io_cs.is_empty() {
                ui.add_space(6.0);
                ui.colored_label(Palette::green(), "✓ nothing outstanding");
            }
            egui::ScrollArea::vertical().id_salt("ioc-list").auto_shrink([false, false]).show(ui, |ui| {
                for ioc in &h.io_cs {
                    ui.horizontal(|ui| {
                        if ui.button("✓ cleaned").on_hover_text("Remove this IOC record").clicked() { rm_ioc = Some(ioc.clone()); }
                        ui.label(egui::RichText::new(&ioc.path).monospace());
                        if !ioc.file_hash.is_empty() {
                            ui.colored_label(Palette::muted(), egui::RichText::new(&ioc.file_hash[..ioc.file_hash.len().min(16)]).monospace().small())
                                .on_hover_text(&ioc.file_hash);
                        }
                    });
                }
            });
        });
        if let Some(t) = open { self.pending_open.push(Tab::Console(t)); }
        if let Some(ioc) = rm_ioc { self.op(Op::RmIoc { ioc }); }
        if rm_host {
            self.confirm("Remove host", format!("Delete the host record for {} (and its IOC list) from the server?", h.hostname),
                vec![Command::Op(Op::RmHost { id: h.id.clone(), uuid: h.host_uuid.clone() })]);
        }
    }
}
