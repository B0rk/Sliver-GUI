//! Windows-only panels: a registry browser (navigate keys, read values,
//! write / create / delete behind confirmation) and a services table
//! (filter, start, stop).

use super::{kit, SliverApp};
use crate::client::{Command, Op, RegValue, Target};
use crate::theme::Palette;

const HIVES: &[&str] = &["HKLM", "HKCU", "HKU", "HKCR", "HKCC"];

fn svc_status(code: u32) -> (&'static str, egui::Color32) {
    match code {
        1 => ("stopped", Palette::muted()),
        2 => ("starting", Palette::yellow()),
        3 => ("stopping", Palette::yellow()),
        4 => ("running", Palette::green()),
        5 => ("resuming", Palette::yellow()),
        6 => ("pausing", Palette::yellow()),
        7 => ("paused", Palette::purple()),
        _ => ("unknown", Palette::muted()),
    }
}

fn svc_start_type(code: u32) -> &'static str {
    match code { 0 => "boot", 1 => "system", 2 => "automatic", 3 => "manual", 4 => "disabled", _ => "—" }
}

fn reg_join(path: &str, key: &str) -> String {
    let p = path.trim_matches('\\');
    if p.is_empty() { key.to_string() } else { format!("{p}\\{key}") }
}

fn reg_parent(path: &str) -> String {
    let p = path.trim_matches('\\');
    p.rsplit_once('\\').map(|(a, _)| a.to_string()).unwrap_or_default()
}

impl SliverApp {
    pub(super) fn registry_tab(&mut self, ui: &mut egui::Ui, target: Target) {
        let key = target.key();
        if self.target_os(&target) != "windows" {
            kit::empty(ui, "⊞", "Registry is Windows-only", "This implant is not running on Windows");
            return;
        }
        let first = !self.ext.reg.contains_key(&key);
        let r = self.ext.reg.entry(key.clone()).or_default();
        let mut go: Option<(String, String)> = if first { Some((r.hive.clone(), r.path.clone())) } else { None };
        kit::toolbar(ui, |ui| {
            let mut hive = r.hive.clone();
            egui::ComboBox::from_id_salt(("reg-hive", key.clone())).selected_text(&hive).width(70.0).show_ui(ui, |ui| {
                for h in HIVES { ui.selectable_value(&mut hive, h.to_string(), *h); }
            });
            if hive != r.hive { go = Some((hive.clone(), String::new())); }
            if ui.button("⬑").on_hover_text("Parent key").clicked() { go = Some((r.hive.clone(), reg_parent(&r.path))); }
            if ui.button("⟳").on_hover_text("Refresh").clicked() { go = Some((r.hive.clone(), r.path.clone())); }
            ui.label(egui::RichText::new(format!("{}\\", r.hive)).monospace().color(Palette::muted()));
            let resp = ui.add(egui::TextEdit::singleline(&mut r.path_edit).desired_width(360.0).font(egui::TextStyle::Monospace));
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) { go = Some((r.hive.clone(), r.path_edit.trim().trim_matches('\\').to_string())); }
            if ui.button("Go").clicked() { go = Some((r.hive.clone(), r.path_edit.trim().trim_matches('\\').to_string())); }
            if r.loading { ui.spinner(); }
        });
        let (hive, path, subkeys, values, value) = (r.hive.clone(), r.path.clone(), r.subkeys.clone(), r.values.clone(), r.value.clone());
        let mut read: Option<String> = None;
        let mut del_key: Option<String> = None;
        let avail = (ui.available_height() - 70.0).max(120.0);
        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            ui.label(egui::RichText::new(format!("SUBKEYS ({})", subkeys.len())).small().strong().color(Palette::muted()));
            egui::ScrollArea::vertical().id_salt(("reg-sub", key.clone())).max_height(avail).auto_shrink([false, false]).show(ui, |ui| {
                for k in &subkeys {
                    let resp = ui.selectable_label(false, format!("🗀 {k}"));
                    if resp.clicked() { go = Some((hive.clone(), reg_join(&path, k))); }
                    resp.context_menu(|ui| {
                        if ui.button("🗀  Open").clicked() { go = Some((hive.clone(), reg_join(&path, k))); ui.close_menu(); }
                        if ui.button("⎘  Copy path").clicked() { ui.ctx().copy_text(format!("{hive}\\{}", reg_join(&path, k))); ui.close_menu(); }
                        if ui.button(egui::RichText::new("✕  Delete key").color(Palette::red())).clicked() { del_key = Some(k.clone()); ui.close_menu(); }
                    });
                }
                if subkeys.is_empty() { ui.colored_label(Palette::muted(), "no subkeys"); }
            });
            let ui = &mut cols[1];
            ui.label(egui::RichText::new(format!("VALUES ({})", values.len())).small().strong().color(Palette::muted()));
            egui::ScrollArea::vertical().id_salt(("reg-val", key.clone())).max_height(avail).auto_shrink([false, false]).show(ui, |ui| {
                for v in &values {
                    let label = if v.is_empty() { "(Default)".to_string() } else { v.clone() };
                    let selected = value.as_ref().is_some_and(|(k, _)| k == v);
                    if ui.selectable_label(selected, format!("▪ {label}")).clicked() { read = Some(v.clone()); }
                }
                if values.is_empty() { ui.colored_label(Palette::muted(), "no values"); }
            });
        });
        if let Some((k, v)) = &value {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(if k.is_empty() { "(Default)" } else { k }).strong());
                ui.label("=");
                ui.add(egui::Label::new(egui::RichText::new(v).monospace().color(Palette::accent())).truncate());
                if ui.small_button("⎘").clicked() { ui.ctx().copy_text(v.clone()); }
            });
        }

        // ---- edit ----
        let r = self.ext.reg.get_mut(&key).expect("registry state");
        let mut write: Option<(String, RegValue)> = None;
        let mut create: Option<String> = None;
        egui::CollapsingHeader::new("✎ Edit (write value / create key)").id_salt(("reg-edit", key.clone())).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Value name");
                ui.add(egui::TextEdit::singleline(&mut r.edit_key).desired_width(160.0));
                ui.selectable_value(&mut r.edit_dword, false, "REG_SZ");
                ui.selectable_value(&mut r.edit_dword, true, "REG_DWORD");
                ui.add(egui::TextEdit::singleline(&mut r.edit_value).desired_width(200.0).hint_text("data"));
                if ui.button("Write…").clicked() && !r.edit_key.trim().is_empty() {
                    let v = if r.edit_dword {
                        r.edit_value.trim().parse::<u32>().ok().map(RegValue::Dword)
                    } else { Some(RegValue::String(r.edit_value.clone())) };
                    if let Some(v) = v { write = Some((r.edit_key.trim().to_string(), v)); }
                }
            });
            ui.horizontal(|ui| {
                ui.label("New subkey");
                ui.add(egui::TextEdit::singleline(&mut r.new_key).desired_width(200.0));
                if ui.button("Create").clicked() && !r.new_key.trim().is_empty() { create = Some(r.new_key.trim().to_string()); }
            });
        });

        if let Some((h, p)) = go {
            r.loading = true;
            r.value = None;
            self.op(Op::RegList { target: target.clone(), hive: h, path: p });
        }
        if let Some(k) = read { self.op(Op::RegRead { target: target.clone(), hive: hive.clone(), path: path.clone(), key: k }); }
        if let Some(k) = create { self.op(Op::RegCreateKey { target: target.clone(), hive: hive.clone(), path: path.clone(), key: k }); }
        if let Some((k, v)) = write {
            let shown = match &v { RegValue::String(s) => format!("\"{s}\" (REG_SZ)"), RegValue::Dword(d) => format!("{d} (REG_DWORD)") };
            self.confirm("Write registry value", format!("Set {hive}\\{path}\\{k} = {shown}?"),
                vec![Command::Op(Op::RegWrite { target: target.clone(), hive: hive.clone(), path: path.clone(), key: k, value: v })]);
        }
        if let Some(k) = del_key {
            self.confirm("Delete registry key", format!("Delete {hive}\\{} and everything under it?", reg_join(&path, &k)),
                vec![Command::Op(Op::RegDeleteKey { target, hive, path, key: k })]);
        }
    }

    pub(super) fn services_tab(&mut self, ui: &mut egui::Ui, target: Target) {
        use egui_extras::Column;
        let key = target.key();
        if self.target_os(&target) != "windows" {
            kit::empty(ui, "⊞", "Services are Windows-only", "This implant is not running on Windows");
            return;
        }
        let first = !self.ext.svcs.contains_key(&key);
        let s = self.ext.svcs.entry(key.clone()).or_default();
        let mut refresh = first;
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() { refresh = true; }
            if s.loading { ui.spinner(); }
            ui.separator();
            kit::search(ui, &mut s.filter, "filter name / display / path / account", 260.0);
            ui.checkbox(&mut s.running_only, "running only");
            ui.colored_label(Palette::muted(), format!("{} services", s.services.len()));
        });
        if refresh {
            s.loading = true;
            self.op(Op::Services { target: target.clone() });
        }
        let mut close_detail = false;
        if let Some(d) = &self.ext.svcs[&key].detail {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&d.name).strong());
                    ui.colored_label(Palette::muted(), &d.display_name);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("✕ Close").clicked() { close_detail = true; }
                    });
                });
                egui::Grid::new("svc-detail").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
                    let (st, sc) = svc_status(d.status);
                    ui.colored_label(Palette::muted(), "Status"); ui.colored_label(sc, st); ui.end_row();
                    ui.colored_label(Palette::muted(), "Start type"); ui.label(svc_start_type(d.startup_type)); ui.end_row();
                    ui.colored_label(Palette::muted(), "Account"); ui.label(&d.account); ui.end_row();
                    ui.colored_label(Palette::muted(), "Binary path"); ui.add(egui::Label::new(egui::RichText::new(&d.bin_path).monospace()).wrap()); ui.end_row();
                    ui.colored_label(Palette::muted(), "Description"); ui.add(egui::Label::new(&d.description).wrap()); ui.end_row();
                });
            });
        }
        if close_detail { self.ext.svcs.get_mut(&key).expect("service view").detail = None; }
        let s = &self.ext.svcs[&key];
        if s.services.is_empty() {
            if s.loading {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| { ui.spinner(); ui.colored_label(Palette::muted(), "enumerating services…"); });
            } else {
                kit::empty(ui, "⚙", "No services listed", "Press Refresh");
            }
            return;
        }
        let needle = s.filter.to_lowercase();
        let rows: Vec<_> = s.services.iter()
            .filter(|x| !s.running_only || x.status == 4)
            .filter(|x| needle.is_empty()
                || x.name.to_lowercase().contains(&needle)
                || x.display_name.to_lowercase().contains(&needle)
                || x.bin_path.to_lowercase().contains(&needle)
                || x.account.to_lowercase().contains(&needle))
            .cloned().collect();
        let mut act: Option<(&'static str, String)> = None;
        kit::table(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(150.0).clip(true))
            .column(Column::auto().at_least(220.0).clip(true))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(150.0).clip(true))
            .column(Column::remainder().clip(true))
            .header(22.0, |mut h| {
                for t in ["Name", "Display name", "Status", "Start", "Account", "Binary path"] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|body| {
                body.rows(22.0, rows.len(), |mut row| {
                    let x = &rows[row.index()];
                    row.col(|ui| { ui.label(egui::RichText::new(&x.name).strong()); });
                    row.col(|ui| { ui.label(&x.display_name).on_hover_text(&x.description); });
                    row.col(|ui| { let (t, c) = svc_status(x.status); kit::badge(ui, t, c); });
                    row.col(|ui| { ui.colored_label(Palette::muted(), svc_start_type(x.startup_type)); });
                    row.col(|ui| { ui.colored_label(Palette::muted(), &x.account); });
                    row.col(|ui| { ui.add(egui::Label::new(egui::RichText::new(&x.bin_path).monospace().small()).truncate()).on_hover_text(&x.bin_path); });
                    row.response().context_menu(|ui| {
                        ui.label(egui::RichText::new(&x.name).strong());
                        ui.separator();
                        if ui.button("ⓘ  Details").clicked() { act = Some(("detail", x.name.clone())); ui.close_menu(); }
                        if ui.button("⎘  Copy name").clicked() { act = Some(("copy", x.name.clone())); ui.close_menu(); }
                        if ui.button("⎘  Copy binary path").clicked() { act = Some(("copy", x.bin_path.clone())); ui.close_menu(); }
                        ui.separator();
                        if ui.button("▶  Start").clicked() { act = Some(("start", x.name.clone())); ui.close_menu(); }
                        if ui.button(egui::RichText::new("■  Stop").color(Palette::red())).clicked() { act = Some(("stop", x.name.clone())); ui.close_menu(); }
                        ui.separator();
                        if ui.button(egui::RichText::new("✕  Remove service…").color(Palette::red())).clicked() { act = Some(("remove", x.name.clone())); ui.close_menu(); }
                    });
                });
            });
        match act {
            Some(("copy", v)) => ui.ctx().copy_text(v),
            Some(("detail", name)) => self.op(Op::ServiceDetail { target, name }),
            Some(("remove", name)) => self.confirm("Remove service", format!("Delete the {name} service from the target's service manager? This cannot be undone."),
                vec![Command::Op(Op::RemoveService { target, name })]),
            Some(("start", name)) => self.op(Op::ServiceStart { target, name }),
            Some(("stop", name)) => self.confirm("Stop service", format!("Stop the {name} service on the target?"),
                vec![Command::Op(Op::ServiceStop { target, name })]),
            _ => {}
        }
    }
}
