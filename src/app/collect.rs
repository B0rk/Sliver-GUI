//! Loot and credential stores — both writable: add/remove loot (local files,
//! remote files, screenshots), preview and save loot content,
//! and add/edit/remove credentials with hash-type tagging and search.

use super::ext::CredForm;
use super::{human_size, kit, SliverApp};
use crate::client::{Command, Op};
use crate::proto::clientpb;
use crate::theme::Palette;

/// Hash types offered in the credential editor (value, label).
pub(super) const COMMON_HASH_TYPES: &[(i32, &str)] = &[
    (-1, "plaintext (no hash)"),
    (1000, "NTLM"),
    (3000, "LM"),
    (5600, "NetNTLMv2"),
    (5500, "NetNTLMv1"),
    (13100, "Kerberos 5 TGS-REP (etype 23)"),
    (18200, "Kerberos 5 AS-REP (etype 23)"),
    (1100, "DCC (MS Cache)"),
    (2100, "DCC2 (MS Cache 2)"),
    (1800, "sha512crypt $6$"),
    (3200, "bcrypt"),
    (0, "MD5"),
    (100, "SHA1"),
    (1400, "SHA2-256"),
];

/// Human label for a Sliver `HashType` value.
pub(super) fn hash_type_name(v: i32) -> String {
    if v == -1 { return "plaintext".into(); }
    if let Some((_, n)) = COMMON_HASH_TYPES.iter().find(|(x, _)| *x == v) {
        return n.to_string();
    }
    clientpb::HashType::try_from(v).map(|h| h.as_str_name().replace('_', " ")).unwrap_or_else(|_| format!("type {v}"))
}

fn cred_secret(c: &clientpb::Credential) -> &str {
    if !c.plaintext.is_empty() { &c.plaintext } else { &c.hash }
}

impl SliverApp {
    /// Hostname for a host UUID, if known (for "origin" columns).
    pub(super) fn host_label(&self, uuid: &str) -> String {
        // Records added without an origin carry the nil UUID.
        if uuid.is_empty() || uuid.chars().all(|c| c == '0' || c == '-') { return "—".into(); }
        self.ext.hosts.iter().find(|h| h.host_uuid == uuid).map(|h| h.hostname.clone())
            .or_else(|| self.sessions.iter().find(|s| s.uuid == uuid).map(|s| s.hostname.clone()))
            .or_else(|| self.beacons.iter().find(|b| b.uuid == uuid).map(|b| b.hostname.clone()))
            .unwrap_or_else(|| uuid.split('-').next().unwrap_or(uuid).to_string())
    }

    pub(super) fn save_cred(&mut self, f: CredForm) {
        let plaintext = f.plaintext.clone();
        let cred = clientpb::Credential {
            id: f.id.clone().unwrap_or_default(),
            username: f.username.trim().to_string(),
            plaintext: f.plaintext,
            hash: f.hash.trim().to_string(),
            hash_type: if f.hash_type < 0 { 0 } else { f.hash_type },
            is_cracked: f.is_cracked || (!plaintext.is_empty() && !f.hash.trim().is_empty()),
            origin_host_uuid: f.origin,
            collection: f.collection.trim().to_string(),
        };
        if f.id.is_some() {
            self.op(Op::UpdateCred(cred));
            return;
        }
        let dupe = self.creds.iter().any(|c| c.username.eq_ignore_ascii_case(&cred.username)
            && cred_secret(c) == cred_secret(&cred));
        if dupe {
            self.set_toast(false, &format!("{} with that secret is already stored", cred.username));
            return;
        }
        self.op(Op::AddCred(cred));
    }

    pub(super) fn loot_tab(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        let mut add_file = false;
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() { self.send(Command::RefreshLoot); }
            if ui.button("+ Add file…").on_hover_text("Store a local file in the server's loot").clicked() { add_file = true; }
            ui.separator();
            kit::search(ui, &mut self.ext.loot_search, "search loot", 200.0);
            ui.colored_label(Palette::muted(), format!("{} items", self.loot.len()));
        });
        if add_file {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                match std::fs::read(&p) {
                    Ok(data) => {
                        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
                        let text = kit::preview_text(&data).0;
                        self.op(Op::AddLoot { name, data, text });
                    }
                    Err(e) => self.set_toast(false, &format!("read {}: {e}", p.display())),
                }
            }
        }
        if self.loot.is_empty() {
            kit::empty(ui, "⛁", "No loot collected", "Add files here, or use \"Add to loot\" from the file browser and screenshots");
            return;
        }
        // Inline rename bar.
        let mut rename: Option<(String, String)> = None;
        let mut cancel_rename = false;
        if let Some((id, name)) = &mut self.ext.loot_rename {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Rename loot").strong());
                let r = ui.add(egui::TextEdit::singleline(name).desired_width(280.0));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.button(egui::RichText::new("Save").strong()).clicked() || enter) && !name.trim().is_empty() {
                    rename = Some((id.clone(), name.trim().to_string()));
                }
                if ui.button("Cancel").clicked() { cancel_rename = true; }
            });
        }
        if let Some((id, name)) = rename {
            self.ext.loot_rename = None;
            self.op(Op::RenameLoot { id, name });
        } else if cancel_rename {
            self.ext.loot_rename = None;
        }
        let needle = self.ext.loot_search.to_lowercase();
        let loot: Vec<clientpb::Loot> = self.loot.iter()
            .filter(|l| needle.is_empty() || l.name.to_lowercase().contains(&needle))
            .cloned().collect();
        let origins: Vec<String> = loot.iter().map(|l| self.host_label(&l.origin_host_uuid)).collect();
        let preview_h = if self.ext.loot_preview.is_some() { (ui.available_height() * 0.45).max(150.0) } else { 0.0 };
        let mut acts: Vec<(&'static str, clientpb::Loot)> = Vec::new();
        ui.push_id("loot-table", |ui| {
            let table_h = ui.available_height() - preview_h;
            kit::table(ui)
                .striped(true)
                .max_scroll_height(table_h)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::auto().at_least(80.0))
                .column(Column::remainder().at_least(220.0).clip(true))
                .column(Column::auto().at_least(70.0))
                .column(Column::auto().at_least(80.0))
                .column(Column::auto().at_least(120.0))
                .column(Column::auto().at_least(150.0))
                .header(22.0, |mut h| {
                    for t in ["ID", "Name", "Type", "Size", "Origin", ""] { h.col(|ui| kit::th(ui, t)); }
                })
                .body(|body| {
                    body.rows(24.0, loot.len(), |mut row| {
                        let i = row.index();
                        let l = &loot[i];
                        row.col(|ui| { ui.monospace(super::short(&l.id)); });
                        row.col(|ui| { ui.label(&l.name); });
                        row.col(|ui| {
                            let (t, c) = match l.file_type { 2 => ("text", Palette::green()), 1 => ("binary", Palette::purple()), _ => ("—", Palette::muted()) };
                            kit::badge(ui, t, c);
                        });
                        row.col(|ui| { ui.colored_label(Palette::muted(), human_size(l.size)); });
                        row.col(|ui| { ui.colored_label(Palette::muted(), &origins[i]); });
                        row.col(|ui| {
                            if ui.small_button("👁").on_hover_text("Preview").clicked() { acts.push(("view", l.clone())); }
                            if ui.small_button("⬇").on_hover_text("Save to disk…").clicked() { acts.push(("save", l.clone())); }
                            if ui.small_button("✎").on_hover_text("Rename").clicked() { acts.push(("rename", l.clone())); }
                            if ui.small_button(egui::RichText::new("✕").color(Palette::red())).on_hover_text("Remove from loot").clicked() { acts.push(("rm", l.clone())); }
                        });
                    });
                });
        });
        for (a, l) in acts {
            match a {
                "view" => {
                    self.ext.loot_preview = Some((l.id.clone(), l.name.clone(), Vec::new()));
                    self.op(Op::LootFetch { id: l.id, save_to: None });
                }
                "save" => {
                    if let Some(p) = rfd::FileDialog::new().set_file_name(&l.name).save_file() {
                        self.op(Op::LootFetch { id: l.id, save_to: Some(p.display().to_string()) });
                    }
                }
                "rename" => self.ext.loot_rename = Some((l.id, l.name)),
                "rm" => self.confirm("Remove loot", format!("Delete '{}' from the server's loot store?", l.name), vec![Command::Op(Op::RmLoot { id: l.id })]),
                _ => {}
            }
        }
        // Preview pane.
        let mut close = false;
        if let Some((_, name, data)) = &self.ext.loot_preview {
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(name).strong());
                ui.colored_label(Palette::muted(), human_size(data.len() as i64));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("✕ Close").clicked() { close = true; }
                });
            });
            if data.is_empty() {
                ui.horizontal(|ui| { ui.spinner(); ui.colored_label(Palette::muted(), "fetching…"); });
            } else {
                let (_, body) = kit::preview_text(data);
                egui::ScrollArea::both().id_salt("loot-preview").auto_shrink([false, false]).show(ui, |ui| {
                    ui.add(egui::Label::new(egui::RichText::new(body).monospace().small()).wrap_mode(egui::TextWrapMode::Extend));
                });
            }
        }
        if close { self.ext.loot_preview = None; }
    }

    pub(super) fn creds_tab(&mut self, ui: &mut egui::Ui) {
        use egui_extras::Column;
        let mut remove_sel = false;
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() { self.send(Command::RefreshCreds); }
            if ui.button("+ Add credential").clicked() { self.ext.cred_form = Some(CredForm { hash_type: -1, ..Default::default() }); }
            ui.separator();
            kit::search(ui, &mut self.ext.cred_search, "user, secret, collection, type", 220.0);
            let before = self.ext.cred_type;
            egui::ComboBox::from_id_salt("cred-type-filter")
                .selected_text(self.ext.cred_type.map_or("any type".to_string(), hash_type_name))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.ext.cred_type, None, "any type");
                    for (v, n) in COMMON_HASH_TYPES.iter().filter(|(v, _)| *v >= 0) {
                        ui.selectable_value(&mut self.ext.cred_type, Some(*v), *n);
                    }
                })
                .response.on_hover_text("Filter by hash type (asks the server)");
            if self.ext.cred_type != before {
                self.ext.cred_type_ids = None;
                if let Some(t) = self.ext.cred_type { self.op(Op::CredsByHashType(t)); }
            }
            ui.colored_label(Palette::muted(), format!("{} credentials", self.creds.len()));
            if !self.ext.cred_sel.is_empty() {
                ui.separator();
                if kit::danger(ui, &format!("✕ Remove {} selected", self.ext.cred_sel.len())) { remove_sel = true; }
            }
        });
        if remove_sel {
            let ids: Vec<String> = self.ext.cred_sel.drain().collect();
            let n = ids.len();
            self.confirm("Remove credentials", format!("Delete {n} credential(s) from the server?"), vec![Command::Op(Op::RmCreds(ids))]);
        }
        if self.creds.is_empty() {
            kit::empty(ui, "⚿", "No credentials stored", "Add one manually, or collect them from your implants");
            return;
        }
        let needle = self.ext.cred_search.to_lowercase();
        let type_ids = match (self.ext.cred_type, &self.ext.cred_type_ids) {
            (Some(t), Some((ft, ids))) if t == *ft => Some(ids),
            _ => None,
        };
        let creds: Vec<clientpb::Credential> = self.creds.iter()
            .filter(|c| self.ext.cred_type.is_none() || type_ids.is_some_and(|ids| ids.contains(&c.id)))
            .filter(|c| needle.is_empty()
                || c.username.to_lowercase().contains(&needle)
                || c.plaintext.to_lowercase().contains(&needle)
                || c.hash.to_lowercase().contains(&needle)
                || c.collection.to_lowercase().contains(&needle)
                || hash_type_name(c.hash_type).to_lowercase().contains(&needle))
            .cloned().collect();
        let origins: Vec<String> = creds.iter().map(|c| self.host_label(&c.origin_host_uuid)).collect();
        let mask = self.settings.mask_secrets;
        let mut acts: Vec<(&'static str, clientpb::Credential)> = Vec::new();
        let mut toggles: Vec<(String, bool)> = Vec::new();
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(24.0))
            .column(Column::auto().at_least(170.0).clip(true))
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::auto().at_least(120.0))
            .column(Column::auto().at_least(70.0))
            .column(Column::auto().at_least(100.0))
            .column(Column::auto().at_least(100.0))
            .column(Column::auto().at_least(120.0))
            .header(22.0, |mut h| {
                for t in ["", "Username", "Secret", "Type", "Cracked", "Collection", "Origin", ""] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|body| {
                body.rows(24.0, creds.len(), |mut row| {
                    let i = row.index();
                    let c = &creds[i];
                    row.col(|ui| {
                        let mut on = self.ext.cred_sel.contains(&c.id);
                        if ui.checkbox(&mut on, "").changed() { toggles.push((c.id.clone(), on)); }
                    });
                    row.col(|ui| { ui.label(egui::RichText::new(&c.username).strong()); });
                    row.col(|ui| {
                        let secret = cred_secret(c);
                        let shown = if mask { "•".repeat(secret.chars().count().clamp(6, 16)) } else { secret.to_string() };
                        let r = ui.add(egui::Label::new(egui::RichText::new(shown).monospace()).truncate().sense(egui::Sense::click()));
                        let r = if mask { r.on_hover_text(secret) } else { r };
                        if r.clicked() { acts.push(("copy-secret", c.clone())); }
                    });
                    row.col(|ui| {
                        if !c.plaintext.is_empty() && c.hash.is_empty() {
                            kit::badge(ui, "plaintext", Palette::green());
                        } else {
                            kit::badge(ui, hash_type_name(c.hash_type), Palette::accent());
                        }
                    });
                    row.col(|ui| {
                        if c.hash.is_empty() { ui.colored_label(Palette::muted(), "n/a"); }
                        else if c.is_cracked || !c.plaintext.is_empty() { kit::badge(ui, "✓ yes", Palette::green()); }
                        else { ui.colored_label(Palette::muted(), "no"); }
                    });
                    row.col(|ui| { if !c.collection.is_empty() { kit::badge(ui, &c.collection, Palette::purple()); } });
                    row.col(|ui| { ui.colored_label(Palette::muted(), &origins[i]); });
                    row.col(|ui| {
                        if ui.small_button("⎘").on_hover_text("Copy username").clicked() { acts.push(("copy-user", c.clone())); }
                        if ui.small_button("✎").on_hover_text("Edit").clicked() { acts.push(("edit", c.clone())); }
                        if ui.small_button(egui::RichText::new("✕").color(Palette::red())).on_hover_text("Remove").clicked() { acts.push(("rm", c.clone())); }
                    });
                });
            });
        for (id, on) in toggles {
            if on { self.ext.cred_sel.insert(id); } else { self.ext.cred_sel.remove(&id); }
        }
        for (a, c) in acts {
            match a {
                "copy-secret" => { ui.ctx().copy_text(cred_secret(&c).to_string()); self.set_toast(true, "secret copied"); }
                "copy-user" => ui.ctx().copy_text(c.username.clone()),
                "edit" => {
                    // Show what we have now; the server's current record replaces it when it arrives.
                    self.op(Op::CredDetail { id: c.id.clone() });
                    self.ext.cred_form = Some(CredForm {
                        id: Some(c.id.clone()),
                        username: c.username.clone(),
                        plaintext: c.plaintext.clone(),
                        hash: c.hash.clone(),
                        hash_type: if c.hash.is_empty() && !c.plaintext.is_empty() { -1 } else { c.hash_type },
                        collection: c.collection.clone(),
                        is_cracked: c.is_cracked,
                        origin: c.origin_host_uuid.clone(),
                    });
                }
                "rm" => self.confirm("Remove credential", format!("Delete the credential for {}?", c.username), vec![Command::Op(Op::RmCreds(vec![c.id]))]),
                _ => {}
            }
        }
    }
}
