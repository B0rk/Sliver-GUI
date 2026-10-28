//! Remote file browser: breadcrumb navigation with back/up history, a cached
//! "recent folders" list and mounts, right-click file operations (download,
//! preview, copy, move/rename, chmod, chown, delete, add to loot), content search
//! (grep) and IOC-tracked uploads.

use super::{fmt_time, human_size, kit, SliverApp};
use crate::client::{Command, Op, Target};
use crate::proto::sliverpb;
use crate::theme::Palette;

#[derive(Default)]
pub(super) struct FileBrowser {
    pub cwd: String,
    pub listing: Option<sliverpb::Ls>,
    pub requested: bool,
    /// Directories visited (most recent first), shown as quick links.
    pub recent: Vec<String>,
    pub back: Vec<String>,
    pub path_edit: String,
    pub filter: String,
    /// Mark uploads as IOCs so they show up in the host cleanup checklist.
    pub track_ioc: bool,
    pub ioc_init: bool,
    pub dialog: Option<FileDialog>,
    /// Bottom pane: 0 none, 1 preview, 2 search.
    pub pane: u8,
}

/// An in-tab dialog for a file operation needing operator input.
pub(super) struct FileDialog {
    pub kind: FileOp,
    pub src: String,
    pub input: String,
    pub recursive: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum FileOp {
    Mkdir,
    Move,
    Copy,
    Chmod,
    Chown,
}

impl FileBrowser {
    /// Record a successful listing of `path`.
    pub fn visited(&mut self, path: &str) {
        if path.is_empty() { return; }
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_string());
        self.recent.truncate(14);
    }
}

/// Split a remote path into clickable breadcrumb segments `(label, path)`.
fn crumbs(path: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if path.is_empty() { return out; }
    let win = path.contains('\\') || path.chars().nth(1) == Some(':');
    if win {
        let mut acc = String::new();
        for (i, part) in path.split('\\').filter(|p| !p.is_empty()).enumerate() {
            if i == 0 { acc = format!("{part}\\"); } else if acc.ends_with('\\') { acc.push_str(part); } else { acc = format!("{acc}\\{part}"); }
            out.push((part.to_string(), acc.clone()));
        }
    } else {
        out.push(("/".to_string(), "/".to_string()));
        let mut acc = String::new();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            acc = format!("{acc}/{part}");
            out.push((part.to_string(), acc.clone()));
        }
    }
    out
}

pub(super) fn join_remote(cwd: &str, name: &str) -> String {
    if cwd.is_empty() || cwd == "." { return name.to_string(); }
    if cwd.contains('\\') || cwd.chars().nth(1) == Some(':') {
        if cwd.ends_with('\\') { format!("{cwd}{name}") } else { format!("{cwd}\\{name}") }
    } else if cwd.ends_with('/') {
        format!("{cwd}{name}")
    } else {
        format!("{cwd}/{name}")
    }
}

pub(super) fn parent_remote(path: &str) -> String {
    if path.is_empty() || path == "." { return "..".into(); }
    if path.contains('\\') || path.chars().nth(1) == Some(':') {
        let t = path.trim_end_matches('\\');
        match t.rfind('\\') {
            // `C:\Users` → `C:\` (keep the drive root's backslash).
            Some(i) if t[..i].ends_with(':') => format!("{}\\", &t[..i]),
            Some(i) => t[..i].to_string(),
            None => format!("{t}\\"),
        }
    } else {
        let t = path.trim_end_matches('/');
        match t.rfind('/') {
            Some(0) | None => "/".into(),
            Some(i) => t[..i].to_string(),
        }
    }
}

impl SliverApp {
    fn files_nav(&mut self, target: &Target, path: String, push_back: bool) {
        let fb = self.files.entry(target.key()).or_default();
        if push_back && !fb.cwd.is_empty() && fb.cwd != path {
            let cwd = fb.cwd.clone();
            fb.back.push(cwd);
            if fb.back.len() > 50 { fb.back.remove(0); }
        }
        fb.requested = true;
        self.send(Command::Ls { target: target.clone(), path });
    }

    pub(super) fn files_tab(&mut self, ui: &mut egui::Ui, target: Target) {
        use egui_extras::Column;
        let key = target.key();
        let is_beacon = target.is_beacon();
        let win = self.target_os(&target) == "windows";
        {
            let fb = self.files.entry(key.clone()).or_default();
            if !fb.ioc_init { fb.track_ioc = true; fb.ioc_init = true; }
        }
        let cwd = self.files[&key].cwd.clone();

        let mut nav: Option<(String, bool)> = None;
        let mut upload = false;
        let mut want_mounts = false;
        // ---- toolbar: navigation + breadcrumbs ----
        kit::toolbar(ui, |ui| {
            let fb = self.files.get_mut(&key).expect("browser state");
            if ui.add_enabled(!fb.back.is_empty(), egui::Button::new("⟵")).on_hover_text("Back").clicked() {
                if let Some(p) = fb.back.pop() { nav = Some((p, false)); }
            }
            if ui.button("⬑").on_hover_text("Up one level").clicked() { nav = Some((parent_remote(&cwd), true)); }
            if ui.button("⟳").on_hover_text("Refresh").clicked() {
                nav = Some((if cwd.is_empty() { ".".into() } else { cwd.clone() }, false));
            }
            ui.separator();
            for (label, path) in crumbs(&cwd) {
                if ui.add(egui::Button::new(egui::RichText::new(&label).monospace()).frame(false)).clicked() {
                    nav = Some((path, true));
                }
                if label != "/" { ui.colored_label(Palette::muted(), "›"); }
            }
            if fb.requested { ui.spinner(); }
        });
        kit::toolbar(ui, |ui| {
            let fb = self.files.get_mut(&key).expect("browser state");
            if fb.path_edit.is_empty() && !cwd.is_empty() { fb.path_edit = cwd.clone(); }
            let r = ui.add(egui::TextEdit::singleline(&mut fb.path_edit).desired_width(260.0).font(egui::TextStyle::Monospace).hint_text("go to path"));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                nav = Some((fb.path_edit.trim().to_string(), true));
            }
            if ui.button("Go").clicked() { nav = Some((fb.path_edit.trim().to_string(), true)); }
            ui.separator();
            if ui.button("⬆ Upload").on_hover_text("Upload a file into this folder").clicked() { upload = true; }
            ui.checkbox(&mut fb.track_ioc, "track as IOC").on_hover_text("Record the upload as an IOC on the host (Hosts tab cleanup checklist)");
            if ui.button("+ New folder").clicked() {
                fb.dialog = Some(FileDialog { kind: FileOp::Mkdir, src: cwd.clone(), input: "new_folder".into(), recursive: false });
            }
            if ui.button("⛁ Mounts").on_hover_text("List drives / mount points").clicked() { want_mounts = true; }
            if ui.selectable_label(fb.pane == 2, "⌕ Search").on_hover_text("Search file contents (grep)").clicked() {
                fb.pane = if fb.pane == 2 { 0 } else { 2 };
            }
            kit::search(ui, &mut fb.filter, "filter names", 140.0);
        });
        if want_mounts { self.op(Op::Mounts { target: target.clone() }); }
        if upload {
            if let Some(p) = rfd::FileDialog::new().pick_file() {
                match std::fs::read(&p) {
                    Ok(data) => {
                        let fname = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "upload.bin".into());
                        let remote = join_remote(&cwd, &fname);
                        if self.files[&key].track_ioc {
                            self.op(Op::UploadIoc { target: target.clone(), remote, data });
                        } else {
                            self.send(Command::Upload { target: target.clone(), remote, data });
                        }
                        nav = Some((if cwd.is_empty() { ".".into() } else { cwd.clone() }, false));
                    }
                    Err(e) => self.set_toast(false, &format!("read {}: {e}", p.display())),
                }
            }
        }

        self.file_dialog_ui(ui, &target, &cwd, &mut nav);

        // ---- body: places column + listing ----
        let listing = self.files[&key].listing.clone();
        let requested = self.files[&key].requested;
        let pane = self.files[&key].pane;
        let recent = self.files[&key].recent.clone();
        let mounts = self.ext.mounts.get(&key).cloned().unwrap_or_default();
        let filter = self.files[&key].filter.to_lowercase();
        let mut file_ops: Vec<(&'static str, String, String)> = Vec::new();

        let bottom_h = if pane == 0 { 0.0 } else { (ui.available_height() * 0.38).max(140.0) };
        let main_h = ui.available_height() - bottom_h;
        ui.horizontal_top(|ui| {
            // Places
            ui.allocate_ui(egui::vec2(190.0, main_h), |ui| {
                egui::ScrollArea::vertical().id_salt(("places", key.clone())).auto_shrink([false, false]).show(ui, |ui| {
                    ui.label(egui::RichText::new("RECENT").small().strong().color(Palette::muted()));
                    for p in &recent {
                        let short = p.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or(p);
                        if ui.selectable_label(*p == cwd, format!("🗀 {short}")).on_hover_text(p).clicked() {
                            nav = Some((p.clone(), true));
                        }
                    }
                    if !mounts.is_empty() {
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("MOUNTS").small().strong().color(Palette::muted()));
                        for m in &mounts {
                            let label = if m.mount_point.is_empty() { m.volume_name.clone() } else { m.mount_point.clone() };
                            let hint = format!("{} {} · {} free of {}", m.volume_type, m.file_system,
                                human_size(m.free_space as i64), human_size(m.total_space as i64));
                            if ui.selectable_label(false, format!("⛁ {label}")).on_hover_text(hint).clicked() {
                                nav = Some((label, true));
                            }
                        }
                    }
                });
            });
            ui.separator();
            ui.vertical(|ui| {
                ui.set_height(main_h);
                if let Some(ls) = &listing {
                    if !ls.exists { ui.colored_label(Palette::red(), "path does not exist"); }
                    let mut entries: Vec<&sliverpb::FileInfo> = ls.files.iter()
                        .filter(|f| f.name != "." && f.name != "..")
                        .filter(|f| filter.is_empty() || f.name.to_lowercase().contains(&filter))
                        .collect();
                    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                    ui.push_id(("ftable", key.clone()), |ui| {
                        kit::table(ui)
                            .striped(true)
                            .sense(egui::Sense::click())
                            .max_scroll_height(main_h - 8.0)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::remainder().at_least(220.0).clip(true))
                            .column(Column::auto().at_least(80.0))
                            .column(Column::auto().at_least(96.0))
                            .column(Column::auto().at_least(130.0))
                            .header(22.0, |mut h| {
                                for t in ["Name", "Size", "Mode", "Modified"] { h.col(|ui| kit::th(ui, t)); }
                            })
                            .body(|body| {
                                body.rows(22.0, entries.len(), |mut row| {
                                    let fi = entries[row.index()];
                                    let full = join_remote(&cwd, &fi.name);
                                    row.col(|ui| {
                                        if fi.is_dir {
                                            ui.label(egui::RichText::new(format!("🗀 {}", fi.name)).color(Palette::accent()));
                                        } else if !fi.link.is_empty() {
                                            ui.label(format!("↪ {}", fi.name)).on_hover_text(format!("→ {}", fi.link));
                                        } else {
                                            ui.label(format!("🗋 {}", fi.name));
                                        }
                                    });
                                    row.col(|ui| { ui.colored_label(Palette::muted(), if fi.is_dir { "—".into() } else { human_size(fi.size) }); });
                                    row.col(|ui| { ui.label(egui::RichText::new(&fi.mode).monospace().small()); });
                                    row.col(|ui| { ui.colored_label(Palette::muted(), fmt_time(fi.mod_time)); });
                                    let resp = row.response();
                                    if resp.double_clicked() || (fi.is_dir && resp.clicked()) {
                                        if fi.is_dir { nav = Some((full.clone(), true)); } else { file_ops.push(("preview", full.clone(), fi.name.clone())); }
                                    }
                                    resp.context_menu(|ui| {
                                        ui.label(egui::RichText::new(&fi.name).strong());
                                        ui.separator();
                                        if fi.is_dir {
                                            if ui.button("🗀  Open").clicked() { nav = Some((full.clone(), true)); ui.close_menu(); }
                                        } else {
                                            if ui.button("⬇  Download…").clicked() { file_ops.push(("dl", full.clone(), fi.name.clone())); ui.close_menu(); }
                                            if ui.button("👁  Preview").clicked() { file_ops.push(("preview", full.clone(), fi.name.clone())); ui.close_menu(); }
                                            if ui.button("⛁  Add to loot").clicked() { file_ops.push(("loot", full.clone(), fi.name.clone())); ui.close_menu(); }
                                        }
                                        if ui.button("⎘  Copy path").clicked() { file_ops.push(("copy-path", full.clone(), fi.name.clone())); ui.close_menu(); }
                                        ui.separator();
                                        if ui.button("✎  Rename / move…").clicked() { file_ops.push(("mv", full.clone(), fi.name.clone())); ui.close_menu(); }
                                        if !fi.is_dir && ui.button("⎘  Copy to…").clicked() { file_ops.push(("cp", full.clone(), fi.name.clone())); ui.close_menu(); }
                                        if ui.button("⚿  Permissions (chmod)…").clicked() { file_ops.push(("chmod", full.clone(), fi.mode.clone())); ui.close_menu(); }
                                        if !win && ui.button("⚇  Owner (chown)…").clicked() { file_ops.push(("chown", full.clone(), fi.name.clone())); ui.close_menu(); }
                                        ui.separator();
                                        if ui.button(egui::RichText::new("✕  Delete").color(Palette::red())).clicked() { file_ops.push(("rm", full.clone(), fi.name.clone())); ui.close_menu(); }
                                    });
                                });
                            });
                    });
                    if entries.is_empty() {
                        kit::empty(ui, "🗀", if filter.is_empty() { "Empty folder" } else { "No matches" }, "");
                    }
                } else if requested {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| { ui.spinner(); ui.colored_label(Palette::muted(), if is_beacon { "queued — waiting for beacon check-in…" } else { "listing…" }); });
                } else {
                    kit::empty(ui, "🗀", "No listing yet", "Press ⟳ to list the current folder");
                }
            });
        });

        // ---- bottom pane: preview or search ----
        if pane != 0 {
            ui.separator();
            if pane == 1 { self.file_preview_pane(ui, &target); } else { self.file_search_pane(ui, &target, &cwd); }
        }

        for (op, path, name) in file_ops {
            match op {
                "dl" => {
                    if let Some(save) = rfd::FileDialog::new().set_file_name(&name).save_file() {
                        self.send(Command::Download { target: target.clone(), path, save_to: save.display().to_string() });
                    }
                }
                "preview" => {
                    self.ext.previews.remove(&key);
                    self.files.get_mut(&key).expect("browser state").pane = 1;
                    self.op(Op::Preview { target: target.clone(), path });
                }
                "loot" => {
                    self.op(Op::LootRemote { target: target.clone(), path });
                    self.set_toast(true, &format!("fetching {name} into loot…"));
                }
                "copy-path" => ui.ctx().copy_text(path),
                "mv" => { self.files.get_mut(&key).expect("browser state").dialog = Some(FileDialog { kind: FileOp::Move, src: path.clone(), input: path, recursive: false }); }
                "cp" => { self.files.get_mut(&key).expect("browser state").dialog = Some(FileDialog { kind: FileOp::Copy, src: path.clone(), input: format!("{path}.copy"), recursive: false }); }
                "chown" => {
                    // The implant resolves names (not numeric ids); start from the implant's user.
                    let user = self.sessions.iter().find(|s| s.id == key).map(|s| s.username.clone())
                        .or_else(|| self.beacons.iter().find(|b| b.id == key).map(|b| b.username.clone()))
                        .unwrap_or_default();
                    let input = if user.is_empty() { String::new() } else { format!("{user}:{user}") };
                    self.files.get_mut(&key).expect("browser state").dialog = Some(FileDialog { kind: FileOp::Chown, src: path, input, recursive: false });
                }
                "chmod" => {
                    let octal = mode_to_octal(&name).unwrap_or_else(|| "644".into());
                    self.files.get_mut(&key).expect("browser state").dialog = Some(FileDialog { kind: FileOp::Chmod, src: path, input: octal, recursive: false });
                }
                "rm" => self.confirm(
                    "Delete remote file",
                    format!("Delete {path} on the target? Folders are removed recursively."),
                    vec![
                        Command::Rm { target: target.clone(), path, recursive: true },
                        Command::Ls { target: target.clone(), path: if cwd.is_empty() { ".".into() } else { cwd.clone() } },
                    ],
                ),
                _ => {}
            }
        }

        if let Some((path, push)) = nav {
            if !path.is_empty() {
                if let Some(fb) = self.files.get_mut(&key) { fb.path_edit.clear(); }
                self.files_nav(&target, path, push);
            }
        }
    }

    /// The inline dialog for mkdir / move / copy / chmod / chown.
    fn file_dialog_ui(&mut self, ui: &mut egui::Ui, target: &Target, cwd: &str, nav: &mut Option<(String, bool)>) {
        let key = target.key();
        let Some(d) = self.files.get_mut(&key).and_then(|f| f.dialog.as_mut()) else { return };
        let mut run = false;
        let mut cancel = false;
        egui::Frame::none()
            .fill(Palette::accent().linear_multiply(0.08))
            .stroke(egui::Stroke::new(1.0_f32, Palette::accent().linear_multiply(0.4)))
            .rounding(6.0)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let label = match d.kind {
                        FileOp::Mkdir => "New folder name",
                        FileOp::Move => "Move / rename to",
                        FileOp::Copy => "Copy to",
                        FileOp::Chmod => "Mode (octal)",
                        FileOp::Chown => "Owner (user:group)",
                    };
                    ui.label(egui::RichText::new(label).strong());
                    if d.kind != FileOp::Mkdir {
                        ui.colored_label(Palette::muted(), egui::RichText::new(&d.src).monospace().small());
                    }
                    let r = ui.add(egui::TextEdit::singleline(&mut d.input).desired_width(280.0).font(egui::TextStyle::Monospace));
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) { run = true; }
                    if matches!(d.kind, FileOp::Chmod | FileOp::Chown) { ui.checkbox(&mut d.recursive, "recursive"); }
                    if ui.button(egui::RichText::new("Apply").strong()).clicked() { run = true; }
                    if ui.button("Cancel").clicked() { cancel = true; }
                });
            });
        ui.add_space(4.0);
        if cancel {
            self.files.get_mut(&key).expect("browser state").dialog = None;
            return;
        }
        if !run { return; }
        let Some(d) = self.files.get_mut(&key).and_then(|f| f.dialog.take()) else { return };
        let input = d.input.trim().to_string();
        if input.is_empty() { return; }
        match d.kind {
            FileOp::Mkdir => self.send(Command::Mkdir { target: target.clone(), path: join_remote(cwd, &input) }),
            FileOp::Move => self.op(Op::Mv { target: target.clone(), src: d.src, dst: input }),
            FileOp::Copy => self.op(Op::Cp { target: target.clone(), src: d.src, dst: input }),
            FileOp::Chmod => self.op(Op::Chmod { target: target.clone(), path: d.src, mode: input, recursive: d.recursive }),
            FileOp::Chown => {
                let (uid, gid) = input.split_once(':').map_or((input.as_str(), input.as_str()), |(u, g)| (u, g));
                self.op(Op::Chown { target: target.clone(), path: d.src, uid: uid.trim().into(), gid: gid.trim().into(), recursive: d.recursive });
            }
        }
        *nav = Some((if cwd.is_empty() { ".".into() } else { cwd.to_string() }, false));
    }

    fn file_preview_pane(&mut self, ui: &mut egui::Ui, target: &Target) {
        let key = target.key();
        let mut close = false;
        let mut to_loot: Option<(String, Vec<u8>)> = None;
        let mut save: Option<(String, Vec<u8>)> = None;
        match self.ext.previews.get(&key) {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.colored_label(Palette::muted(), "fetching preview…");
                    if ui.small_button("✕").clicked() { close = true; }
                });
            }
            Some((path, data)) => {
                let (is_text, body) = kit::preview_text(data);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(path).monospace().strong());
                    kit::badge(ui, if is_text { "text" } else { "binary" }, Palette::purple());
                    ui.colored_label(Palette::muted(), human_size(data.len() as i64));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("✕ Close").clicked() { close = true; }
                        if ui.small_button("⬇ Save…").clicked() { save = Some((path.clone(), data.clone())); }
                        if ui.small_button("⛁ Add to loot").clicked() { to_loot = Some((path.clone(), data.clone())); }
                    });
                });
                egui::ScrollArea::both().id_salt(("preview", key.clone())).auto_shrink([false, false]).show(ui, |ui| {
                    ui.add(egui::Label::new(egui::RichText::new(body).monospace().small()).wrap_mode(egui::TextWrapMode::Extend));
                });
            }
        }
        if close {
            self.ext.previews.remove(&key);
            if let Some(fb) = self.files.get_mut(&key) { fb.pane = 0; }
        }
        if let Some((path, data)) = save {
            let name = path.rsplit(['/', '\\']).next().unwrap_or("file").to_string();
            if let Some(p) = rfd::FileDialog::new().set_file_name(&name).save_file() {
                match std::fs::write(&p, &data) {
                    Ok(_) => self.set_toast(true, &format!("saved → {}", p.display())),
                    Err(e) => self.set_toast(false, &format!("save failed: {e}")),
                }
            }
        }
        if let Some((path, data)) = to_loot {
            let name = path.rsplit(['/', '\\']).next().unwrap_or("file").to_string();
            let text = kit::preview_text(&data).0;
            self.op(Op::AddLoot { name, data, text });
        }
    }

    fn file_search_pane(&mut self, ui: &mut egui::Ui, target: &Target, cwd: &str) {
        let key = target.key();
        let g = self.ext.grep.entry(key.clone()).or_default();
        let mut run = false;
        let mut open: Option<String> = None;
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Search contents").strong());
            let r = ui.add(egui::TextEdit::singleline(&mut g.pattern).desired_width(220.0).hint_text("regex, e.g. password|secret"));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) { run = true; }
            ui.checkbox(&mut g.recursive, "recursive");
            ui.colored_label(Palette::muted(), egui::RichText::new(format!("in {}", if cwd.is_empty() { "." } else { cwd })).small());
            if ui.add_enabled(!g.pattern.trim().is_empty() && !g.running, egui::Button::new("Search")).clicked() { run = true; }
            if g.running { ui.spinner(); }
            if !g.hits.is_empty() { ui.colored_label(Palette::muted(), format!("{} match(es)", g.hits.len())); }
        });
        egui::ScrollArea::vertical().id_salt(("grep", key.clone())).auto_shrink([false, false]).show(ui, |ui| {
            for h in &g.hits {
                ui.horizontal(|ui| {
                    if ui.add(egui::Label::new(egui::RichText::new(&h.file).monospace().small().color(Palette::accent())).sense(egui::Sense::click())).on_hover_text("Open containing folder").clicked() {
                        open = Some(parent_remote(&h.file));
                    }
                    if h.line_no > 0 { ui.colored_label(Palette::muted(), egui::RichText::new(format!(":{}", h.line_no)).monospace().small()); }
                    ui.label(egui::RichText::new(h.line.trim()).monospace().small());
                });
            }
        });
        if run && !g.pattern.trim().is_empty() {
            g.running = true;
            g.hits.clear();
            let (pattern, recursive) = (g.pattern.trim().to_string(), g.recursive);
            self.op(Op::Grep { target: target.clone(), path: if cwd.is_empty() { ".".into() } else { cwd.to_string() }, pattern, recursive });
        }
        if let Some(p) = open { self.files_nav(target, p, true); }
    }
}

/// Convert an `ls` mode string like `-rwxr-x---` to octal `750`.
fn mode_to_octal(mode: &str) -> Option<String> {
    let m: Vec<char> = mode.chars().collect();
    if m.len() < 10 { return None; }
    let mut out = String::new();
    for g in 0..3 {
        let base = 1 + g * 3;
        let mut v = 0;
        if m[base] == 'r' { v += 4; }
        if m[base + 1] == 'w' { v += 2; }
        if matches!(m[base + 2], 'x' | 's' | 't') { v += 1; }
        out.push(char::from_digit(v, 8)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_paths() {
        assert_eq!(join_remote("/home/operator", "a.txt"), "/home/operator/a.txt");
        assert_eq!(join_remote("/", "etc"), "/etc");
        assert_eq!(join_remote("", "x"), "x");
        assert_eq!(parent_remote("/home/operator"), "/home");
        assert_eq!(parent_remote("/home"), "/");
        assert_eq!(parent_remote("/"), "/");
        let c = crumbs("/home/operator");
        assert_eq!(c, vec![("/".into(), "/".into()), ("home".into(), "/home".into()), ("operator".into(), "/home/operator".into())]);
    }

    #[test]
    fn windows_paths() {
        assert_eq!(join_remote("C:\\Users", "operator"), "C:\\Users\\operator");
        assert_eq!(join_remote("C:\\", "Windows"), "C:\\Windows");
        assert_eq!(parent_remote("C:\\Users\\operator"), "C:\\Users");
        assert_eq!(parent_remote("C:\\Users"), "C:\\");
        let c = crumbs("C:\\Users\\operator");
        assert_eq!(c.last().unwrap().1, "C:\\Users\\operator");
        assert_eq!(c[0].1, "C:\\");
    }

    #[test]
    fn chmod_octal() {
        assert_eq!(mode_to_octal("-rwxr-x---").as_deref(), Some("750"));
        assert_eq!(mode_to_octal("drw-r--r--").as_deref(), Some("644"));
        assert_eq!(mode_to_octal("-rwsr-xr-x").as_deref(), Some("755"));
        assert_eq!(mode_to_octal("bad"), None);
    }
}
