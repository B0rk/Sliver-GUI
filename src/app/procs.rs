//! Process browser: a filterable process table or tree with right-click
//! actions (kill, copy, migrate, impersonate).

use std::collections::HashMap;

use super::{kit, ModuleSpec, SliverApp, Tab};
use crate::client::{Command, Op, Target};
use crate::proto::commonpb;
use crate::theme::Palette;

/// A row to draw: the process and its tree depth.
struct Row {
    p: commonpb::Process,
    depth: usize,
}

/// Order processes as a depth-first tree (children under their parent).
fn tree_rows(procs: &[commonpb::Process]) -> Vec<Row> {
    let pids: std::collections::HashSet<i32> = procs.iter().map(|p| p.pid).collect();
    let mut children: HashMap<i32, Vec<&commonpb::Process>> = HashMap::new();
    let mut roots: Vec<&commonpb::Process> = Vec::new();
    for p in procs {
        if p.ppid != p.pid && pids.contains(&p.ppid) {
            children.entry(p.ppid).or_default().push(p);
        } else {
            roots.push(p);
        }
    }
    for v in children.values_mut() { v.sort_by_key(|p| p.pid); }
    roots.sort_by_key(|p| p.pid);
    let mut out = Vec::with_capacity(procs.len());
    let mut stack: Vec<(&commonpb::Process, usize)> = roots.into_iter().rev().map(|p| (p, 0)).collect();
    while let Some((p, d)) = stack.pop() {
        out.push(Row { p: p.clone(), depth: d });
        if let Some(kids) = children.get(&p.pid) {
            for k in kids.iter().rev() { stack.push((k, d + 1)); }
        }
    }
    out
}

fn proc_name(p: &commonpb::Process) -> String {
    p.executable.rsplit(['/', '\\']).next().unwrap_or(&p.executable).to_string()
}

impl SliverApp {
    pub(super) fn processes_tab(&mut self, ui: &mut egui::Ui, target: Target) {
        use egui_extras::Column;
        let key = target.key();
        let own_pid = self.sessions.iter().find(|s| s.id == key).map(|s| s.pid)
            .or_else(|| self.beacons.iter().find(|b| b.id == key).map(|b| b.pid))
            .unwrap_or(-1);
        let is_win = self.target_os(&target) == "windows";

        let view = self.ext.procs.entry(key.clone()).or_default();
        let mut refresh = false;
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() { refresh = true; }
            if view.loading { ui.spinner(); }
            ui.separator();
            ui.selectable_value(&mut view.tree, false, "☰ Table");
            ui.selectable_value(&mut view.tree, true, "⑂ Tree");
            ui.separator();
            kit::search(ui, &mut view.filter, "filter name / pid / owner / cmdline", 260.0);
            ui.colored_label(Palette::muted(), format!("{} processes", view.procs.len()));
            if target.is_beacon() {
                ui.colored_label(Palette::yellow(), "beacon — refresh is queued until the next check-in");
            }
        });
        if refresh {
            view.loading = true;
            self.op(Op::ProcList { target: target.clone() });
            return;
        }

        let view = &self.ext.procs[&key];
        if view.procs.is_empty() {
            if view.loading {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| { ui.spinner(); ui.colored_label(Palette::muted(), "listing processes…"); });
            } else {
                kit::empty(ui, "⚙", "No process list yet", "Press Refresh to list processes on the target");
            }
            return;
        }
        let needle = view.filter.to_lowercase();
        let rows: Vec<Row> = if view.tree && needle.is_empty() {
            tree_rows(&view.procs)
        } else {
            let mut v: Vec<Row> = view.procs.iter()
                .filter(|p| needle.is_empty()
                    || p.executable.to_lowercase().contains(&needle)
                    || p.owner.to_lowercase().contains(&needle)
                    || p.pid.to_string() == needle
                    || p.cmd_line.join(" ").to_lowercase().contains(&needle))
                .map(|p| Row { p: p.clone(), depth: 0 })
                .collect();
            v.sort_by_key(|r| r.p.pid);
            v
        };
        let selected = view.selected;

        let mut actions: Vec<(&'static str, commonpb::Process)> = Vec::new();
        let mut select: Option<i32> = None;
        kit::table(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(64.0))
            .column(Column::auto().at_least(64.0))
            .column(Column::auto().at_least(220.0).clip(true))
            .column(Column::auto().at_least(150.0).clip(true))
            .column(Column::auto().at_least(56.0))
            .column(Column::auto().at_least(50.0))
            .column(Column::remainder().clip(true))
            .header(22.0, |mut h| {
                for t in ["PID", "PPID", "Name", "Owner", "Arch", "Sess", "Command line"] {
                    h.col(|ui| kit::th(ui, t));
                }
            })
            .body(|body| {
                body.rows(22.0, rows.len(), |mut row| {
                    let r = &rows[row.index()];
                    let p = &r.p;
                    let own = p.pid == own_pid;
                    let privileged = {
                        let o = p.owner.to_lowercase();
                        o.contains("system") || o == "root" || o.ends_with("\\root")
                    };
                    row.set_selected(selected == Some(p.pid));
                    row.col(|ui| {
                        ui.label(egui::RichText::new(p.pid.to_string()).monospace().color(if own { Palette::green() } else { Palette::text() }));
                    });
                    row.col(|ui| { ui.label(egui::RichText::new(p.ppid.to_string()).monospace().color(Palette::muted())); });
                    row.col(|ui| {
                        let indent = "   ".repeat(r.depth);
                        let branch = if r.depth > 0 { "└ " } else { "" };
                        let txt = egui::RichText::new(format!("{indent}{branch}{}", proc_name(p)));
                        let txt = if own { txt.color(Palette::green()).strong() } else { txt };
                        ui.label(txt).on_hover_text(&p.executable);
                        if own { kit::badge(ui, "implant", Palette::green()); }
                    });
                    row.col(|ui| {
                        ui.colored_label(if privileged { Palette::yellow() } else { Palette::text() }, &p.owner);
                    });
                    row.col(|ui| { ui.colored_label(Palette::muted(), &p.architecture); });
                    row.col(|ui| { ui.colored_label(Palette::muted(), p.session_id.to_string()); });
                    row.col(|ui| {
                        let cl = p.cmd_line.join(" ");
                        ui.add(egui::Label::new(egui::RichText::new(&cl).small().color(Palette::muted())).truncate()).on_hover_text(cl);
                    });
                    let resp = row.response();
                    if resp.clicked() { select = Some(p.pid); }
                    resp.context_menu(|ui| {
                        ui.label(egui::RichText::new(format!("{} — pid {}", proc_name(p), p.pid)).strong());
                        ui.separator();
                        if ui.button("⎘  Copy PID").clicked() { actions.push(("copy-pid", p.clone())); ui.close_menu(); }
                        if ui.button("⎘  Copy command line").clicked() { actions.push(("copy-cmd", p.clone())); ui.close_menu(); }
                        if is_win {
                            ui.separator();
                            if ui.button("↪  Migrate implant into this process").clicked() { actions.push(("migrate", p.clone())); ui.close_menu(); }
                            if ui.button("⇄  Impersonate owner").clicked() { actions.push(("impersonate", p.clone())); ui.close_menu(); }
                        }
                        ui.separator();
                        if ui.button(egui::RichText::new("✕  Kill process").color(Palette::red())).clicked() { actions.push(("kill", p.clone())); ui.close_menu(); }
                        if ui.button(egui::RichText::new("✕  Force kill").color(Palette::red())).clicked() { actions.push(("kill-force", p.clone())); ui.close_menu(); }
                    });
                });
            });
        if let Some(pid) = select {
            if let Some(v) = self.ext.procs.get_mut(&key) { v.selected = Some(pid); }
        }

        for (what, p) in actions {
            let name = proc_name(&p);
            match what {
                "copy-pid" => ui.ctx().copy_text(p.pid.to_string()),
                "copy-cmd" => ui.ctx().copy_text(p.cmd_line.join(" ")),
                "migrate" => self.confirm(
                    "Migrate implant",
                    format!("Migrate the implant into {name} (pid {})? The current process keeps running.", p.pid),
                    vec![Command::Module { target: target.clone(), spec: ModuleSpec::Migrate { pid: p.pid as u32, process: String::new() } }],
                ),
                "impersonate" => {
                    self.send(Command::Module { target: target.clone(), spec: ModuleSpec::Impersonate { username: p.owner.clone() } });
                    self.pending_open.push(Tab::Console(target.clone()));
                }
                "kill" | "kill-force" => self.confirm(
                    "Kill process",
                    format!("Terminate {name} (pid {}) on the target?{}", p.pid,
                        if p.pid == own_pid { "\n\nThis is the implant's own process — the session will end." } else { "" }),
                    vec![Command::Op(Op::Terminate { target: target.clone(), pid: p.pid, force: what == "kill-force" })],
                ),
                _ => {}
            }
        }
    }
}
