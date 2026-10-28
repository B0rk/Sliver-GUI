//! Pivoting: client-side tunnels (SOCKS5, local and reverse port-forwards),
//! the server's record of reverse port-forwards on an implant (including ones
//! other operators started), implant-chaining pivot listeners (TCP / named
//! pipe), and WireGuard SOCKS / port-forwards for sessions on the wg transport.

use super::{kit, short, split_host_port, SliverApp};
use crate::client::{Command, Op, Target};
use crate::theme::Palette;

/// Form state for the Pivoting tab.
pub(super) struct PivotForm {
    pub session_idx: usize,
    /// 0 tunnels, 1 implant chaining, 2 WireGuard
    pub section: u8,
    pub kind: u8, // 0 = SOCKS, 1 = port-forward, 2 = reverse port-forward
    pub socks_bind: String,
    pub fwd_bind: String,
    pub fwd_remote: String,
    pub rport_bind: String,
    pub rport_fwd: String,
    pub pivot_pipe: bool,
    pub pivot_bind: String,
    pub wg_socks_port: i32,
    pub wg_fwd_local: i32,
    pub wg_fwd_remote: String,
}

impl Default for PivotForm {
    fn default() -> Self {
        Self {
            session_idx: 0,
            section: 0,
            kind: 0,
            socks_bind: "127.0.0.1:1081".into(),
            fwd_bind: "127.0.0.1:8080".into(),
            fwd_remote: "127.0.0.1:80".into(),
            rport_bind: "0.0.0.0:8080".into(),
            rport_fwd: "127.0.0.1:3000".into(),
            pivot_pipe: false,
            pivot_bind: "0.0.0.0:9898".into(),
            wg_socks_port: 3090,
            wg_fwd_local: 1080,
            wg_fwd_remote: "127.0.0.1:22".into(),
        }
    }
}

impl SliverApp {
    pub(super) fn pivoting_tab(&mut self, ui: &mut egui::Ui) {
        kit::toolbar(ui, |ui| {
            ui.selectable_value(&mut self.pivot_form.section, 0, "⇄ Tunnels");
            ui.selectable_value(&mut self.pivot_form.section, 1, "⛓ Implant chaining");
            ui.selectable_value(&mut self.pivot_form.section, 2, "◍ WireGuard");
            ui.separator();
            if self.sessions.is_empty() {
                ui.colored_label(Palette::muted(), "pivots require a live session — none connected");
            } else {
                let sessions = self.sessions.clone();
                if self.pivot_form.session_idx >= sessions.len() { self.pivot_form.session_idx = 0; }
                ui.label("Session:");
                let cur = &sessions[self.pivot_form.session_idx];
                egui::ComboBox::from_id_salt("pivot-session")
                    .selected_text(format!("{} ({}) · {}", cur.name, cur.hostname, cur.transport))
                    .show_ui(ui, |ui| {
                        for (i, s) in sessions.iter().enumerate() {
                            ui.selectable_value(&mut self.pivot_form.session_idx, i, format!("{} ({}) {} · {}", s.name, s.hostname, short(&s.id), s.transport));
                        }
                    });
            }
        });
        let target = self.sessions.get(self.pivot_form.session_idx).map(|s| Target::session(&s.id));
        match self.pivot_form.section {
            0 => {
                self.tunnels_section(ui, target.clone());
                if let Some(t) = target { self.implant_rportfwd_section(ui, t); }
            }
            1 => self.chaining_section(ui, target),
            _ => self.wireguard_section(ui, target),
        }
    }

    fn tunnels_section(&mut self, ui: &mut egui::Ui, target: Option<Target>) {
        use egui_extras::Column;
        if let Some(t) = target {
            kit::section(ui, "New tunnel");
            ui.horizontal(|ui| {
                ui.label("Type:");
                ui.selectable_value(&mut self.pivot_form.kind, 0, "SOCKS5 proxy");
                ui.selectable_value(&mut self.pivot_form.kind, 1, "Local port-forward");
                ui.selectable_value(&mut self.pivot_form.kind, 2, "Reverse port-forward");
            });
            match self.pivot_form.kind {
                0 => {
                    ui.horizontal(|ui| {
                        ui.label("Local bind:");
                        ui.text_edit_singleline(&mut self.pivot_form.socks_bind);
                        if ui.button("▶ Start SOCKS5").clicked() {
                            self.send(Command::StartSocks { target: t.clone(), bind: self.pivot_form.socks_bind.clone() });
                        }
                    });
                    ui.colored_label(Palette::muted(), "proxy client traffic through the implant, e.g. curl --socks5-hostname 127.0.0.1:1081 …");
                }
                1 => {
                    ui.horizontal(|ui| {
                        ui.label("Local bind:");
                        ui.text_edit_singleline(&mut self.pivot_form.fwd_bind);
                        ui.label("Remote (from implant):");
                        ui.text_edit_singleline(&mut self.pivot_form.fwd_remote);
                        if ui.button("▶ Start").clicked() {
                            if let Some((h, p)) = split_host_port(&self.pivot_form.fwd_remote) {
                                self.send(Command::StartPortfwd { target: t.clone(), bind: self.pivot_form.fwd_bind.clone(), remote_host: h, remote_port: p });
                            } else {
                                self.set_toast(false, "remote must be host:port");
                            }
                        }
                    });
                }
                _ => {
                    ui.horizontal(|ui| {
                        ui.label("Implant bind:");
                        ui.text_edit_singleline(&mut self.pivot_form.rport_bind);
                        ui.label("Forward to:");
                        ui.text_edit_singleline(&mut self.pivot_form.rport_fwd);
                        if ui.button("▶ Start").clicked() {
                            match (split_host_port(&self.pivot_form.rport_bind), split_host_port(&self.pivot_form.rport_fwd)) {
                                (Some((ba, bp)), Some((fa, fp))) => self.send(Command::StartRportfwd {
                                    target: t.clone(), bind_addr: ba, bind_port: bp, fwd_addr: fa, fwd_port: fp,
                                }),
                                _ => self.set_toast(false, "bind and forward must be host:port"),
                            }
                        }
                    });
                }
            }
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            kit::section(ui, "Active tunnels");
            if ui.small_button("⟳").clicked() { self.send(Command::RefreshPivotsList); }
        });
        if self.pivot_list.is_empty() {
            kit::empty(ui, "⇄", "No active tunnels", "");
            return;
        }
        let list = self.pivot_list.clone();
        let mut stop: Option<u32> = None;
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(40.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(140.0))
            .column(Column::auto().at_least(140.0))
            .column(Column::auto().at_least(110.0))
            .column(Column::auto().at_least(55.0))
            .column(Column::remainder().at_least(80.0))
            .header(22.0, |mut h| {
                for t in ["ID", "Type", "Bind", "Destination", "Session", "Conns", ""] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|mut body| {
                for p in &list {
                    let sname = self.names.get(&p.session).cloned().unwrap_or_else(|| short(&p.session).to_string());
                    body.row(24.0, |mut row| {
                        row.col(|ui| { ui.monospace(p.id.to_string()); });
                        row.col(|ui| { kit::badge(ui, &p.kind, Palette::purple()); });
                        row.col(|ui| { ui.monospace(&p.bind); });
                        row.col(|ui| { ui.monospace(&p.dest); });
                        row.col(|ui| { ui.label(sname); });
                        row.col(|ui| { ui.label(p.conns.to_string()); });
                        row.col(|ui| {
                            if ui.small_button(egui::RichText::new("✕ Stop").color(Palette::red())).clicked() { stop = Some(p.id); }
                        });
                    });
                }
            });
        if let Some(id) = stop { self.send(Command::StopPivot { id }); }
    }

    /// Reverse port-forwards the server has open on this implant — every operator's,
    /// not only the ones this client started.
    fn implant_rportfwd_section(&mut self, ui: &mut egui::Ui, t: Target) {
        let key = t.key();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            kit::section(ui, "Reverse port-forwards on this implant (server view)");
            if ui.small_button("⟳").on_hover_text("Ask the server").clicked() { self.op(Op::RportFwds { target: t.clone() }); }
        });
        let Some(list) = self.ext.rportfwds.get(&key).cloned() else {
            ui.colored_label(Palette::muted(), "press ⟳ to list");
            return;
        };
        if list.is_empty() {
            ui.colored_label(Palette::muted(), "none");
            return;
        }
        let mut stop: Option<u32> = None;
        egui::Grid::new("implant-rportfwds").striped(true).num_columns(4).spacing([24.0, 4.0]).show(ui, |ui| {
            for h in ["ID", "Implant bind", "Forwards to", ""] { kit::th(ui, h); }
            ui.end_row();
            for l in &list {
                ui.monospace(l.id.to_string());
                ui.monospace(format!("{}:{}", l.bind_address, l.bind_port));
                ui.monospace(format!("{}:{}", l.forward_address, l.forward_port));
                if ui.small_button(egui::RichText::new("✕ Stop").color(Palette::red())).clicked() { stop = Some(l.id); }
                ui.end_row();
            }
        });
        if let Some(id) = stop {
            self.confirm("Stop reverse port-forward", format!("Stop reverse port-forward {id} on the implant?"),
                vec![Command::Op(Op::RportFwdStop { target: t, id })]);
        }
    }

    fn chaining_section(&mut self, ui: &mut egui::Ui, target: Option<Target>) {
        use egui_extras::Column;
        ui.colored_label(Palette::muted(),
            "Pivot listeners let a session relay C2 for implants that can't reach the server directly. Build the downstream implant with a TCP-pivot or named-pipe C2 pointing at this host.");
        let Some(t) = target else { return };
        let host_ip = self.sessions.iter().find(|s| s.id == t.session_id)
            .map(|s| s.remote_address.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default())
            .unwrap_or_default();
        kit::section(ui, "New pivot listener");
        let mut start = false;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.pivot_form.pivot_pipe, false, "TCP");
            ui.selectable_value(&mut self.pivot_form.pivot_pipe, true, "Named pipe (Windows)");
            ui.label(if self.pivot_form.pivot_pipe { "Pipe name:" } else { "Bind:" });
            ui.add(egui::TextEdit::singleline(&mut self.pivot_form.pivot_bind).desired_width(180.0).font(egui::TextStyle::Monospace));
            if ui.button("▶ Start listener").clicked() { start = true; }
            if ui.button("⟳ List").clicked() { self.op(Op::PivotListeners { target: t.clone() }); }
        });
        if self.pivot_form.pivot_pipe && self.pivot_form.pivot_bind.contains(':') {
            self.pivot_form.pivot_bind = "pivotpipe".into();
        } else if !self.pivot_form.pivot_pipe && !self.pivot_form.pivot_bind.contains(':') {
            self.pivot_form.pivot_bind = "0.0.0.0:9898".into();
        }
        // Hint for building the downstream implant.
        let c2_hint = if self.pivot_form.pivot_pipe {
            format!("namedpipe://{}/pipe/{}", if host_ip.is_empty() { "<pivot-host>" } else { &host_ip }, self.pivot_form.pivot_bind)
        } else {
            let port = self.pivot_form.pivot_bind.rsplit(':').next().unwrap_or("9898");
            format!("tcppivot://{}:{port}", if host_ip.is_empty() { "<pivot-host-ip>" } else { &host_ip })
        };
        ui.horizontal(|ui| {
            ui.colored_label(Palette::muted(), "Downstream implant C2:");
            ui.label(egui::RichText::new(&c2_hint).monospace().color(Palette::accent()));
            if ui.small_button("⎘").on_hover_text("Copy").clicked() { ui.ctx().copy_text(c2_hint.clone()); }
            if ui.small_button("✦ Open generator").clicked() {
                if self.pivot_form.pivot_pipe { self.generate_form.named_pipe = c2_hint.trim_start_matches("namedpipe://").into(); }
                else { self.generate_form.tcp_pivot = c2_hint.trim_start_matches("tcppivot://").into(); }
                self.show_generate = true;
            }
        });
        if start {
            self.op(Op::PivotStart { target: t.clone(), named_pipe: self.pivot_form.pivot_pipe, bind: self.pivot_form.pivot_bind.trim().to_string() });
        }

        ui.add_space(6.0);
        kit::section(ui, "Pivot listeners on this session");
        let listeners = self.ext.pivot_listeners.get(&t.key()).cloned().unwrap_or_default();
        if listeners.is_empty() {
            kit::empty(ui, "⛓", "No pivot listeners", "Start one above, then press List to refresh");
            return;
        }
        let mut stop: Option<u32> = None;
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(40.0))
            .column(Column::auto().at_least(100.0))
            .column(Column::auto().at_least(180.0))
            .column(Column::remainder().at_least(160.0))
            .column(Column::auto().at_least(70.0))
            .header(22.0, |mut h| {
                for t in ["ID", "Type", "Bind", "Connected peers", ""] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|mut body| {
                for l in &listeners {
                    body.row(24.0, |mut row| {
                        row.col(|ui| { ui.monospace(l.id.to_string()); });
                        row.col(|ui| {
                            let k = match l.r#type { 2 => "named pipe", 1 => "udp", _ => "tcp" };
                            kit::badge(ui, k, Palette::purple());
                        });
                        row.col(|ui| { ui.monospace(&l.bind_address); });
                        row.col(|ui| {
                            if l.pivots.is_empty() { ui.colored_label(Palette::muted(), "none"); }
                            for p in &l.pivots { ui.label(egui::RichText::new(&p.remote_address).monospace().small()); }
                        });
                        row.col(|ui| {
                            if ui.small_button(egui::RichText::new("✕ Stop").color(Palette::red())).clicked() { stop = Some(l.id); }
                        });
                    });
                }
            });
        if let Some(id) = stop {
            self.confirm("Stop pivot listener", format!("Stop pivot listener {id}? Chained implants using it will lose their C2 path."),
                vec![Command::Op(Op::PivotStop { target: t, id })]);
        }
    }

    fn wireguard_section(&mut self, ui: &mut egui::Ui, target: Option<Target>) {
        use egui_extras::Column;
        ui.colored_label(Palette::muted(),
            "WireGuard SOCKS and port-forwards run inside the WG tunnel of a session on the wg transport. Connect your machine with an exported client config.");
        ui.horizontal(|ui| {
            if ui.button("⬇ Export WG client config…").on_hover_text("Generate a wg-quick config for an operator machine").clicked() {
                if let Some(p) = rfd::FileDialog::new().set_file_name("sliver-wg.conf").save_file() {
                    let host = self.configs.get(self.selected_cfg).map(|c| c.lhost.clone()).unwrap_or_default();
                    let port = self.jobs.iter().find(|j| j.name == "wg").map(|j| j.port).unwrap_or(53);
                    self.op(Op::WgClientConfig { save_to: p.display().to_string(), endpoint: format!("{host}:{port}") });
                }
            }
            if ui.button("≡ Start WG listener…").clicked() {
                self.listener_form.kind = 4;
                if self.listener_form.port == 8888 { self.listener_form.port = 53; }
                self.show_listeners = true;
            }
        });
        let Some(t) = target else { return };
        let is_wg = self.sessions.iter().find(|s| s.id == t.session_id).is_some_and(|s| s.transport == "wg");
        if !is_wg {
            ui.add_space(6.0);
            ui.colored_label(Palette::yellow(), "The selected session is not on the wg transport — pick a WireGuard session above.");
            return;
        }
        kit::section(ui, "New WireGuard tunnel");
        ui.horizontal(|ui| {
            ui.label("SOCKS5 port (in tunnel):");
            ui.add(egui::DragValue::new(&mut self.pivot_form.wg_socks_port).range(1..=65535));
            if ui.button("▶ Start SOCKS").clicked() { self.op(Op::WgSocksStart { target: t.clone(), port: self.pivot_form.wg_socks_port }); }
        });
        ui.horizontal(|ui| {
            ui.label("Port-forward: local port");
            ui.add(egui::DragValue::new(&mut self.pivot_form.wg_fwd_local).range(1..=65535));
            ui.label("→ remote");
            ui.add(egui::TextEdit::singleline(&mut self.pivot_form.wg_fwd_remote).desired_width(160.0));
            if ui.button("▶ Start forward").clicked() {
                self.op(Op::WgFwdStart { target: t.clone(), local_port: self.pivot_form.wg_fwd_local, remote: self.pivot_form.wg_fwd_remote.trim().to_string() });
            }
            if ui.button("⟳ List").clicked() { self.op(Op::WgList { target: t.clone() }); }
        });
        let (socks, fwds) = self.ext.wg.get(&t.key()).cloned().unwrap_or_default();
        kit::section(ui, "Active WireGuard tunnels");
        if socks.is_empty() && fwds.is_empty() {
            kit::empty(ui, "◍", "No WireGuard tunnels", "");
            return;
        }
        let mut stop: Option<(bool, i32)> = None;
        kit::table(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(40.0))
            .column(Column::auto().at_least(100.0))
            .column(Column::auto().at_least(180.0))
            .column(Column::remainder().at_least(160.0))
            .column(Column::auto().at_least(70.0))
            .header(22.0, |mut h| {
                for t in ["ID", "Type", "Local (in tunnel)", "Remote", ""] { h.col(|ui| kit::th(ui, t)); }
            })
            .body(|mut body| {
                for s in &socks {
                    body.row(24.0, |mut row| {
                        row.col(|ui| { ui.monospace(s.id.to_string()); });
                        row.col(|ui| { kit::badge(ui, "socks5", Palette::purple()); });
                        row.col(|ui| { ui.monospace(&s.local_addr); });
                        row.col(|ui| { ui.colored_label(Palette::muted(), "—"); });
                        row.col(|ui| { if ui.small_button(egui::RichText::new("✕").color(Palette::red())).clicked() { stop = Some((true, s.id)); } });
                    });
                }
                for f in &fwds {
                    body.row(24.0, |mut row| {
                        row.col(|ui| { ui.monospace(f.id.to_string()); });
                        row.col(|ui| { kit::badge(ui, "portfwd", Palette::purple()); });
                        row.col(|ui| { ui.monospace(&f.local_addr); });
                        row.col(|ui| { ui.monospace(&f.remote_addr); });
                        row.col(|ui| { if ui.small_button(egui::RichText::new("✕").color(Palette::red())).clicked() { stop = Some((false, f.id)); } });
                    });
                }
            });
        match stop {
            Some((true, id)) => self.op(Op::WgSocksStop { target: t, id }),
            Some((false, id)) => self.op(Op::WgFwdStop { target: t, id }),
            None => {}
        }
    }
}
