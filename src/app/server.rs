//! Server tab: what the Sliver server itself reports — the operator CA and
//! issued certificates, the compiler's supported targets and cross-compilers,
//! registered external builders, and the AI assistant's providers and saved
//! conversations (read-only, with delete).

use super::{fmt_time, kit, SliverApp};
use crate::client::{Command, Op};
use crate::proto::clientpb;
use crate::theme::Palette;

/// Display name for an `OutputFormat` value.
pub(super) fn format_name(v: i32) -> &'static str {
    match clientpb::OutputFormat::try_from(v) {
        Ok(clientpb::OutputFormat::Executable) => "exe",
        Ok(clientpb::OutputFormat::SharedLib) => "shared lib",
        Ok(clientpb::OutputFormat::Shellcode) => "shellcode",
        Ok(clientpb::OutputFormat::Service) => "service",
        Ok(clientpb::OutputFormat::ThirdParty) => "third-party",
        Ok(clientpb::OutputFormat::GoArchive) => "Go archive",
        Err(_) => "other",
    }
}

/// `os/arch → formats` rows from a target list, sorted.
fn target_rows(targets: &[clientpb::CompilerTarget]) -> Vec<(String, String)> {
    let mut map: std::collections::BTreeMap<String, Vec<&'static str>> = Default::default();
    for t in targets {
        let f = map.entry(format!("{}/{}", t.goos, t.goarch)).or_default();
        let name = format_name(t.format);
        if !f.contains(&name) { f.push(name); }
    }
    map.into_iter().map(|(k, v)| (k, v.join(", "))).collect()
}

/// AI timestamps may be seconds or milliseconds.
fn ai_time(t: i64) -> String {
    fmt_time(if t > 100_000_000_000 { t / 1000 } else { t })
}

impl SliverApp {
    pub(super) fn server_tab(&mut self, ui: &mut egui::Ui) {
        let mut refresh = false;
        kit::toolbar(ui, |ui| {
            if ui.button("⟳ Refresh").clicked() { refresh = true; }
            if self.ext.server_loading { ui.spinner(); }
            ui.separator();
            ui.colored_label(Palette::muted(), format!("Sliver server {}", if self.version.is_empty() { "—" } else { &self.version }));
            if let Some(c) = self.ext.server.as_ref().and_then(|s| s.compiler.as_ref()) {
                ui.colored_label(Palette::muted(), format!("· host {}/{}", c.goos, c.goarch));
            }
        });
        if refresh {
            self.ext.server_loading = true;
            self.op(Op::RefreshServerInfo);
            self.op(Op::AiConversations);
        }
        let Some(info) = self.ext.server.clone() else {
            if self.ext.server_loading {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| { ui.spinner(); ui.colored_label(Palette::muted(), "asking the server…"); });
            } else {
                kit::empty(ui, "🖧", "No server details yet", "Press Refresh");
            }
            return;
        };

        let mut ai_open: Option<String> = None;
        let mut ai_delete: Option<(String, String)> = None;
        let mut ai_close = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for e in &info.errors {
                ui.colored_label(Palette::yellow(), format!("⚠ {e}"));
            }

            // ---- compiler ----
            kit::section(ui, "Compile targets");
            match &info.compiler {
                None => { ui.colored_label(Palette::muted(), "not reported"); }
                Some(c) => {
                    ui.colored_label(Palette::muted(), "What this server can build. The generator warns when a selection is outside this list.");
                    egui::Grid::new("srv-targets").striped(true).num_columns(2).spacing([24.0, 4.0]).show(ui, |ui| {
                        kit::th(ui, "OS / arch"); kit::th(ui, "Formats"); ui.end_row();
                        for (k, v) in target_rows(&c.targets) {
                            ui.monospace(k);
                            ui.label(v);
                            ui.end_row();
                        }
                    });
                    if !c.unsupported_targets.is_empty() {
                        ui.add_space(4.0);
                        let rows = target_rows(&c.unsupported_targets);
                        let list: Vec<String> = rows.iter().map(|(k, v)| format!("{k} ({v})")).collect();
                        ui.colored_label(Palette::muted(), format!("{} more OS/arch pairs need a cross-compiler (hover for the list)", rows.len()))
                            .on_hover_text(list.join("\n"));
                    }
                    if !c.cross_compilers.is_empty() {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Cross-compilers").strong());
                        egui::Grid::new("srv-cc").striped(true).num_columns(3).spacing([24.0, 4.0]).show(ui, |ui| {
                            kit::th(ui, "Target"); kit::th(ui, "CC"); kit::th(ui, "CXX"); ui.end_row();
                            for x in &c.cross_compilers {
                                ui.monospace(format!("{}/{}", x.target_goos, x.target_goarch));
                                ui.monospace(&x.cc_path);
                                ui.monospace(&x.cxx_path);
                                ui.end_row();
                            }
                        });
                    }
                }
            }

            // ---- external builders ----
            kit::section(ui, &format!("External builders ({})", info.builders.len()));
            if info.builders.is_empty() {
                ui.colored_label(Palette::muted(), "none registered — builders connect with `sliver-server builder`");
            } else {
                egui::Grid::new("srv-builders").striped(true).num_columns(5).spacing([24.0, 4.0]).show(ui, |ui| {
                    for t in ["Name", "Operator", "Host", "Targets", "Templates"] { kit::th(ui, t); }
                    ui.end_row();
                    for b in &info.builders {
                        ui.label(egui::RichText::new(&b.name).strong());
                        ui.label(&b.operator_name);
                        ui.monospace(format!("{}/{}", b.goos, b.goarch));
                        let targets: Vec<String> = target_rows(&b.targets).into_iter().map(|(k, _)| k).collect();
                        ui.label(targets.join(", "));
                        ui.colored_label(Palette::muted(), b.templates.join(", "));
                        ui.end_row();
                    }
                });
            }

            // ---- certificates ----
            kit::section(ui, "Certificate authorities");
            cert_grid(ui, "srv-ca", info.ca.iter().map(|c| [&c.cn, &c.r#type, &c.key_algorithm, &c.validity_start, &c.validity_expiry]).collect());
            kit::section(ui, &format!("Certificates ({})", info.certs.len()));
            ui.horizontal(|ui| { kit::search(ui, &mut self.ext.cert_filter, "filter CN / type", 220.0); });
            let needle = self.ext.cert_filter.to_lowercase();
            cert_grid(ui, "srv-certs", info.certs.iter()
                .filter(|c| needle.is_empty() || c.cn.to_lowercase().contains(&needle) || c.r#type.to_lowercase().contains(&needle))
                .map(|c| [&c.cn, &c.r#type, &c.key_algorithm, &c.validity_start, &c.validity_expiry]).collect());

            // ---- AI assistant ----
            kit::section(ui, "AI assistant");
            if info.ai_providers.is_empty() {
                ui.colored_label(Palette::muted(), "no providers reported");
            } else {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Providers:");
                    for p in &info.ai_providers {
                        if p.configured { ui.colored_label(Palette::green(), format!("{} ✓", p.name)); }
                        else { ui.colored_label(Palette::muted(), format!("{} (not configured)", p.name)); }
                    }
                });
            }
            ui.add_space(4.0);
            if self.ext.ai_convs.is_empty() {
                ui.colored_label(Palette::muted(), "no saved conversations");
            } else {
                egui::Grid::new("srv-ai").striped(true).num_columns(5).spacing([20.0, 4.0]).show(ui, |ui| {
                    for t in ["Title", "Operator", "Model", "Updated", ""] { kit::th(ui, t); }
                    ui.end_row();
                    for c in &self.ext.ai_convs {
                        let title = if c.title.is_empty() { "(untitled)" } else { &c.title };
                        ui.label(egui::RichText::new(title).strong()).on_hover_text(&c.summary);
                        ui.label(&c.operator_name);
                        ui.colored_label(Palette::muted(), format!("{} {}", c.provider, c.model).trim().to_string());
                        ui.colored_label(Palette::muted(), ai_time(c.updated_at));
                        ui.horizontal(|ui| {
                            if ui.small_button("👁 View").clicked() { ai_open = Some(c.id.clone()); }
                            if ui.small_button(egui::RichText::new("✕").color(Palette::red())).on_hover_text("Delete").clicked() {
                                ai_delete = Some((c.id.clone(), title.to_string()));
                            }
                        });
                        ui.end_row();
                    }
                });
            }
            if let Some(conv) = &self.ext.ai_sel {
                ui.add_space(6.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(if conv.title.is_empty() { "(untitled)" } else { &conv.title }).strong());
                        ui.colored_label(Palette::muted(), format!("{} messages", conv.messages.len()));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("✕ Close").clicked() { ai_close = true; }
                        });
                    });
                    for m in &conv.messages {
                        let body = if !m.content.is_empty() { m.content.clone() }
                            else if !m.tool_name.is_empty() { format!("[tool {}] {}", m.tool_name, m.tool_result) }
                            else { m.error_text.clone() };
                        if body.trim().is_empty() { continue; }
                        let color = match m.role.as_str() { "user" => Palette::accent(), "assistant" => Palette::green(), _ => Palette::muted() };
                        ui.colored_label(color, egui::RichText::new(&m.role).small().strong());
                        ui.add(egui::Label::new(body).wrap());
                        ui.add_space(2.0);
                    }
                });
            }
        });
        if let Some(id) = ai_open { self.op(Op::AiConversation { id }); }
        if ai_close { self.ext.ai_sel = None; }
        if let Some((id, title)) = ai_delete {
            if self.ext.ai_sel.as_ref().is_some_and(|c| c.id == id) { self.ext.ai_sel = None; }
            self.confirm("Delete AI conversation", format!("Delete the saved conversation \"{title}\" from the server?"),
                vec![Command::Op(Op::AiDelete { id })]);
        }
    }
}

/// CN / type / key / valid-from / expires rows.
fn cert_grid(ui: &mut egui::Ui, id: &str, rows: Vec<[&String; 5]>) {
    if rows.is_empty() {
        ui.colored_label(Palette::muted(), "none");
        return;
    }
    egui::Grid::new(id).striped(true).num_columns(5).spacing([20.0, 4.0]).show(ui, |ui| {
        for t in ["Common name", "Type", "Key", "Valid from", "Expires"] { kit::th(ui, t); }
        ui.end_row();
        for [cn, ty, key, from, to] in rows {
            ui.label(egui::RichText::new(cn.as_str()).strong());
            ui.label(ty.as_str());
            ui.colored_label(Palette::muted(), key.as_str());
            ui.colored_label(Palette::muted(), from.as_str());
            ui.colored_label(Palette::muted(), to.as_str());
            ui.end_row();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_targets_group_by_os_arch() {
        let t = |os: &str, arch: &str, f: clientpb::OutputFormat| clientpb::CompilerTarget { goos: os.into(), goarch: arch.into(), format: f as i32 };
        let rows = target_rows(&[
            t("windows", "amd64", clientpb::OutputFormat::Executable),
            t("linux", "amd64", clientpb::OutputFormat::Executable),
            t("windows", "amd64", clientpb::OutputFormat::Shellcode),
            t("windows", "amd64", clientpb::OutputFormat::Executable),
        ]);
        assert_eq!(rows, vec![
            ("linux/amd64".to_string(), "exe".to_string()),
            ("windows/amd64".to_string(), "exe, shellcode".to_string()),
        ]);
        assert_eq!(ai_time(0), "—");
    }
}
