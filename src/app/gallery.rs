//! Screenshot gallery: every capture is saved to the data directory and
//! listed here per host with timestamps and operator notes; view with zoom,
//! add to loot, or delete.

use super::{kit, SliverApp};
use crate::client::Op;
use crate::settings::Shot;
use crate::theme::Palette;

impl SliverApp {
    /// Persist a capture to disk and record it in the gallery index.
    pub(super) fn save_shot(&mut self, target_key: &str, png: &[u8]) {
        let Some(dir) = crate::settings::data_dir().map(|d| d.join("screenshots")) else { return };
        if std::fs::create_dir_all(&dir).is_err() { return; }
        let (host, implant) = self.sessions.iter().find(|s| s.id == target_key).map(|s| (s.hostname.clone(), s.name.clone()))
            .or_else(|| self.beacons.iter().find(|b| b.id == target_key).map(|b| (b.hostname.clone(), b.name.clone())))
            .unwrap_or_else(|| ("unknown".into(), super::short(target_key).to_string()));
        let now = chrono::Local::now();
        let safe: String = host.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect();
        let path = dir.join(format!("{safe}_{}.png", now.format("%Y%m%d-%H%M%S")));
        if std::fs::write(&path, png).is_ok() {
            self.settings.shots.push(Shot { file: path.display().to_string(), host, implant, time: now.timestamp(), note: String::new() });
            self.settings_dirty = true;
        }
    }

    fn shot_texture(&mut self, ctx: &egui::Context, file: &str) -> Option<egui::TextureHandle> {
        if let Some(t) = self.ext.shot_tex.get(file) { return Some(t.clone()); }
        let bytes = std::fs::read(file).ok()?;
        let tex = super::decode_png(ctx, file, &bytes)?;
        self.ext.shot_tex.insert(file.to_string(), tex.clone());
        Some(tex)
    }

    pub(super) fn gallery_tab(&mut self, ui: &mut egui::Ui) {
        self.ext.shot_tex_retired.clear();
        if self.ext.shot_zoom <= 0.0 { self.ext.shot_zoom = 1.0; }
        let mut hosts: Vec<String> = self.settings.shots.iter().map(|s| s.host.clone()).collect();
        hosts.sort();
        hosts.dedup();
        kit::toolbar(ui, |ui| {
            ui.label("Host:");
            egui::ComboBox::from_id_salt("shot-host")
                .selected_text(if self.ext.shot_filter.is_empty() { "all hosts".to_string() } else { self.ext.shot_filter.clone() })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.ext.shot_filter, String::new(), "all hosts");
                    for h in &hosts { ui.selectable_value(&mut self.ext.shot_filter, h.clone(), h); }
                });
            ui.colored_label(Palette::muted(), format!("{} captures", self.settings.shots.len()));
            if let Some(d) = crate::settings::data_dir() {
                ui.colored_label(Palette::muted(), egui::RichText::new(d.join("screenshots").display().to_string()).small());
            }
        });
        if self.settings.shots.is_empty() {
            kit::empty(ui, "▣", "No screenshots yet", "Right-click a session → Screenshot; captures are kept here");
            return;
        }
        let filter = self.ext.shot_filter.clone();
        let idxs: Vec<usize> = (0..self.settings.shots.len()).rev()
            .filter(|i| filter.is_empty() || self.settings.shots[*i].host == filter)
            .collect();
        if self.ext.shot_sel.map_or(true, |s| s >= self.settings.shots.len()) {
            self.ext.shot_sel = idxs.first().copied();
        }
        let ctx = ui.ctx().clone();
        let mut pick: Option<usize> = None;
        let mut delete: Option<usize> = None;
        let mut loot: Option<usize> = None;
        let strip_w = 210.0;
        ui.horizontal_top(|ui| {
            // Thumbnail strip.
            ui.allocate_ui(egui::vec2(strip_w, ui.available_height()), |ui| {
                egui::ScrollArea::vertical().id_salt("shot-strip").auto_shrink([false, false]).show(ui, |ui| {
                    for &i in &idxs {
                        let s = self.settings.shots[i].clone();
                        let selected = self.ext.shot_sel == Some(i);
                        let frame = egui::Frame::none()
                            .fill(if selected { Palette::accent().linear_multiply(0.15) } else { Palette::panel_hi() })
                            .stroke(egui::Stroke::new(1.0_f32, if selected { Palette::accent() } else { Palette::border() }))
                            .rounding(6.0)
                            .inner_margin(4.0);
                        let r = frame.show(ui, |ui| ui.vertical(|ui| {
                            ui.set_width(strip_w - 18.0);
                            if let Some(tex) = self.shot_texture(&ctx, &s.file) {
                                let size = tex.size_vec2();
                                let scale = (strip_w - 26.0) / size.x;
                                ui.add(egui::Image::new(&tex).fit_to_exact_size(size * scale));
                            } else {
                                ui.colored_label(Palette::red(), "missing file");
                            }
                            ui.label(egui::RichText::new(&s.host).strong().small());
                            ui.colored_label(Palette::muted(), egui::RichText::new(super::fmt_time(s.time)).small());
                        })).response;
                        if ui.interact(r.rect, egui::Id::new(("shot", i)), egui::Sense::click()).clicked() { pick = Some(i); }
                        ui.add_space(4.0);
                    }
                });
            });
            ui.separator();
            // Viewer.
            ui.vertical(|ui| {
                let Some(i) = self.ext.shot_sel else { return };
                let s = self.settings.shots[i].clone();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&s.host).strong());
                    ui.colored_label(Palette::muted(), format!("{} · {}", s.implant, super::fmt_time(s.time)));
                    ui.separator();
                    ui.add(egui::Slider::new(&mut self.ext.shot_zoom, 0.1..=2.0).text("zoom").fixed_decimals(2));
                    if ui.small_button("fit").clicked() { self.ext.shot_zoom = 0.0; }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(egui::RichText::new("✕ Delete").color(Palette::red())).clicked() { delete = Some(i); }
                        if ui.small_button("⛁ Add to loot").clicked() { loot = Some(i); }
                    });
                });
                let note = &mut self.settings.shots[i].note;
                if ui.add(egui::TextEdit::singleline(note).hint_text("note for this capture…").desired_width(f32::INFINITY)).changed() {
                    self.settings_dirty = true;
                }
                if let Some(tex) = self.shot_texture(&ctx, &s.file) {
                    let size = tex.size_vec2();
                    let avail = ui.available_width();
                    if self.ext.shot_zoom <= 0.0 { self.ext.shot_zoom = (avail / size.x).min(1.0); }
                    let zoom = self.ext.shot_zoom;
                    egui::ScrollArea::both().id_salt("shot-view").auto_shrink([false, false]).show(ui, |ui| {
                        ui.add(egui::Image::new(&tex).fit_to_exact_size(size * zoom));
                    });
                }
            });
        });
        // Dev-only: delete the selected capture after N gallery frames (SLIVER_GUI_SHOTDEL=<n>).
        if let Some(n) = std::env::var("SLIVER_GUI_SHOTDEL").ok().and_then(|v| v.parse::<u32>().ok()) {
            static FRAMES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            if FRAMES.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == n { delete = self.ext.shot_sel; }
        }
        if let Some(i) = pick { self.ext.shot_sel = Some(i); }
        if let Some(i) = loot {
            let s = &self.settings.shots[i];
            if let Ok(data) = std::fs::read(&s.file) {
                let name = std::path::Path::new(&s.file).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "screenshot.png".into());
                self.op(Op::AddLoot { name, data, text: false });
            }
        }
        if let Some(i) = delete {
            let s = self.settings.shots.remove(i);
            let _ = std::fs::remove_file(&s.file);
            if let Some(tex) = self.ext.shot_tex.remove(&s.file) { self.ext.shot_tex_retired.push(tex); }
            self.ext.shot_sel = None;
            self.settings_dirty = true;
        }
    }
}
