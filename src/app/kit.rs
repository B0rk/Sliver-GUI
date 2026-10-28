//! Small shared UI building blocks so every tab looks consistent: tab
//! toolbars, coloured tags, section headers, empty states and table headers.

use crate::theme::Palette;

/// A full-width toolbar strip at the top of a tab.
pub fn toolbar<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let r = egui::Frame::none()
        .fill(Palette::panel_hi())
        .rounding(6.0)
        .stroke(egui::Stroke::new(1.0_f32, Palette::border()))
        .inner_margin(egui::Margin::symmetric(8.0, 5.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(add).inner
        })
        .inner;
    ui.add_space(4.0);
    r
}

/// A short coloured tag, e.g. a transport or hash type. Plain text, no fill.
pub fn badge(ui: &mut egui::Ui, text: impl Into<String>, color: egui::Color32) -> egui::Response {
    ui.label(egui::RichText::new(text.into()).color(color))
}

/// A table whose rows take clicks anywhere. Labels are selectable by default,
/// so without this the cell text swallows clicks and only the gaps between
/// cells reach the row.
pub fn table(ui: &mut egui::Ui) -> egui_extras::TableBuilder<'_> {
    ui.style_mut().interaction.selectable_labels = false;
    egui_extras::TableBuilder::new(ui)
}

/// A section header with a subtle rule underneath.
pub fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(4.0);
    ui.label(egui::RichText::new(title).strong().color(Palette::text()));
    let r = ui.available_rect_before_wrap();
    ui.painter().hline(r.x_range(), r.top(), egui::Stroke::new(1.0_f32, Palette::border()));
    ui.add_space(4.0);
}

/// A centred empty-state message with a large glyph and a hint line.
pub fn empty(ui: &mut egui::Ui, glyph: &str, title: &str, hint: &str) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new(glyph).size(30.0).color(Palette::border()));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(title).color(Palette::muted()).strong());
        if !hint.is_empty() {
            ui.label(egui::RichText::new(hint).small().color(Palette::muted()));
        }
    });
}

/// Table header cell text.
pub fn th(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text.to_uppercase()).small().strong().color(Palette::muted()));
}

/// A search box with a clear button; returns true when the text changed.
pub fn search(ui: &mut egui::Ui, value: &mut String, hint: &str, width: f32) -> bool {
    let r = ui.add(egui::TextEdit::singleline(value).hint_text(format!("⌕ {hint}")).desired_width(width));
    let mut changed = r.changed();
    if !value.is_empty() && ui.small_button("✕").on_hover_text("Clear").clicked() {
        value.clear();
        changed = true;
    }
    changed
}

/// A red-tinted button for destructive actions.
pub fn danger(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add(egui::Button::new(egui::RichText::new(text).color(Palette::red()))).clicked()
}

/// The OS and architecture as plain text, the OS coloured per platform.
pub fn os_badge(ui: &mut egui::Ui, os: &str, arch: &str) {
    let color = match os {
        "windows" => Palette::accent(),
        "linux" => Palette::yellow(),
        "darwin" => Palette::purple(),
        _ => Palette::muted(),
    };
    badge(ui, if os.is_empty() { "?" } else { os }, color);
    ui.colored_label(Palette::muted(), egui::RichText::new(arch).small());
}

/// Render binary or text bytes for a preview pane: UTF-8 text if it looks
/// like text, otherwise a hex dump of the first few KB.
pub fn preview_text(data: &[u8]) -> (bool, String) {
    let sample = &data[..data.len().min(8192)];
    let printable = sample.iter().filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace() || **b >= 0x80).count();
    if !sample.is_empty() && printable * 100 / sample.len() >= 95 && std::str::from_utf8(sample).is_ok() {
        let text = String::from_utf8_lossy(&data[..data.len().min(256 * 1024)]).into_owned();
        return (true, text);
    }
    let mut out = String::new();
    for (i, chunk) in data[..data.len().min(4096)].chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{b:02x} ")).collect();
        let ascii: String = chunk.iter().map(|b| if b.is_ascii_graphic() { *b as char } else { '.' }).collect();
        out.push_str(&format!("{:08x}  {hex:<48} {ascii}\n", i * 16));
    }
    if data.len() > 4096 {
        out.push_str(&format!("… {} bytes total\n", data.len()));
    }
    (false, out)
}

#[cfg(test)]
mod tests {
    use super::{preview_text, table};

    /// Click on a cell's text (not the gap between cells) and report whether
    /// the row registered it, across a press frame and a release frame.
    fn row_click_on_text(selectable_off: bool) -> bool {
        let ctx = egui::Context::default();
        // One frame; returns the label's rect and whether the row was clicked.
        let frame = |ctx: &egui::Context, events: Vec<egui::Event>| {
            let (mut text_rect, mut clicked) = (egui::Rect::NOTHING, false);
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0))),
                events,
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let t = if selectable_off { table(ui) } else { egui_extras::TableBuilder::new(ui) };
                    t.sense(egui::Sense::click())
                        .column(egui_extras::Column::exact(300.0))
                        .body(|mut body| {
                            body.row(26.0, |mut row| {
                                row.col(|ui| { text_rect = ui.label("workstation-01 session").rect; });
                                if row.response().clicked() { clicked = true; }
                            });
                        });
                });
            });
            (text_rect, clicked)
        };
        let p = frame(&ctx, vec![]).0.center();
        let btn = |pressed| egui::Event::PointerButton { pos: p, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        let events = [vec![egui::Event::PointerMoved(p)], vec![btn(true)], vec![btn(false)], vec![]];
        events.into_iter().fold(false, |any, ev| frame(&ctx, ev).1 || any)
    }

    #[test]
    fn table_rows_take_clicks_on_cell_text() {
        assert!(!row_click_on_text(false), "baseline: selectable label text swallows the row click");
        assert!(row_click_on_text(true), "kit::table rows must take clicks on cell text");
    }

    #[test]
    fn preview_detects_text_and_binary() {
        let (is_text, body) = preview_text(b"hello\nworld\n");
        assert!(is_text);
        assert_eq!(body, "hello\nworld\n");
        let (is_text, body) = preview_text(&[0u8, 1, 2, 3, 0xff, 0x10, 0x41]);
        assert!(!is_text);
        assert!(body.starts_with("00000000  00 01 02 03 ff 10 41"));
    }
}
