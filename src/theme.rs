//! Operator themes: a dark default and a light variant, switchable at runtime.

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use egui::{Color32, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals};

/// Whether the light theme is active (read by every [`Palette`] accessor).
static LIGHT: AtomicBool = AtomicBool::new(false);

pub fn is_light() -> bool {
    LIGHT.load(Relaxed)
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

/// (dark, light) variants of each theme colour.
type Pair = (Color32, Color32);
const BG: Pair = (rgb(0x0f, 0x11, 0x15), rgb(0xe9, 0xed, 0xf2));
const PANEL: Pair = (rgb(0x16, 0x1a, 0x20), rgb(0xf7, 0xf8, 0xfa));
const PANEL_HI: Pair = (rgb(0x1f, 0x24, 0x2c), rgb(0xff, 0xff, 0xff));
const BORDER: Pair = (rgb(0x2b, 0x31, 0x3b), rgb(0xd0, 0xd6, 0xde));
const TEXT: Pair = (rgb(0xdf, 0xe4, 0xea), rgb(0x1c, 0x23, 0x2e));
const MUTED: Pair = (rgb(0x8b, 0x95, 0xa3), rgb(0x5c, 0x67, 0x75));
// Light-theme accent / status tones are dark enough for WCAG AA text contrast
// (≥ 4.5:1) on every light surface; the dark-theme ones already clear it.
const ACCENT: Pair = (rgb(0x4e, 0xa1, 0xff), rgb(0x1b, 0x64, 0xc2));
const GREEN: Pair = (rgb(0x4f, 0xd1, 0x8b), rgb(0x13, 0x7a, 0x3a));
const YELLOW: Pair = (rgb(0xf0, 0xc3, 0x5a), rgb(0x8f, 0x5e, 0x00));
const RED: Pair = (rgb(0xef, 0x6b, 0x6b), rgb(0xc4, 0x37, 0x37));
const PURPLE: Pair = (rgb(0xb4, 0x8c, 0xff), rgb(0x76, 0x4b, 0xd2));

/// Theme colours. Each accessor returns the dark or light variant depending
/// on the active theme, so UI code reads `Palette::text()` everywhere.
pub struct Palette;
impl Palette {
    fn pick((dark, light): Pair) -> Color32 {
        if is_light() { light } else { dark }
    }
    pub fn bg() -> Color32 { Self::pick(BG) }
    pub fn panel() -> Color32 { Self::pick(PANEL) }
    pub fn panel_hi() -> Color32 { Self::pick(PANEL_HI) }
    pub fn border() -> Color32 { Self::pick(BORDER) }
    pub fn text() -> Color32 { Self::pick(TEXT) }
    pub fn muted() -> Color32 { Self::pick(MUTED) }
    pub fn accent() -> Color32 { Self::pick(ACCENT) }
    pub fn green() -> Color32 { Self::pick(GREEN) }
    pub fn yellow() -> Color32 { Self::pick(YELLOW) }
    pub fn red() -> Color32 { Self::pick(RED) }
    pub fn purple() -> Color32 { Self::pick(PURPLE) }

    /// Re-resolve a colour captured under either theme to the active theme.
    /// Console lines keep the colour they were printed with, so without this
    /// dark-theme text stays light grey after switching to the light theme.
    pub fn retheme(c: Color32) -> Color32 {
        [TEXT, MUTED, ACCENT, GREEN, YELLOW, RED, PURPLE]
            .into_iter()
            .find(|(d, l)| c == *d || c == *l)
            .map_or(c, Self::pick)
    }

    /// Colour for plain command output: the text colour in the dark theme,
    /// the timestamp grey in the light theme (easier on a white background).
    pub fn output() -> Color32 {
        if is_light() { Self::muted() } else { Self::text() }
    }
}

/// Append system fallback fonts with good symbol/arrow coverage so our UI
/// glyphs (●, ▸, arrows, etc.) render instead of showing as tofu boxes.
pub fn install_fonts(ctx: &egui::Context) {
    let candidates = [
        ("dejavu", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        ("dejavu", "/usr/share/fonts/dejavu/DejaVuSans.ttf"),
        ("symbols2", "/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf"),
        ("symbols", "/usr/share/fonts/truetype/noto/NotoSansSymbols-Regular.ttf"),
        // Windows / macOS equivalents (first hit per name wins).
        ("symbols2", r"C:\Windows\Fonts\seguisym.ttf"),
        ("symbols2", "/System/Library/Fonts/Apple Symbols.ttf"),
        ("symbols", "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
    ];
    let mut fonts = egui::FontDefinitions::default();
    let mut added = Vec::new();
    for (name, path) in candidates {
        if added.contains(&name) {
            continue;
        }
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(name.to_string(), egui::FontData::from_owned(bytes));
            added.push(name);
        }
    }
    if added.is_empty() {
        return;
    }
    for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        if let Some(list) = fonts.families.get_mut(&fam) {
            for name in &added {
                list.push(name.to_string());
            }
        }
    }
    ctx.set_fonts(fonts);
}

/// One-time setup: fonts plus the initial theme.
pub fn init(ctx: &egui::Context, light: bool) {
    install_fonts(ctx);
    apply(ctx, light);
}

/// Apply (or re-apply) the dark or light theme.
pub fn apply(ctx: &egui::Context, light: bool) {
    LIGHT.store(light, Relaxed);
    let mut style = (*ctx.style()).clone();

    style.text_styles = [
        (TextStyle::Heading, FontId::new(18.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
    ]
    .into();

    let mut v = if light { Visuals::light() } else { Visuals::dark() };
    v.override_text_color = Some(Palette::text());
    v.panel_fill = Palette::panel();
    v.window_fill = Palette::panel();
    v.extreme_bg_color = Palette::bg();
    v.faint_bg_color = if light { Palette::bg() } else { Palette::panel_hi() };
    v.code_bg_color = Palette::bg();
    v.window_stroke = Stroke::new(1.0_f32, Palette::border());
    v.window_rounding = Rounding::same(8.0);
    v.menu_rounding = Rounding::same(6.0);
    v.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 6.0),
        blur: 18.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if light { 40 } else { 110 }),
    };
    v.popup_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 3.0),
        blur: 10.0,
        spread: 0.0,
        color: Color32::from_black_alpha(if light { 30 } else { 90 }),
    };
    v.selection.bg_fill = Palette::accent().linear_multiply(if light { 0.16 } else { 0.22 });
    v.selection.stroke = Stroke::new(1.0_f32, Palette::accent());
    v.hyperlink_color = Palette::accent();
    v.striped = true;

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = Palette::panel();
    w.noninteractive.fg_stroke = Stroke::new(1.0_f32, Palette::muted());
    w.noninteractive.bg_stroke = Stroke::new(1.0_f32, Palette::border());
    w.noninteractive.rounding = Rounding::same(5.0);
    w.inactive.bg_fill = Palette::panel_hi();
    w.inactive.weak_bg_fill = Palette::panel_hi();
    w.inactive.bg_stroke = Stroke::new(1.0_f32, Palette::border());
    w.inactive.fg_stroke = Stroke::new(1.0_f32, Palette::text());
    w.inactive.rounding = Rounding::same(5.0);
    // Hover is one step above the raised surface, still ≥ 4.5:1 for muted/red text.
    let hover_fill = if light { Palette::bg() } else { rgb(0x26, 0x2c, 0x35) };
    w.hovered.bg_fill = hover_fill;
    w.hovered.weak_bg_fill = hover_fill;
    w.hovered.bg_stroke = Stroke::new(1.0_f32, Palette::accent().linear_multiply(0.6));
    w.hovered.fg_stroke = Stroke::new(1.0_f32, Palette::text());
    w.hovered.rounding = Rounding::same(5.0);
    // No grow-on-hover: it makes dense tables and toolbars jitter.
    w.hovered.expansion = 0.0;
    w.active.expansion = 0.0;
    w.active.bg_fill = Palette::accent().linear_multiply(0.5);
    w.active.weak_bg_fill = Palette::accent().linear_multiply(0.5);
    w.active.fg_stroke = Stroke::new(1.0_f32, if light { Palette::text() } else { Color32::WHITE });
    w.active.rounding = Rounding::same(5.0);
    w.open.bg_fill = Palette::panel_hi();
    w.open.weak_bg_fill = Palette::panel_hi();
    w.open.rounding = Rounding::same(5.0);

    style.visuals = v;
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(12.0);
    style.spacing.menu_margin = egui::Margin::same(6.0);
    // 24 px minimum target height (WCAG 2.2 target size).
    style.spacing.interact_size.y = 24.0;
    style.spacing.tooltip_width = 380.0;
    // Tooltips a little snappier than egui's 0.5 s, still only once the pointer rests.
    style.interaction.tooltip_delay = 0.3;
    style.interaction.show_tooltips_only_when_still = true;

    ctx.set_style(style);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retheme_follows_active_theme() {
        let dark_text = TEXT.0;
        LIGHT.store(true, Relaxed);
        assert_eq!(Palette::retheme(dark_text), TEXT.1, "dark text re-resolves to light text");
        assert_eq!(Palette::retheme(RED.0), RED.1);
        assert_eq!(Palette::output(), MUTED.1, "light-theme output is the timestamp grey");
        let other = Color32::from_rgb(1, 2, 3);
        assert_eq!(Palette::retheme(other), other, "non-palette colours pass through");
        LIGHT.store(false, Relaxed);
        assert_eq!(Palette::retheme(TEXT.1), TEXT.0);
        assert_eq!(Palette::output(), TEXT.0);
    }
}
