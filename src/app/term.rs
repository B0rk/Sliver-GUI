//! Sliver Console tab: the official `sliver-client` running in a local PTY and
//! rendered by a small terminal emulator (vt100), with keystrokes passed
//! straight through, so every Sliver console command is available as-is.
//! The same terminal backs the Local Terminal tab. Each terminal also notes the
//! command lines the operator submits (for the terminal log), without touching
//! what is sent to the program.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use portable_pty::{Child, CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};

use super::{kit, SliverApp};
use crate::theme::Palette;

const FONT_SIZE: f32 = 13.0;
const SCROLLBACK: usize = 5000;

/// A program running in a local pseudo-terminal.
pub(super) struct LocalTerm {
    parser: Arc<Mutex<vt100::Parser>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    exited: Arc<AtomicBool>,
    size: (u16, u16),
    /// Lines scrolled back from the live screen.
    scroll: usize,
    scroll_acc: f32,
    pub exit: Option<String>,
    /// When an interrupt was sent while the program was busy (for "Force stop").
    pub interrupted_at: Option<std::time::Instant>,
    /// Command lines submitted since the owner last took them (unix time, line).
    submitted: Vec<(i64, String)>,
}

impl LocalTerm {
    pub(super) fn spawn(program: &str, ctx: &egui::Context) -> Result<Self, String> {
        let size = (30u16, 120u16);
        let pair = NativePtySystem::default()
            .openpty(PtySize { rows: size.0, cols: size.1, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| e.to_string())?;
        let mut cmd = CommandBuilder::new(program);
        cmd.env("TERM", "xterm-256color");
        if let Some(home) = dirs::home_dir() { cmd.cwd(home); }
        let child = pair.slave.spawn_command(cmd).map_err(|e| format!("{program}: {e}"))?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = Arc::new(Mutex::new(pair.master.take_writer().map_err(|e| e.to_string())?));
        let parser = Arc::new(Mutex::new(vt100::Parser::new(size.0, size.1, SCROLLBACK)));
        let exited = Arc::new(AtomicBool::new(false));
        {
            let (parser, writer, exited, ctx) = (parser.clone(), writer.clone(), exited.clone(), ctx.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 16384];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 { break; }
                    if let Ok(mut p) = parser.lock() {
                        // Readline asks where the cursor is and waits for the answer.
                        for (chunk, query) in split_queries(&buf[..n]) {
                            p.process(chunk);
                            let reply = match query {
                                Some(Query::Cursor) => { let (r, c) = p.screen().cursor_position(); format!("\x1b[{};{}R", r + 1, c + 1) }
                                Some(Query::Attributes) => "\x1b[?62;22c".into(),
                                None => continue,
                            };
                            if let Ok(mut w) = writer.lock() { let _ = w.write_all(reply.as_bytes()); let _ = w.flush(); }
                        }
                    }
                    ctx.request_repaint();
                }
                exited.store(true, Ordering::SeqCst);
                ctx.request_repaint();
            });
        }
        Ok(Self { parser, writer, master: pair.master, child, exited, size, scroll: 0, scroll_acc: 0.0, exit: None, interrupted_at: None, submitted: Vec::new() })
    }

    /// False once the program has exited (`exit` then says how).
    pub(super) fn alive(&mut self) -> bool {
        if self.exit.is_some() { return false; }
        let done = self.exited.load(Ordering::SeqCst) || matches!(self.child.try_wait(), Ok(Some(_)));
        if done {
            self.exit = Some(match self.child.try_wait() {
                Ok(Some(st)) if st.success() => "exited".into(),
                Ok(Some(st)) => format!("exited with code {}", st.exit_code()),
                _ => "closed".into(),
            });
        }
        !done
    }

    pub(super) fn write(&mut self, b: &[u8]) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(b);
            let _ = w.flush();
        }
    }

    fn resize(&mut self, rows: u16, cols: u16) {
        if (rows, cols) == self.size { return; }
        self.size = (rows, cols);
        let _ = self.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
        if let Ok(mut p) = self.parser.lock() { p.set_size(rows, cols); }
    }

    /// The visible screen as plain text.
    /// Ctrl-C to the program, and remember when, so the toolbar can offer a
    /// force stop: sliver-client can't cancel some commands while it waits on
    /// the server (a build, getsystem), and a signal doesn't help (it exits
    /// the client when idle).
    pub(super) fn interrupt(&mut self) {
        self.write(&[0x03]);
        self.interrupted_at = Some(std::time::Instant::now());
    }

    pub(super) fn contents(&self) -> String {
        self.parser.lock().map(|p| p.screen().contents()).unwrap_or_default()
    }

    /// Command lines the operator submitted since the last call, oldest first.
    pub(super) fn take_submitted(&mut self) -> Vec<(i64, String)> {
        std::mem::take(&mut self.submitted)
    }

    /// The line the cursor is on, joined across soft-wrapped rows: the prompt plus the
    /// command as the program shows it (after Tab completion or history recall). None
    /// in a full-screen program (vim, less, top), whose screen isn't a command line.
    fn cursor_line(&self) -> Option<String> {
        let mut p = self.parser.lock().ok()?;
        p.set_scrollback(0);
        let s = p.screen();
        if s.alternate_screen() { return None; }
        let (row, _) = s.cursor_position();
        let (_, cols) = s.size();
        let rows: Vec<String> = s.rows(0, cols).collect();
        let mut start = row;
        while start > 0 && s.row_wrapped(start - 1) { start -= 1; }
        Some((start..=row).filter_map(|r| rows.get(r as usize).cloned()).collect::<String>().trim_end().to_string())
    }

    /// Note a submitted line: what's on the cursor line plus `pending`, typed this frame
    /// and not yet echoed. Blank lines aren't noted.
    fn note_submit(&mut self, pending: &str) {
        let Some(mut line) = self.cursor_line() else { return };
        line.push_str(pending);
        if !line.trim().is_empty() {
            self.submitted.push((chrono::Local::now().timestamp(), line));
        }
    }

    /// Draw the screen into the remaining space and feed it the keyboard while focused.
    pub(super) fn ui(&mut self, ui: &mut egui::Ui) {
        let font = egui::FontId::monospace(FONT_SIZE);
        let (cw, rh) = ui.fonts(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let (rect, resp) = ui.allocate_exact_size(ui.available_size(), egui::Sense::click());
        let id = resp.id;
        let cols = ((rect.width() - 8.0) / cw).floor().clamp(20.0, 500.0) as u16;
        let rows = ((rect.height() - 8.0) / rh).floor().clamp(5.0, 300.0) as u16;
        self.resize(rows, cols);
        if resp.clicked() { resp.request_focus(); }
        let focused = resp.has_focus();
        if focused {
            // Tab, arrows and Escape belong to the program, not egui's focus cycling.
            ui.memory_mut(|m| m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true }));
            self.handle_input(ui);
        }
        if resp.hovered() {
            self.scroll_acc += ui.input(|i| i.raw_scroll_delta.y) / rh;
            let lines = self.scroll_acc.trunc();
            if lines != 0.0 {
                self.scroll_acc -= lines;
                self.scroll = (self.scroll as i64 + lines as i64).clamp(0, SCROLLBACK as i64) as usize;
            }
        }

        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, Palette::bg());
        let Ok(mut parser) = self.parser.lock() else { return };
        parser.set_scrollback(self.scroll);
        self.scroll = parser.screen().scrollback();
        let screen = parser.screen();
        let origin = rect.min + egui::vec2(4.0, 4.0);
        // Paint cell by cell on the exact `col * cw` grid. Laying a whole row out as one
        // galley lets egui's per-glyph pixel rounding accumulate, so the text drifts away
        // from the cursor box (drawn below on that same grid) the further right you go —
        // placing each glyph on the grid keeps text and cursor aligned.
        for row in 0..rows {
            let y = origin.y + row as f32 * rh;
            for col in 0..cols {
                let Some(cell) = screen.cell(row, col) else { continue };
                if cell.is_wide_continuation() { continue; }
                let x = origin.x + col as f32 * cw;
                let fmt = cell_format(cell, &font);
                let width = if cell.is_wide() { 2.0 } else { 1.0 };
                if fmt.background != egui::Color32::TRANSPARENT {
                    painter.rect_filled(egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(cw * width, rh)), 0.0, fmt.background);
                }
                let s = cell.contents();
                if s.is_empty() || s == " " { continue; }
                let mut job = egui::text::LayoutJob::default();
                job.append(&s, 0.0, egui::TextFormat { background: egui::Color32::TRANSPARENT, ..fmt });
                let galley = ui.fonts(|f| f.layout_job(job));
                painter.galley(egui::pos2(x, y), galley, fmt.color);
            }
        }
        if self.scroll == 0 && !screen.hide_cursor() {
            let (cr, cc) = screen.cursor_position();
            let r = egui::Rect::from_min_size(origin + egui::vec2(cc as f32 * cw, cr as f32 * rh), egui::vec2(cw, rh));
            if focused {
                painter.rect_filled(r, 0.0, Palette::accent().gamma_multiply(0.7));
            } else {
                painter.rect_stroke(r, 0.0, egui::Stroke::new(1.0_f32, Palette::muted()));
            }
        }
        if self.scroll > 0 {
            painter.text(rect.right_top() + egui::vec2(-8.0, 6.0), egui::Align2::RIGHT_TOP,
                format!("↑ {} lines back — scroll down or type to return", self.scroll), egui::FontId::proportional(11.0), Palette::yellow());
        }
    }

    fn handle_input(&mut self, ui: &egui::Ui) {
        let (app_cursor, bracketed) = self.parser.lock().map(|p| (p.screen().application_cursor(), p.screen().bracketed_paste())).unwrap_or((false, false));
        let events = ui.input(|i| i.events.clone());
        let mut out: Vec<u8> = Vec::new();
        // Printable text typed this frame, not yet on screen (for the command log only).
        let mut pending = String::new();
        for ev in events {
            match ev {
                egui::Event::Text(t) => { pending.push_str(&t); out.extend_from_slice(t.as_bytes()) }
                egui::Event::Paste(t) => {
                    // Each pasted line break submits a line.
                    let text = t.replace("\r\n", "\n").replace('\r', "\n");
                    let mut parts = text.split('\n').peekable();
                    let mut first = true;
                    while let Some(part) = parts.next() {
                        if parts.peek().is_none() { pending.push_str(part); break; }
                        if first { self.note_submit(&format!("{pending}{part}")); first = false; }
                        else if !part.trim().is_empty() { self.submitted.push((chrono::Local::now().timestamp(), part.to_string())); }
                        pending.clear();
                    }
                    if bracketed { out.extend_from_slice(b"\x1b[200~"); }
                    out.extend_from_slice(t.replace("\r\n", "\r").replace('\n', "\r").as_bytes());
                    if bracketed { out.extend_from_slice(b"\x1b[201~"); }
                }
                // egui turns Ctrl-C / Ctrl-X into clipboard events; a terminal wants the control bytes.
                egui::Event::Copy => { self.interrupt(); continue; }
                egui::Event::Cut => out.push(0x18),
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    if key == egui::Key::Enter && !modifiers.ctrl && !modifiers.alt {
                        self.note_submit(&pending);
                        pending.clear();
                    } else if key != egui::Key::Enter {
                        // Editing keys change the line in ways only the screen shows.
                        if matches!(key, egui::Key::Backspace | egui::Key::Tab | egui::Key::ArrowUp | egui::Key::ArrowDown
                            | egui::Key::ArrowLeft | egui::Key::ArrowRight | egui::Key::Home | egui::Key::End | egui::Key::Delete) || modifiers.ctrl {
                            pending.clear();
                        }
                    }
                    if let Some(b) = key_bytes(key, modifiers, app_cursor) { out.extend_from_slice(&b); }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            self.scroll = 0;
            self.write(&out);
        }
    }
}

impl Drop for LocalTerm {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[derive(Debug, PartialEq)]
enum Query { Cursor, Attributes }

/// Split terminal output at the queries a terminal must answer (cursor
/// position `ESC[6n`, device attributes `ESC[c` / `ESC[0c`): each chunk is
/// followed by the query that ended it, if any.
fn split_queries(data: &[u8]) -> Vec<(&[u8], Option<Query>)> {
    let mut out = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < data.len() {
        let rest = &data[i..];
        let q = if rest.starts_with(b"\x1b[6n") { Some((Query::Cursor, 4)) }
            else if rest.starts_with(b"\x1b[c") { Some((Query::Attributes, 3)) }
            else if rest.starts_with(b"\x1b[0c") { Some((Query::Attributes, 4)) }
            else { None };
        match q {
            Some((q, len)) => { out.push((&data[start..i], Some(q))); i += len; start = i; }
            None => i += 1,
        }
    }
    out.push((&data[start..], None));
    out
}

/// Bytes a terminal sends for a non-text key.
fn key_bytes(key: egui::Key, m: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    use egui::Key as K;
    let arrow = |c: u8| if app_cursor { vec![0x1b, b'O', c] } else { vec![0x1b, b'[', c] };
    Some(match key {
        K::Enter => b"\r".to_vec(),
        K::Backspace => vec![0x7f],
        K::Tab if m.shift => b"\x1b[Z".to_vec(),
        K::Tab => b"\t".to_vec(),
        K::Escape => vec![0x1b],
        K::ArrowUp => arrow(b'A'),
        K::ArrowDown => arrow(b'B'),
        K::ArrowRight => arrow(b'C'),
        K::ArrowLeft => arrow(b'D'),
        K::Home => b"\x1b[H".to_vec(),
        K::End => b"\x1b[F".to_vec(),
        K::Insert => b"\x1b[2~".to_vec(),
        K::Delete => b"\x1b[3~".to_vec(),
        K::PageUp => b"\x1b[5~".to_vec(),
        K::PageDown => b"\x1b[6~".to_vec(),
        _ if m.ctrl && !m.alt => {
            let name = key.name();
            let c = name.chars().next().filter(|c| name.len() == 1 && c.is_ascii_alphabetic())?;
            vec![(c.to_ascii_uppercase() as u8) & 0x1f]
        }
        _ => return None,
    })
}

fn cell_format(cell: &vt100::Cell, font: &egui::FontId) -> egui::TextFormat {
    let mut fg = color(cell.fgcolor(), cell.bold()).unwrap_or_else(Palette::output);
    let mut bg = color(cell.bgcolor(), false).unwrap_or(egui::Color32::TRANSPARENT);
    if cell.inverse() {
        let new_bg = if fg == egui::Color32::TRANSPARENT { Palette::output() } else { fg };
        fg = if bg == egui::Color32::TRANSPARENT { Palette::bg() } else { bg };
        bg = new_bg;
    }
    egui::TextFormat {
        font_id: font.clone(),
        color: fg,
        background: bg,
        italics: cell.italic(),
        underline: if cell.underline() { egui::Stroke::new(1.0_f32, fg) } else { egui::Stroke::NONE },
        ..Default::default()
    }
}

/// xterm colour → egui; `None` for the default colour.
fn color(c: vt100::Color, bold: bool) -> Option<egui::Color32> {
    const BASE: [(u8, u8, u8); 16] = [
        (0x1e, 0x1e, 0x1e), (0xe0, 0x5a, 0x5a), (0x5a, 0xc8, 0x6e), (0xd8, 0xb4, 0x4a),
        (0x4a, 0x8c, 0xe6), (0xb4, 0x6e, 0xdc), (0x46, 0xb4, 0xc8), (0xc8, 0xc8, 0xc8),
        (0x6e, 0x6e, 0x6e), (0xff, 0x78, 0x78), (0x78, 0xe6, 0x8c), (0xf0, 0xd2, 0x6e),
        (0x78, 0xaa, 0xff), (0xd2, 0x8c, 0xf5), (0x6e, 0xd7, 0xe6), (0xf5, 0xf5, 0xf5),
    ];
    match c {
        vt100::Color::Default => None,
        vt100::Color::Rgb(r, g, b) => Some(egui::Color32::from_rgb(r, g, b)),
        vt100::Color::Idx(i) => {
            let i = if bold && i < 8 { i + 8 } else { i };
            Some(match i {
                0..=15 => { let (r, g, b) = BASE[i as usize]; egui::Color32::from_rgb(r, g, b) }
                16..=231 => {
                    let v = i - 16;
                    let lvl = |x: u8| if x == 0 { 0 } else { 55 + x * 40 };
                    egui::Color32::from_rgb(lvl(v / 36), lvl((v / 6) % 6), lvl(v % 6))
                }
                _ => { let g = 8 + (i - 232) * 10; egui::Color32::from_gray(g) }
            })
        }
    }
}

/// `sliver-client` at the `configured` override (a binary or its directory) or on PATH.
fn find_client(configured: &str) -> Option<String> {
    crate::deps::resolve("sliver-client", configured)
}

impl SliverApp {
    pub(super) fn server_cli_tab(&mut self, ui: &mut egui::Ui) {
        let found = find_client(&self.settings.sliver_client_path);
        let running = self.ext.cli.as_mut().is_some_and(|t| t.alive());
        // Start on first view; after an exit the operator restarts it.
        if self.ext.cli.is_none() && !self.ext.cli_tried {
            self.ext.cli_tried = true;
            if let Some(p) = &found { self.start_cli(ui.ctx(), p.clone()); }
        }
        let mut restart = false;
        kit::toolbar(ui, |ui| {
            match (&self.ext.cli, running) {
                (Some(_), true) => { ui.colored_label(Palette::green(), "● sliver-client"); }
                (Some(t), false) => { ui.colored_label(Palette::red(), format!("● sliver-client {}", t.exit.as_deref().unwrap_or("exited"))); }
                (None, _) => { ui.colored_label(Palette::muted(), "● not running"); }
            }
            if ui.button(if running { "⟳ Restart" } else { "▶ Start" }).on_hover_text("Start a fresh sliver-client").clicked() { restart = true; }
            if ui.add_enabled(running, egui::Button::new("Ctrl-C"))
                .on_hover_text("Cancel the running command (also Ctrl-C in the terminal)").clicked() {
                if let Some(t) = self.ext.cli.as_mut() { t.interrupt(); }
            }
            // For a minute after Ctrl-C, offer to kill a client that didn't respond.
            if let Some(t) = self.ext.cli.as_mut().filter(|_| running) {
                match t.interrupted_at {
                    Some(at) if at.elapsed().as_secs() < 60 => {
                        if ui.button(egui::RichText::new("■ Force stop").color(Palette::red()))
                            .on_hover_text("Still stuck after Ctrl-C? Kill sliver-client and start a fresh one. \
                                Anything the server already started (a build, a task on an implant) carries on.").clicked() {
                            restart = true;
                        }
                        ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
                    }
                    Some(_) => t.interrupted_at = None,
                    None => {}
                }
            }
            if ui.add_enabled(self.ext.cli.is_some(), egui::Button::new("⧉ Copy screen")).clicked() {
                if let Some(t) = &self.ext.cli { ui.ctx().copy_text(t.contents()); }
            }
            ui.separator();
            ui.label("sliver-client");
            let r = ui.add(egui::TextEdit::singleline(&mut self.settings.sliver_client_path).desired_width(220.0)
                .hint_text(found.as_deref().unwrap_or("not on PATH: set its path")));
            if r.changed() { self.settings_dirty = true; }
            if ui.button("Browse…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.settings.sliver_client_path = p.display().to_string();
                    self.settings_dirty = true;
                }
            }
        });
        if restart {
            self.ext.cli = None;
            match find_client(&self.settings.sliver_client_path) {
                Some(p) => self.start_cli(ui.ctx(), p),
                None => self.ext.cli_err = "sliver-client not found: install it or set its path above.".into(),
            }
        }
        if !self.ext.cli_err.is_empty() && self.ext.cli.is_none() {
            ui.colored_label(Palette::red(), &self.ext.cli_err);
        }
        // Dev-only: type a command once the prompt is up (SLIVER_GUI_CLI_TYPE=<line>).
        static TYPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if let (Ok(line), Some(t)) = (std::env::var("SLIVER_GUI_CLI_TYPE"), self.ext.cli.as_mut()) {
            static SEEN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            let prompt = t.contents().contains("sliver") && t.contents().trim_end().ends_with('>');
            // Readline flushes input typed before it switches to raw mode; give it a moment.
            let ready = prompt && SEEN.get_or_init(std::time::Instant::now).elapsed().as_millis() > 1500;
            if !TYPED.load(Ordering::SeqCst) && ready {
                TYPED.store(true, Ordering::SeqCst);
                t.write(format!("{line}\r").as_bytes());
                println!("[gui] cli: typed '{line}'");
            }
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        }
        // Dev-only: press Ctrl-C N seconds after the typed command, then Force
        // stop 4 s later (SLIVER_GUI_CLI_INTERRUPT=<secs>).
        if let (Ok(secs), true) = (std::env::var("SLIVER_GUI_CLI_INTERRUPT"), TYPED.load(Ordering::SeqCst)) {
            static AT: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            static STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
            let (secs, el) = (secs.parse::<u64>().unwrap_or(5), AT.get_or_init(std::time::Instant::now).elapsed().as_secs());
            let st = STATE.load(Ordering::SeqCst);
            if st == 0 && el >= secs {
                if let Some(t) = self.ext.cli.as_mut() { t.interrupt(); }
                println!("[gui] cli: Ctrl-C sent");
                STATE.store(1, Ordering::SeqCst);
            } else if st == 1 && el >= secs + 4 {
                let screen = self.ext.cli.as_ref().map(|t| t.contents()).unwrap_or_default();
                println!("[gui] cli: 4s after Ctrl-C, last line: {:?}", screen.trim_end().lines().last().unwrap_or(""));
                let old = self.ext.cli.take();
                drop(old);
                if let Some(p) = find_client(&self.settings.sliver_client_path) { self.start_cli(ui.ctx(), p); }
                println!("[gui] cli: force-stopped; fresh client running={}", self.ext.cli.as_mut().is_some_and(|t| t.alive()));
                STATE.store(2, Ordering::SeqCst);
            }
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        }
        let submitted = self.ext.cli.as_mut().map(|t| t.take_submitted()).unwrap_or_default();
        self.log_terminal("sliver-console", submitted);
        match self.ext.cli.as_mut() {
            Some(t) => t.ui(ui),
            None => {
                kit::empty(ui, "❯", "Sliver's own command line",
                    "Runs the official sliver-client here, with the operator configs in ~/.sliver-client/configs. \
                     Install sliver-client (the same version as the server) or set its path above, then press Start.");
            }
        }
    }

    fn start_cli(&mut self, ctx: &egui::Context, program: String) {
        match LocalTerm::spawn(&program, ctx) {
            Ok(t) => { self.ext.cli = Some(t); self.ext.cli_err.clear(); }
            Err(e) => self.ext.cli_err = format!("Couldn't start {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_queries_are_split_out() {
        let parts = split_queries(b"ab\x1b[6ncd\x1b[cef");
        assert_eq!(parts, vec![(&b"ab"[..], Some(Query::Cursor)), (&b"cd"[..], Some(Query::Attributes)), (&b"ef"[..], None)]);
        assert_eq!(split_queries(b"plain"), vec![(&b"plain"[..], None)]);
        assert_eq!(key_bytes(egui::Key::C, egui::Modifiers::CTRL, false), Some(vec![3]));
        assert_eq!(key_bytes(egui::Key::ArrowUp, egui::Modifiers::NONE, true), Some(b"\x1bOA".to_vec()));
    }
}
