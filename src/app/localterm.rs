//! Local Terminal tab: an interactive shell on the machine running the GUI (zsh, bash,
//! fish, PowerShell, cmd …), in the same PTY + vt100 terminal as the Sliver Console.
//! The shell is the operator's choice in the toolbar; by default it's the login shell
//! (`$SHELL`) on Linux/macOS and PowerShell on Windows.

use std::sync::atomic::{AtomicBool, Ordering};

use super::term::LocalTerm;
use super::{kit, SliverApp};
use crate::theme::Palette;

/// Shells worth offering on this host, most preferred first.
pub(super) fn available_shells() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |p: String| if !p.is_empty() && !out.contains(&p) { out.push(p) };
    if cfg!(windows) {
        for exe in ["pwsh", "powershell", "cmd"] {
            if let Some(p) = crate::deps::resolve(exe, "") { add(p); }
        }
        if let Ok(c) = std::env::var("COMSPEC") { add(c); }
    } else {
        if let Ok(s) = std::env::var("SHELL") { if std::path::Path::new(&s).exists() { add(s); } }
        // /etc/shells lists the login shells installed here.
        let listed = std::fs::read_to_string("/etc/shells").unwrap_or_default();
        for line in listed.lines().map(str::trim).filter(|l| l.starts_with('/')) {
            if std::path::Path::new(line).exists() { add(line.to_string()); }
        }
        for p in ["/bin/zsh", "/bin/bash", "/usr/bin/fish", "/bin/sh"] {
            if std::path::Path::new(p).exists() { add(p.to_string()); }
        }
        if let Some(p) = crate::deps::resolve("pwsh", "") { add(p); }
    }
    dedupe_links(out)
}

/// Drop entries that are the same binary under another path (/bin vs /usr/bin on
/// merged-/usr systems), keeping the first.
fn dedupe_links(list: Vec<String>) -> Vec<String> {
    let mut seen = Vec::new();
    list.into_iter().filter(|p| {
        let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.into());
        if seen.contains(&real) { false } else { seen.push(real); true }
    }).collect()
}

/// The shell to start: the operator's choice, else the first available one.
pub(super) fn pick_shell(configured: &str, available: &[String]) -> Option<String> {
    let c = configured.trim();
    if !c.is_empty() { return Some(c.to_string()); }
    available.first().cloned()
}

/// Short display name of a shell path ("zsh", "pwsh").
fn shell_name(path: &str) -> &str {
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    file.strip_suffix(".exe").unwrap_or(file)
}

impl SliverApp {
    pub(super) fn local_term_tab(&mut self, ui: &mut egui::Ui) {
        if self.ext.local_shells.is_empty() { self.ext.local_shells = available_shells(); }
        let shell = pick_shell(&self.settings.local_shell, &self.ext.local_shells);
        let running = self.ext.local.as_mut().is_some_and(|t| t.alive());
        // Start on first view; after the shell exits the operator restarts it.
        if self.ext.local.is_none() && !self.ext.local_tried {
            self.ext.local_tried = true;
            if let Some(s) = &shell { self.start_local(ui.ctx(), s.clone()); }
        }
        let mut restart = false;
        kit::toolbar(ui, |ui| {
            let label = self.ext.local_running.clone();
            match (&self.ext.local, running) {
                (Some(_), true) => { ui.colored_label(Palette::green(), format!("● {label}")); }
                (Some(t), false) => { ui.colored_label(Palette::red(), format!("● {label} {}", t.exit.as_deref().unwrap_or("exited"))); }
                (None, _) => { ui.colored_label(Palette::muted(), "● not running"); }
            }
            if ui.button(if running { "⟳ Restart" } else { "▶ Start" }).on_hover_text("Start a fresh shell").clicked() { restart = true; }
            if ui.add_enabled(running, egui::Button::new("Ctrl-C")).on_hover_text("Interrupt the running command (also Ctrl-C in the terminal)").clicked() {
                if let Some(t) = self.ext.local.as_mut() { t.interrupt(); }
            }
            if ui.add_enabled(self.ext.local.is_some(), egui::Button::new("⧉ Copy screen")).clicked() {
                if let Some(t) = &self.ext.local { ui.ctx().copy_text(t.contents()); }
            }
            ui.separator();
            ui.label("Shell");
            let current = shell.clone().unwrap_or_default();
            let before = self.settings.local_shell.clone();
            egui::ComboBox::from_id_salt("local-shell")
                .selected_text(if current.is_empty() { "none found".to_string() } else { shell_name(&current).to_string() })
                .show_ui(ui, |ui| {
                    let auto = self.ext.local_shells.first().map_or("auto".to_string(), |s| format!("auto ({})", shell_name(s)));
                    ui.selectable_value(&mut self.settings.local_shell, String::new(), auto);
                    for s in self.ext.local_shells.clone() {
                        ui.selectable_value(&mut self.settings.local_shell, s.clone(), s);
                    }
                })
                .response.on_hover_text(if current.is_empty() { "No shell found — Browse… to one" } else { current.as_str() });
            if ui.button("Browse…").on_hover_text("Use another shell or program").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() { self.settings.local_shell = p.display().to_string(); }
            }
            if self.settings.local_shell != before {
                self.settings_dirty = true;
                restart = true;
            }
        });
        if restart {
            self.ext.local = None;
            match pick_shell(&self.settings.local_shell, &self.ext.local_shells) {
                Some(s) => self.start_local(ui.ctx(), s),
                None => self.ext.local_err = "No shell found on this host — Browse… to one.".into(),
            }
        }
        if !self.ext.local_err.is_empty() && self.ext.local.is_none() {
            ui.colored_label(Palette::red(), &self.ext.local_err);
        }
        // Dev-only: type a line once the shell has drawn its prompt (SLIVER_GUI_LOCAL_TYPE=<line>).
        static TYPED: AtomicBool = AtomicBool::new(false);
        if let (Ok(line), Some(t)) = (std::env::var("SLIVER_GUI_LOCAL_TYPE"), self.ext.local.as_mut()) {
            static SEEN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            let ready = !t.contents().trim().is_empty() && SEEN.get_or_init(std::time::Instant::now).elapsed().as_millis() > 1500;
            if ready && !TYPED.swap(true, Ordering::SeqCst) {
                t.write(format!("{line}\r").as_bytes());
                println!("[gui] local terminal: typed '{line}'");
            }
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        }
        let submitted = self.ext.local.as_mut().map(|t| t.take_submitted()).unwrap_or_default();
        let source = format!("local:{}", self.ext.local_running);
        self.log_terminal(&source, submitted);
        match self.ext.local.as_mut() {
            Some(t) => t.ui(ui),
            None => kit::empty(ui, "❯", "A shell on this machine", "Pick a shell above and press Start."),
        }
    }

    fn start_local(&mut self, ctx: &egui::Context, program: String) {
        match LocalTerm::spawn(&program, ctx) {
            Ok(t) => {
                self.ext.local = Some(t);
                self.ext.local_err.clear();
                self.ext.local_running = shell_name(&program).to_string();
            }
            Err(e) => self.ext.local_err = format!("Couldn't start {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_choice_and_names() {
        let avail = vec!["/usr/bin/zsh".to_string(), "/bin/bash".to_string()];
        assert_eq!(pick_shell("", &avail).as_deref(), Some("/usr/bin/zsh"));
        assert_eq!(pick_shell(" /bin/bash ", &avail).as_deref(), Some("/bin/bash"));
        assert_eq!(pick_shell("", &[]), None);
        assert_eq!(shell_name("/usr/bin/zsh"), "zsh");
        assert_eq!(shell_name("C:\\Program Files\\PowerShell\\7\\pwsh.exe"), "pwsh");
        // Whatever this host has, the list is non-empty and every entry exists.
        let found = available_shells();
        assert!(!found.is_empty());
        assert!(found.iter().all(|p| std::path::Path::new(p).exists()));
    }
}
