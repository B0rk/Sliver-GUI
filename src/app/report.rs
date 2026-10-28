//! Engagement reporting: export a Markdown report (hosts, implants, IOCs,
//! listeners, credentials, loot, builds, timeline) and the event log as CSV,
//! plus an optional daily event-log file.

use std::fmt::Write as _;
use std::io::Write as _;

use super::{fmt_time, human_size, SliverApp};

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn csv_cell(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

impl SliverApp {
    /// Build the Markdown report text.
    pub(super) fn report_markdown(&self, include_secrets: bool) -> String {
        let mut o = String::new();
        let cfg = self.configs.get(self.selected_cfg);
        let _ = writeln!(o, "# Sliver engagement report\n");
        let _ = writeln!(o, "- Generated: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
        if let Some(c) = cfg { let _ = writeln!(o, "- Operator / server: `{}` ({})", c.label(), self.version); }
        let iocs: usize = self.ext.hosts.iter().map(|h| h.io_cs.len()).sum();
        let _ = writeln!(o, "- Hosts: {} · sessions: {} · beacons: {} · listeners: {}", self.ext.hosts.len(), self.sessions.len(), self.beacons.len(), self.jobs.len());
        let _ = writeln!(o, "- Credentials: {} ({} with plaintext) · loot items: {} · open IOCs: {}\n",
            self.creds.len(), self.creds.iter().filter(|c| !c.plaintext.is_empty()).count(), self.loot.len(), iocs);

        let _ = writeln!(o, "## Hosts\n\n| Hostname | OS | Locale | First contact | Live implants | Open IOCs |\n|---|---|---|---|---|---|");
        for h in &self.ext.hosts {
            let n = self.sessions.iter().filter(|s| s.uuid == h.host_uuid).count() + self.beacons.iter().filter(|b| b.uuid == h.host_uuid).count();
            let _ = writeln!(o, "| {} | {} | {} | {} | {} | {} |", md_cell(&h.hostname), md_cell(&h.os_version), md_cell(&h.locale), fmt_time(h.first_contact), n, h.io_cs.len());
        }
        let _ = writeln!(o);
        for h in self.ext.hosts.iter().filter(|h| !h.io_cs.is_empty()) {
            let _ = writeln!(o, "### Outstanding IOCs — {}\n", h.hostname);
            for i in &h.io_cs {
                let _ = writeln!(o, "- [ ] `{}`{}", i.path, if i.file_hash.is_empty() { String::new() } else { format!(" (sha256 `{}`)", i.file_hash) });
            }
            let _ = writeln!(o);
        }
        for h in &self.ext.hosts {
            if let Some(n) = self.settings.host_notes.get(&h.host_uuid).filter(|n| !n.trim().is_empty()) {
                let _ = writeln!(o, "### Notes — {}\n\n{}\n", h.hostname, n.trim());
            }
        }

        let _ = writeln!(o, "## Sessions\n\n| ID | Name | Host | User | OS/Arch | Transport | Remote | Integrity | Last seen |\n|---|---|---|---|---|---|---|---|---|");
        for s in &self.sessions {
            let _ = writeln!(o, "| `{}` | {} | {} | {} | {}/{} | {} | {} | {} | {} |", super::short(&s.id), md_cell(&s.name), md_cell(&s.hostname), md_cell(&s.username),
                s.os, s.arch, s.transport, s.remote_address, md_cell(&s.integrity), fmt_time(s.last_checkin));
        }
        let _ = writeln!(o, "\n## Beacons\n\n| ID | Name | Host | User | OS/Arch | Interval | Tasks | Last seen |\n|---|---|---|---|---|---|---|---|");
        for b in &self.beacons {
            let _ = writeln!(o, "| `{}` | {} | {} | {} | {}/{} | {}s ±{}s | {}/{} | {} |", super::short(&b.id), md_cell(&b.name), md_cell(&b.hostname), md_cell(&b.username),
                b.os, b.arch, b.interval / 1_000_000_000, b.jitter / 1_000_000_000, b.tasks_count_completed, b.tasks_count, fmt_time(b.last_checkin));
        }
        let _ = writeln!(o, "\n## Listeners\n\n| Job | Name | Protocol | Port | Domains |\n|---|---|---|---|---|");
        for j in &self.jobs {
            let _ = writeln!(o, "| {} | {} | {} | {} | {} |", j.id, j.name, j.protocol, j.port, md_cell(&j.domains.join(", ")));
        }
        let _ = writeln!(o, "\n## Credentials\n\n| Username | Type | Cracked | Collection | Origin |{}\n|---|---|---|---|---|{}",
            if include_secrets { " Secret |" } else { "" }, if include_secrets { "---|" } else { "" });
        for c in &self.creds {
            let ty = if c.hash.is_empty() && !c.plaintext.is_empty() { "plaintext".to_string() } else { super::collect::hash_type_name(c.hash_type) };
            let secret = if !c.plaintext.is_empty() { &c.plaintext } else { &c.hash };
            let cracked = if c.hash.is_empty() { "n/a" } else if c.is_cracked || !c.plaintext.is_empty() { "yes" } else { "no" };
            let _ = writeln!(o, "| {} | {} | {} | {} | {} |{}", md_cell(&c.username), ty, cracked, md_cell(&c.collection),
                md_cell(&self.host_label(&c.origin_host_uuid)), if include_secrets { format!(" `{}` |", md_cell(secret)) } else { String::new() });
        }
        if !include_secrets { let _ = writeln!(o, "\n_Secrets omitted from this report._"); }
        let _ = writeln!(o, "\n## Loot\n\n| Name | Type | Size | Origin |\n|---|---|---|---|");
        for l in &self.loot {
            let _ = writeln!(o, "| {} | {} | {} | {} |", md_cell(&l.name), match l.file_type { 2 => "text", 1 => "binary", _ => "—" }, human_size(l.size), md_cell(&self.host_label(&l.origin_host_uuid)));
        }
        let _ = writeln!(o, "\n## Implant builds\n\n| Implant | Target | Format | Mode | C2 |\n|---|---|---|---|---|");
        for b in &self.ext.builds {
            let _ = writeln!(o, "| {} | {}/{} | {} | {} | {} |", b.name, b.os, b.arch, super::builds::format_name(b.format), if b.beacon { "beacon" } else { "session" }, md_cell(&b.c2.join(", ")));
        }
        // Beacon tasks, with the server's own times (only beacons whose history was loaded).
        let mut tasks: Vec<(&String, &crate::proto::clientpb::BeaconTask)> = self.beacon_tasks.iter()
            .flat_map(|(b, ts)| ts.iter().map(move |t| (b, t))).collect();
        if !tasks.is_empty() {
            tasks.sort_by_key(|(_, t)| t.created_at);
            let _ = writeln!(o, "\n## Beacon tasks\n\n| Created | Sent | Completed | Beacon | Task | State |\n|---|---|---|---|---|---|");
            for (b, t) in tasks {
                let when = |x: i64| if x > 0 { fmt_time_secs(x) } else { "—".into() };
                let _ = writeln!(o, "| {} | {} | {} | {} | {} | {} |", when(t.created_at), when(t.sent_at), when(t.completed_at),
                    md_cell(&self.implant_label(b)), md_cell(&t.description), t.state);
            }
        }
        // One chronological timeline: server/client events, every operator action sent
        // to an implant or the server (with results), and terminal command lines.
        let _ = writeln!(o, "\n## Timeline (this client session)\n\nTimes are local with their UTC offset.\n\n| Time | Source | Target | Entry |\n|---|---|---|---|");
        for (ts, source, target, entry) in self.timeline() {
            let entry = if source.starts_with("local:") || source == "sliver-console" { format!("`{}`", entry.replace('`', "'")) } else { entry };
            let _ = writeln!(o, "| {} | {} | {} | {} |", fmt_time_secs(ts), source, md_cell(&target), md_cell(&entry));
        }
        o
    }

    pub(super) fn export_report(&mut self, include_secrets: bool) {
        // Refresh the inputs the report relies on so a later export is current.
        self.op(crate::client::Op::RefreshHosts);
        self.op(crate::client::Op::RefreshBuilds);
        let name = format!("sliver-report-{}.md", chrono::Local::now().format("%Y%m%d-%H%M"));
        if let Some(p) = rfd::FileDialog::new().set_file_name(&name).add_filter("Markdown", &["md"]).save_file() {
            match std::fs::write(&p, self.report_markdown(include_secrets)) {
                Ok(_) => self.set_toast(true, &format!("report written → {}", p.display())),
                Err(e) => self.set_toast(false, &format!("report failed: {e}")),
            }
        }
    }

    /// The merged timeline as CSV.
    pub(super) fn timeline_csv(&self) -> String {
        let mut o = String::from("time,unix_time,source,target,entry\n");
        for (ts, source, target, entry) in self.timeline() {
            let _ = writeln!(o, "{},{ts},{},{},{}", csv_cell(&fmt_time_secs(ts)), csv_cell(&source), csv_cell(&target), csv_cell(&entry));
        }
        o
    }

    pub(super) fn export_events_csv(&mut self) {
        let name = format!("sliver-timeline-{}.csv", chrono::Local::now().format("%Y%m%d-%H%M"));
        if let Some(p) = rfd::FileDialog::new().set_file_name(&name).save_file() {
            match std::fs::write(&p, self.timeline_csv()) {
                Ok(_) => self.set_toast(true, &format!("timeline exported → {}", p.display())),
                Err(e) => self.set_toast(false, &format!("export failed: {e}")),
            }
        }
    }

    /// "name@host (id)" for an implant key, for logs.
    pub(super) fn implant_label(&self, key: &str) -> String {
        let found = self.sessions.iter().find(|s| s.id == key).map(|s| (s.name.clone(), s.hostname.clone()))
            .or_else(|| self.beacons.iter().find(|b| b.id == key).map(|b| (b.name.clone(), b.hostname.clone())));
        match found {
            Some((name, host)) => format!("{name}@{host} ({})", super::short(key)),
            None => super::short(key).to_string(),
        }
    }

    /// Record one operator action against `target` (an implant label, or "server"):
    /// kept for the report timeline and, when enabled, appended to today's
    /// `activity-YYYYMMDD.log`.
    pub(super) fn audit(&self, target: &str, what: String) {
        let ts = chrono::Local::now().timestamp();
        if self.settings.log_activity {
            if let Some(dir) = crate::settings::data_dir().map(|d| d.join("logs")).filter(|d| std::fs::create_dir_all(d).is_ok()) {
                let file = dir.join(format!("activity-{}.log", chrono::Local::now().format("%Y%m%d")));
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(file) {
                    let _ = writeln!(f, "{} [{target}] {what}", fmt_time_secs(ts));
                }
            }
        }
        let mut log = self.ext.activity.borrow_mut();
        log.push((ts, target.to_string(), what));
        let excess = log.len().saturating_sub(10_000);
        log.drain(..excess);
    }

    /// Everything this client session logged — events, operator activity and terminal
    /// command lines — as (time, source, target, entry), oldest first.
    pub(super) fn timeline(&self) -> Vec<(i64, String, String, String)> {
        let mut rows: Vec<(i64, String, String, String)> = Vec::new();
        for (ts, kind, text) in self.events.iter().rev() { rows.push((*ts, format!("event:{kind}"), String::new(), text.clone())); }
        for (ts, target, what) in self.ext.activity.borrow().iter() { rows.push((*ts, "operator".into(), target.clone(), what.clone())); }
        for (ts, source, line) in &self.ext.term_log { rows.push((*ts, source.clone(), "local".into(), line.clone())); }
        rows.sort_by_key(|r| r.0);
        rows
    }

    /// Record command lines submitted in a terminal tab: kept for the report and, when
    /// enabled, appended to today's `terminal-YYYYMMDD.log`.
    pub(super) fn log_terminal(&mut self, source: &str, lines: Vec<(i64, String)>) {
        if lines.is_empty() || !self.settings.log_terminal { return; }
        let file = crate::settings::data_dir().map(|d| d.join("logs")).filter(|d| std::fs::create_dir_all(d).is_ok())
            .and_then(|d| std::fs::OpenOptions::new().create(true).append(true)
                .open(d.join(format!("terminal-{}.log", chrono::Local::now().format("%Y%m%d")))).ok());
        for (ts, line) in lines {
            if let Some(mut f) = file.as_ref() { let _ = writeln!(f, "{} [{source}] {line}", fmt_time_secs(ts)); }
            self.ext.term_log.push((ts, source.to_string(), line));
        }
        let excess = self.ext.term_log.len().saturating_sub(5000);
        self.ext.term_log.drain(..excess);
    }

    /// Append one event to today's log file (if enabled).
    pub(super) fn log_event_line(&self, ts: i64, kind: &str, text: &str) {
        if !self.settings.log_events { return; }
        let Some(dir) = crate::settings::data_dir().map(|d| d.join("logs")) else { return };
        if std::fs::create_dir_all(&dir).is_err() { return; }
        let file = dir.join(format!("events-{}.log", chrono::Local::now().format("%Y%m%d")));
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(file) {
            let _ = writeln!(f, "{} [{kind}] {text}", fmt_time_secs(ts));
        }
    }
}

pub(super) fn fmt_time_secs(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|dt| dt.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S %:z").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_times_carry_date_and_utc_offset() {
        // e.g. "2026-10-28 13:29:39 -06:00"
        let s = fmt_time_secs(1_800_000_000);
        let (date, rest) = s.split_once(' ').unwrap();
        let (time, offset) = rest.split_once(' ').unwrap();
        assert_eq!(date.len(), 10);
        assert_eq!(time.len(), 8);
        assert!(offset.starts_with('+') || offset.starts_with('-'), "offset in {s:?}");
        assert_eq!(offset.len(), 6);
    }
}
