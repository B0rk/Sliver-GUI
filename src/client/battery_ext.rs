//! Headless checks for the extended operator features (process kill, file
//! operations, hosts/IOCs, pivot listeners, loot/creds writes, profiles and
//! builds, C2 profiles, WireGuard, operators, beacon reconfigure, and the
//! read-only Windows registry/services views). Driven from `selftest`.

use std::time::Duration;

use super::{gunzip, Report, Rpc, Target};
use crate::proto::{clientpb, commonpb, sliverpb};

fn err_of(r: &Option<commonpb::Response>) -> Option<String> {
    r.as_ref().map(|x| x.err.clone()).filter(|e| !e.is_empty())
}

/// Per-session extended checks (Unix sessions; Windows sessions get the
/// read-only registry/services checks via [`windows_checks`]).
pub(super) async fn session_checks(c: &mut Rpc, sid: &str, is_win: bool, rep: &mut Report) {
    let t = Target::session(sid);
    let req = |secs| Some(t.request(secs));

    // ---- process browser data + kill ----
    match c.ps(sliverpb::PsReq { full_info: true, request: req(60) }).await {
        Ok(r) => {
            let p = r.into_inner().processes;
            let with_cmd = p.iter().filter(|x| !x.cmd_line.is_empty()).count();
            if with_cmd > 0 { rep.pass("ps(full-info)", format!("{} procs, {with_cmd} with command lines", p.len())) }
            else { rep.fail("ps(full-info)", "no command lines returned") }
        }
        Err(e) => rep.fail("ps(full-info)", e.message()),
    }
    if is_win {
        rep.na("terminate", "spawn/kill check runs on unix test sessions");
    } else {
        // Spawn a disposable sleep, then kill it.
        let spawn = c.execute(sliverpb::ExecuteReq { path: "/usr/bin/sleep".into(), args: vec!["600".into()], output: false, request: req(30), ..Default::default() }).await;
        match spawn {
            Ok(r) => {
                let pid = r.into_inner().pid as i32;
                if pid <= 0 {
                    rep.fail("spawn-test-proc", "no pid returned");
                } else {
                    rep.pass("spawn-test-proc", format!("sleep pid {pid}"));
                    match c.terminate(sliverpb::TerminateReq { pid, force: true, request: req(30) }).await {
                        Ok(r) => match err_of(&r.into_inner().response) {
                            Some(e) => rep.fail("terminate", e),
                            None => {
                                tokio::time::sleep(Duration::from_millis(800)).await;
                                let gone = c.ps(sliverpb::PsReq { full_info: false, request: req(60) }).await.ok()
                                    .map(|r| !r.into_inner().processes.iter().any(|p| p.pid == pid)).unwrap_or(false);
                                if gone { rep.pass("terminate", format!("pid {pid} killed + verified gone")) } else { rep.fail("terminate", "process still listed") }
                            }
                        },
                        Err(e) => rep.fail("terminate", e.message()),
                    }
                }
            }
            Err(e) => rep.fail("spawn-test-proc", e.message()),
        }
    }

    // ---- file operations: cd / pwd / cp / mv / chmod / grep / mount / IOC upload ----
    let orig = c.pwd(sliverpb::PwdReq { request: req(30) }).await.ok().map(|r| r.into_inner().path).unwrap_or_default();
    let (base, dir) = if is_win { ("C:\\Windows\\Temp", "C:\\Windows\\Temp\\gui_ext") } else { ("/tmp", "/tmp/gui_ext") };
    let sep = if is_win { "\\" } else { "/" };
    let f = |n: &str| format!("{dir}{sep}{n}");
    match c.cd(sliverpb::CdReq { path: base.into(), request: req(30) }).await {
        Ok(r) => {
            let p = r.into_inner().path;
            if p.trim_end_matches(['/', '\\']).eq_ignore_ascii_case(base) { rep.pass("cd", p) } else { rep.fail("cd", format!("now in {p}")) }
        }
        Err(e) => rep.fail("cd", e.message()),
    }
    match c.pwd(sliverpb::PwdReq { request: req(30) }).await {
        Ok(r) => { let p = r.into_inner().path; if p.eq_ignore_ascii_case(base) { rep.pass("pwd", p) } else { rep.fail("pwd", p) } }
        Err(e) => rep.fail("pwd", e.message()),
    }
    let body = b"sliver-gui ext battery needle-7c1f\n".to_vec();
    let _ = c.mkdir(sliverpb::MkdirReq { path: dir.into(), request: req(30) }).await;
    match c.upload(sliverpb::UploadReq { path: f("a.txt"), data: body.clone(), is_ioc: true, request: req(60), ..Default::default() }).await {
        Ok(_) => rep.pass("upload(ioc)", f("a.txt")),
        Err(e) => rep.fail("upload(ioc)", e.message()),
    }
    match c.cp(sliverpb::CpReq { src: f("a.txt"), dst: f("b.txt"), request: req(60) }).await {
        Ok(r) => match err_of(&r.into_inner().response) { Some(e) => rep.fail("cp", e), None => rep.pass("cp", "a.txt → b.txt") },
        Err(e) => rep.fail("cp", e.message()),
    }
    match c.mv(sliverpb::MvReq { src: f("b.txt"), dst: f("c.txt"), request: req(60) }).await {
        Ok(r) => match err_of(&r.into_inner().response) { Some(e) => rep.fail("mv", e), None => rep.pass("mv", "b.txt → c.txt") },
        Err(e) => rep.fail("mv", e.message()),
    }
    if is_win {
        rep.na("chmod", "unix permissions");
    } else {
        match c.chmod(sliverpb::ChmodReq { path: f("c.txt"), file_mode: "600".into(), recursive: false, request: req(30) }).await {
            Ok(r) => match err_of(&r.into_inner().response) {
                Some(e) => rep.fail("chmod", e),
                None => {
                    let mode = c.ls(sliverpb::LsReq { path: dir.into(), request: req(30) }).await.ok()
                        .and_then(|r| r.into_inner().files.into_iter().find(|x| x.name == "c.txt").map(|x| x.mode)).unwrap_or_default();
                    if mode.ends_with("rw-------") { rep.pass("chmod", format!("c.txt mode {mode}")) } else { rep.fail("chmod", format!("mode is {mode}")) }
                }
            },
            Err(e) => rep.fail("chmod", e.message()),
        }
    }
    match c.download(sliverpb::DownloadReq { path: f("c.txt"), request: req(60), ..Default::default() }).await {
        Ok(r) => {
            let d = r.into_inner();
            let bytes = if d.encoder == "gzip" { gunzip(&d.data) } else { d.data };
            if bytes == body { rep.pass("cp+mv content", "copied file byte-identical") } else { rep.fail("cp+mv content", "content differs") }
        }
        Err(e) => rep.fail("cp+mv content", e.message()),
    }
    match c.grep(sliverpb::GrepReq { search_pattern: "needle-7c1f".into(), path: dir.into(), recursive: true, request: req(60), ..Default::default() }).await {
        Ok(r) => {
            let g = r.into_inner();
            let hits: usize = g.results.values().map(|x| x.file_results.len()).sum();
            if hits >= 2 { rep.pass("grep", format!("{hits} hits in {} files", g.results.len())) } else { rep.fail("grep", format!("{hits} hits")) }
        }
        Err(e) => rep.fail("grep", e.message()),
    }
    match c.mount(sliverpb::MountReq { request: req(30) }).await {
        Ok(r) => { let n = r.into_inner().info.len(); if n > 0 { rep.pass("mounts", format!("{n} mounts")) } else { rep.fail("mounts", "0") } }
        Err(e) => rep.na("mounts", format!("not supported here: {}", e.message())),
    }

    // ---- hosts / IOC checklist ----
    let uuid = c.get_sessions(commonpb::Empty {}).await.ok()
        .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id == sid)).map(|s| s.uuid).unwrap_or_default();
    match c.hosts(commonpb::Empty {}).await {
        Ok(r) => match r.into_inner().hosts.into_iter().find(|h| h.host_uuid == uuid) {
            Some(h) => {
                rep.pass("hosts", format!("{} found ({} IOCs, record id {:?})", h.hostname, h.io_cs.len(), h.id));
                match h.io_cs.iter().find(|i| i.path.ends_with("a.txt") && i.path.contains("gui_ext")).cloned() {
                    Some(ioc) => {
                        rep.pass("ioc-recorded", ioc.path.clone());
                        match c.host_ioc_rm(ioc.clone()).await {
                            Ok(_) => {
                                let still = c.hosts(commonpb::Empty {}).await.ok()
                                    .map(|r| r.into_inner().hosts.iter().any(|h| h.io_cs.iter().any(|i| i.id == ioc.id))).unwrap_or(true);
                                if still { rep.fail("ioc-cleared", "IOC still listed") } else { rep.pass("ioc-cleared", "removed from checklist") }
                            }
                            Err(e) => rep.fail("ioc-cleared", e.message()),
                        }
                    }
                    None => rep.fail("ioc-recorded", "uploaded file not in host IOCs"),
                }
            }
            None => rep.fail("hosts", "session host not in host list"),
        },
        Err(e) => rep.fail("hosts", e.message()),
    }
    let _ = c.rm(sliverpb::RmReq { path: dir.into(), recursive: true, force: true, request: req(30) }).await;
    if !orig.is_empty() { let _ = c.cd(sliverpb::CdReq { path: orig, request: req(30) }).await; }

    // ---- implant-chaining pivot listener lifecycle ----
    match c.pivot_start_listener(sliverpb::PivotStartListenerReq { r#type: sliverpb::PivotType::Tcp as i32, bind_address: "127.0.0.1:19898".into(), options: Vec::new(), request: req(30) }).await {
        Ok(r) => {
            let l = r.into_inner();
            match err_of(&l.response) {
                Some(e) => rep.fail("pivot-listener-start", e),
                None => {
                    rep.pass("pivot-listener-start", format!("id {} on {}", l.id, l.bind_address));
                    let listed = c.pivot_session_listeners(sliverpb::PivotListenersReq { request: req(30) }).await.ok()
                        .map(|r| r.into_inner().listeners.iter().any(|x| x.id == l.id)).unwrap_or(false);
                    if listed { rep.pass("pivot-listeners", "listener listed") } else { rep.fail("pivot-listeners", "not listed") }
                    match c.pivot_stop_listener(sliverpb::PivotStopListenerReq { id: l.id, request: req(30) }).await {
                        Ok(_) => {
                            let gone = c.pivot_session_listeners(sliverpb::PivotListenersReq { request: req(30) }).await.ok()
                                .map(|r| !r.into_inner().listeners.iter().any(|x| x.id == l.id)).unwrap_or(false);
                            if gone { rep.pass("pivot-listener-stop", "stopped + verified") } else { rep.fail("pivot-listener-stop", "still listed") }
                        }
                        Err(e) => rep.fail("pivot-listener-stop", e.message()),
                    }
                }
            }
        }
        Err(e) => rep.fail("pivot-listener-start", e.message()),
    }
}

/// Read-only Windows registry + services checks.
pub(super) async fn windows_checks(c: &mut Rpc, sid: &str, rep: &mut Report) {
    let t = Target::session(sid);
    match c.registry_list_sub_keys(sliverpb::RegistrySubKeyListReq { hive: "HKLM".into(), path: "SOFTWARE".into(), hostname: String::new(), request: Some(t.request(30)) }).await {
        Ok(r) => { let n = r.into_inner().subkeys.len(); if n > 0 { rep.pass("registry-list", format!("HKLM\\SOFTWARE: {n} subkeys")) } else { rep.fail("registry-list", "0 subkeys") } }
        Err(e) => rep.fail("registry-list", e.message()),
    }
    match c.registry_list_values(sliverpb::RegistryListValuesReq { hive: "HKLM".into(), path: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".into(), hostname: String::new(), request: Some(t.request(30)) }).await {
        Ok(r) => { let n = r.into_inner().value_names.len(); if n > 0 { rep.pass("registry-values", format!("{n} values")) } else { rep.fail("registry-values", "0 values") } }
        Err(e) => rep.fail("registry-values", e.message()),
    }
    match c.registry_read(sliverpb::RegistryReadReq { hive: "HKLM".into(), path: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion".into(), key: "ProductName".into(), hostname: String::new(), request: Some(t.request(30)) }).await {
        Ok(r) => { let v = r.into_inner().value; if !v.is_empty() { rep.pass("registry-read", v) } else { rep.fail("registry-read", "empty") } }
        Err(e) => rep.fail("registry-read", e.message()),
    }
    match tokio::time::timeout(Duration::from_secs(90), c.services(sliverpb::ServicesReq { hostname: String::new(), request: Some(t.request(60)) })).await {
        Ok(Ok(r)) => {
            let s = r.into_inner();
            let running = s.details.iter().filter(|d| d.status == 4).count();
            if !s.details.is_empty() { rep.pass("services", format!("{} services, {running} running", s.details.len())) } else { rep.fail("services", s.error) }
        }
        Ok(Err(e)) => rep.fail("services", e.message()),
        Err(_) => rep.fail("services", "timed out"),
    }
}

/// Server-side checks: creds/loot writes, profiles, builds, canaries, C2
/// profiles, operators, WireGuard.
pub(super) async fn global_checks(c: &mut Rpc, rep: &mut Report) {
    // ---- credentials add / update / remove ----
    let user = "gui-battery-user";
    let cred = clientpb::Credential { username: user.into(), plaintext: "Battery!Pass1".into(), collection: "battery".into(), ..Default::default() };
    match c.creds_add(clientpb::Credentials { credentials: vec![cred] }).await {
        Ok(_) => {
            let found = c.creds(commonpb::Empty {}).await.ok().and_then(|r| r.into_inner().credentials.into_iter().find(|x| x.username == user));
            match found {
                Some(mut x) => {
                    rep.pass("creds-add", format!("id {}", super::short_id(&x.id)));
                    x.collection = "battery-updated".into();
                    x.hash = "8846f7eaee8fb117ad06bdd830b7586c".into();
                    x.hash_type = 1000;
                    match c.creds_update(clientpb::Credentials { credentials: vec![x.clone()] }).await {
                        Ok(_) => {
                            let ok = c.creds(commonpb::Empty {}).await.ok()
                                .map(|r| r.into_inner().credentials.iter().any(|y| y.id == x.id && y.collection == "battery-updated" && y.hash_type == 1000)).unwrap_or(false);
                            if ok { rep.pass("creds-update", "collection + NTLM hash type applied") } else { rep.fail("creds-update", "change not visible") }
                        }
                        Err(e) => rep.fail("creds-update", e.message()),
                    }
                    match c.creds_rm(clientpb::Credentials { credentials: vec![clientpb::Credential { id: x.id.clone(), ..Default::default() }] }).await {
                        Ok(_) => {
                            let gone = c.creds(commonpb::Empty {}).await.ok().map(|r| !r.into_inner().credentials.iter().any(|y| y.id == x.id)).unwrap_or(false);
                            if gone { rep.pass("creds-rm", "removed + verified") } else { rep.fail("creds-rm", "still listed") }
                        }
                        Err(e) => rep.fail("creds-rm", e.message()),
                    }
                }
                None => rep.fail("creds-add", "not listed after add"),
            }
        }
        Err(e) => rep.fail("creds-add", e.message()),
    }

    // ---- loot add / content / remove ----
    let data = b"sliver-gui loot roundtrip\n".to_vec();
    let loot = clientpb::Loot { name: "gui-battery.txt".into(), file_type: clientpb::FileType::Text as i32, size: data.len() as i64,
        file: Some(commonpb::File { name: "gui-battery.txt".into(), data: data.clone() }), ..Default::default() };
    match c.loot_add(loot).await {
        Ok(r) => {
            let id = r.into_inner().id;
            rep.pass("loot-add", format!("id {}", super::short_id(&id)));
            match c.loot_content(clientpb::Loot { id: id.clone(), ..Default::default() }).await {
                Ok(r) => {
                    let got = r.into_inner().file.map(|f| f.data).unwrap_or_default();
                    if got == data { rep.pass("loot-content", "byte-identical") } else { rep.fail("loot-content", format!("{} bytes differ", got.len())) }
                }
                Err(e) => rep.fail("loot-content", e.message()),
            }
            match c.loot_rm(clientpb::Loot { id: id.clone(), ..Default::default() }).await {
                Ok(_) => {
                    let gone = c.loot_all(commonpb::Empty {}).await.ok().map(|r| !r.into_inner().loot.iter().any(|l| l.id == id)).unwrap_or(false);
                    if gone { rep.pass("loot-rm", "removed + verified") } else { rep.fail("loot-rm", "still listed") }
                }
                Err(e) => rep.fail("loot-rm", e.message()),
            }
        }
        Err(e) => rep.fail("loot-add", e.message()),
    }

    // ---- implant profiles save / list / delete ----
    let ns = 1_000_000_000i64;
    let cfg = clientpb::ImplantConfig {
        goos: "linux".into(), goarch: "amd64".into(), format: 2,
        c2: vec![clientpb::ImplantC2 { url: "mtls://127.0.0.1:8888".into(), ..Default::default() }],
        include_mtls: true, reconnect_interval: 60 * ns, max_connection_errors: 1000, poll_timeout: 360 * ns,
        template_name: "sliver".into(), httpc2_config_name: "default".into(),
        limit_hostname: "gui-battery-only".into(),
        ..Default::default()
    };
    let pname = "gui-battery-profile";
    match c.save_implant_profile(clientpb::ImplantProfile { id: String::new(), name: pname.into(), config: Some(cfg) }).await {
        Ok(_) => {
            let listed = c.implant_profiles(commonpb::Empty {}).await.ok()
                .and_then(|r| r.into_inner().profiles.into_iter().find(|p| p.name == pname));
            match listed {
                Some(p) => {
                    let lh = p.config.map(|c| c.limit_hostname).unwrap_or_default();
                    if lh == "gui-battery-only" { rep.pass("profile-save", "saved + config round-trips") } else { rep.fail("profile-save", "config mismatch") }
                }
                None => rep.fail("profile-save", "not listed"),
            }
            match c.delete_implant_profile(clientpb::DeleteReq { name: pname.into() }).await {
                Ok(_) => {
                    let gone = c.implant_profiles(commonpb::Empty {}).await.ok().map(|r| !r.into_inner().profiles.iter().any(|p| p.name == pname)).unwrap_or(false);
                    if gone { rep.pass("profile-delete", "removed + verified") } else { rep.fail("profile-delete", "still listed") }
                }
                Err(e) => rep.fail("profile-delete", e.message()),
            }
        }
        Err(e) => rep.fail("profile-save", e.message()),
    }

    // ---- build history + regenerate (prefer a small linux build) ----
    match c.implant_builds(commonpb::Empty {}).await {
        Ok(r) => {
            let b = r.into_inner();
            rep.pass("implant-builds", format!("{} builds", b.configs.len()));
            let pick = b.configs.iter().find(|(_, c)| c.goos == "linux" && c.format == 2).or_else(|| b.configs.iter().next()).map(|(n, _)| n.clone());
            match pick {
                Some(name) => match tokio::time::timeout(Duration::from_secs(180), c.regenerate(clientpb::RegenerateReq { implant_name: name.clone() })).await {
                    Ok(Ok(r)) => {
                        let n = r.into_inner().file.map(|f| f.data.len()).unwrap_or(0);
                        if n > 0 { rep.pass("regenerate", format!("{name}: {n} bytes")) } else { rep.fail("regenerate", "no file") }
                    }
                    Ok(Err(e)) => rep.fail("regenerate", e.message()),
                    Err(_) => rep.fail("regenerate", "timed out"),
                },
                None => rep.na("regenerate", "no builds on server"),
            }
        }
        Err(e) => rep.fail("implant-builds", e.message()),
    }
    match c.canaries(commonpb::Empty {}).await {
        Ok(r) => rep.pass("canaries", format!("{} canaries", r.into_inner().canaries.len())),
        Err(e) => rep.fail("canaries", e.message()),
    }

    // ---- HTTP C2 profiles: list, fetch, JSON round-trip ----
    match c.get_httpc2_profiles(commonpb::Empty {}).await {
        Ok(r) => {
            let names: Vec<String> = r.into_inner().configs.into_iter().map(|p| p.name).collect();
            rep.pass("c2-profiles", format!("{} profiles: {}", names.len(), names.join(", ")));
            if let Some(n) = names.first() {
                match c.get_httpc2_profile_by_name(clientpb::C2ProfileReq { name: n.clone() }).await {
                    Ok(r) => {
                        let p = r.into_inner();
                        let json = serde_json::to_string(&p).unwrap_or_default();
                        let back: Option<clientpb::Httpc2Config> = serde_json::from_str(&json).ok();
                        if back.as_ref() == Some(&p) { rep.pass("c2-profile-json", format!("'{n}' export/import round-trips ({} bytes)", json.len())) }
                        else { rep.fail("c2-profile-json", "JSON round-trip mismatch") }
                    }
                    Err(e) => rep.fail("c2-profile-get", e.message()),
                }
            }
        }
        Err(e) => rep.fail("c2-profiles", e.message()),
    }

    // ---- multiplayer presence ----
    match c.get_operators(commonpb::Empty {}).await {
        Ok(r) => {
            let o = r.into_inner().operators;
            let online: Vec<String> = o.iter().filter(|x| x.online).map(|x| x.name.clone()).collect();
            // A headless test client has no event stream, so the server may not
            // count it as online; the roster itself is what the GUI shows.
            if !o.is_empty() { rep.pass("operators", format!("{} known, online now: {}", o.len(), if online.is_empty() { "none".into() } else { online.join(", ") })) }
            else { rep.fail("operators", "empty operator list") }
        }
        Err(e) => rep.fail("operators", e.message()),
    }

    // ---- WireGuard listener lifecycle + client config ----
    // udp/51821: 51820 is commonly held by a persistent WG listener.
    match c.start_wg_listener(clientpb::WgListenerReq { host: "0.0.0.0".into(), port: 51821, tun_ip: "100.64.0.1".into(), n_port: 8888, key_port: 1337 }).await {
        Ok(r) => {
            let jid = r.into_inner().job_id;
            rep.pass("start-wg-listener", format!("job {jid} udp/51821"));
            match c.kill_job(clientpb::KillJobReq { id: jid }).await {
                Ok(_) => rep.pass("kill-job(wg)", format!("job {jid}")), Err(e) => rep.fail("kill-job(wg)", e.message()),
            }
        }
        Err(e) => rep.fail("start-wg-listener", e.message()),
    }
    match c.generate_wg_client_config(commonpb::Empty {}).await {
        Ok(r) => { let w = r.into_inner(); if !w.client_ip.is_empty() && !w.server_pub_key.is_empty() { rep.pass("wg-client-config", format!("client ip {}", w.client_ip)) } else { rep.fail("wg-client-config", "incomplete") } }
        Err(e) => rep.fail("wg-client-config", e.message()),
    }
}

/// Beacon reconfigure: change the interval, wait for the task to complete,
/// verify the server record, then restore the original cadence.
pub(super) async fn beacon_reconfigure(c: &mut Rpc, bid: &str, rep: &mut Report) {
    const NS: i64 = 1_000_000_000;
    let t = Target::beacon(bid);
    let Some(b) = c.get_beacons(commonpb::Empty {}).await.ok().and_then(|r| r.into_inner().beacons.into_iter().find(|b| b.id == bid)) else {
        rep.fail("beacon-reconfigure", "beacon not found");
        return;
    };
    let (orig_i, orig_j) = (b.interval, b.jitter);
    let new_i = if orig_i == 4 * NS { 5 * NS } else { 4 * NS };
    let task = match c.reconfigure(sliverpb::ReconfigureReq { beacon_interval: new_i, beacon_jitter: 0, request: Some(t.request(60)), ..Default::default() }).await {
        Ok(r) => r.into_inner().response.map(|x| x.task_id).unwrap_or_default(),
        Err(e) => { rep.fail("beacon-reconfigure", e.message()); return; }
    };
    rep.pass("beacon-reconfigure-queued", format!("{}s → {}s (task {})", orig_i / NS, new_i / NS, super::short_id(&task)));
    let polls = ((orig_i + orig_j) / NS) as usize + 20;
    let mut applied = false;
    for _ in 0..polls {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let done = c.get_beacon_tasks(clientpb::Beacon { id: bid.into(), ..Default::default() }).await.ok()
            .map(|r| r.into_inner().tasks.iter().any(|x| x.id == task && x.state == "completed")).unwrap_or(false);
        let interval = c.get_beacons(commonpb::Empty {}).await.ok()
            .and_then(|r| r.into_inner().beacons.into_iter().find(|b| b.id == bid)).map(|b| b.interval).unwrap_or(0);
        if done && interval == new_i { applied = true; break; }
    }
    if applied { rep.pass("beacon-reconfigure-applied", format!("interval now {}s", new_i / NS)) } else { rep.fail("beacon-reconfigure-applied", format!("interval not updated within ~{}s", polls * 2)) }
    // Restore.
    let _ = c.reconfigure(sliverpb::ReconfigureReq { beacon_interval: orig_i, beacon_jitter: orig_j, request: Some(t.request(60)), ..Default::default() }).await;
    for _ in 0..polls {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let interval = c.get_beacons(commonpb::Empty {}).await.ok()
            .and_then(|r| r.into_inner().beacons.into_iter().find(|b| b.id == bid)).map(|b| b.interval).unwrap_or(0);
        if interval == orig_i { rep.pass("beacon-reconfigure-restore", format!("back to {}s", orig_i / NS)); return; }
    }
    rep.fail("beacon-reconfigure-restore", format!("original interval not restored within ~{}s", polls * 2));
}

/// Host-record removal by host UUID (opt-in: it deletes a real host record).
pub(super) async fn host_rm_check(c: &mut Rpc, hostname: &str, rep: &mut Report) {
    let Some(h) = c.hosts(commonpb::Empty {}).await.ok().and_then(|r| r.into_inner().hosts.into_iter().find(|h| h.hostname == hostname)) else {
        rep.fail("host-rm", format!("{hostname} not in host list"));
        return;
    };
    match c.host_rm(clientpb::Host { id: h.id.clone(), host_uuid: h.host_uuid.clone(), ..Default::default() }).await {
        Ok(_) => {
            let gone = c.hosts(commonpb::Empty {}).await.ok().map(|r| !r.into_inner().hosts.iter().any(|x| x.host_uuid == h.host_uuid)).unwrap_or(false);
            if gone { rep.pass("host-rm", format!("{hostname} record removed + verified")) } else { rep.fail("host-rm", "record still listed") }
        }
        Err(e) => rep.fail("host-rm", e.message()),
    }
}

/// Seed (or remove) sample data so the GUI's Loot / Credentials / Hosts /
/// Builds views can be captured with live content.
pub(super) async fn seed(c: &mut Rpc, sid: Option<&str>, remove: bool) {
    const USERS: [(&str, &str, &str, i32); 3] = [
        ("CORP\\svc_backup", "", "8846f7eaee8fb117ad06bdd830b7586c", 1000),
        ("operator", "example-password", "", 0),
        ("CORP\\Administrator", "", "aad3b435b51404eeaad3b435b51404ee", 3000),
    ];
    if remove {
        if let Ok(r) = c.creds(commonpb::Empty {}).await {
            let ids: Vec<clientpb::Credential> = r.into_inner().credentials.into_iter()
                .filter(|x| x.collection == "gui-seed").map(|x| clientpb::Credential { id: x.id, ..Default::default() }).collect();
            println!("[seed] removing {} creds", ids.len());
            let _ = c.creds_rm(clientpb::Credentials { credentials: ids }).await;
        }
        if let Ok(r) = c.loot_all(commonpb::Empty {}).await {
            for l in r.into_inner().loot.into_iter().filter(|l| l.name.starts_with("gui-seed")) {
                println!("[seed] removing loot {}", l.name);
                let _ = c.loot_rm(clientpb::Loot { id: l.id, ..Default::default() }).await;
            }
        }
        let _ = c.delete_implant_profile(clientpb::DeleteReq { name: "gui-seed-linux".into() }).await;
        if let Some(sid) = sid {
            let t = Target::session(sid);
            let _ = c.rm(sliverpb::RmReq { path: "/tmp/gui-seed-tool.sh".into(), recursive: false, force: true, request: Some(t.request(30)) }).await;
            if let Ok(r) = c.hosts(commonpb::Empty {}).await {
                for h in r.into_inner().hosts {
                    for i in h.io_cs.into_iter().filter(|i| i.path.contains("gui-seed")) {
                        println!("[seed] clearing IOC {}", i.path);
                        let _ = c.host_ioc_rm(i).await;
                    }
                }
            }
        }
        return;
    }
    let creds = USERS.iter().map(|(u, p, h, t)| clientpb::Credential {
        username: u.to_string(), plaintext: p.to_string(), hash: h.to_string(), hash_type: *t,
        is_cracked: !p.is_empty(), collection: "gui-seed".into(), ..Default::default()
    }).collect();
    println!("[seed] creds: {:?}", c.creds_add(clientpb::Credentials { credentials: creds }).await.map(|_| "ok").map_err(|e| e.message().to_string()));
    let notes = b"gui-seed notes\nrecon summary for workstation-01\n".to_vec();
    let loot = clientpb::Loot { name: "gui-seed-notes.txt".into(), file_type: clientpb::FileType::Text as i32, size: notes.len() as i64,
        file: Some(commonpb::File { name: "gui-seed-notes.txt".into(), data: notes }), ..Default::default() };
    println!("[seed] loot: {:?}", c.loot_add(loot).await.map(|_| "ok").map_err(|e| e.message().to_string()));
    let ns = 1_000_000_000i64;
    let cfg = clientpb::ImplantConfig {
        goos: "linux".into(), goarch: "amd64".into(), format: 2, is_beacon: true, beacon_interval: 30 * ns, beacon_jitter: 5 * ns,
        c2: vec![clientpb::ImplantC2 { url: "mtls://192.0.2.10:8888".into(), ..Default::default() }],
        include_mtls: true, reconnect_interval: 60 * ns, max_connection_errors: 1000, poll_timeout: 360 * ns,
        template_name: "sliver".into(), httpc2_config_name: "default".into(), limit_hostname: "workstation-01".into(),
        ..Default::default()
    };
    println!("[seed] profile: {:?}", c.save_implant_profile(clientpb::ImplantProfile { id: String::new(), name: "gui-seed-linux".into(), config: Some(cfg) }).await.map(|_| "ok").map_err(|e| e.message().to_string()));
    if let Some(sid) = sid {
        let t = Target::session(sid);
        let up = c.upload(sliverpb::UploadReq { path: "/tmp/gui-seed-tool.sh".into(), data: b"#!/bin/sh\necho seed\n".to_vec(), is_ioc: true, request: Some(t.request(60)), ..Default::default() }).await;
        println!("[seed] ioc upload: {:?}", up.map(|_| "ok").map_err(|e| e.message().to_string()));
    }
}

/// WireGuard in-tunnel SOCKS + port-forward lifecycle (sessions on the wg transport).
pub(super) async fn wg_checks(c: &mut Rpc, sid: &str, rep: &mut Report) {
    let t = Target::session(sid);
    let list = |c: &mut Rpc| {
        let mut c = c.clone();
        let t = t.clone();
        async move {
            let s = c.wg_list_socks_servers(sliverpb::WgSocksServersReq { request: Some(t.request(30)) }).await.map(|r| r.into_inner().servers);
            let f = c.wg_list_forwarders(sliverpb::WgtcpForwardersReq { request: Some(t.request(30)) }).await.map(|r| r.into_inner().forwarders);
            (s.unwrap_or_default(), f.unwrap_or_default())
        }
    };
    match c.wg_start_socks(sliverpb::WgSocksStartReq { port: 3090, request: Some(t.request(30)) }).await {
        Ok(r) => {
            let r = r.into_inner();
            match (err_of(&r.response), r.server) {
                (None, Some(srv)) => {
                    rep.pass("wg-socks-start", format!("id {} on {}", srv.id, srv.local_addr));
                    let (socks, _) = list(c).await;
                    if socks.iter().any(|x| x.id == srv.id) { rep.pass("wg-socks-list", "listed") } else { rep.fail("wg-socks-list", "not listed") }
                    match c.wg_stop_socks(sliverpb::WgSocksStopReq { id: srv.id, request: Some(t.request(30)) }).await {
                        Ok(_) => { let (socks, _) = list(c).await; if socks.iter().any(|x| x.id == srv.id) { rep.fail("wg-socks-stop", "still listed") } else { rep.pass("wg-socks-stop", "stopped + verified") } }
                        Err(e) => rep.fail("wg-socks-stop", e.message()),
                    }
                }
                (e, _) => rep.fail("wg-socks-start", e.unwrap_or_else(|| "no server returned".into())),
            }
        }
        Err(e) => rep.fail("wg-socks-start", e.message()),
    }
    match c.wg_start_port_forward(sliverpb::WgPortForwardStartReq { local_port: 1080, remote_address: "127.0.0.1:22".into(), request: Some(t.request(30)) }).await {
        Ok(r) => {
            let r = r.into_inner();
            match (err_of(&r.response), r.forwarder) {
                (None, Some(f)) => {
                    rep.pass("wg-portfwd-start", format!("id {} {} → {}", f.id, f.local_addr, f.remote_addr));
                    let (_, fwds) = list(c).await;
                    if fwds.iter().any(|x| x.id == f.id) { rep.pass("wg-portfwd-list", "listed") } else { rep.fail("wg-portfwd-list", "not listed") }
                    match c.wg_stop_port_forward(sliverpb::WgPortForwardStopReq { id: f.id, request: Some(t.request(30)) }).await {
                        Ok(_) => { let (_, fwds) = list(c).await; if fwds.iter().any(|x| x.id == f.id) { rep.fail("wg-portfwd-stop", "still listed") } else { rep.pass("wg-portfwd-stop", "stopped + verified") } }
                        Err(e) => rep.fail("wg-portfwd-stop", e.message()),
                    }
                }
                (e, _) => rep.fail("wg-portfwd-start", e.unwrap_or_else(|| "no forwarder returned".into())),
            }
        }
        Err(e) => rep.fail("wg-portfwd-start", e.message()),
    }
}

/// Serve a small and a large file from a throwaway website on its own HTTP
/// listener, download both over plain HTTP and compare the bytes exactly.
pub async fn hosted_download_check(c: &mut Rpc, server: &str, rep: &mut Report) {
    const SITE: &str = "sliver-gui-dltest";
    const PORT: u32 = 9446;
    let small = b"sliver-gui hosted download test\n".to_vec();
    // Non-repeating bytes, so a doubled or cut-off body is detectable. With
    // SLIVER_GUI_HOSTDL_HOLD=<secs> the site stays up afterwards (40 MB file)
    // so another machine can download it too.
    let hold = std::env::var("SLIVER_GUI_HOSTDL_HOLD").ok().and_then(|v| v.parse::<u64>().ok());
    let big_len = if hold.is_some() { 40 << 20 } else { 6 << 20 };
    let mut big = Vec::with_capacity(big_len);
    let mut x: u32 = 0x9e37_79b9;
    while big.len() < big_len {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        big.extend_from_slice(&x.to_le_bytes());
    }
    let files = [("/small.txt", "text/plain", small), ("/big.bin", "application/octet-stream", big)];
    let contents = files.iter().map(|(p, t, d)| (p.to_string(), clientpb::WebContent {
        path: p.to_string(), content_type: t.to_string(), size: d.len() as u64, content: d.clone(), replace_content: true, ..Default::default()
    })).collect();
    if let Err(e) = c.website_add_content(clientpb::WebsiteAddContent { name: SITE.into(), contents }).await {
        return rep.fail("hosted-download", format!("add content: {}", e.message()));
    }
    let job = match c.start_http_listener(clientpb::HttpListenerReq { host: "0.0.0.0".into(), port: PORT, website: SITE.into(), ..Default::default() }).await {
        Ok(r) => r.into_inner().job_id,
        Err(e) => {
            rep.fail("hosted-download", format!("listener: {}", e.message()));
            let _ = c.website_remove(clientpb::Website { name: SITE.into(), ..Default::default() }).await;
            return;
        }
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Plain URLs hit the double-serve bug on Sliver servers older than May 2026;
    // the GUI's download links carry `?v=1`, which must always come back intact.
    let urls: Vec<(String, &Vec<u8>, bool)> = files.iter()
        .flat_map(|(p, _, d)| [(format!("{p}?v=1"), d, true), (p.to_string(), d, false)])
        .collect();
    for (path, want, required) in urls {
        let url = format!("http://{server}:{PORT}{path}");
        let got = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            let resp = ureq::get(&url).timeout(Duration::from_secs(60)).call().map_err(|e| e.to_string())?;
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut resp.into_reader(), &mut buf).map_err(|e| e.to_string())?;
            Ok(buf)
        }).await.map_err(|e| e.to_string()).and_then(|r| r);
        let check = format!("hosted-download {path}");
        match got {
            Ok(b) if b == *want => rep.pass(&check, format!("{} bytes, identical", b.len())),
            Ok(b) if !required && b.len() == want.len() * 2 && b[..want.len()] == want[..] && b[want.len()..] == want[..] =>
                rep.na(&check, "server bug: plain URL serves content twice (fixed upstream May 2026); GUI links add ?v=1"),
            Ok(b) if b.len() == want.len() * 2 && b[..want.len()] == want[..] && b[want.len()..] == want[..] =>
                rep.fail(&check, format!("server sent the content twice ({} bytes for a {}-byte file)", b.len(), want.len())),
            Ok(b) => rep.fail(&check, format!("got {} bytes, expected {}", b.len(), want.len())),
            Err(e) => rep.fail(&check, e),
        }
    }
    if let Some(secs) = hold {
        println!("[selftest] holding http://{server}:{PORT}/big.bin?v=1 ({big_len} bytes) for {secs}s");
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
    let _ = c.kill_job(clientpb::KillJobReq { id: job }).await;
    let _ = c.website_remove(clientpb::Website { name: SITE.into(), ..Default::default() }).await;
}
