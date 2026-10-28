//! Headless checks for server administration and implant upkeep: certificates,
//! compile targets, builders, AI history, client log, loot rename, credential
//! lookups, hosted-file replace and content type; ping, environment, chown, server-side
//! reverse port-forwards, WASM extensions, service details, and a beacon's
//! interactive session open/close. Driven from `selftest`.

use std::time::Duration;

use super::{Report, Rpc, Target};
use crate::proto::{clientpb, commonpb, sliverpb};

fn err_of(r: &Option<commonpb::Response>) -> Option<String> {
    r.as_ref().map(|x| x.err.clone()).filter(|e| !e.is_empty())
}

/// Host and port of a C2 URL such as `mtls://198.51.100.5:8888` or `https://example.com`.
fn c2_host_port(url: &str) -> Option<(String, u32)> {
    let (scheme, rest) = url.split_once("://")?;
    let hostport = rest.split(['/', '?']).next()?;
    match hostport.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((hostport.to_string(), match scheme { "https" => 443, "http" => 80, _ => return None })),
    }
}

/// An implant build without a handler answers "unknown message type".
fn unsupported(msg: &str) -> bool {
    msg.contains("unknown message type")
}

pub(super) async fn admin_checks(c: &mut Rpc, rep: &mut Report) {
    // ---- certificates / compiler / builders / AI ----
    match c.get_certificate_authority_info(commonpb::Empty {}).await {
        Ok(r) => {
            let ca = r.into_inner().info;
            if ca.is_empty() { rep.fail("ca-info", "no CAs reported") } else { rep.pass("ca-info", format!("{} CAs ({})", ca.len(), ca.iter().map(|x| x.r#type.as_str()).collect::<Vec<_>>().join(", "))) }
        }
        Err(e) => rep.fail("ca-info", e.message()),
    }
    match c.get_certificate_info(clientpb::CertificatesReq::default()).await {
        Ok(r) => rep.pass("certificate-info", format!("{} certificates", r.into_inner().info.len())),
        Err(e) => rep.fail("certificate-info", e.message()),
    }
    match c.get_compiler(commonpb::Empty {}).await {
        Ok(r) => {
            let cc = r.into_inner();
            if cc.targets.is_empty() { rep.fail("compiler", "no targets") } else { rep.pass("compiler", format!("host {}/{}, {} targets, {} cross-compilers", cc.goos, cc.goarch, cc.targets.len(), cc.cross_compilers.len())) }
        }
        Err(e) => rep.fail("compiler", e.message()),
    }
    match c.builders(commonpb::Empty {}).await {
        Ok(r) => rep.pass("builders", format!("{} external builders", r.into_inner().builders.len())),
        Err(e) => rep.fail("builders", e.message()),
    }
    match c.get_ai_providers(commonpb::Empty {}).await {
        Ok(r) => rep.pass("ai-providers", format!("{} providers", r.into_inner().providers.len())),
        Err(e) => rep.fail("ai-providers", e.message()),
    }
    match c.get_ai_conversations(commonpb::Empty {}).await {
        Ok(r) => rep.pass("ai-conversations", format!("{} saved", r.into_inner().conversations.len())),
        Err(e) => rep.fail("ai-conversations", e.message()),
    }

    // ---- client log stream ----
    let line = clientpb::ClientLogData { stream: "sliver-gui".into(), data: b"sliver-gui battery: client log check\n".to_vec() };
    // The server writes the stream to logs/clients/<operator>/ and ends the call
    // without a reply message, which tonic reports as "Missing response message".
    match c.client_log(tokio_stream::iter(vec![line])).await {
        Ok(_) => rep.pass("client-log", "1 line streamed"),
        Err(e) if e.message().contains("Missing response message") => rep.pass("client-log", "1 line streamed (server closes without a reply)"),
        Err(e) => rep.fail("client-log", e.message()),
    }

    // ---- credential lookups ----
    // The sniffer only names unambiguous formats; bare hex (NTLM/MD5/SHA1) comes back INVALID.
    const NTLM: &str = "8846f7eaee8fb117ad06bdd830b7586c";
    const SHA512CRYPT: &str = "$6$rounds=5000$saltsalt$Zh1R8Uq/2uT2E0yH6r5K2C7gJk3Bq9cWJ0nqFQ2rS9eZ1C8kQb4b7XbL5bF8y6m3c0vX2bR7aQ9zM6nP1tS4u.";
    match c.creds_sniff_hash_type(clientpb::Credential { hash: SHA512CRYPT.into(), ..Default::default() }).await {
        Ok(r) => {
            let t = r.into_inner().hash_type;
            if t == clientpb::HashType::Sha512CryptUnix as i32 { rep.pass("creds-sniff-hash-type", "sha512crypt recognised") } else { rep.fail("creds-sniff-hash-type", format!("sha512crypt sample → type {t}")) }
        }
        Err(e) => rep.fail("creds-sniff-hash-type", e.message()),
    }
    let user = "gui-battery-cred";
    let cred = clientpb::Credential { username: user.into(), hash: NTLM.into(), hash_type: clientpb::HashType::Ntlm as i32, collection: "battery".into(), ..Default::default() };
    match c.creds_add(clientpb::Credentials { credentials: vec![cred] }).await {
        Ok(_) => {
            let id = c.creds(commonpb::Empty {}).await.ok()
                .and_then(|r| r.into_inner().credentials.into_iter().find(|x| x.username == user).map(|x| x.id))
                .unwrap_or_default();
            match c.get_creds_by_hash_type(clientpb::Credential { hash_type: clientpb::HashType::Ntlm as i32, ..Default::default() }).await {
                Ok(r) => {
                    let list = r.into_inner().credentials;
                    if list.iter().any(|x| x.id == id) { rep.pass("creds-by-hash-type", format!("{} NTLM creds, test cred included", list.len())) }
                    else { rep.fail("creds-by-hash-type", "test cred missing from NTLM filter") }
                }
                Err(e) => rep.fail("creds-by-hash-type", e.message()),
            }
            match c.get_cred_by_id(clientpb::Credential { id: id.clone(), ..Default::default() }).await {
                Ok(r) => {
                    let x = r.into_inner();
                    if x.username == user && x.hash == NTLM { rep.pass("cred-by-id", user) } else { rep.fail("cred-by-id", format!("got {:?}", x.username)) }
                }
                Err(e) => rep.fail("cred-by-id", e.message()),
            }
            let _ = c.creds_rm(clientpb::Credentials { credentials: vec![clientpb::Credential { id, ..Default::default() }] }).await;
        }
        Err(e) => rep.fail("creds-add(battery)", e.message()),
    }

    // ---- loot rename ----
    let name = "gui-battery-loot.txt";
    let loot = clientpb::Loot {
        name: name.into(), file_type: clientpb::FileType::Text as i32, size: 5,
        file: Some(commonpb::File { name: name.into(), data: b"hello".to_vec() }), ..Default::default()
    };
    match c.loot_add(loot).await {
        Ok(r) => {
            let id = r.into_inner().id;
            let renamed = "gui-battery-renamed.txt";
            match c.loot_update(clientpb::Loot { id: id.clone(), name: renamed.into(), ..Default::default() }).await {
                Ok(_) => {
                    let listed = c.loot_all(commonpb::Empty {}).await.ok()
                        .and_then(|r| r.into_inner().loot.into_iter().find(|l| l.id == id)).map(|l| l.name).unwrap_or_default();
                    if listed == renamed { rep.pass("loot-update(rename)", renamed) } else { rep.fail("loot-update(rename)", format!("listed as {listed:?}")) }
                }
                Err(e) => rep.fail("loot-update(rename)", e.message()),
            }
            let _ = c.loot_rm(clientpb::Loot { id, ..Default::default() }).await;
        }
        Err(e) => rep.fail("loot-add(battery)", e.message()),
    }

    // ---- hosted file replace ----
    let site = "sliver-gui-replace-test".to_string();
    let path = "/replace.txt".to_string();
    let content = |data: &[u8]| clientpb::WebContent { path: path.clone(), content_type: "text/plain".into(), size: data.len() as u64, content: data.to_vec(), ..Default::default() };
    match c.website_add_content(clientpb::WebsiteAddContent { name: site.clone(), contents: [(path.clone(), content(b"v1"))].into() }).await {
        Ok(_) => {
            let listed = |c: &mut Rpc| {
                let mut c = c.clone();
                let (site, path) = (site.clone(), path.clone());
                async move {
                    super::list_websites(&mut c).await.ok()
                        .and_then(|s| s.into_iter().find(|w| w.name == site))
                        .and_then(|w| w.contents.into_values().find(|x| x.path == path)).map(|x| (x.content_type, x.size))
                }
            };
            // Replace the bytes (what the GUI's ⟳ does) …
            let v2 = b"version two, longer";
            match c.website_add_content(clientpb::WebsiteAddContent { name: site.clone(), contents: [(path.clone(), clientpb::WebContent { replace_content: true, ..content(v2) })].into() }).await {
                Ok(_) => match listed(c).await {
                    Some((_, n)) if n == v2.len() as u64 => rep.pass("website-replace-content", format!("{path} now {n} bytes")),
                    other => rep.fail("website-replace-content", format!("after replace {other:?}")),
                },
                Err(e) => rep.fail("website-replace-content", e.message()),
            }
            // … then change only the content type.
            let ct = clientpb::WebContent { path: path.clone(), content_type: "application/octet-stream".into(), ..Default::default() };
            match c.website_update_content(clientpb::WebsiteAddContent { name: site.clone(), contents: [(path.clone(), ct)].into() }).await {
                Ok(_) => match listed(c).await {
                    Some((t, n)) if t == "application/octet-stream" && n == v2.len() as u64 => rep.pass("website-update-content", "content type changed, bytes kept"),
                    other => rep.fail("website-update-content", format!("after update {other:?}")),
                },
                Err(e) => rep.fail("website-update-content", e.message()),
            }
            let _ = c.website_remove(clientpb::Website { name: site, ..Default::default() }).await;
        }
        Err(e) => rep.fail("website-add(replace-test)", e.message()),
    }

}

/// Per-session upkeep checks.
pub(super) async fn session_upkeep(c: &mut Rpc, sid: &str, is_win: bool, rep: &mut Report) {
    let t = Target::session(sid);
    let req = |secs| Some(t.request(secs));

    match c.ping(sliverpb::Ping { nonce: 4242, response: None, request: req(30) }).await {
        Ok(r) => { let r = r.into_inner(); if r.nonce == 4242 { rep.pass("ping", "nonce echoed") } else { rep.fail("ping", format!("nonce {}", r.nonce)) } }
        Err(e) => rep.fail("ping", e.message()),
    }

    // ---- environment set → read → unset ----
    // Read the whole environment: a by-name lookup always answers, with "" once unset.
    let key = "SLIVER_GUI_BATTERY";
    let read = |c: &mut Rpc| {
        let mut c = c.clone();
        let r = req(30);
        async move {
            c.get_env(sliverpb::EnvReq { name: String::new(), request: r }).await.ok()
                .map(|v| v.into_inner().variables.into_iter().find(|x| x.key == key).map(|x| x.value))
        }
    };
    match c.set_env(sliverpb::SetEnvReq { variable: Some(commonpb::EnvVar { key: key.into(), value: "on".into() }), request: req(30) }).await {
        Ok(r) => match err_of(&r.into_inner().response) {
            Some(e) => rep.fail("setenv", e),
            None => match read(c).await {
                Some(Some(v)) if v == "on" => rep.pass("setenv", format!("{key}=on read back")),
                other => rep.fail("setenv", format!("read back {other:?}")),
            },
        },
        Err(e) if unsupported(e.message()) => rep.na("setenv", "handler not in this implant build"),
        Err(e) => rep.fail("setenv", e.message()),
    }
    match c.unset_env(sliverpb::UnsetEnvReq { name: key.into(), request: req(30) }).await {
        Ok(r) => match err_of(&r.into_inner().response) {
            Some(e) => rep.fail("unsetenv", e),
            None => match read(c).await {
                Some(None) => rep.pass("unsetenv", format!("{key} gone")),
                other => rep.fail("unsetenv", format!("still present: {other:?}")),
            },
        },
        Err(e) if unsupported(e.message()) => rep.na("unsetenv", "handler not in this implant build"),
        Err(e) => rep.fail("unsetenv", e.message()),
    }

    // ---- chown (unix): a scratch file to the implant's own user:group (names, not ids) ----
    if is_win {
        rep.na("chown", "unix only");
    } else {
        let path = "/tmp/gui_bat_chown.txt";
        let ids = c.execute(sliverpb::ExecuteReq { path: "/usr/bin/id".into(), args: vec!["-un".into()], output: true, request: req(30), ..Default::default() }).await.ok()
            .map(|r| String::from_utf8_lossy(&r.into_inner().stdout).trim().to_string());
        let gid = c.execute(sliverpb::ExecuteReq { path: "/usr/bin/id".into(), args: vec!["-gn".into()], output: true, request: req(30), ..Default::default() }).await.ok()
            .map(|r| String::from_utf8_lossy(&r.into_inner().stdout).trim().to_string());
        let up = c.upload(sliverpb::UploadReq { path: path.into(), data: b"chown".to_vec(), request: req(30), ..Default::default() }).await;
        match (ids, gid, up) {
            (Some(uid), Some(gid), Ok(_)) => {
                match c.chown(sliverpb::ChownReq { path: path.into(), uid: uid.clone(), gid: gid.clone(), recursive: false, request: req(30) }).await {
                    Ok(r) => match err_of(&r.into_inner().response) {
                        Some(e) => rep.fail("chown", e),
                        None => rep.pass("chown", format!("{uid}:{gid} {path}")),
                    },
                    Err(e) if unsupported(e.message()) => rep.na("chown", "handler not in this implant build"),
                    Err(e) => rep.fail("chown", e.message()),
                }
                let _ = c.rm(sliverpb::RmReq { path: path.into(), request: req(30), ..Default::default() }).await;
            }
            _ => rep.fail("chown", "could not prepare the scratch file"),
        }
    }

    // ---- local port-forward request: the implant dials its own C2 address over a fresh
    //      tunnel (catches protocol-value changes such as v1.7.9 rejecting 0) ----
    let c2 = c.get_sessions(commonpb::Empty {}).await.ok()
        .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id == sid)).map(|s| s.active_c2).unwrap_or_default();
    match c2_host_port(&c2) {
        None => rep.na("portfwd(request)", format!("can't read a host:port from {c2:?}")),
        Some((host, port)) => match c.create_tunnel(sliverpb::Tunnel { session_id: sid.into(), ..Default::default() }).await {
            Err(e) => rep.fail("portfwd(request)", format!("create tunnel: {}", e.message())),
            Ok(tn) => {
                let tid = tn.into_inner().tunnel_id;
                // Bind the tunnel on a TunnelData stream (primed with its bind frame) and
                // wait for the server's bind ack, as the GUI's port-forward path does.
                let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<sliverpb::TunnelData>();
                let _ = out_tx.send(sliverpb::TunnelData { tunnel_id: tid, session_id: sid.into(), ..Default::default() });
                let mut cc = c.clone();
                if let Ok(Ok(resp)) = tokio::time::timeout(Duration::from_secs(10), cc.tunnel_data(tokio_stream::wrappers::UnboundedReceiverStream::new(out_rx))).await {
                    let mut stream = resp.into_inner();
                    let _ = tokio::time::timeout(Duration::from_secs(10), stream.message()).await;
                    tokio::spawn(async move { while let Ok(Some(_)) = stream.message().await {} });
                }
                match c.portfwd(sliverpb::PortfwdReq { port, protocol: super::PORTFWD_TCP, host: host.clone(), keep_alive: -1, tunnel_id: tid, request: req(30) }).await {
                    Ok(r) => match err_of(&r.into_inner().response) {
                        Some(e) => rep.fail("portfwd(request)", e),
                        None => rep.pass("portfwd(request)", format!("implant accepted TCP forward to {host}:{port}")),
                    },
                    Err(e) => rep.fail("portfwd(request)", e.message()),
                }
                let _ = out_tx.send(sliverpb::TunnelData { tunnel_id: tid, session_id: sid.into(), closed: true, ..Default::default() });
                let _ = c.close_tunnel(sliverpb::Tunnel { tunnel_id: tid, session_id: sid.into(), ..Default::default() }).await;
            }
        },
    }

    match c.get_rport_fwd_listeners(sliverpb::RportFwdListenersReq { request: req(30) }).await {
        Ok(r) => rep.pass("rportfwd-listeners", format!("{} on this implant", r.into_inner().listeners.len())),
        Err(e) if unsupported(e.message()) => rep.na("rportfwd-listeners", "handler not in this implant build"),
        Err(e) => rep.fail("rportfwd-listeners", e.message()),
    }
    match c.list_wasm_extensions(sliverpb::ListWasmExtensionsReq { request: req(30) }).await {
        Ok(r) => rep.pass("wasm-list", format!("{} loaded", r.into_inner().names.len())),
        Err(e) if unsupported(e.message()) => rep.na("wasm-list", "handler not in this implant build"),
        Err(e) => rep.fail("wasm-list", e.message()),
    }
    if is_win {
        match c.service_detail(sliverpb::ServiceDetailReq {
            service_info: Some(sliverpb::ServiceInfoReq { service_name: "Spooler".into(), hostname: String::new() }), request: req(60),
        }).await {
            Ok(r) => {
                let r = r.into_inner();
                match (err_of(&r.response), r.detail) {
                    (Some(e), _) => rep.fail("service-detail", e),
                    (None, Some(d)) if !d.bin_path.is_empty() => rep.pass("service-detail", format!("Spooler → {}", d.bin_path)),
                    (None, other) => rep.fail("service-detail", format!("no binary path: {other:?}")),
                }
            }
            Err(e) => rep.fail("service-detail", e.message()),
        }
        // A throwaway service (never started) created with sc.exe, then removed over RPC.
        let svc = "SliverGuiBatterySvc";
        let created = c.execute(sliverpb::ExecuteReq {
            path: "C:\\Windows\\System32\\sc.exe".into(),
            args: ["create", svc, "binPath=", "C:\\Windows\\System32\\cmd.exe", "start=", "demand"].map(String::from).to_vec(),
            output: true, request: req(30), ..Default::default()
        }).await.ok().map(|r| String::from_utf8_lossy(&r.into_inner().stdout).to_string()).unwrap_or_default();
        if !created.contains("SUCCESS") {
            rep.na("remove-service", format!("sc create needs an elevated session: {}", created.trim()));
        } else {
            match c.remove_service(sliverpb::RemoveServiceReq {
                service_info: Some(sliverpb::ServiceInfoReq { service_name: svc.into(), hostname: String::new() }), request: req(60),
            }).await {
                Ok(r) => match err_of(&r.into_inner().response) {
                    Some(e) => rep.fail("remove-service", e),
                    None => {
                        let gone = c.execute(sliverpb::ExecuteReq {
                            path: "C:\\Windows\\System32\\sc.exe".into(), args: vec!["query".into(), svc.into()],
                            output: true, request: req(30), ..Default::default()
                        }).await.ok().map(|r| String::from_utf8_lossy(&r.into_inner().stdout).contains("1060")).unwrap_or(false);
                        if gone { rep.pass("remove-service", format!("{svc} created by sc.exe, removed")) } else { rep.fail("remove-service", "service still registered") }
                    }
                },
                Err(e) => rep.fail("remove-service", e.message()),
            }
        }
    } else {
        rep.na("service-detail", "Windows only");
        rep.na("remove-service", "Windows only");
    }
}

/// Beacon upkeep: re-read the record, then open an interactive session over the
/// beacon's C2, confirm it registers, and close it again.
pub(super) async fn beacon_upkeep(c: &mut Rpc, bid: &str, polls: usize, rep: &mut Report) {
    let b = match c.get_beacon(clientpb::Beacon { id: bid.into(), ..Default::default() }).await {
        Ok(r) => {
            let b = r.into_inner();
            if b.id == bid { rep.pass("get-beacon", format!("{} on {} via {}", b.name, b.hostname, b.active_c2)) } else { rep.fail("get-beacon", "wrong record") }
            b
        }
        Err(e) => { rep.fail("get-beacon", e.message()); return; }
    };
    let before: Vec<String> = c.get_sessions(commonpb::Empty {}).await.map(|r| r.into_inner().sessions.into_iter().map(|s| s.id).collect()).unwrap_or_default();
    let t = Target::beacon(bid);
    match c.open_session(sliverpb::OpenSession { c2s: vec![b.active_c2.clone()], delay: 0, response: None, request: Some(t.request(60)) }).await {
        Ok(r) => match err_of(&r.into_inner().response) {
            Some(e) => { rep.fail("open-session", e); return; }
            None => rep.pass("open-session", "queued"),
        },
        Err(e) => { rep.fail("open-session", e.message()); return; }
    }
    let mut new_sid = None;
    for _ in 0..polls {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Ok(r) = c.get_sessions(commonpb::Empty {}).await {
            if let Some(s) = r.into_inner().sessions.into_iter().find(|s| !before.contains(&s.id) && s.uuid == b.uuid) {
                new_sid = Some(s.id);
                break;
            }
        }
    }
    let Some(sid) = new_sid else { rep.fail("open-session(registered)", format!("no session within ~{}s", polls * 2)); return; };
    rep.pass("open-session(registered)", format!("session {}", super::short_id(&sid)));
    let st = Target::session(&sid);
    match c.close_session(sliverpb::CloseSession { response: None, request: Some(st.request(30)) }).await {
        Ok(_) => {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let alive = c.get_sessions(commonpb::Empty {}).await.ok()
                .and_then(|r| r.into_inner().sessions.into_iter().find(|s| s.id == sid)).is_some_and(|s| !s.is_dead);
            if alive { rep.fail("close-session", "session still listed as alive") } else { rep.pass("close-session", "session gone; beacon keeps checking in") }
        }
        Err(e) => rep.fail("close-session", e.message()),
    }
}
