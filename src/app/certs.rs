//! TLS certificates for HTTPS listeners: generate a self-signed pair locally
//! (saved under the data directory) or summarise a PEM pair the operator
//! picked, so the listener dialog can hand Sliver its own cert and key.

use std::path::{Path, PathBuf};

use super::ListenerForm;
use crate::theme::Palette;

/// The HTTPS-listener certificate section of the listener dialog.
pub(super) fn listener_cert_ui(ui: &mut egui::Ui, f: &mut ListenerForm, srv_lhost: &str) {
    ui.horizontal(|ui| {
        ui.label("Certificate");
        ui.radio_value(&mut f.tls, 0, "Sliver self-signed").on_hover_text("Sliver generates a throwaway self-signed certificate");
        ui.radio_value(&mut f.tls, 1, "Certificate files").on_hover_text("Use a PEM certificate + key: generate one below or pick your own");
        ui.radio_value(&mut f.tls, 2, "Let's Encrypt").on_hover_text("Sliver requests a real certificate for the Domain");
    });
    match f.tls {
        1 => {
            for (label, path, filter) in [("Cert (PEM)", &mut f.cert, ["crt", "pem", "cer"]), ("Key (PEM) ", &mut f.key, ["key", "pem", "pem"])] {
                ui.horizontal(|ui| {
                    ui.label(label);
                    ui.add(egui::TextEdit::singleline(path).desired_width(250.0).hint_text("path, or generate one below"));
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().add_filter("PEM", &filter).pick_file() {
                            *path = p.display().to_string();
                        }
                    }
                });
            }
            if !f.cert.trim().is_empty() {
                match fingerprint(f.cert.trim()) {
                    Some(fp) => { ui.colored_label(Palette::muted(), format!("SHA-256 {}…", &fp[..23])).on_hover_text(fp); }
                    None => { ui.colored_label(Palette::red(), "Can't read a PEM certificate from that file."); }
                }
            }
            egui::CollapsingHeader::new("Generate a self-signed certificate").id_salt("listener-gencert").default_open(f.cert.trim().is_empty()).show(ui, |ui| {
                let default_cn = if !f.domain.trim().is_empty() { f.domain.split(',').next().unwrap_or("").trim().to_string() } else { srv_lhost.to_string() };
                ui.horizontal(|ui| {
                    ui.label("Name (CN)  ");
                    ui.add(egui::TextEdit::singleline(&mut f.cert_cn).desired_width(240.0).hint_text(&default_cn))
                        .on_hover_text("The name implants connect to: the listener's domain or the server's IP");
                });
                ui.horizontal(|ui| {
                    ui.label("Other names");
                    ui.add(egui::TextEdit::singleline(&mut f.cert_sans).desired_width(240.0).hint_text("comma-separated DNS names / IPs"));
                });
                ui.horizontal(|ui| {
                    ui.label("Valid for");
                    ui.add(egui::DragValue::new(&mut f.cert_days).range(1..=3650).suffix(" days"));
                });
                if ui.button("Generate").clicked() {
                    let cn = if f.cert_cn.trim().is_empty() { default_cn } else { f.cert_cn.trim().to_string() };
                    let sans: Vec<String> = f.cert_sans.split(',').map(|s| s.trim().to_string()).collect();
                    f.cert_msg = Some(match cert_dir().ok_or_else(|| "no data directory".to_string()).and_then(|d| generate(&cn, &sans, f.cert_days, &d)) {
                        Ok((crt, key)) => {
                            f.cert = crt.display().to_string();
                            f.key = key.display().to_string();
                            (true, format!("Generated {} and its key.", crt.display()))
                        }
                        Err(e) => (false, format!("Couldn't generate: {e}")),
                    });
                }
            });
            if let Some((ok, msg)) = &f.cert_msg {
                ui.colored_label(if *ok { Palette::green() } else { Palette::red() }, msg);
            }
        }
        2 => {
            ui.colored_label(if f.domain.trim().is_empty() { Palette::yellow() } else { Palette::muted() },
                "Needs the Domain above to resolve publicly to this server, with TCP 80 reachable for the challenge.");
        }
        _ => {}
    }
    ui.colored_label(Palette::muted(), "Implants don't check this certificate (Sliver encrypts C2 traffic itself). \
        Build them against https://<the certificate's name>:<port>.");
}

/// Whether the certificate settings are complete enough to start the listener.
pub(super) fn cert_ready(f: &ListenerForm) -> bool {
    !f.secure || match f.tls { 1 => !f.cert.trim().is_empty() && !f.key.trim().is_empty(), 2 => !f.domain.trim().is_empty(), _ => true }
}

/// Where generated pairs are written.
pub(crate) fn cert_dir() -> Option<PathBuf> {
    crate::settings::data_dir().map(|d| d.join("certs"))
}

/// Generate a self-signed ECDSA P-256 certificate for `cn` (plus `sans`,
/// IPs or DNS names) valid for `days`, and write `<cn>.crt` / `<cn>.key`
/// into `dir`. Returns the two paths.
pub(crate) fn generate(cn: &str, sans: &[String], days: u32, dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let cn = cn.trim();
    if cn.is_empty() { return Err("common name is empty".into()); }
    let mut names: Vec<String> = vec![cn.to_string()];
    for s in sans.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !names.iter().any(|n| n.eq_ignore_ascii_case(s)) { names.push(s.to_string()); }
    }
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = names.iter().map(|n| match n.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(rcgen::SanType::IpAddress(ip)),
        Err(_) => rcgen::Ia5String::try_from(n.as_str()).map(rcgen::SanType::DnsName).map_err(|e| format!("{n}: {e}")),
    }).collect::<Result<_, _>>()?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let ymd = |d: chrono::DateTime<chrono::Utc>| {
        use chrono::Datelike;
        rcgen::date_time_ymd(d.year(), d.month() as u8, d.day() as u8)
    };
    let now = chrono::Utc::now();
    params.not_before = ymd(now - chrono::Duration::days(1));
    params.not_after = ymd(now + chrono::Duration::days(days.max(1) as i64));
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;

    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let stem: String = cn.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect();
    let (crt, kp) = (dir.join(format!("{stem}.crt")), dir.join(format!("{stem}.key")));
    std::fs::write(&crt, cert.pem()).map_err(|e| format!("{}: {e}", crt.display()))?;
    write_private(&kp, key.serialize_pem().as_bytes()).map_err(|e| format!("{}: {e}", kp.display()))?;
    Ok((crt, kp))
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

/// Read and sanity-check a PEM cert/key pair for a listener request.
pub fn load_pair(cert: &str, key: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let c = std::fs::read(cert).map_err(|e| format!("certificate {cert}: {e}"))?;
    let k = std::fs::read(key).map_err(|e| format!("key {key}: {e}"))?;
    if first_cert_der(&c).is_none() { return Err(format!("{cert} has no PEM certificate")); }
    if !String::from_utf8_lossy(&k).contains("PRIVATE KEY-----") { return Err(format!("{key} has no PEM private key")); }
    Ok((c, k))
}

fn first_cert_der(pem: &[u8]) -> Option<Vec<u8>> {
    rustls_pemfile::certs(&mut &pem[..]).next()?.ok().map(|d| d.to_vec())
}

/// "SHA-256 AB:CD:… " fingerprint of a PEM file's first certificate.
pub(crate) fn fingerprint(cert: &str) -> Option<String> {
    let der = first_cert_der(&std::fs::read(cert).ok()?)?;
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &der);
    Some(d.as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pair_loads_and_has_a_fingerprint() {
        let dir = std::env::temp_dir().join(format!("sliver-gui-cert-test-{}", std::process::id()));
        let (crt, key) = generate("c2.example.com", &["192.0.2.10".into(), "C2.example.com".into()], 30, &dir).unwrap();
        let (c, k) = load_pair(&crt.display().to_string(), &key.display().to_string()).unwrap();
        assert!(String::from_utf8_lossy(&c).starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(String::from_utf8_lossy(&k).contains("PRIVATE KEY-----"));
        assert_eq!(fingerprint(&crt.display().to_string()).unwrap().len(), 32 * 3 - 1);
        assert!(load_pair(&key.display().to_string(), &key.display().to_string()).is_err());
        assert!(generate(" ", &[], 30, &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
