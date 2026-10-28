#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Sliver GUI — a graphical operator client for the Sliver C2 framework.

mod app;
mod armory;
mod client;
mod config;
mod deps;
mod settings;
mod theme;
mod tls;

/// Generated protobuf + gRPC bindings for the Sliver operator API.
pub mod proto {
    pub mod commonpb {
        tonic::include_proto!("commonpb");
    }
    pub mod sliverpb {
        tonic::include_proto!("sliverpb");
    }
    pub mod clientpb {
        tonic::include_proto!("clientpb");
    }
    pub mod rpcpb {
        tonic::include_proto!("rpcpb");
    }
}

fn main() -> eframe::Result<()> {
    // rustls needs a process-wide crypto provider installed before first use.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Hidden headless connection self-test against a live server (no GUI).
    if let Ok(path) = std::env::var("SLIVER_GUI_CONNECT_TEST") {
        match config::OperatorConfig::load_file(std::path::Path::new(&path)) {
            Ok(cfg) => client::selftest(cfg),
            Err(e) => println!("[selftest] config load failed: {e:#}"),
        }
        std::process::exit(0);
    }

    // Hidden offline self-test of the armory client (no GUI).
    if std::env::var("SLIVER_GUI_ARMORY_TEST").is_ok() {
        match armory::fetch_index(armory::DEFAULT_REPO_URL, armory::OFFICIAL_PUBLIC_KEY) {
            Ok(idx) => {
                println!("index OK: {} extensions, {} aliases", idx.extensions.len(), idx.aliases.len());
                for e in idx.extensions.iter().take(8) {
                    println!("  ext {} (cmd {})", e.name, e.command_name);
                }
            }
            Err(e) => println!("armory error: {e:#}"),
        }
        if let Ok(name) = std::env::var("SLIVER_GUI_ARMORY_INSTALL") {
            match armory::fetch_index(armory::DEFAULT_REPO_URL, armory::OFFICIAL_PUBLIC_KEY) {
                Ok(idx) => {
                    if let Some(pkg) = idx.extensions.iter().find(|e| e.command_name == name) {
                        match armory::install_extension(pkg) {
                            Ok(inst) => println!("installed {} v{} → {} ({} files, bof={})",
                                inst.name, inst.version, inst.root.display(), inst.files.len(), inst.is_bof),
                            Err(e) => println!("install error: {e:#}"),
                        }
                    } else {
                        println!("package {name} not found");
                    }
                }
                Err(e) => println!("index error: {e:#}"),
            }
        }
        std::process::exit(0);
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 880.0])
            .with_min_inner_size([960.0, 600.0])
            .with_title("Sliver GUI"),
        ..Default::default()
    };

    eframe::run_native(
        "Sliver GUI",
        native_options,
        Box::new(|cc| Ok(Box::new(app::SliverApp::new(cc)))),
    )
}
