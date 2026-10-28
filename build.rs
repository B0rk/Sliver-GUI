use std::path::PathBuf;

// We compile the Sliver protobuf definitions into Rust using `protox` (a pure-Rust
// protobuf compiler) so that no external `protoc` binary is required on the build host.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/commonpb/common.proto",
        "proto/sliverpb/sliver.proto",
        "proto/clientpb/client.proto",
        "proto/rpcpb/services.proto",
    ];
    let includes = ["proto"];

    for p in &protos {
        println!("cargo:rerun-if-changed={p}");
    }

    // Parse the .proto files into a FileDescriptorSet.
    let file_descriptors = protox::compile(protos, includes)?;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("sliver_descriptor.bin");
    std::fs::write(&descriptor_path, {
        use protox::prost::Message;
        file_descriptors.encode_to_vec()
    })?;

    // HTTP C2 profiles are exported/imported as JSON from the GUI.
    let mut builder = tonic_build::configure();
    for ty in [
        "HTTPC2Config", "HTTPC2ServerConfig", "HTTPC2ImplantConfig", "HTTPC2Cookie",
        "HTTPC2Header", "HTTPC2URLParameter", "HTTPC2PathSegment",
    ] {
        builder = builder.type_attribute(
            format!(".clientpb.{ty}"),
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(default)]",
        );
    }

    builder
        .build_server(false)
        .build_client(true)
        .compile_fds(file_descriptors)?;

    Ok(())
}
