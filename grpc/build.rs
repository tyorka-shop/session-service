fn main() {
    let proto_file = "./proto/session-service.proto";
    tonic_build::configure()
        .file_descriptor_set_path("./src/description.bin")
        .build_client(true)
        .build_server(true)
        .out_dir("./src")
        .compile(&[proto_file], &["."])
        .unwrap_or_else(|e| panic!("protobuf compile error: {}", e));
    println!("cargo:rerun-if-changed={}", proto_file);
}
