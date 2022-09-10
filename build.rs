fn main() {
    let proto_file = "./proto/session-service.proto";
    tonic_build::configure()
        .file_descriptor_set_path("./src/grpc/description.bin")
        .build_server(true)
        .out_dir("./src/grpc")
        .compile(&[proto_file], &["."])
        .unwrap_or_else(|e| panic!("protobuf compile error: {}", e));
    println!("cargo:rerun-if-changed={}", proto_file);
}
