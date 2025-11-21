fn main() {
    napi_build::setup();
    println!("cargo:rerun-if-changed=src/lib.rs");
}
