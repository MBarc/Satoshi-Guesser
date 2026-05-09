extern crate napi_build;

use std::path::PathBuf;

fn main() {
    napi_build::setup();

    // Compile our C wrapper that will (eventually) expose libsecp256k1
    // internal functions for batched modular inversion. Today this is just
    // a stub returning a known sentinel value to verify the build pipeline.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wrapper_dir = manifest_dir.join("c-wrapper");

    cc::Build::new()
        .file(wrapper_dir.join("wrapper.c"))
        .opt_level(3)
        .warnings(true)
        .compile("sgn_wrapper");

    println!("cargo:rerun-if-changed=c-wrapper/wrapper.c");
}
