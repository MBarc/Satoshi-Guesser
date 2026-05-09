extern crate napi_build;

use std::path::PathBuf;

fn main() {
    napi_build::setup();

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wrapper_dir = manifest_dir.join("c-wrapper");

    let mut build = cc::Build::new();
    build
        .file(wrapper_dir.join("wrapper.c"))
        .opt_level(3)
        .warnings(true);

    // ripemd160_8way uses AVX2 intrinsics; enable them on the C side.
    // The production runner is Intel Xeon Platinum 8370C (avx2 + avx512 +
    // sha_ni), so AVX2 is always available.
    if !cfg!(target_os = "windows") {
        build.flag("-mavx2");
    }

    build.compile("sgn_wrapper");

    println!("cargo:rerun-if-changed=c-wrapper/wrapper.c");
}
