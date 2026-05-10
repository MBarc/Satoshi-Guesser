extern crate napi_build;

use std::path::PathBuf;

fn main() {
    napi_build::setup();

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wrapper_dir = manifest_dir.join("c-wrapper");
    let libsecp_dir = wrapper_dir.join("libsecp256k1");
    let libsecp_inc = libsecp_dir.join("include");
    let libsecp_src = libsecp_dir.join("src");

    let mut build = cc::Build::new();
    build
        .file(wrapper_dir.join("wrapper.c"))
        .include(&libsecp_inc)
        .include(&libsecp_src)
        .include(&libsecp_dir)
        .opt_level(3)
        .warnings(false) // libsecp emits a few benign -Wstrict-prototypes warnings
        // libsecp config — values match what secp256k1-sys uses upstream.
        .define("ECMULT_WINDOW_SIZE", Some("15"))
        .define("ECMULT_GEN_PREC_BITS", Some("4"))
        .define("USE_FIELD_5X52", Some("1"))
        .define("USE_SCALAR_4X64", Some("1"))
        .define("USE_FORCE_WIDEMUL_INT128", Some("1"))
        .define("SECP256K1_BUILD", None);

    // ripemd160_8way uses AVX2 intrinsics; sha256_pubkey_ni uses Intel SHA
    // extensions (-msha enables _mm_sha256rnds2_epu32 etc.). Production
    // runners are Xeon Platinum 8370C (avx2, sha_ni, avx512), so both are
    // always available. -msse4.1 is implied by -mavx2 but spelled explicitly
    // since SHA-NI depends on it.
    if !cfg!(target_os = "windows") {
        build.flag("-mavx2").flag("-msha").flag("-msse4.1");
    }

    build.compile("sgn_wrapper");

    println!("cargo:rerun-if-changed=c-wrapper");
}
