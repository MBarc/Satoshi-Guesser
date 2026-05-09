#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use ripemd::{Digest as _, Ripemd160};
use sha2::{Digest as _, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use k256::elliptic_curve::point::BatchNormalize;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};

/* =============================================================
 * FFI surface against c-wrapper/wrapper.c
 * ============================================================= */

#[repr(C)]
struct CMatch {
    found: u32,
    batch_offset: u32,
    priv_key: [u8; 32],
    hash160: [u8; 20],
}

extern "C" {
    fn sgn_wrapper_sentinel() -> u32;

    /// EC-only path: writes N × 64 bytes (32B BE x || 32B BE y) into out_xy.
    /// Kept for cross-validation tests and as a fallback.
    fn sgn_compute_affine_batch(k0_bytes: *const u8, n: u32, out_xy: *mut u8) -> i32;

    /// 8-way AVX2 RIPEMD-160 (kept for tests).
    fn ripemd160_8way(in_8x32: *const u8, out_8x20: *mut u8);

    /// SHA-NI single-input two-block compress over a 65-byte uncompressed
    /// pubkey -> 32-byte digest.
    fn sha256_pubkey_ni(out: *mut u8, pub65: *const u8);

    /// Initialize the process-global target table. Idempotent.
    fn sgn_set_targets(targets: *const u8, n_targets: u32);

    /// Unified hot path: EC + SHA-NI + 8-way RIPEMD + target lookup, all in C.
    /// Returns 1 if a match was found (out_match populated), 0 otherwise.
    fn sgn_search_batch(k0_bytes: *const u8, n: u32, out_match: *mut CMatch) -> i32;
}

#[napi]
pub fn c_wrapper_alive() -> bool {
    let sentinel = unsafe { sgn_wrapper_sentinel() };
    sentinel == 0xCAFE_BABE
}

/* =============================================================
 * One-time target table init (idempotent across worker_threads)
 * ============================================================= */

static TARGETS_SET: OnceLock<()> = OnceLock::new();

fn ensure_targets_loaded(targets: &[Buffer]) {
    TARGETS_SET.get_or_init(|| {
        let mut flat: Vec<u8> = Vec::with_capacity(targets.len() * 20);
        for t in targets {
            if t.len() == 20 {
                flat.extend_from_slice(t);
            }
        }
        unsafe {
            sgn_set_targets(flat.as_ptr(), (flat.len() / 20) as u32);
        }
    });
}

/* =============================================================
 * Public napi API
 * ============================================================= */

#[napi(object)]
pub struct MatchResult {
    pub priv_key_hex: String,
    pub hash160_hex: String,
    pub batch_offset: u32,
}

#[napi(object)]
pub struct SearchResult {
    pub keys_checked: u32,
    pub elapsed_ms: u32,
    pub found: Option<MatchResult>,
}

/// Search for a matching hash160. Each iteration of the outer loop:
///   1. Picks a random base scalar k0.
///   2. Calls into C: scalar mult + Jacobian walk + Montgomery batch invert
///      + SHA-NI + 8-way AVX2 RIPEMD-160 + target hashtable lookup.
///   3. Returns if a match was found.
///
/// The whole hot path lives in `sgn_search_batch` — Rust just supplies random
/// bytes and decodes the result. The target table is loaded once per process
/// via OnceLock.
#[napi]
pub fn search(
    targets: Vec<Buffer>,
    duration_ms: u32,
    batch_size: u32,
) -> SearchResult {
    ensure_targets_loaded(&targets);

    let mut rng = rand::thread_rng();
    let start = Instant::now();
    let max_dur = Duration::from_millis(duration_ms as u64);
    let mut keys_checked: u32 = 0;
    let batch_size = batch_size.max(1);

    let mut k0_bytes = [0u8; 32];
    let mut m: CMatch = unsafe { std::mem::zeroed() };

    loop {
        if start.elapsed() >= max_dur {
            break;
        }

        rng.fill_bytes(&mut k0_bytes);

        let hit = unsafe {
            sgn_search_batch(k0_bytes.as_ptr(), batch_size, &mut m as *mut CMatch)
        };

        keys_checked = keys_checked.saturating_add(batch_size);

        if hit != 0 && m.found != 0 {
            return SearchResult {
                keys_checked,
                elapsed_ms: start.elapsed().as_millis() as u32,
                found: Some(MatchResult {
                    priv_key_hex: hex::encode(m.priv_key),
                    hash160_hex: hex::encode(m.hash160),
                    batch_offset: m.batch_offset,
                }),
            };
        }
    }

    SearchResult {
        keys_checked,
        elapsed_ms: start.elapsed().as_millis() as u32,
        found: None,
    }
}

/// Convenience: derive the uncompressed-key hash160 for a given 32-byte private
/// key via secp256k1 (libsecp256k1 bindings). Test reference.
#[napi]
pub fn derive_hash160(priv_key: Buffer) -> Result<Buffer> {
    if priv_key.len() != 32 {
        return Err(Error::new(
            Status::InvalidArg,
            "private key must be 32 bytes",
        ));
    }
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&priv_key)
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid privkey: {}", e)))?;
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pub_uncompressed = pk.serialize_uncompressed();
    let sha = Sha256::digest(pub_uncompressed);
    let h160: [u8; 20] = Ripemd160::digest(sha).into();
    Ok(Buffer::from(h160.to_vec()))
}

/* =============================================================
 * Tests
 * ============================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    fn k256_xy_chain(k0_bytes: &[u8; 32], n: usize) -> Vec<u8> {
        let k0 = Option::<Scalar>::from(Scalar::from_repr((*k0_bytes).into()))
            .expect("test key in field");
        let g_aff: AffinePoint = ProjectivePoint::GENERATOR.to_affine();
        let mut projective: Vec<ProjectivePoint> = Vec::with_capacity(n);
        let mut p = ProjectivePoint::GENERATOR * k0;
        for _ in 0..n {
            projective.push(p);
            p += g_aff;
        }
        let affines = <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(
            projective.as_slice(),
        );
        let aff_slice: &[AffinePoint] = affines.as_ref();
        let mut out = Vec::with_capacity(n * 64);
        for a in aff_slice {
            let enc = a.to_encoded_point(false);
            let bytes = enc.as_bytes();
            out.extend_from_slice(&bytes[1..33]);
            out.extend_from_slice(&bytes[33..65]);
        }
        out
    }

    fn secp_h160(priv_key: &[u8; 32]) -> [u8; 20] {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(priv_key).expect("valid key");
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pub_uncompressed = pk.serialize_uncompressed();
        let sha = Sha256::digest(pub_uncompressed);
        Ripemd160::digest(sha).into()
    }

    /// SHA-NI sha256_pubkey_ni must match sha2 crate output for fixed pubkeys.
    #[test]
    fn sha_ni_matches_sha2_crate() {
        // Use a few fixed 65-byte uncompressed pubkeys (real-ish: 0x04 prefix
        // + 32-byte x + 32-byte y, content can be arbitrary for hash purposes).
        let mut pub65s: Vec<[u8; 65]> = Vec::new();
        for seed in 0u8..8 {
            let mut p = [0u8; 65];
            p[0] = 0x04;
            for i in 1..65 {
                p[i] = seed.wrapping_mul(31).wrapping_add(i as u8);
            }
            pub65s.push(p);
        }

        for p in &pub65s {
            let mut got = [0u8; 32];
            unsafe { sha256_pubkey_ni(got.as_mut_ptr(), p.as_ptr()) };
            let expected: [u8; 32] = Sha256::digest(p).into();
            assert_eq!(
                got, expected,
                "SHA-NI disagrees with sha2 crate on pub65 {}",
                hex::encode(p)
            );
        }
    }

    /// EC-only path (sgn_compute_affine_batch) must match k256 byte-for-byte.
    #[test]
    fn libsecp_xy_matches_k256_on_fixed_k0s() {
        let mut k1 = [0u8; 32];
        k1[31] = 1;
        let k2 = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let k2: [u8; 32] = k2.try_into().unwrap();

        for k0 in &[k1, k2] {
            let n = 32usize;
            let mut c_buf = vec![0u8; n * 64];
            let ok = unsafe { sgn_compute_affine_batch(k0.as_ptr(), n as u32, c_buf.as_mut_ptr()) };
            assert_eq!(ok, 1);
            let k_buf = k256_xy_chain(k0, n);
            assert_eq!(c_buf, k_buf, "C/k256 disagree for k0={}", hex::encode(k0));
        }
    }

    /// 8-way RIPEMD-160 lane equality vs scalar Ripemd160 on randomized inputs.
    #[test]
    fn ripemd160_8way_random_inputs() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let mut packed_in = [0u8; 8 * 32];
            rng.fill_bytes(&mut packed_in);
            let mut packed_out = [0u8; 8 * 20];
            unsafe { ripemd160_8way(packed_in.as_ptr(), packed_out.as_mut_ptr()) };
            for lane in 0..8 {
                let input = &packed_in[lane * 32..(lane + 1) * 32];
                let expected: [u8; 20] = Ripemd160::digest(input).into();
                let got: [u8; 20] = packed_out[lane * 20..(lane + 1) * 20].try_into().unwrap();
                assert_eq!(got, expected);
            }
        }
    }

    /// End-to-end: sgn_search_batch's match path produces the same hash160 as
    /// the secp256k1 reference for a known k0+offset. We force a hit by adding
    /// the corresponding h160 to the target table and confirming match data.
    #[test]
    fn search_batch_matches_secp256k1_reference() {
        // Pick a fixed k0 and an offset i. Compute reference h160(k0+i) via
        // secp256k1, install it as the only target, run sgn_search_batch with
        // n large enough to include offset i, expect a match at i.
        let mut k0 = [0u8; 32];
        k0[31] = 7;
        let target_offset: u32 = 5;

        // Reference h160 at k0+target_offset.
        let k0_scalar = Option::<Scalar>::from(Scalar::from_repr(k0.into())).unwrap();
        let priv_scalar = k0_scalar + Scalar::from(target_offset as u64);
        let priv_bytes: [u8; 32] = priv_scalar.to_bytes().into();
        let target_h160 = secp_h160(&priv_bytes);

        // Install single target. Note: the OnceLock guard means we can only
        // really set targets once per process; we deliberately bypass it here
        // by calling sgn_set_targets directly. This test must run alone.
        unsafe { sgn_set_targets(target_h160.as_ptr(), 1) };

        let mut m: CMatch = unsafe { std::mem::zeroed() };
        let hit = unsafe { sgn_search_batch(k0.as_ptr(), 16, &mut m as *mut CMatch) };
        assert_eq!(hit, 1);
        assert_eq!(m.found, 1);
        assert_eq!(m.batch_offset, target_offset);
        assert_eq!(m.hash160, target_h160);
        assert_eq!(m.priv_key, priv_bytes);
    }
}
