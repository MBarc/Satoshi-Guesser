#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use ripemd::{Digest as _, Ripemd160};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use k256::elliptic_curve::point::BatchNormalize;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};

/* =============================================================
 * FFI surface against c-wrapper/wrapper.c
 * ============================================================= */

extern "C" {
    fn sgn_wrapper_sentinel() -> u32;

    /// Computes (k0+i)*G's affine x/y for i=0..n-1 via libsecp256k1 internals
    /// (scalar mult + Jacobian walk + Montgomery batch invert). Writes
    /// n × 64 bytes into out_xy: each block is 32-byte BE x then 32-byte BE y.
    /// Returns 1 on success, 0 if k0 is out-of-range or zero.
    fn sgn_compute_affine_batch(k0_bytes: *const u8, n: u32, out_xy: *mut u8) -> i32;

    /// 8-way AVX2 RIPEMD-160. Reads 8 × 32-byte inputs, writes 8 × 20-byte outputs.
    fn ripemd160_8way(in_8x32: *const u8, out_8x20: *mut u8);
}

#[napi]
pub fn c_wrapper_alive() -> bool {
    let sentinel = unsafe { sgn_wrapper_sentinel() };
    sentinel == 0xCAFE_BABE
}

const SIMD_LANES: usize = 8;

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
///   2. Calls into libsecp256k1 via FFI: scalar mult + Jacobian walk for N
///      points + Montgomery batch invert + serialize to N affine x/y pairs.
///   3. SHA-256 each uncompressed pubkey via sha2 (SHA-NI on this CPU). Then
///      RIPEMD-160 of each via the 8-way AVX2 path in C, in groups of 8 with a
///      scalar tail for any remainder.
///   4. Each resulting hash160 is checked against the target set.
///
/// Hybrid hot path: EC math runs in C against libsecp's hand-tuned field
/// arithmetic; hashing stays in Rust to keep SHA-NI hardware acceleration.
#[napi]
pub fn search(
    targets: Vec<Buffer>,
    duration_ms: u32,
    batch_size: u32,
) -> SearchResult {
    let target_set: HashSet<[u8; 20]> = targets
        .iter()
        .filter_map(|b| {
            if b.len() == 20 {
                let mut a = [0u8; 20];
                a.copy_from_slice(b);
                Some(a)
            } else {
                None
            }
        })
        .collect();

    let mut rng = rand::thread_rng();
    let start = Instant::now();
    let max_dur = Duration::from_millis(duration_ms as u64);
    let mut keys_checked: u32 = 0;
    let batch_size = batch_size.max(1) as usize;

    // Heap allocation per call (size ~ 64 * batch_size bytes — 512 KB at 8192).
    // Reused across the whole call so the syscall happens once.
    let mut xy_buf: Vec<u8> = vec![0u8; batch_size * 64];
    let mut sha_buf = [0u8; SIMD_LANES * 32];
    let mut h160_buf = [0u8; SIMD_LANES * 20];
    let mut pub_buf = [0u8; 65];
    pub_buf[0] = 0x04;

    loop {
        if start.elapsed() >= max_dur {
            break;
        }

        let mut k0_bytes = [0u8; 32];
        rng.fill_bytes(&mut k0_bytes);

        // Generate the affine x/y batch via libsecp256k1.
        let ok = unsafe {
            sgn_compute_affine_batch(
                k0_bytes.as_ptr(),
                batch_size as u32,
                xy_buf.as_mut_ptr(),
            )
        };
        if ok == 0 {
            // k0 out of range / zero — try a fresh one.
            continue;
        }

        // We also need k0 as a k256 Scalar to recover the private key on a hit
        // (priv = k0 + i). Scalar::from_repr may fail for the same out-of-range
        // case the C side already rejected; treat that as belt-and-suspenders.
        let k0_scalar = match Option::<Scalar>::from(Scalar::from_repr(k0_bytes.into())) {
            Some(s) => s,
            None => continue,
        };

        let mut idx = 0usize;

        // Fast 8-way path
        while idx + SIMD_LANES <= batch_size {
            for j in 0..SIMD_LANES {
                let xy_off = (idx + j) * 64;
                pub_buf[1..33].copy_from_slice(&xy_buf[xy_off..xy_off + 32]);
                pub_buf[33..65].copy_from_slice(&xy_buf[xy_off + 32..xy_off + 64]);
                let sha = Sha256::digest(pub_buf);
                sha_buf[j * 32..(j + 1) * 32].copy_from_slice(&sha);
            }

            unsafe {
                ripemd160_8way(sha_buf.as_ptr(), h160_buf.as_mut_ptr());
            }

            for j in 0..SIMD_LANES {
                let mut h160_arr = [0u8; 20];
                h160_arr.copy_from_slice(&h160_buf[j * 20..(j + 1) * 20]);
                keys_checked = keys_checked.saturating_add(1);

                if target_set.contains(&h160_arr) {
                    let final_priv_scalar = k0_scalar + Scalar::from((idx + j) as u64);
                    let final_priv_bytes = final_priv_scalar.to_bytes();
                    return SearchResult {
                        keys_checked,
                        elapsed_ms: start.elapsed().as_millis() as u32,
                        found: Some(MatchResult {
                            priv_key_hex: hex::encode(final_priv_bytes),
                            hash160_hex: hex::encode(h160_arr),
                            batch_offset: (idx + j) as u32,
                        }),
                    };
                }
            }
            idx += SIMD_LANES;
        }

        // Scalar tail
        while idx < batch_size {
            let xy_off = idx * 64;
            pub_buf[1..33].copy_from_slice(&xy_buf[xy_off..xy_off + 32]);
            pub_buf[33..65].copy_from_slice(&xy_buf[xy_off + 32..xy_off + 64]);
            let sha = Sha256::digest(pub_buf);
            let h160_arr: [u8; 20] = Ripemd160::digest(sha).into();
            keys_checked = keys_checked.saturating_add(1);

            if target_set.contains(&h160_arr) {
                let final_priv_scalar = k0_scalar + Scalar::from(idx as u64);
                let final_priv_bytes = final_priv_scalar.to_bytes();
                return SearchResult {
                    keys_checked,
                    elapsed_ms: start.elapsed().as_millis() as u32,
                    found: Some(MatchResult {
                        priv_key_hex: hex::encode(final_priv_bytes),
                        hash160_hex: hex::encode(h160_arr),
                        batch_offset: idx as u32,
                    }),
                };
            }
            idx += 1;
        }

        if start.elapsed() >= max_dur {
            break;
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
        // Returns concatenated 64-byte (x_be || y_be) blocks for (k0+i)*G.
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
            let enc = a.to_encoded_point(false); // 65 bytes: 0x04 || x || y
            let bytes = enc.as_bytes();
            assert_eq!(bytes.len(), 65);
            out.extend_from_slice(&bytes[1..33]);  // x
            out.extend_from_slice(&bytes[33..65]); // y
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

    /// The C path's affine x/y bytes must match k256's, byte-for-byte. If this
    /// passes, all downstream hashes will agree by construction (same input).
    #[test]
    fn libsecp_xy_matches_k256_on_fixed_k0s() {
        let mut k1 = [0u8; 32];
        k1[31] = 1;
        let k2 = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let k2: [u8; 32] = k2.try_into().unwrap();
        let k3 = hex::decode("c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec001")
            .unwrap();
        let k3: [u8; 32] = k3.try_into().unwrap();

        for k0 in &[k1, k2, k3] {
            let n = 32usize;
            let mut c_buf = vec![0u8; n * 64];
            let ok = unsafe { sgn_compute_affine_batch(k0.as_ptr(), n as u32, c_buf.as_mut_ptr()) };
            assert_eq!(ok, 1, "C path rejected k0={}", hex::encode(k0));

            let k_buf = k256_xy_chain(k0, n);
            assert_eq!(c_buf.len(), k_buf.len());
            for i in 0..n {
                let off = i * 64;
                assert_eq!(
                    &c_buf[off..off + 64],
                    &k_buf[off..off + 64],
                    "C and k256 disagree on (k0+{}) for k0={}",
                    i,
                    hex::encode(k0)
                );
            }
        }
    }

    /// End-to-end: C path's xy + sha2 + scalar Ripemd160 == secp256k1 reference.
    #[test]
    fn libsecp_full_chain_matches_secp256k1_reference() {
        let mut k0 = [0u8; 32];
        k0[31] = 7;
        let n = 16usize;

        let mut c_buf = vec![0u8; n * 64];
        let ok = unsafe { sgn_compute_affine_batch(k0.as_ptr(), n as u32, c_buf.as_mut_ptr()) };
        assert_eq!(ok, 1);

        for i in 0..n {
            let off = i * 64;
            let mut pub65 = [0u8; 65];
            pub65[0] = 0x04;
            pub65[1..33].copy_from_slice(&c_buf[off..off + 32]);
            pub65[33..65].copy_from_slice(&c_buf[off + 32..off + 64]);
            let sha = Sha256::digest(pub65);
            let h160_c: [u8; 20] = Ripemd160::digest(sha).into();

            // Reference: derive secp256k1 hash160 directly from priv = k0 + i.
            let k0_scalar = Option::<Scalar>::from(Scalar::from_repr(k0.into())).unwrap();
            let priv_scalar = k0_scalar + Scalar::from(i as u64);
            let priv_bytes: [u8; 32] = priv_scalar.to_bytes().into();
            let h160_ref = secp_h160(&priv_bytes);

            assert_eq!(h160_c, h160_ref, "hash160 mismatch at offset {}", i);
        }
    }

    #[test]
    fn ripemd160_8way_matches_scalar_carry_over() {
        // Quick smoke check that the 8-way RIPEMD path still works on this branch.
        let mut packed_in = [0u8; 8 * 32];
        for (lane, byte) in packed_in.iter_mut().enumerate() {
            *byte = ((lane as u8).wrapping_mul(31)).wrapping_add((lane / 8) as u8);
        }
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
