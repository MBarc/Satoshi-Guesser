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
    /// 8-way AVX2 RIPEMD-160. Reads 8 × 32-byte inputs from `in_8x32`,
    /// writes 8 × 20-byte outputs to `out_8x20`. Each input is hashed
    /// independently; the 8 results are byte-identical to scalar
    /// Ripemd160::digest of the same 32-byte input.
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
///   2. Builds N projective points (k0+i)*G for i=0..N via mixed Jacobian
///      additions (no field inversions in this stage).
///   3. Batch-normalizes all N to affine in a single Montgomery-trick pass
///      (one field inversion + 3(N-1) multiplications, amortized over N keys).
///   4. SHA-256 of each uncompressed pubkey via the sha2 crate (SHA-NI on this
///      CPU). Then RIPEMD-160 of each via the 8-way AVX2 path in C, processing
///      candidates in groups of 8 and falling back to scalar for the tail.
///   5. Each resulting hash160 is checked against the target set.
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
    let g_affine: AffinePoint = ProjectivePoint::GENERATOR.to_affine();

    let start = Instant::now();
    let max_dur = Duration::from_millis(duration_ms as u64);
    let mut keys_checked: u32 = 0;
    let batch_size = batch_size.max(1) as usize;

    let mut projective: Vec<ProjectivePoint> = Vec::with_capacity(batch_size);
    let mut sha_buf = [0u8; SIMD_LANES * 32];
    let mut h160_buf = [0u8; SIMD_LANES * 20];

    loop {
        if start.elapsed() >= max_dur {
            break;
        }

        let mut k0_bytes = [0u8; 32];
        rng.fill_bytes(&mut k0_bytes);

        let k0_scalar = match Option::<Scalar>::from(Scalar::from_repr(k0_bytes.into())) {
            Some(s) if !bool::from(s.is_zero()) => s,
            _ => continue,
        };

        projective.clear();
        let mut p = ProjectivePoint::GENERATOR * k0_scalar;
        for _ in 0..batch_size {
            projective.push(p);
            p += g_affine;
        }

        let affines = <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(
            projective.as_slice(),
        );
        let affines_slice: &[AffinePoint] = affines.as_ref();

        let n = affines_slice.len();
        let mut idx = 0usize;

        // Fast 8-way path: process complete groups of 8.
        while idx + SIMD_LANES <= n {
            for j in 0..SIMD_LANES {
                let encoded = affines_slice[idx + j].to_encoded_point(false);
                let pub_uncompressed = encoded.as_bytes();
                debug_assert_eq!(pub_uncompressed.len(), 65);
                let sha = Sha256::digest(pub_uncompressed);
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

        // Scalar tail for any remainder (and the rare identity-encoding edge case).
        while idx < n {
            let encoded = affines_slice[idx].to_encoded_point(false);
            let pub_uncompressed = encoded.as_bytes();
            if pub_uncompressed.len() != 65 {
                idx += 1;
                continue;
            }
            let sha = Sha256::digest(pub_uncompressed);
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

    fn k256_h160(priv_key: &[u8; 32]) -> [u8; 20] {
        let scalar = Option::<Scalar>::from(Scalar::from_repr((*priv_key).into()))
            .expect("test key is in field");
        let point = ProjectivePoint::GENERATOR * scalar;
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(false);
        let sha = Sha256::digest(encoded.as_bytes());
        Ripemd160::digest(sha).into()
    }

    fn secp_h160(priv_key: &[u8; 32]) -> [u8; 20] {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(priv_key).expect("valid key");
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pub_uncompressed = pk.serialize_uncompressed();
        let sha = Sha256::digest(pub_uncompressed);
        Ripemd160::digest(sha).into()
    }

    /// Carry-over from the prior k256 PR: confirms our derivation chain
    /// (k256 + sha2 + ripemd) matches secp256k1's reference output.
    #[test]
    fn k256_matches_secp256k1_on_fixed_keys() {
        let mut k1 = [0u8; 32];
        k1[31] = 1;

        let k2 = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let k2: [u8; 32] = k2.try_into().unwrap();

        let k3 = hex::decode("c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec001")
            .unwrap();
        let k3: [u8; 32] = k3.try_into().unwrap();

        for key in &[k1, k2, k3] {
            assert_eq!(k256_h160(key), secp_h160(key), "mismatch on {}", hex::encode(key));
        }
    }

    /// Each lane of the 8-way RIPEMD-160 must equal the scalar `Ripemd160`
    /// crate's output for the same 32-byte input. Tests both fixed inputs
    /// (so failures reproduce) and randomized inputs (catches lane-ordering
    /// or transpose bugs that fixed inputs might miss).
    #[test]
    fn ripemd160_8way_matches_scalar() {
        // Fixed inputs designed to exercise different bit patterns per lane.
        let mut inputs = [[0u8; 32]; 8];
        for (lane, input) in inputs.iter_mut().enumerate() {
            for (i, byte) in input.iter_mut().enumerate() {
                *byte = ((lane as u8).wrapping_mul(31)).wrapping_add(i as u8);
            }
        }

        // Pack into the contiguous 8x32 byte buffer the C function expects.
        let mut packed_in = [0u8; 8 * 32];
        for (lane, input) in inputs.iter().enumerate() {
            packed_in[lane * 32..(lane + 1) * 32].copy_from_slice(input);
        }

        let mut packed_out = [0u8; 8 * 20];
        unsafe {
            ripemd160_8way(packed_in.as_ptr(), packed_out.as_mut_ptr());
        }

        for lane in 0..8 {
            let expected: [u8; 20] = Ripemd160::digest(&inputs[lane]).into();
            let got: [u8; 20] = packed_out[lane * 20..(lane + 1) * 20].try_into().unwrap();
            assert_eq!(
                got, expected,
                "lane {} mismatch: got {} expected {}",
                lane,
                hex::encode(got),
                hex::encode(expected)
            );
        }
    }

    #[test]
    fn ripemd160_8way_random_inputs() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        for trial in 0..32 {
            let mut packed_in = [0u8; 8 * 32];
            rng.fill_bytes(&mut packed_in);

            let mut packed_out = [0u8; 8 * 20];
            unsafe {
                ripemd160_8way(packed_in.as_ptr(), packed_out.as_mut_ptr());
            }

            for lane in 0..8 {
                let input = &packed_in[lane * 32..(lane + 1) * 32];
                let expected: [u8; 20] = Ripemd160::digest(input).into();
                let got: [u8; 20] = packed_out[lane * 20..(lane + 1) * 20].try_into().unwrap();
                assert_eq!(
                    got, expected,
                    "trial {} lane {} disagrees with scalar Ripemd160",
                    trial, lane
                );
            }
        }
    }
}
