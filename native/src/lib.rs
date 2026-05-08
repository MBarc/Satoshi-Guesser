#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use k256::elliptic_curve::point::BatchNormalize;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};

// FFI to the C wrapper. Kept as a fallback escape hatch: if k256-based batched
// inversion proves insufficient, the libsecp256k1 internal-API path scaffolded
// behind this symbol is the next step. Not on the hot path today.
extern "C" {
    fn sgn_wrapper_sentinel() -> u32;
}

/// Build-pipeline check: returns true iff the C wrapper is linked and
/// returning its expected sentinel value (0xCAFEBABE).
#[napi]
pub fn c_wrapper_alive() -> bool {
    let sentinel = unsafe { sgn_wrapper_sentinel() };
    sentinel == 0xCAFE_BABE
}

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
///   1. picks a random base scalar k0,
///   2. builds N projective points (k0+i)*G for i=0..N via mixed Jacobian
///      additions (no field inversions in this stage),
///   3. batch-normalizes all N to affine in a single Montgomery-trick pass
///      (one field inversion + 3(N-1) multiplications, amortized over N keys),
///   4. SHA-256 + RIPEMD-160 of each uncompressed pubkey, checked against
///      the target set.
///
/// Returns when either a match is found or `duration_ms` elapses.
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
    // Affine generator. Computed once via to_affine (single inversion at
    // startup, amortized to zero) so we don't depend on AffinePoint::GENERATOR
    // being an exposed constant on every k256 version.
    let g_affine: AffinePoint = ProjectivePoint::GENERATOR.to_affine();

    let start = Instant::now();
    let max_dur = Duration::from_millis(duration_ms as u64);
    let mut keys_checked: u32 = 0;
    let batch_size = batch_size.max(1) as usize;

    let mut projective: Vec<ProjectivePoint> = Vec::with_capacity(batch_size);

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

        for (i, aff) in affines_slice.iter().enumerate() {
            let encoded = aff.to_encoded_point(false);
            let pub_uncompressed = encoded.as_bytes();
            // Identity would serialize to a single byte; statistically unreachable
            // here (would require k0+i ≡ 0 mod n) but guard defensively.
            if pub_uncompressed.len() != 65 {
                continue;
            }
            let sha = Sha256::digest(pub_uncompressed);
            let h160_arr: [u8; 20] = Ripemd160::digest(sha).into();
            keys_checked = keys_checked.saturating_add(1);

            if target_set.contains(&h160_arr) {
                let final_priv_scalar = k0_scalar + Scalar::from(i as u64);
                let final_priv_bytes = final_priv_scalar.to_bytes();
                return SearchResult {
                    keys_checked,
                    elapsed_ms: start.elapsed().as_millis() as u32,
                    found: Some(MatchResult {
                        priv_key_hex: hex::encode(final_priv_bytes),
                        hash160_hex: hex::encode(h160_arr),
                        batch_offset: i as u32,
                    }),
                };
            }
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
/// key via secp256k1 (libsecp256k1 bindings). Used by tests and JS to verify
/// the k256 hot path agrees with the reference implementation.
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

    #[test]
    fn k256_matches_secp256k1_on_fixed_keys() {
        let mut k1 = [0u8; 32];
        k1[31] = 1;

        let mut k2 = [0u8; 32];
        k2[31] = 0xFF;
        k2[30] = 0xFF;

        let k3_vec =
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let k3: [u8; 32] = k3_vec.try_into().unwrap();

        let k4_vec =
            hex::decode("c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec001")
                .unwrap();
        let k4: [u8; 32] = k4_vec.try_into().unwrap();

        for key in &[k1, k2, k3, k4] {
            assert_eq!(
                k256_h160(key),
                secp_h160(key),
                "k256 and secp256k1 disagree on key {}",
                hex::encode(key)
            );
        }
    }

    #[test]
    fn batched_chain_matches_individual_derivation() {
        // Verifies that the batched path produces the same hash160 sequence as
        // computing each (k0+i)*G independently — i.e. that the chain walk and
        // batch normalization are equivalent to N separate derivations.
        let mut k0_bytes = [0u8; 32];
        k0_bytes[31] = 0x42;
        let k0 = Option::<Scalar>::from(Scalar::from_repr(k0_bytes.into())).unwrap();

        let n = 16usize;
        let g: AffinePoint = ProjectivePoint::GENERATOR.to_affine();

        let mut projective: Vec<ProjectivePoint> = Vec::with_capacity(n);
        let mut p = ProjectivePoint::GENERATOR * k0;
        for _ in 0..n {
            projective.push(p);
            p += g;
        }
        let affines =
            <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(
                projective.as_slice(),
            );
        let batch_h160s: Vec<[u8; 20]> = affines
            .as_ref()
            .iter()
            .map(|a| {
                let enc = a.to_encoded_point(false);
                let sha = Sha256::digest(enc.as_bytes());
                Ripemd160::digest(sha).into()
            })
            .collect();

        for i in 0..n {
            let scalar_i = k0 + Scalar::from(i as u64);
            let bytes = scalar_i.to_bytes();
            let key_arr: [u8; 32] = bytes.into();
            assert_eq!(
                batch_h160s[i],
                secp_h160(&key_arr),
                "batched h160 at offset {} does not match independent derivation",
                i
            );
        }
    }
}
