#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant};

// FFI binding to our C wrapper. Used today only to verify the build pipeline
// works (returns a known sentinel). Next session, this header will declare a
// function that performs a batched walk + Montgomery-trick normalization
// using libsecp256k1's internal Jacobian-coordinate API.
extern "C" {
    fn sgn_wrapper_sentinel() -> u32;
}

/// Build-pipeline check: returns true iff the C wrapper is linked and
/// returning its expected sentinel value (0xCAFEBABE). Exported so the
/// JS side can confirm before relying on any C-wrapper functionality.
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

/// Search for a matching hash160 by generating random base private keys, deriving
/// public keys, and checking each derived hash160 against the target set. Uses
/// the incremental pubkey trick: pick random k0, compute P0 = k0 * G once, then
/// derive successive points via P_(i+1) = P_i + G (cheap point addition) for
/// `batch_size` iterations before re-randomizing.
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

    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    // Precomputed PublicKey representation of G (the curve generator). Adding
    // this to a pubkey via PublicKey::combine performs a true point addition
    // (~1-2us per call), unlike PublicKey::add_exp_tweak with scalar 1, which
    // internally performs a full scalar multiplication.
    let g_pubkey = {
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one_sk =
            SecretKey::from_slice(&one_bytes).expect("scalar 1 is a valid private key");
        PublicKey::from_secret_key(&secp, &one_sk)
    };

    let start = Instant::now();
    let max_dur = Duration::from_millis(duration_ms as u64);
    let mut keys_checked: u32 = 0;
    let batch_size = batch_size.max(1);

    'outer: loop {
        if start.elapsed() >= max_dur {
            break;
        }

        let mut k0_bytes = [0u8; 32];
        rng.fill_bytes(&mut k0_bytes);

        let k0 = match SecretKey::from_slice(&k0_bytes) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let mut pub_k = PublicKey::from_secret_key(&secp, &k0);

        for i in 0..batch_size {
            let pub_uncompressed = pub_k.serialize_uncompressed();
            let sha = Sha256::digest(pub_uncompressed);
            let h160_arr: [u8; 20] = Ripemd160::digest(sha).into();
            keys_checked = keys_checked.saturating_add(1);

            if target_set.contains(&h160_arr) {
                let final_priv = if i == 0 {
                    k0
                } else {
                    let mut tweak_bytes = [0u8; 32];
                    let i_be = (i as u64).to_be_bytes();
                    tweak_bytes[24..].copy_from_slice(&i_be);
                    let tweak =
                        Scalar::from_be_bytes(tweak_bytes).expect("offset fits below order");
                    k0.add_tweak(&tweak)
                        .expect("tweak addition cannot wrap for small i")
                };
                return SearchResult {
                    keys_checked,
                    elapsed_ms: start.elapsed().as_millis() as u32,
                    found: Some(MatchResult {
                        priv_key_hex: hex::encode(final_priv.secret_bytes()),
                        hash160_hex: hex::encode(h160_arr),
                        batch_offset: i,
                    }),
                };
            }

            if i + 1 < batch_size {
                // P_(i+1) = P_i + G via true point addition. The combine call
                // can only fail if the result is the point at infinity, which
                // requires P_i = -G — probability ~1/n, statistically zero.
                pub_k = pub_k
                    .combine(&g_pubkey)
                    .expect("point addition cannot produce identity in random walk");
            }
        }

        // Re-check timeout between batches so that very large batch_size
        // values do not delay returning.
        if start.elapsed() >= max_dur {
            break 'outer;
        }
    }

    SearchResult {
        keys_checked,
        elapsed_ms: start.elapsed().as_millis() as u32,
        found: None,
    }
}

/// Convenience: derive the uncompressed-key hash160 for a given 32-byte private
/// key. Useful for verifying the JS path matches the native path on test vectors.
#[napi]
pub fn derive_hash160(priv_key: Buffer) -> Result<Buffer> {
    if priv_key.len() != 32 {
        return Err(Error::new(
            Status::InvalidArg,
            "private key must be 32 bytes",
        ));
    }
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&priv_key)
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid privkey: {}", e)))?;
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let pub_uncompressed = pk.serialize_uncompressed();
    let sha = Sha256::digest(pub_uncompressed);
    let h160: [u8; 20] = Ripemd160::digest(sha).into();
    Ok(Buffer::from(h160.to_vec()))
}
