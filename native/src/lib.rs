#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant};

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

    // Scalar 1: adding this as a tweak to a pubkey adds G.
    let one = {
        let mut b = [0u8; 32];
        b[31] = 1;
        Scalar::from_be_bytes(b).expect("scalar 1 fits below curve order")
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
                pub_k = pub_k
                    .add_exp_tweak(&secp, &one)
                    .expect("scalar 1 always yields a valid pubkey");
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
