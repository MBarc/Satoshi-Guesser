import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);

  let result = '';
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % 58n)] + result;
    num /= 58n;
  }

  return '1'.repeat(leadingZeros) + result;
}

function base58Check(payload) {
  const checksum = sha256(sha256(payload)).subarray(0, 4);
  const full = new Uint8Array(payload.length + 4);
  full.set(payload);
  full.set(checksum, payload.length);
  return base58Encode(full);
}

function hash160(pubKey) {
  return ripemd160(sha256(pubKey));
}

function toAddress(h160) {
  const versioned = new Uint8Array(21);
  versioned[0] = 0x00;
  versioned.set(h160, 1);
  return base58Check(versioned);
}

export function randomPrivKey() {
  return secp256k1.utils.randomPrivateKey();
}

// Returns both compressed and uncompressed addresses — Satoshi used uncompressed
export function deriveAddresses(privKey) {
  const pubUncompressed = secp256k1.getPublicKey(privKey, false);
  const pubCompressed = secp256k1.getPublicKey(privKey, true);

  return {
    privKeyHex: Buffer.from(privKey).toString('hex'),
    addressUncompressed: toAddress(hash160(pubUncompressed)),
    addressCompressed: toAddress(hash160(pubCompressed)),
  };
}
