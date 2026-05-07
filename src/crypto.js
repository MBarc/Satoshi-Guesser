import { createRequire } from 'module';
import { randomBytes } from 'crypto';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

// secp256k1 native package uses CJS exports — use createRequire to load it in ESM
const require = createRequire(import.meta.url);
const { publicKeyCreate, privateKeyVerify } = require('secp256k1');

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
  let key;
  do { key = randomBytes(32); } while (!privateKeyVerify(key));
  return key;
}

// WIF = Base58Check(0x80 + privkey [+ 0x01 if compressed])
export function toWIF(privKey, compressed = true) {
  const payload = new Uint8Array(compressed ? 34 : 33);
  payload[0] = 0x80;
  payload.set(privKey, 1);
  if (compressed) payload[33] = 0x01;
  return base58Check(payload);
}

// Satoshi's addresses used uncompressed keys — only derive that one
export function deriveAddress(privKey) {
  const pubUncompressed = publicKeyCreate(privKey, false);
  return {
    privKeyHex: Buffer.from(privKey).toString('hex'),
    address: toAddress(hash160(pubUncompressed)),
  };
}
