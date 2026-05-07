import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { sha256 } from '@noble/hashes/sha256';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_PATH = join(__dirname, '..', 'data', 'addresses.txt');
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str) {
  let num = 0n;
  for (const c of str) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx === -1) throw new Error(`invalid base58 char: ${c}`);
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  let leadingOnes = 0;
  for (const c of str) {
    if (c === '1') leadingOnes++;
    else break;
  }
  for (let i = 0; i < leadingOnes; i++) bytes.unshift(0);
  return new Uint8Array(bytes);
}

// Decode a P2PKH (mainnet, version byte 0x00) address to its 20-byte hash160.
// Returns null for non-P2PKH addresses or any decode/checksum failure.
function addressToHash160(addr) {
  if (!addr.startsWith('1')) return null;
  let decoded;
  try {
    decoded = base58Decode(addr);
  } catch {
    return null;
  }
  if (decoded.length !== 25) return null;
  if (decoded[0] !== 0x00) return null;
  const payload = decoded.subarray(0, 21);
  const checksum = decoded.subarray(21, 25);
  const expected = sha256(sha256(payload)).subarray(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) return null;
  }
  return payload.subarray(1, 21);
}

const content = readFileSync(DATA_PATH, 'utf-8');
const allAddresses = content.split('\n').map(l => l.trim()).filter(Boolean);
const addressSet = new Set(allAddresses);

console.log(`Loaded ${allAddresses.length.toLocaleString()} Satoshi addresses`);

// Pre-converted hash160 buffers for the native path (P2PKH only). Non-P2PKH
// addresses (e.g. P2SH "3..." or bech32 "bc1...") are unreachable from a
// random P2PKH derivation, so dropping them is correct, not lossy.
export const targetHash160s = (() => {
  const out = [];
  for (const addr of allAddresses) {
    const h = addressToHash160(addr);
    if (h) out.push(Buffer.from(h));
  }
  console.log(`Prepared ${out.length.toLocaleString()} P2PKH hash160 targets for native path`);
  return out;
})();

export const addressCount = allAddresses.length;

export function isMatch(address) {
  return addressSet.has(address);
}
