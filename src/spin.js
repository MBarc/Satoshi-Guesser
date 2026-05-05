import { randomPrivKey, deriveAddresses } from './crypto.js';
import { isMatch, addressCount } from './checker.js';
import { notifyHit } from './notify.js';

const WORKER_ID = process.env.WORKER_ID ?? '1';
const DURATION_MS = Number(process.env.DURATION_MINUTES ?? 350) * 60 * 1000;
const LOG_EVERY = 50_000;

const start = Date.now();
let count = 0;

console.log(`Worker ${WORKER_ID} | ${addressCount.toLocaleString()} targets | running for ${DURATION_MS / 60000} min`);

while (Date.now() - start < DURATION_MS) {
  const privKey = randomPrivKey();
  const { privKeyHex, addressUncompressed, addressCompressed } = deriveAddresses(privKey);

  const hit = isMatch(addressUncompressed)
    ? addressUncompressed
    : isMatch(addressCompressed)
    ? addressCompressed
    : null;

  if (hit) {
    console.log(`MATCH: ${hit}`);
    await notifyHit(privKeyHex, hit);
    process.exit(0);
  }

  count++;

  if (count % LOG_EVERY === 0) {
    const elapsed = (Date.now() - start) / 1000;
    const rate = Math.round(count / elapsed).toLocaleString();
    console.log(`Worker ${WORKER_ID} | ${count.toLocaleString()} checked | ${rate} keys/sec`);
  }
}

const elapsed = ((Date.now() - start) / 1000).toFixed(1);
const rate = Math.round(count / parseFloat(elapsed)).toLocaleString();
console.log(`Worker ${WORKER_ID} done | ${count.toLocaleString()} keys in ${elapsed}s | avg ${rate} keys/sec`);
