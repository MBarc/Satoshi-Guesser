import { workerData, parentPort } from 'worker_threads';
import { randomPrivKey, deriveAddresses, toWIF } from './crypto.js';
import { isMatch } from './checker.js';

const { durationMs, threadIndex } = workerData;
const LOG_EVERY = 50_000;
const start = Date.now();
let count = 0;

while (Date.now() - start < durationMs) {
  const privKey = randomPrivKey();
  const { privKeyHex, addressUncompressed, addressCompressed } = deriveAddresses(privKey);

  const hit = isMatch(addressUncompressed)
    ? addressUncompressed
    : isMatch(addressCompressed)
    ? addressCompressed
    : null;

  if (hit) {
    parentPort.postMessage({
      type: 'hit',
      privKeyHex,
      address: hit,
      wifCompressed: toWIF(privKey, true),
      wifUncompressed: toWIF(privKey, false),
      count,
    });
    break;
  }

  count++;

  if (count % LOG_EVERY === 0) {
    const elapsed = (Date.now() - start) / 1000;
    const rate = Math.round(count / elapsed).toLocaleString();
    parentPort.postMessage({ type: 'log', message: `thread ${threadIndex} | ${count.toLocaleString()} checked | ${rate} keys/sec` });
  }
}

parentPort.postMessage({ type: 'done', count });
