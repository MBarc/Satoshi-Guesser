import { workerData, parentPort } from 'worker_threads';
import { randomPrivKey, deriveAddress, toWIF } from './crypto.js';
import { isMatch, targetHash160s } from './checker.js';

const { durationMs, threadIndex } = workerData;
const start = Date.now();
let totalCount = 0;

let nativeSearch = null;
try {
  const native = await import('../native/index.js');
  nativeSearch = native.search;
  parentPort.postMessage({
    type: 'log',
    message: `thread ${threadIndex} | native module loaded`,
  });
} catch (err) {
  parentPort.postMessage({
    type: 'log',
    message: `thread ${threadIndex} | native module unavailable (${err.message}); using JS fallback`,
  });
}

function postHit(privKey) {
  const { privKeyHex, address } = deriveAddress(privKey);
  parentPort.postMessage({
    type: 'hit',
    privKeyHex,
    address,
    wifCompressed: toWIF(privKey, true),
    wifUncompressed: toWIF(privKey, false),
    count: totalCount,
  });
}

if (nativeSearch) {
  const PROGRESS_INTERVAL_MS = 60_000;
  const BATCH_SIZE = 4096;

  while (Date.now() - start < durationMs) {
    const remaining = durationMs - (Date.now() - start);
    const chunk = Math.min(remaining, PROGRESS_INTERVAL_MS);
    const result = nativeSearch(targetHash160s, chunk, BATCH_SIZE);
    totalCount += result.keysChecked;

    if (result.found) {
      const privKey = Buffer.from(result.found.privKeyHex, 'hex');
      postHit(privKey);
      break;
    }

    const elapsed = (Date.now() - start) / 1000;
    const rate = Math.round(totalCount / elapsed).toLocaleString();
    parentPort.postMessage({
      type: 'log',
      message: `thread ${threadIndex} | ${totalCount.toLocaleString()} checked | ${rate} keys/sec (native)`,
    });
  }
} else {
  const LOG_EVERY = 50_000;
  while (Date.now() - start < durationMs) {
    const privKey = randomPrivKey();
    const { address } = deriveAddress(privKey);

    if (isMatch(address)) {
      postHit(privKey);
      break;
    }

    totalCount++;

    if (totalCount % LOG_EVERY === 0) {
      const elapsed = (Date.now() - start) / 1000;
      const rate = Math.round(totalCount / elapsed).toLocaleString();
      parentPort.postMessage({
        type: 'log',
        message: `thread ${threadIndex} | ${totalCount.toLocaleString()} checked | ${rate} keys/sec`,
      });
    }
  }
}

parentPort.postMessage({ type: 'done', count: totalCount });
