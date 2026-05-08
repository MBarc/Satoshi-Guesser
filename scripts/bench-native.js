// Direct-call throughput benchmark for the native addon. Runs `search()`
// in-process (no worker_threads) for a fixed wall-clock duration at each
// requested batch size, prints keys/sec for comparison.
//
// Env knobs:
//   BENCH_MS              total duration per batch size (default 30000)
//   BENCH_BATCH_SIZES     comma-separated list (default "256,1024,4096")

import { search } from '../native/index.js';
import { targetHash160s } from '../src/checker.js';

const DURATION_MS = parseInt(process.env.BENCH_MS || '30000', 10);
const BATCH_SIZES = (process.env.BENCH_BATCH_SIZES || '256,1024,4096')
  .split(',')
  .map(s => parseInt(s.trim(), 10))
  .filter(n => Number.isFinite(n) && n > 0);

console.log(`Loaded ${targetHash160s.length.toLocaleString()} hash160 targets`);
console.log(`Duration per batch size: ${DURATION_MS} ms`);
console.log(`Batch sizes: ${BATCH_SIZES.join(', ')}`);
console.log('');

const results = [];
for (const batchSize of BATCH_SIZES) {
  process.stdout.write(`batch_size=${batchSize}\trunning... `);
  const result = search(targetHash160s, DURATION_MS, batchSize);
  const rate = Math.round((result.keysChecked * 1000) / Math.max(1, result.elapsedMs));
  results.push({ batchSize, ...result, rate });
  console.log(
    `keys=${result.keysChecked.toLocaleString()}\telapsed=${result.elapsedMs}ms\trate=${rate.toLocaleString()} keys/sec` +
      (result.found ? `\tHIT priv=${result.found.privKeyHex}` : '')
  );
}

console.log('');
console.log('Summary (keys/sec):');
for (const r of results) {
  console.log(`  ${String(r.batchSize).padStart(6)} -> ${r.rate.toLocaleString()}`);
}

if (results.some(r => r.found)) {
  console.log('\nA hit was found during the bench (extraordinary luck).');
}
