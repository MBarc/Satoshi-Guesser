// Multi-threaded throughput bench. Spawns BENCH_THREADS worker_threads (one
// per CPU by default, mirroring src/spin.js production behavior) and runs each
// for `BENCH_MS` ms at every batch size in `BENCH_BATCH_SIZES`. Reports per-
// thread keys/sec plus the aggregate (sum / wall time).
//
// Env knobs:
//   BENCH_MS              wall-clock duration per batch size (default 120000)
//   BENCH_BATCH_SIZES     comma-separated list (default "4096")
//   BENCH_THREADS         worker thread count (default cpus().length)

import { Worker } from 'worker_threads';
import { cpus } from 'os';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DURATION_MS = parseInt(process.env.BENCH_MS || '120000', 10);
const BATCH_SIZES = (process.env.BENCH_BATCH_SIZES || '4096')
  .split(',')
  .map(s => parseInt(s.trim(), 10))
  .filter(n => Number.isFinite(n) && n > 0);
const THREAD_COUNT = parseInt(
  process.env.BENCH_THREADS || String(cpus().length),
  10
);

console.log(`Threads: ${THREAD_COUNT}`);
console.log(`Duration per batch size: ${DURATION_MS} ms`);
console.log(`Batch sizes: ${BATCH_SIZES.join(', ')}`);
console.log('');

function runBatch(batchSize) {
  return new Promise((resolveAll, reject) => {
    const startWall = Date.now();
    const results = new Array(THREAD_COUNT);
    let done = 0;
    for (let i = 0; i < THREAD_COUNT; i++) {
      const threadIndex = i + 1;
      const worker = new Worker(join(__dirname, 'bench-thread.js'), {
        workerData: { durationMs: DURATION_MS, batchSize, threadIndex },
      });
      worker.on('message', (msg) => {
        results[i] = msg;
        if (++done === THREAD_COUNT) {
          const wallMs = Date.now() - startWall;
          resolveAll({ batchSize, results, wallMs });
        }
      });
      worker.on('error', reject);
    }
  });
}

const summary = [];
for (const batchSize of BATCH_SIZES) {
  console.log(`batch_size=${batchSize}`);
  const { results, wallMs } = await runBatch(batchSize);

  let totalKeys = 0;
  for (const r of results) {
    const rate = Math.round((r.keysChecked * 1000) / Math.max(1, r.elapsedMs));
    console.log(
      `  thread ${r.threadIndex} | ${r.keysChecked.toLocaleString()} keys | ${rate.toLocaleString()} keys/sec`
    );
    totalKeys += r.keysChecked;
    if (r.found) {
      console.log(`  thread ${r.threadIndex} HIT priv=${r.found.privKeyHex}`);
    }
  }
  const aggregateRate = Math.round((totalKeys * 1000) / Math.max(1, wallMs));
  console.log(
    `  AGGREGATE: ${totalKeys.toLocaleString()} keys in ${wallMs}ms | ${aggregateRate.toLocaleString()} keys/sec`
  );
  console.log('');
  summary.push({ batchSize, aggregateRate, totalKeys, wallMs });
}

console.log('Summary (aggregate keys/sec across all threads):');
for (const r of summary) {
  console.log(`  batch=${String(r.batchSize).padStart(6)} -> ${r.aggregateRate.toLocaleString()}`);
}
