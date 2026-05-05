import { writeFileSync } from 'fs';
import { Worker } from 'worker_threads';
import { cpus } from 'os';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { addressCount } from './checker.js';
import { notifyHit } from './notify.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKER_ID = process.env.WORKER_ID ?? '1';
const DURATION_MS = Number(process.env.DURATION_MINUTES ?? 350) * 60 * 1000;
const THREAD_COUNT = cpus().length;

console.log(`Worker ${WORKER_ID} | ${THREAD_COUNT} threads | ${addressCount.toLocaleString()} targets | running for ${DURATION_MS / 60000} min`);

const start = Date.now();
let totalCount = 0;
let finished = 0;
let hitFound = false;
const threads = [];

for (let i = 0; i < THREAD_COUNT; i++) {
  const thread = new Worker(join(__dirname, 'worker.js'), {
    workerData: { durationMs: DURATION_MS, threadIndex: i + 1 },
  });

  thread.on('message', async (msg) => {
    if (msg.type === 'log') {
      console.log(`Worker ${WORKER_ID} | ${msg.message}`);

    } else if (msg.type === 'hit' && !hitFound) {
      hitFound = true;
      totalCount += msg.count;
      console.log(`Worker ${WORKER_ID} | MATCH: ${msg.address}`);
      writeFileSync(`worker-${WORKER_ID}-count.txt`, String(totalCount), 'utf-8');
      for (const t of threads) if (t !== thread) t.terminate();
      await notifyHit(msg.privKeyHex, msg.address, msg.wifUncompressed, msg.wifCompressed);
      process.exit(0);

    } else if (msg.type === 'done') {
      totalCount += msg.count;
      finished++;
      if (finished === THREAD_COUNT) {
        const elapsed = ((Date.now() - start) / 1000).toFixed(1);
        const rate = Math.round(totalCount / parseFloat(elapsed)).toLocaleString();
        console.log(`Worker ${WORKER_ID} done | ${totalCount.toLocaleString()} keys in ${elapsed}s | avg ${rate} keys/sec`);
        writeFileSync(`worker-${WORKER_ID}-count.txt`, String(totalCount), 'utf-8');
      }
    }
  });

  thread.on('error', (err) => console.error(`Worker ${WORKER_ID} thread ${i + 1} error:`, err));
  threads.push(thread);
}
