// One thread of a multi-threaded throughput bench. Mirrors src/worker.js but
// strips the production logging/notification glue so the math is the same as
// what each production worker_thread actually does.

import { workerData, parentPort } from 'worker_threads';
import { search } from '../native/index.js';
import { targetHash160s } from '../src/checker.js';

const { durationMs, batchSize, threadIndex } = workerData;

const result = search(targetHash160s, durationMs, batchSize);

parentPort.postMessage({
  threadIndex,
  keysChecked: result.keysChecked,
  elapsedMs: result.elapsedMs,
  found: result.found ?? null,
});
