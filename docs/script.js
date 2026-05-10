// =============================================================================
// Satoshi Guesser — live counter + stats fetcher
// =============================================================================
//
// The counter shows an estimated cumulative key count since the project began
// running on GitHub Actions. The estimate uses seven throughput phases that
// match the actual code evolution on main:
//
//   Phase 1 (pre-f507834):    ~6 billion keys/day      — pure JS, slow EC
//   Phase 2 (post-f507834):   ~75 billion keys/day     — native secp256k1 binding
//   Phase 3 (post-Plan 8):    ~1.25 trillion keys/day  — native Rust addon, per-step combine
//   Phase 4 (post-PR #2):     ~4.69 trillion keys/day  — k256 batched inversion, BATCH_SIZE=8192
//   Phase 5 (post-PR #3):     ~5.53 trillion keys/day  — 8-way AVX2 RIPEMD-160
//   Phase 6 (post-PR #4):     ~6.87 trillion keys/day  — libsecp256k1 EC math (hybrid)
//   Phase 7 (post-PR #5):     ~7.42 trillion keys/day  — full hot path consolidated in C (SHA-NI inline)
//
// When the weekly stats workflow has populated stats.json with a real
// cumulative total, that value overrides the estimate and the counter
// continues ticking from there at the current rate.
// =============================================================================

const PHASE_BOUNDARIES = {
  // Approximate dates the project was launched and when each major
  // throughput change landed on main. Adjust if you have better records.
  LAUNCH:    new Date('2026-05-04T00:00:00Z').getTime(),
  F507834:   new Date('2026-05-06T00:00:00Z').getTime(),
  PLAN_8:    new Date('2026-05-07T21:40:00Z').getTime(), // PR #1 merge time
  PR_2:      new Date('2026-05-09T00:57:00Z').getTime(), // PR #2 merge time (k256 batched inversion)
  PR_3:      new Date('2026-05-09T03:23:37Z').getTime(), // PR #3 merge time (8-way AVX2 RIPEMD-160)
  PR_4:      new Date('2026-05-09T20:16:18Z').getTime(), // PR #4 merge time (libsecp hybrid)
  PR_5:      new Date('2026-05-10T13:36:33Z').getTime(), // PR #5 merge time (hot-path consolidation)
};

const RATES_PER_DAY = {
  phase1: 6e9,
  phase2: 75e9,
  phase3: 1.25e12,
  phase4: 4.69e12,
  phase5: 5.53e12,
  phase6: 6.87e12,
  phase7: 7.42e12,
};

const SECONDS_PER_DAY = 86_400;
const CURRENT_RATE_PER_SECOND = RATES_PER_DAY.phase7 / SECONDS_PER_DAY;

const TARGETS = 21953;
const KEYSPACE_LOG10 = 77.064; // log10(2^256) ≈ 77.064

// ---------------------------------------------------------------------------

function estimatedKeysSinceLaunch(now = Date.now()) {
  const seconds = (a, b) => Math.max(0, b - a) / 1000;

  const p1End = Math.min(now, PHASE_BOUNDARIES.F507834);
  const p2End = Math.min(now, PHASE_BOUNDARIES.PLAN_8);
  const p3End = Math.min(now, PHASE_BOUNDARIES.PR_2);
  const p4End = Math.min(now, PHASE_BOUNDARIES.PR_3);
  const p5End = Math.min(now, PHASE_BOUNDARIES.PR_4);
  const p6End = Math.min(now, PHASE_BOUNDARIES.PR_5);

  const p1 = seconds(PHASE_BOUNDARIES.LAUNCH, p1End)    * (RATES_PER_DAY.phase1 / SECONDS_PER_DAY);
  const p2 = seconds(PHASE_BOUNDARIES.F507834, p2End)   * (RATES_PER_DAY.phase2 / SECONDS_PER_DAY);
  const p3 = seconds(PHASE_BOUNDARIES.PLAN_8, p3End)    * (RATES_PER_DAY.phase3 / SECONDS_PER_DAY);
  const p4 = seconds(PHASE_BOUNDARIES.PR_2, p4End)      * (RATES_PER_DAY.phase4 / SECONDS_PER_DAY);
  const p5 = seconds(PHASE_BOUNDARIES.PR_3, p5End)      * (RATES_PER_DAY.phase5 / SECONDS_PER_DAY);
  const p6 = seconds(PHASE_BOUNDARIES.PR_4, p6End)      * (RATES_PER_DAY.phase6 / SECONDS_PER_DAY);
  const p7 = seconds(PHASE_BOUNDARIES.PR_5, now)        * (RATES_PER_DAY.phase7 / SECONDS_PER_DAY);

  return Math.floor(p1 + p2 + p3 + p4 + p5 + p6 + p7);
}

function formatNumber(n) {
  return n.toLocaleString('en-US');
}

function formatDate(d) {
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

// State that may be overridden by stats.json
let officialBaseTotal = null;
let officialBaseTime  = null;

function getDisplayedTotal() {
  if (officialBaseTotal !== null && officialBaseTime !== null) {
    const elapsed = (Date.now() - officialBaseTime) / 1000;
    return officialBaseTotal + Math.floor(elapsed * CURRENT_RATE_PER_SECOND);
  }
  return estimatedKeysSinceLaunch();
}

function updateCounter() {
  const counter = document.getElementById('counter');
  if (!counter) return;
  counter.textContent = formatNumber(getDisplayedTotal());
}

function updateRate() {
  const rate = document.getElementById('rate-display');
  if (!rate) return;
  rate.textContent = formatNumber(Math.round(CURRENT_RATE_PER_SECOND));
}

async function tryFetchOfficialStats() {
  const url = 'https://raw.githubusercontent.com/MBarc/Satoshi-Guesser/main/stats.json'
    + '?cb=' + Math.floor(Date.now() / 60000); // minute-level cache bust
  try {
    const res = await fetch(url, { cache: 'no-cache' });
    if (!res.ok) throw new Error('fetch failed: ' + res.status);
    const stats = await res.json();
    const lastUpdated = stats.lastUpdated ? new Date(stats.lastUpdated) : null;

    const lastUpdateEl = document.getElementById('last-update');
    if (lastUpdated && lastUpdated.getTime() > 0) {
      if (lastUpdateEl) lastUpdateEl.textContent = formatDate(lastUpdated);

      if (typeof stats.total === 'number' && stats.total > 0) {
        officialBaseTotal = stats.total;
        officialBaseTime  = lastUpdated.getTime();
      }
    } else {
      if (lastUpdateEl) lastUpdateEl.textContent = 'pending first weekly sync';
    }
  } catch {
    const lastUpdateEl = document.getElementById('last-update');
    if (lastUpdateEl) lastUpdateEl.textContent = 'unavailable';
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

updateRate();
updateCounter();

// Tick the counter ten times per second so the digits move smoothly.
setInterval(updateCounter, 100);

// Pull the official cumulative total in the background.
tryFetchOfficialStats();
