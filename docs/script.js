// =============================================================================
// Satoshi Guesser — live counter + stats fetcher
// =============================================================================
//
// The counter shows an estimated cumulative key count since the project began
// running on GitHub Actions. The estimate uses four throughput phases that
// match the actual code evolution on main:
//
//   Phase 1 (pre-f507834):    ~6 billion keys/day      — pure JS, slow EC
//   Phase 2 (post-f507834):   ~75 billion keys/day     — native secp256k1 binding
//   Phase 3 (post-Plan 8):    ~1.25 trillion keys/day  — native Rust addon, per-step combine
//   Phase 4 (post-PR #2):     ~4.69 trillion keys/day  — k256 batched inversion, BATCH_SIZE=8192
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
};

const RATES_PER_DAY = {
  phase1: 6e9,
  phase2: 75e9,
  phase3: 1.25e12,
  phase4: 4.69e12,
};

const SECONDS_PER_DAY = 86_400;
const CURRENT_RATE_PER_SECOND = RATES_PER_DAY.phase4 / SECONDS_PER_DAY;

const TARGETS = 21953;
const KEYSPACE_LOG10 = 77.064; // log10(2^256) ≈ 77.064

// ---------------------------------------------------------------------------

function estimatedKeysSinceLaunch(now = Date.now()) {
  const seconds = (a, b) => Math.max(0, b - a) / 1000;

  const p1End = Math.min(now, PHASE_BOUNDARIES.F507834);
  const p2End = Math.min(now, PHASE_BOUNDARIES.PLAN_8);
  const p3End = Math.min(now, PHASE_BOUNDARIES.PR_2);

  const p1 = seconds(PHASE_BOUNDARIES.LAUNCH, p1End)    * (RATES_PER_DAY.phase1 / SECONDS_PER_DAY);
  const p2 = seconds(PHASE_BOUNDARIES.F507834, p2End)   * (RATES_PER_DAY.phase2 / SECONDS_PER_DAY);
  const p3 = seconds(PHASE_BOUNDARIES.PLAN_8, p3End)    * (RATES_PER_DAY.phase3 / SECONDS_PER_DAY);
  const p4 = seconds(PHASE_BOUNDARIES.PR_2, now)        * (RATES_PER_DAY.phase4 / SECONDS_PER_DAY);

  return Math.floor(p1 + p2 + p3 + p4);
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
