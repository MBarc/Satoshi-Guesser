/**
 * Reads all run-total JSON files from run-totals/, sums them,
 * adds to the cumulative total in stats.json, and patches README.md.
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const STATS_PATH = join(ROOT, 'stats.json');
const README_PATH = join(ROOT, 'README.md');
const TOTALS_DIR = join(ROOT, 'run-totals');

// Sum all run-total.json files downloaded this week
let weekTotal = 0;
function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full);
    else if (entry === 'run-total.json') {
      try {
        const { total } = JSON.parse(readFileSync(full, 'utf-8'));
        if (typeof total === 'number') weekTotal += total;
      } catch {}
    }
  }
}
try { walk(TOTALS_DIR); } catch {}

// Load existing cumulative stats
let stats = { total: 0, lastUpdated: null };
try { stats = JSON.parse(readFileSync(STATS_PATH, 'utf-8')); } catch {}

stats.total += weekTotal;
stats.lastUpdated = new Date().toISOString();

// Format total with commas
const formatted = stats.total.toLocaleString('en-US');
const date = new Date(stats.lastUpdated).toLocaleDateString('en-US', {
  year: 'numeric', month: 'long', day: 'numeric',
});

console.log(`Week total:  ${weekTotal.toLocaleString()}`);
console.log(`All-time:    ${formatted}`);

// Patch README stats block
const readme = readFileSync(README_PATH, 'utf-8');
const block = `<!-- STATS -->
Total keys checked: **${formatted}**
Last updated ${date}
<!-- /STATS -->`;

const updated = readme.replace(/<!-- STATS -->[\s\S]*?<!-- \/STATS -->/, block);
if (updated === readme) {
  console.error('Stats marker not found in README — add <!-- STATS --><!-- /STATS --> placeholder');
  process.exit(1);
}

writeFileSync(STATS_PATH, JSON.stringify(stats, null, 2), 'utf-8');
writeFileSync(README_PATH, updated, 'utf-8');
console.log('README and stats.json updated.');
