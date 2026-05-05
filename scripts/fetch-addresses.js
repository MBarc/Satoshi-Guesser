/**
 * Downloads the Patoshi-pattern Satoshi addresses from the original SatoshiGuesser repo
 * and writes them to data/addresses.txt (one address per line).
 */

import { writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(__dirname, '..', 'data', 'addresses.txt');

const SOURCE_URL =
  'https://raw.githubusercontent.com/Pathos0925/SatoshiGuesser/main/data/wallets.csv';

console.log('Fetching Satoshi address list...');

const res = await fetch(SOURCE_URL);
if (!res.ok) throw new Error(`Failed to fetch: ${res.status} ${res.statusText}`);

const csv = await res.text();

// CSV format: address,balance_satoshis — extract the address column
const addresses = csv
  .split('\n')
  .map(line => line.split(',')[0].trim())
  .filter(addr => addr.startsWith('1') || addr.startsWith('3') || addr.startsWith('bc1'));

if (addresses.length === 0) throw new Error('No addresses parsed — check CSV format');

writeFileSync(OUT_PATH, addresses.join('\n'), 'utf-8');
console.log(`Saved ${addresses.length.toLocaleString()} addresses to data/addresses.txt`);
