import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_PATH = join(__dirname, '..', 'data', 'addresses.txt');

function loadAddresses() {
  const content = readFileSync(DATA_PATH, 'utf-8');
  const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
  console.log(`Loaded ${lines.length.toLocaleString()} Satoshi addresses`);
  return new Set(lines);
}

const addresses = loadAddresses();

export const addressCount = addresses.size;

export function isMatch(address) {
  return addresses.has(address);
}
