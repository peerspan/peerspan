// Syntax-checks every JavaScript source of the managed operator. No dependencies.
import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));
const sources = readdirSync(root, { recursive: true })
  .filter(file => /\.m?js$/.test(file) && !file.split(/[\/]/).includes('node_modules'))
  .sort();
for (const file of sources) execFileSync(process.execPath, ['--check', join(root, file)], { stdio: 'inherit' });
console.log(`Checked ${sources.length} JavaScript sources.`);
