#!/usr/bin/env node
// Fetch the real-phishing test sets from Phishing Pot (https://github.com/rf-peixoto/phishing_pot, CC BY-NC 4.0).
// Only the selected files are downloaded. They go into samples/, which git ignores: don't commit or redistribute them.
//
//   npm run samples            two sets of 80: samples/tuning and samples/unseen
//   npm run samples -- --all   every sample (about 12,000 files, several hundred MB) into samples/all
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url)), cache = join(root, 'samples', '.cache', 'phishing_pot');
// The sets are pinned by file name and commit (scripts/sample-sets.json) so results are reproducible.
// tuning: the rules were adjusted while looking at these. unseen: kept aside to check the rules generalise.
const SETS = JSON.parse(readFileSync(join(root, 'scripts', 'sample-sets.json'), 'utf8'));
const REPO = SETS.source + '.git', COMMIT = SETS.commit;
const all = process.argv.includes('--all');

const git = (...args) => execFileSync('git', args, { cwd: cache, stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 64 * 1024 * 1024 }).toString();
mkdirSync(cache, { recursive: true });
if (!existsSync(join(cache, '.git'))) {
  git('init', '-q');
  git('remote', 'add', 'origin', REPO);
}
console.log(`Fetching the file list at ${COMMIT.slice(0, 8)}…`);
git('fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', COMMIT);
const files = git('ls-tree', '-r', '--name-only', 'FETCH_HEAD', 'email').split('\n').filter(f => /\.eml$/.test(f))
  .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
const wanted = all ? { all: files } : { tuning: SETS.tuning.map(n => 'email/' + n), unseen: SETS.unseen.map(n => 'email/' + n) };
const paths = [...new Set(Object.values(wanted).flat())];
console.log(`Downloading ${paths.length} samples…`);
git('sparse-checkout', 'set', '--no-cone', ...(all ? ['/email/'] : paths.map(p => '/' + p)));
git('checkout', '-q', 'FETCH_HEAD');
for (const [name, list] of Object.entries(wanted)) {
  const dir = join(root, 'samples', name);
  rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true });
  for (const p of list) copyFileSync(join(cache, p), join(dir, p.split('/').pop()));
  console.log(`  samples/${name}: ${readdirSync(dir).length} emails`);
}
console.log('Done. Run `npm run test:real` to score them.');
