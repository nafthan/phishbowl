#!/usr/bin/env node
// Fetch the real-email test sets into samples/ (git ignores it). Everything is pinned in scripts/sample-sets.json
// so results are reproducible. Don't commit or redistribute these emails: they keep their own licences.
//
//   npm run samples              everything: phishing (2 × 80) and legitimate (about 4,170)
//   npm run samples -- phishing  only the phishing sets
//   npm run samples -- legit     only the legitimate sets
//
// Phishing: Phishing Pot (github.com/rf-peixoto/phishing_pot, CC BY-NC 4.0), real phishing and spam from honeypots.
// Legitimate: the SpamAssassin public corpus (npm package @stdlib/datasets-spam-assassin), and real modern messages
// kept as test fixtures by open-source email libraries (MIT / MIT-0).
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url)), samples = join(root, 'samples'), cache = join(samples, '.cache');
const SETS = JSON.parse(readFileSync(join(root, 'scripts', 'sample-sets.json'), 'utf8'));
const which = process.argv[2] || 'all';
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 256 * 1024 * 1024, shell: process.platform === 'win32' && cmd === 'npm' }).toString();
const fresh = dir => { rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true }); return dir; };
const report = name => console.log(`  samples/${name}: ${readdirSync(join(samples, name)).length} emails`);

/** Shallow, blob-less fetch of one commit, then check out only the listed paths. */
function sparse(repo, commit, paths, dir) {
  mkdirSync(dir, { recursive: true });
  const git = (...a) => run('git', a, dir);
  if (!existsSync(join(dir, '.git'))) { git('init', '-q'); git('remote', 'add', 'origin', repo); }
  git('fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', commit);
  git('sparse-checkout', 'set', '--no-cone', ...paths.map(p => '/' + p));
  git('checkout', '-q', 'FETCH_HEAD');
}

if (which === 'all' || which === 'phishing') {
  const p = SETS.phishing;
  console.log(`Phishing: ${p.source} at ${p.commit.slice(0, 8)}`);
  const dir = join(cache, 'phishing_pot'), names = Object.values(p.sets).flat();
  sparse(p.source + '.git', p.commit, [...new Set(names)].map(n => 'email/' + n), dir);
  for (const [set, list] of Object.entries(p.sets)) {
    const out = fresh(join(samples, set));
    for (const n of list) copyFileSync(join(dir, 'email', n), join(out, n));
    report(set);
  }
}

if (which === 'all' || which === 'legit') {
  const sa = SETS.legitimate.spamassassin;
  console.log(`Legitimate: ${sa.package}@${sa.version}`);
  const dir = fresh(join(cache, 'spamassassin'));
  const tgz = run('npm', ['pack', `${sa.package}@${sa.version}`, '--silent', '--pack-destination', dir], root).trim().split('\n').pop();
  run('tar', ['xzf', tgz], dir);
  for (const [set, folder] of Object.entries(sa.sets)) {
    const from = join(dir, 'package', 'data', folder), out = fresh(join(samples, set));
    for (const f of readdirSync(from).filter(x => x.endsWith('.txt'))) copyFileSync(join(from, f), join(out, f.replace(/\.txt$/, '.eml')));
    report(set);
  }
  const m = SETS.legitimate.modern, out = fresh(join(samples, m.set));
  console.log(`Legitimate (modern): ${m.repos.length} repositories`);
  for (const r of m.repos) {
    const name = r.repo.split('/').slice(-2).join('_'), dir = join(cache, name);
    sparse(r.repo + '.git', r.commit, r.files, dir);
    for (const f of r.files) copyFileSync(join(dir, f), join(out, `${name.split('_')[1]}--${basename(f).replace(/\.(msg|txt)$/, '')}.eml`));
  }
  report(m.set);
}
console.log('Done. Run `npm run test:real` to score them.');
