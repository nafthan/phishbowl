// Score the real-phishing sets (fetch them first with `npm run samples`). Every sample is phishing or spam, so a
// "Likely legitimate" verdict is a miss. Fails if any set misses more than its baseline allows.
//
//   npm run test:real              summary per set
//   npm run test:real -- -v        also list every miss with its flagged checks
//   npm run test:real -- --update  write the current miss counts as the new baseline
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyseFile, emlFiles } from '../src/node/index.js';

const root = fileURLToPath(new URL('..', import.meta.url)), baselinePath = join(root, 'scripts', 'real-baseline.json');
const baseline: Record<string, { maxMissed: number; total: number }> = JSON.parse(readFileSync(baselinePath, 'utf8'));
const verbose = process.argv.includes('-v'), update = process.argv.includes('--update');
let failed = false;
const next: typeof baseline = {};

for (const set of Object.keys(baseline)) {
  const dir = join(root, 'samples', set);
  if (!existsSync(dir)) { console.log(`samples/${set} missing: run \`npm run samples\` first`); failed = true; continue; }
  const tally = { malicious: 0, suspicious: 0, clean: 0, text: 0 }, misses: string[] = [];
  const files = await emlFiles(dir);
  for (const f of files) {
    const a = await analyseFile(f);
    if (a.kind !== 'email') { tally.text++; misses.push(f); continue; }
    tally[a.verdict.v]++;
    if (a.verdict.v === 'clean') {
      misses.push(f);
      if (verbose) {
        console.log(`  missed ${f.split('/').pop()} (score ${a.verdict.score}): ${a.subj.slice(0, 70)}`);
        for (const c of a.checks.filter(x => x.status === 'bad' || x.status === 'warn')) console.log(`      ${c.status.padEnd(4)} ${c.id.padEnd(22)} ${c.result.slice(0, 90)}`);
      }
    }
  }
  const missed = misses.length, allowed = baseline[set].maxMissed;
  const ok = missed <= allowed;
  if (!ok) failed = true;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${set.padEnd(8)} ${files.length} emails · ${tally.malicious} malicious · ${tally.suspicious} suspicious · ${missed} missed (allowed ${allowed})` +
    (tally.text ? ` · ${tally.text} not read as email` : ''));
  next[set] = { maxMissed: missed, total: files.length };
}
if (update) { writeFileSync(baselinePath, JSON.stringify(next, null, 2) + '\n'); console.log('Baseline updated.'); }
else if (failed) process.exit(1);
