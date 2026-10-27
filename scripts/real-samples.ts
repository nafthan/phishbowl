// Score the real-email sets (fetch them first with `npm run samples`) and compare with scripts/real-baseline.json.
//
// Phishing sets: every email is phishing or spam, so "Likely legitimate" is a miss.
// Legitimate sets: every email is genuine, so "Malicious" is a false alarm, and "Suspicious" is counted too.
// Fails if any set does worse than its baseline.
//
//   npm run test:real                    summary per set
//   npm run test:real -- -v              also list every miss or false alarm, with its flagged checks
//   npm run test:real -- --update        accept the current results as the new baseline
//   npm run test:real -- legit-hard -v   one set only
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyseFile, emlFiles } from '../src/node/index.js';
import type { EmailAnalysis } from '../src/types.js';

interface Limit { kind: 'phishing' | 'legitimate'; total: number; maxMissed?: number; maxMalicious?: number; maxSuspicious?: number }
const root = fileURLToPath(new URL('..', import.meta.url)), baselinePath = join(root, 'scripts', 'real-baseline.json');
const baseline: Record<string, Limit> = JSON.parse(readFileSync(baselinePath, 'utf8'));
const args = process.argv.slice(2), verbose = args.includes('-v'), update = args.includes('--update');
const only = args.filter(a => !a.startsWith('-'));
let failed = false;
const next: Record<string, Limit> = { ...baseline };
const pct = (n: number, d: number) => d ? `${(100 * n / d).toFixed(1)}%` : '–';

function detail(f: string, a: EmailAnalysis) {
  console.log(`    ${a.verdict.v.padEnd(10)} ${String(a.verdict.score).padStart(3)}  ${basename(f).slice(0, 40).padEnd(40)} ${a.subj.slice(0, 60)}`);
  for (const c of a.checks.filter(x => x.status === 'bad' || x.status === 'warn')) console.log(`          ${c.status.padEnd(4)} ${c.id.padEnd(22)} ${c.result.slice(0, 90)}`);
}

for (const [set, limit] of Object.entries(baseline)) {
  if (only.length && !only.includes(set)) continue;
  const dir = join(root, 'samples', set);
  if (!existsSync(dir)) { console.log(`skip ${set.padEnd(13)} samples/${set} missing: run \`npm run samples\` first`); failed = true; continue; }
  const files = await emlFiles(dir);
  const tally = { malicious: 0, suspicious: 0, clean: 0, text: 0 };
  for (const f of files) {
    const a = await analyseFile(f);
    if (a.kind !== 'email') { tally.text++; if (verbose) console.log(`    not read as email: ${basename(f)}`); continue; }
    tally[a.verdict.v]++;
    const wrong = limit.kind === 'phishing' ? a.verdict.v === 'clean' : a.verdict.v !== 'clean';
    if (verbose && wrong) detail(f, a);
  }
  if (limit.kind === 'phishing') {
    const missed = tally.clean + tally.text, ok = missed <= (limit.maxMissed ?? Infinity);
    if (!ok) failed = true;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${set.padEnd(13)} phishing    ${files.length} · flagged ${files.length - missed} (${pct(files.length - missed, files.length)}) · missed ${missed}, allowed ${limit.maxMissed}`);
    next[set] = { kind: 'phishing', total: files.length, maxMissed: missed };
  } else {
    const ok = tally.malicious <= (limit.maxMalicious ?? Infinity) && tally.suspicious <= (limit.maxSuspicious ?? Infinity);
    if (!ok) failed = true;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${set.padEnd(13)} legitimate  ${files.length} · clean ${tally.clean} (${pct(tally.clean, files.length)}) · suspicious ${tally.suspicious}, allowed ${limit.maxSuspicious} · malicious ${tally.malicious}, allowed ${limit.maxMalicious}` +
      (tally.text ? ` · ${tally.text} not read as email` : ''));
    next[set] = { kind: 'legitimate', total: files.length, maxMalicious: tally.malicious, maxSuspicious: tally.suspicious };
  }
}
if (update) { writeFileSync(baselinePath, JSON.stringify(next, null, 2) + '\n'); console.log('Baseline updated.'); }
else if (failed) process.exit(1);
