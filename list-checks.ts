// Regenerate docs/checks.md from what the checks actually produce on the test emails:
//   npx tsx scripts/list-checks.ts > docs/checks.md
// Uses test/fixtures, plus samples/tuning and samples/unseen if they have been fetched.
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyseBytes, analyseFile } from '../src/node/index.js';
const root = fileURLToPath(new URL('..', import.meta.url));
import { GROUPS, WEIGHT } from '../src/verdict.js';
const seen = new Map<string, { group: string; name: string; st: Set<string> }>();
for (const d of ['test/fixtures', 'samples/tuning', 'samples/unseen'].map(x => join(root, x)).filter(existsSync)) for (const f of readdirSync(d).filter(x => x.endsWith('.eml'))) {
  const a = await analyseFile(d + '/' + f, { ownDomains: d.endsWith('fixtures') ? ['northwind.example'] : [] });
  if (a.kind !== 'email') continue;
  for (const c of a.checks) { const k = seen.get(c.id) || { group: c.group, name: c.name, st: new Set() }; k.st.add(c.status); seen.set(c.id, k); }
}
{ const a = await analyseBytes(new TextEncoder().encode('From: a@b.example\nSubject: x\nDate: Mon, 19 Oct 2026 09:00:00 +0000\n\nhello'));
  if (a.kind === 'email') for (const c of a.checks) { const k = seen.get(c.id) || { group: c.group, name: c.name, st: new Set<string>() }; k.st.add(c.status); seen.set(c.id, k); } }
const out = ['# Checks', '', 'Every check Phishbowl runs, by group. A red flag (bad) adds its weight to the score; unlisted red flags weigh 3, a warning weighs 1, and content warnings add at most 2 in total.',
  'A red flag weighing 5 or more is critical: Malicious on its own. Otherwise Malicious at a score of 12, Suspicious at 5 or with any red flag.', '',
  'Statuses seen are the ones the test emails produced; some checks can produce others.', ''];
for (const [g, label] of GROUPS) {
  const rows = [...seen].filter(([, v]) => v.group === g); if (!rows.length) continue;
  out.push(`## ${label}`, '', '| Check | Id | Weight as a red flag | Statuses seen |', '| --- | --- | --- | --- |');
  for (const [id, v] of rows) out.push(`| ${v.name} | \`${id}\` | ${v.st.has('bad') || WEIGHT[id] ? (WEIGHT[id] || 3) + ((WEIGHT[id] || 0) >= 5 ? ' (critical)' : '') : '–'} | ${['bad', 'warn', 'ok', 'info', 'na'].filter(s => v.st.has(s)).join(', ')} |`);
  out.push('');
}
console.log(out.join('\n'));
