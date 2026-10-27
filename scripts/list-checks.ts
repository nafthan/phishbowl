// Regenerate docs/checks.md from what the checks actually produce on the test emails:
//   npx tsx scripts/list-checks.ts > docs/checks.md
// Uses test/fixtures, plus fetched samples (phishing, modern and hard legitimate mail) if present.
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyseBytes, analyseFile } from '../src/node/index.js';
const root = fileURLToPath(new URL('..', import.meta.url));
import { GROUPS, WEIGHT } from '../src/verdict.js';
const seen = new Map<string, { group: string; name: string; st: Set<string> }>();
for (const d of ['test/fixtures', 'samples/tuning', 'samples/unseen', 'samples/legit-modern', 'samples/legit-hard'].map(x => join(root, x)).filter(existsSync)) for (const f of readdirSync(d).filter(x => /\.(eml|msg)$/.test(x))) {
  const a = await analyseFile(d + '/' + f, { ownDomains: d.endsWith('fixtures') ? ['northwind.example'] : [] });
  if (a.kind !== 'email') continue;
  for (const c of a.checks) { const k = seen.get(c.id) || { group: c.group, name: c.name, st: new Set() }; k.st.add(c.status); seen.set(c.id, k); }
}
{ const a = await analyseBytes(new TextEncoder().encode('From: a@b.example\nSubject: x\nDate: Mon, 19 Oct 2026 09:00:00 +0000\n\nhello'));
  if (a.kind === 'email') for (const c of a.checks) { const k = seen.get(c.id) || { group: c.group, name: c.name, st: new Set<string>() }; k.st.add(c.status); seen.set(c.id, k); } }
// Allowlist and online checks only appear when turned on: run them on a few emails, with a fake network.
const add = (a: Awaited<ReturnType<typeof analyseBytes>>) => { if (a.kind === 'email') for (const c of a.checks) { const k = seen.get(c.id) || { group: c.group, name: c.name, st: new Set<string>() }; k.st.add(c.status); seen.set(c.id, k); } };
const fx = (n: string) => join(root, 'test/fixtures', n);
add(await analyseFile(fx('l11-hr-system-real-saas.eml'), { allow: { domains: ['bamboohr.com'] } }));
add(await analyseFile(fx('h3-phish-parcel-fee.eml'), { allow: { domains: ['rm-redelivery.test'] } }));
const J = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status });
const fake = (reg: string, mx: boolean, nx = false) => (async (u: string | URL) => {
  const url = String(u);
  if (url.includes('iana.org')) return J({ services: [[['com'], ['https://rdap.example/']]] });
  if (url.startsWith('https://rdap.example/')) return nx ? J({}, 404) : J({ events: [{ eventAction: 'registration', eventDate: reg }] });
  if (url.includes('dns-query')) return J(nx ? { Status: 3 } : { Status: 0, Answer: mx && /type=MX/.test(url) ? [{ type: 15, data: '10 mx.example.com.' }] : [] });
  if (url.includes('openphish')) return new Response('https://brand-new-portal.com/login\n');
  throw new Error('offline');
}) as typeof fetch;
const mail = (from: string, link: string) => new TextEncoder().encode(`From: <${from}>\nTo: a@b.example\nSubject: x\nDate: Mon, 19 Oct 2026 09:00:00 +0000\nContent-Type: text/html\n\n<a href="${link}">x</a>`);
add(await analyseBytes(mail('a@brand-new-portal.com', 'https://brand-new-portal.com/login'), { online: { fetch: fake(new Date(Date.now() - 5 * 864e5).toISOString(), false) } }));
add(await analyseBytes(mail('a@older-portal.com', 'https://brand-new-portal.com/other'), { online: { fetch: fake(new Date(Date.now() - 60 * 864e5).toISOString(), true) } }));
add(await analyseBytes(mail('a@gone-portal.com', 'https://gone-portal.com/'), { online: { fetch: fake('', false, true), feeds: false } }));
add(await analyseBytes(mail('a@x.example', 'https://x.example/'), { online: { fetch: fake('', false) } }));
add(await analyseBytes(mail('a@offline-portal.com', 'https://offline-portal.com/'), { online: { fetch: (async () => { throw new Error('offline'); }) as unknown as typeof fetch } }));
add(await analyseBytes(mail('a@old-portal.com', 'https://old-portal.com/'), { online: { fetch: fake('2001-01-01T00:00:00Z', true) } }));

const out = ['# Checks', '', 'Every check Phishbowl runs, by group. A red flag (bad) adds its weight to the score; unlisted red flags weigh 3, a warning weighs 1, and content warnings add at most 2 in total.',
  'A red flag weighing 5 or more is critical: Malicious on its own. Otherwise Malicious at a score of 12, Suspicious at 6 or with any red flag. Route, link-hygiene and wording warnings are capped (1, 1 and 2).', '',
  'Statuses seen are the ones the test emails produced; some checks can produce others. Online lookups and the allowlist only run when turned on.', ''];
for (const [g, label] of GROUPS) {
  const rows = [...seen].filter(([, v]) => v.group === g); if (!rows.length) continue;
  out.push(`## ${label}`, '', '| Check | Id | Weight as a red flag | Statuses seen |', '| --- | --- | --- | --- |');
  for (const [id, v] of rows) out.push(`| ${v.name} | \`${id}\` | ${v.st.has('bad') || WEIGHT[id] ? (WEIGHT[id] || 3) + ((WEIGHT[id] || 0) >= 5 ? ' (critical)' : '') : '–'} | ${['bad', 'warn', 'ok', 'info', 'na'].filter(s => v.st.has(s)).join(', ')} |`);
  out.push('');
}
console.log(out.join('\n'));
