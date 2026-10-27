// Allowlist and feedback.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyseFile } from '../src/node/index.js';
import { allowProblems } from '../src/allow.js';
import { exportFixtures, outcome, readFeedback, recordFeedback, summarise } from '../src/node/feedback.js';
import { startServer } from '../src/node/dashboard.js';
import type { EmailAnalysis } from '../src/types.js';

const dir = join(import.meta.dirname, 'fixtures'), own = ['northwind.example'];
const load = async (name: string, allow?: { senders?: string[]; domains?: string[] }) => await analyseFile(join(dir, name), { ownDomains: own, allow }) as EmailAnalysis;
const check = (a: EmailAnalysis, id: string) => a.checks.find(c => c.id === id);

test('an authenticated, allowlisted sender: warnings stay visible but stop counting', async () => {
  const before = await load('l11-hr-system-real-saas.eml');
  assert.ok(before.verdict.score > 0);
  const a = await load('l11-hr-system-real-saas.eml', { domains: ['bamboohr.com'] });
  assert.equal(check(a, 'sender.allowed')?.status, 'ok');
  assert.equal(a.verdict.score, 0);
  assert.equal(a.verdict.warn, before.verdict.warn, 'warnings still listed');
  assert.equal(a.verdict.v, 'clean');
});

test('allowlisting never hides red flags (a trusted sender\'s mailbox can be hacked)', async () => {
  const a = await load('p02-compromised-sender-pages-dev.eml', { domains: ['smallbakery-leeds.test'] });
  assert.equal(check(a, 'sender.allowed')?.status, 'ok');
  assert.equal(a.verdict.v, 'malicious');
});

test('an allowlisted sender that is not authenticated gets no pass', async () => {
  const before = await load('h3-phish-parcel-fee.eml');
  const a = await load('h3-phish-parcel-fee.eml', { senders: ['info@rm-redelivery.test'] });
  assert.equal(check(a, 'sender.allowed'), undefined);
  assert.equal(check(a, 'sender.allowed-unverified')?.status, 'warn');
  assert.ok(a.verdict.score > before.verdict.score);
});

test('shared domains (Gmail, SES…) cannot be allowlisted as a domain, only as exact addresses', async () => {
  const a = await load('p01-bec-giftcards-freemail.eml', { domains: ['gmail.com'] });
  assert.equal(check(a, 'sender.allowed'), undefined);
  assert.deepEqual(allowProblems({ domains: ['gmail.com', 'amazonses.com', 'a@b.com', 'fine.example'], senders: ['nope'] }).length, 4);
});

test('feedback: record, summarise, suggest allowlist entries, export fixtures', async () => {
  const data = mkdtempSync(join(tmpdir(), 'pb-fb-')), out = join(data, 'fixtures');
  try {
    const rec = async (name: string, says: 'phish' | 'legit' | 'spam', keep = false) => {
      const a = await load(name); return recordFeedback(a, new Uint8Array(readFileSync(join(dir, name))), { file: join(dir, name), says, keep, version: 'test', dir: data });
    };
    const e1 = await rec('h4-phish-thread-hijack.eml', 'legit', true);   // suspicious, but say it's fine: a false alarm
    assert.equal(outcome(e1), 'false-alarm');
    assert.equal(e1.file, 'h4-phish-thread-hijack.eml', 'file name only, not the path');
    await rec('l01-mailchimp-newsletter.eml', 'phish', true);              // clean, but say phishing: a miss
    await rec('l11-hr-system-real-saas.eml', 'legit');
    await rec('l03-github-password-reset.eml', 'legit');
    await rec('l03-github-password-reset.eml', 'legit');                   // same email twice counts once
    await rec('p04-callback-pdf-freemail.eml', 'spam');
    const entries = readFeedback(data);
    assert.equal(entries.length, 5);
    const s = summarise(entries);
    assert.equal(s.falseAlarms.length, 1);
    assert.equal(s.misses.length, 1);
    assert.equal(s.noisyChecks[0].id, 'links.hosting');
    assert.deepEqual(s.allowSuggestions, [], 'one legitimate email per sender is not enough');
    const s2 = summarise([...entries, { ...entries.find(e => e.fromDomain === 'bamboohr.com')!, sha256: 'x' }]);
    assert.deepEqual(s2.allowSuggestions, [{ entry: 'bamboohr.com', kind: 'domain', count: 2 }]);
    assert.deepEqual(summarise([...entries, { ...entries.find(e => e.fromDomain === 'bamboohr.com')!, sha256: 'x' }], { domains: ['bamboohr.com'] }).allowSuggestions, []);
    const r = exportFixtures(out, data);
    assert.equal(r.written.length, 2);
    const exp = JSON.parse(readFileSync(join(out, 'expected.json'), 'utf8'));
    assert.deepEqual(Object.values(exp.emails).map((x: any) => x.expect).sort(), ['clean', 'notclean']);
    for (const f of r.written) assert.ok(existsSync(join(out, f)));
  } finally { rmSync(data, { recursive: true, force: true }); }
});

test('dashboard records feedback through the local server', async () => {
  const data = mkdtempSync(join(tmpdir(), 'pb-fb-'));
  const s = await startServer({ port: 0, ownDomains: own, feedback: true, feedbackDir: data });
  try {
    const body = readFileSync(join(dir, 'l05-docusign-envelope.eml'));
    const { summary } = await (await fetch(s.url + 'api/analyses', { method: 'POST', body, headers: { 'X-Phishbowl': '1', 'x-filename': '../../etc/x.eml' } })).json() as { summary: { id: string } };
    const post = (b: unknown, h: Record<string, string> = { 'X-Phishbowl': '1' }) => fetch(`${s.url}api/analyses/${summary.id}/feedback`, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: JSON.stringify(b) });
    assert.equal((await post({ says: 'legit' }, {})).status, 403, 'needs the X-Phishbowl header');
    assert.equal((await post({ says: 'maybe' })).status, 400);
    assert.equal((await post({ says: 'legit', keep: true })).status, 200);
    const e = readFeedback(data);
    assert.equal(e.length, 1);
    assert.equal(e[0].file, 'x.eml');
    assert.match(e[0].kept!, /^legit-[0-9a-f]{12}\.eml$/);
  } finally { s.server.close(); rmSync(data, { recursive: true, force: true }); }
});
