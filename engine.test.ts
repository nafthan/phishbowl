// Engine tests. Fixtures in test/fixtures are made-up emails modelled on real header patterns
// (Mailchimp, Salesforce Marketing Cloud, SES, DocuSign, Microsoft 365…) plus phishing variants.
// The real-phishing check lives in scripts/real-samples.ts (npm run test:real).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyseBytes, analyseFile } from '../src/node/index.js';
import { buildCustomerEmail } from '../src/report/customer.js';
import { exportAs } from '../src/report/exports.js';
import { buildReport, reportMarkdown, reportText } from '../src/report/report.js';
import { defang, defangAll, refang } from '../src/defang.js';
import { looksLikeEmail } from '../src/mime.js';
import { verdictOf } from '../src/verdict.js';
import type { Analysis, EmailAnalysis } from '../src/types.js';

const dir = join(import.meta.dirname, 'fixtures');
const expected: { ownDomains: string[]; emails: Record<string, { expect: string; set: string }> } = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8'));
const own = expected.ownDomains;
const load = async (name: string, ownDomains = own) => analyseFile(join(dir, name), { ownDomains });
const email = (a: Analysis): EmailAnalysis => { assert.equal(a.kind, 'email'); return a as EmailAnalysis; };
const status = (a: EmailAnalysis, id: string) => a.checks.find(c => c.id === id)?.status;
const enc = (s: string) => new TextEncoder().encode(s);

test('every fixture gets the expected verdict', async t => {
  for (const [file, { expect }] of Object.entries(expected.emails)) {
    await t.test(file, async () => {
      const a = email(await load(file));
      const got = a.verdict.v, flagged = a.checks.filter(c => c.status === 'bad' || c.status === 'warn').map(c => `${c.status} ${c.id}`).join(', ');
      if (expect === 'notclean') assert.notEqual(got, 'clean', `expected suspicious or malicious, got clean (${flagged})`);
      else assert.equal(got, expect, `score ${a.verdict.score}: ${flagged}`);
    });
  }
});

test('example email: the key findings, QR code and hashes', async () => {
  const a = email(await load('example-northwind-payroll.eml'));
  assert.equal(a.verdict.v, 'malicious');
  assert.equal(status(a, 'sender.spoof-own'), 'bad');
  assert.equal(status(a, 'links.mismatch'), 'bad');
  assert.equal(status(a, 'att.cred-form'), 'bad');
  assert.equal(status(a, 'links.qr'), 'bad');
  const qr = a.atts.find(x => x.extra.qr);
  assert.equal(qr?.extra.qr, 'https://northwind-hr-portal.test/m/8812');
  // Checked against Python's hashlib.
  const html = a.atts.find(x => x.name === 'Payroll_Policy_Oct2026.pdf.html')!;
  assert.equal(html.sha256, 'ca0364b0136b7ac261cb29bcb0d2ca274d5a4884c63ff6365aa60fa8ba740aeb');
  assert.equal(html.sha1, '25822b6a4654f79717e467b4ddbb5ccb1279ed35');
  assert.equal(html.md5, '197dba72f3d06afe98394a6a3ad9794e');
  assert.ok(a.links.some(l => l.unwrapped === 'Microsoft Safe Links' && l.href.startsWith('https://northwind-hr-portal.test/')));
  // The spoofed sender is kept as an indicator even though it is "your" domain.
  assert.ok(a.indicators.some(f => f.type === 'email' && f.value === 'payroll@northwind.example' && !f.off));
});

test('without your domains, the spoof of your domain is not detected but the email is still malicious', async () => {
  const a = email(await load('example-northwind-payroll.eml', []));
  assert.equal(status(a, 'sender.spoof-own'), undefined);
  assert.equal(a.verdict.v, 'malicious');
});

test('Microsoft SFV:NSPM ("not spam") is not mistaken for SPM', async () => {
  const a = email(await load('l01-mailchimp-newsletter.eml'));
  assert.equal(status(a, 'filter.sfv'), 'ok');
});

test('internal Exchange mail is not treated as spoofing your domain', async () => {
  const a = email(await load('l02-internal-colleague-invoice.eml'));
  assert.equal(status(a, 'sender.spoof-own'), 'ok');
});

test('text that is not an email: indicators only, refanged', async () => {
  const a = await analyseFile(join(dir, 'example-threat-report.txt'));
  assert.equal(a.kind, 'text');
  const v = (type: string) => a.indicators.filter(f => f.type === type).map(f => f.value);
  assert.ok(v('url').includes('https://northwind-hr-portal.test/verify/login.php?id=8812'));
  assert.ok(v('ipv4').includes('203.0.113.77'));
  assert.ok(v('email').includes('backup.archive.77@mailbox-relay.test'));
  assert.ok(v('cve').includes('CVE-2024-21413'));
  assert.ok(v('attack').includes('T1566.002'));
  assert.ok(v('sha256').includes('2e5f502eec9a7e8c3ad09385484da336a96b3cc58e1c4d593fcafa88fb2769e8'));
  // Private IPs and well-known sites are found but left out of exports by default.
  assert.ok(a.indicators.find(f => f.value === '10.20.4.112')?.off);
  assert.ok(a.indicators.find(f => f.value === 'attack.mitre.org')?.off);
});

test('defang and refang', () => {
  assert.equal(defang('url', 'https://evil.example/a.b'), 'hxxps://evil[.]example/a.b');
  assert.equal(defang('email', 'a.b@evil.example'), 'a.b[@]evil[.]example');
  assert.equal(refang('hxxps://evil[.]example and x[@]y(dot)test'), 'https://evil.example and x@y.test');
  assert.equal(defangAll('see https://evil.example/x, or mail a@b.test.'), 'see hxxps://evil[.]example/x, or mail a[@]b[.]test.');
});

test('an email with a very long header block is still recognised (From after 8 KB of Received headers)', () => {
  const received = Array.from({ length: 60 }, (_, i) => `Received: from relay${i}.example.net (relay${i}.example.net [192.0.2.${i}]) by mx.example.org with ESMTPS id ${'x'.repeat(80)}; Mon, 19 Oct 2026 09:00:00 +0000`).join('\n');
  const raw = `${received}\nFrom: a@b.example\nSubject: hi\n\nbody`;
  assert.ok(raw.indexOf('From:') > 8000);
  assert.ok(looksLikeEmail(raw));
  assert.ok(!looksLikeEmail('Hello,\nFrom: someone in a threat report\nSubject: also prose\n\nmore'));
});

test('bytes are decoded with each part\'s declared charset, and 8-bit UTF-8 headers are read', async () => {
  const head = 'From: =?utf-8?B?Q2Fmw6k=?= <a@b.example>\nSubject: Réunion\nDate: Mon, 19 Oct 2026 09:00:00 +0000\nMIME-Version: 1.0\n';
  const latin1Body = Uint8Array.from([...'Content-Type: text/plain; charset=windows-1252\nContent-Transfer-Encoding: 8bit\n\nCaf'].map(c => c.charCodeAt(0)).concat([0xe9, 0x0a]));
  const bytes = new Uint8Array([...enc(head), ...latin1Body]);
  const a = email(await analyseBytes(bytes));
  assert.equal(a.fromName, 'Café');
  assert.equal(a.subj, 'Réunion');
  assert.equal(a.body.trim(), 'Café');
});

test('lookalike letters and invisible characters in the sender name are caught', async () => {
  const mk = (name: string) => `From: "${name}" <support@rule.example>\nSubject: Device update\nDate: Mon, 19 Oct 2026 09:00:00 +0000\nMessage-ID: <x@rule.example>\n\nPlease update.`;
  const greek = email(await analyseBytes(enc(mk('[ LΕDGΕR ]'))));
  assert.equal(status(greek, 'sender.script'), 'bad');
  assert.equal(status(greek, 'sender.display-brand'), 'bad');
  const hidden = email(await analyseBytes(enc(mk('Mic\u{E0139}ros\u{E0139}oft Service'))));
  assert.equal(status(hidden, 'sender.script'), 'bad');
  assert.equal(status(hidden, 'sender.display-brand'), 'bad');
});

test('reports and the customer email contain nothing clickable', async () => {
  const a = await load('example-northwind-payroll.eml');
  for (const audience of ['tech', 'mgmt', 'staff'] as const) {
    const r = buildReport(a, { audience, ownDomains: own });
    for (const text of [reportText(r), reportMarkdown(r)]) assert.doesNotMatch(text, /\bhttps?:\/\//i, `${audience} report has a live URL`);
  }
  const m = buildCustomerEmail(a, { ownDomains: own });
  assert.deepEqual(m.hits, []);
  assert.match(m.body, /^Hello Northwind team,/);
});

test('"already done" actions move from next steps to actions taken', async () => {
  const a = await load('example-northwind-payroll.eml');
  const before = reportText(buildReport(a, { ownDomains: own }));
  const after = reportText(buildReport(a, { ownDomains: own, done: ['purge'] }));
  assert.match(before, /RECOMMENDED NEXT STEPS[\s\S]*remove the message from every mailbox/);
  assert.match(after, /ACTIONS TAKEN\n- Searched for other recipients/);
});

test('exports', async () => {
  const a = await load('example-northwind-payroll.eml');
  const stix = JSON.parse(exportAs('stix', a));
  assert.equal(stix.type, 'bundle');
  assert.ok(stix.objects.length > 5 && stix.objects.every((o: { pattern: string }) => o.pattern.startsWith('[')));
  assert.match(exportAs('kql', a), /union isfuzzy=true/);
  assert.match(exportAs('kql', a), /Subject in~ \(ioc_subjects\)/);
  assert.match(exportAs('csv', a).split('\n')[0], /^type,indicator,defanged,seen,notes$/);
  assert.doesNotMatch(exportAs('list', a), /\bhttps?:\/\//);
  const json = JSON.parse(exportAs('json', a));
  assert.equal(json.verdict.result, 'malicious');
  assert.ok(json.checks.length > 50);
});

test('verdict scoring: content warnings are capped, a critical red flag is malicious on its own', () => {
  const w = (group: 'content' | 'sender', id: string) => ({ group, id, name: id, status: 'warn' as const, result: '' });
  assert.equal(verdictOf([1, 2, 3, 4, 5, 6].map(i => w('content', 'content.x' + i))).score, 2);
  assert.equal(verdictOf([{ group: 'att', id: 'att.macros', name: '', status: 'bad', result: '' }]).v, 'malicious');
  assert.equal(verdictOf([{ group: 'sender', id: 'sender.replyto', name: '', status: 'bad', result: '' }]).v, 'suspicious');
});
