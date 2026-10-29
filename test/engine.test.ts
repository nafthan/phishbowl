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

// ── Lessons from real legitimate mail (SpamAssassin corpus and library fixtures) ─────────────────────────────
const msg = (headers: string, body = 'Hello.') => enc(`${headers}\nDate: Mon, 19 Oct 2026 09:00:00 +0000\nMessage-ID: <t@x.example>\n\n${body}`);

test('mbox exports: a leading "From sender date" line is skipped', async () => {
  const a = await analyseBytes(enc('From news@shop.example  Wed Sep  4 18:34:43 2002\nFrom: Shop <news@shop.example>\nSubject: Sale\nDate: Wed, 4 Sep 2002 18:00:00 +0000\n\nHello'));
  assert.equal(a.kind, 'email');
});

test('short brand names do not match inside words; a brand at the edge of a domain is only a warning', async () => {
  const html = (href: string) => msg('From: Search <news@search.example>\nSubject: Weekly picks\nMIME-Version: 1.0\nContent-Type: text/html', `<a href="${href}">Read more</a>`);
  const irs = email(await analyseBytes(html('https://www.firststopwebsearch.com/')));
  assert.equal(status(irs, 'links.lookalike'), 'ok');
  const edge = email(await analyseBytes(html('https://www.outlooksecure.example/')));
  assert.equal(status(edge, 'links.lookalike'), 'warn');
  const glyph = email(await analyseBytes(html('https://login.micros0ft-mailbox.example/')));
  assert.equal(status(glyph, 'links.lookalike'), 'bad');
});

test('a newsletter linking through its own domain is click tracking; showing a brand it isn\'t is a mismatch', async () => {
  const html = (text: string) => msg('From: News <alerts@newsletter.online.example>\nSubject: Today\nMIME-Version: 1.0\nContent-Type: text/html',
    `<a href="https://clickthru.online.example/c/123">${text}</a>`);
  assert.equal(status(email(await analyseBytes(html('news.com'))), 'links.mismatch'), 'warn');
  assert.equal(status(email(await analyseBytes(html('paypal.com'))), 'links.mismatch'), 'bad');
});

test('callback scams need a charge and "if you didn\'t authorise this, call…", not just a phone number', async () => {
  const footer = email(await analyseBytes(msg('From: Books <orders@books.example>\nSubject: New titles', 'New titles this month from $29.95. To order, call 1-800-998-9938.')));
  assert.equal(status(footer, 'content.callback'), undefined);
  const scam = email(await analyseBytes(msg('From: "PayPal Billing" <billing.renewals77@gmail.com>\nSubject: Order #88231',
    'Your subscription renewed for $399.99. If you did not authorise this payment, call our billing desk on +44 20 7946 0999.')));
  assert.equal(status(scam, 'content.callback'), 'bad');
});

test('a brand written as two words in the sender name is still a brand claim', async () => {
  const a = email(await analyseBytes(msg('From: "Royal Mail" <info@rm-redelivery.example>\nSubject: Parcel')));
  assert.equal(status(a, 'sender.display-brand'), 'bad');
});

test('a real bounce relaxes DMARC; a fake "delivery failed" email does not', async () => {
  const dsnHead = 'From: MAILER-DAEMON@mx.example (Mail Delivery System)\nSubject: Undelivered Mail Returned to Sender\nAuthentication-Results: mx.example; spf=none; dkim=none; dmarc=fail header.from=mx.example\nMIME-Version: 1.0\n';
  const real = email(await analyseBytes(enc(dsnHead + 'Content-Type: multipart/report; report-type=delivery-status; boundary="b"\nDate: Mon, 19 Oct 2026 09:00:00 +0000\n\n--b\nContent-Type: text/plain\n\nCould not deliver.\n--b\nContent-Type: message/delivery-status\n\nStatus: 5.1.1\n--b--\n')));
  assert.equal(status(real, 'sender.dmarc'), 'warn');
  assert.equal(status(real, 'sender.bounce'), 'info');
  const fake = email(await analyseBytes(enc(dsnHead + 'Content-Type: text/plain\nDate: Mon, 19 Oct 2026 09:00:00 +0000\n\nYour message could not be delivered. Sign in to release it.')));
  assert.equal(status(fake, 'sender.dmarc'), 'bad');
});

test('strike-through overlay letters are a script trick, and are folded away for brand matching', async () => {
  const raw = 'From: "Correios" <envio@entregas-rapidas.example>\nSubject: Fa̷lha na e̷ntrega: sua entrega está pendente\nDate: Mon, 19 Oct 2026 09:00:00 +0000\nMessage-ID: <x@entregas-rapidas.example>\n\nSua entrega está pendente.';
  const a = email(await analyseBytes(enc(raw)));
  assert.equal(status(a, 'sender.script'), 'bad');
  assert.match(a.checks.find(c => c.id === 'sender.script')!.result, /overlay/);
});

test('a forwarded brand lure is judged by the original sender, not the forwarding mailbox', async () => {
  // Forwarded from a Hotmail account (owned by Microsoft): the Microsoft lure inside must still be caught.
  const raw = ['Received: from mail-a.outlook.example (mail-a.outlook.example [192.0.2.9]) by mx.example.org with ESMTPS; Mon, 19 Oct 2026 09:00:02 +0000',
    'Authentication-Results: spf=pass smtp.mailfrom=hotmail.com; dkim=pass header.d=hotmail.com; dmarc=pass header.from=hotmail.com',
    'From: Jo <jo.reader@hotmail.com>', 'To: soc@example.org', 'Subject: Fw: Microsoft account unusual sign-in activity', 'Date: Mon, 19 Oct 2026 09:00:00 +0000',
    'Message-ID: <f1@hotmail.com>', '', 'Is this real?', '', '________________________________', 'From: Microsoft account team <alerts@ms-account-security.example>',
    'Sent: Monday, 19 October 2026 08:40', 'Subject: Microsoft account unusual sign-in activity', '', 'We detected unusual sign-in activity. Review your account now.'].join('\n');
  const a = email(await analyseBytes(enc(raw)));
  assert.equal(status(a, 'sender.forwarded'), 'warn');
  assert.equal(status(a, 'content.brand'), 'bad');
  assert.notEqual(a.verdict.v, 'clean');
});

test('account-lure wording is recognised beyond English', async () => {
  const mk = (subj: string) => `From: "Atendimento" <aviso@clientes-aviso.example>\nSubject: ${subj}\nDate: Mon, 19 Oct 2026 09:00:00 +0000\nMessage-ID: <y@itau-clientes.example>\n\n${subj}`;
  for (const subj of ['Itau: sua conta foi bloqueada', 'PayPal: tu cuenta ha sido bloqueada', 'PayPal : votre compte a été suspendu', 'PayPal: Ihr Konto wurde gesperrt', 'Itau: atualize seus dados'])
    assert.equal(status(email(await analyseBytes(enc(mk(subj)))), 'content.brand'), 'bad', subj);
});

test('the Suspicious line is 6: five points of background warnings alone stay legitimate', () => {
  const w = (group: 'content' | 'route' | 'links' | 'sender', id: string) => ({ group, id, name: id, status: 'warn' as const, result: '' });
  const background = [w('route', 'route.tls'), w('route', 'route.ptr'), w('content', 'content.urgency'), w('content', 'content.creds'), w('links', 'links.http'), w('sender', 'sender.returnpath')];
  assert.equal(verdictOf(background).score, 5);
  assert.equal(verdictOf(background).v, 'clean');
  assert.equal(verdictOf([...background, w('sender', 'sender.dkim')]).v, 'suspicious');
});

test('a user\'s report (original attached) is analysed as the original, with the reporter recorded', async () => {
  const a = email(await load('r01-report-as-attachment.eml'));
  assert.equal(a.subj, 'Action required: confirm your bank details before 23 Oct payroll');
  assert.equal(a.verdict.v, 'malicious');
  assert.equal(status(a, 'sender.spoof-own'), 'bad', 'the original\'s own headers are used');
  assert.match(a.reportedBy?.from || '', /j\.cole@northwind\.example/);
  assert.equal(status(a, 'sender.reported'), 'info');
  const legit = email(await load('r02-report-of-legit-newsletter.eml'));
  assert.equal(legit.subj, 'Last chance: 20% off autumn blends ends today');
  assert.equal(legit.verdict.v, 'clean');
});

test('an outside email that attaches a phishing email is malicious because of what it carries', async () => {
  const a = email(await load('p08-attached-email-attack.eml'));
  assert.equal(a.subj, 'Remittance advice attached');
  assert.equal(a.reportedBy, undefined);
  assert.equal(status(a, 'att.nested'), 'bad');
  assert.equal(a.nested?.[0].verdict.v, 'malicious');
  assert.ok(a.indicators.some(f => f.value.includes('micros0ft-mailbox.test')), 'the attached email\'s indicators are exported too');
  const flat = email(await analyseFile(join(dir, 'p08-attached-email-attack.eml'), { ownDomains: own, unwrap: 'never' }));
  assert.equal(flat.verdict.v, 'clean', 'without unwrapping, the envelope alone looks clean: that is the evasion');
});

test('a malicious envelope is never mistaken for a report, whatever its subject says', async () => {
  const lure = readFileSync(join(dir, 'p05-ses-lookalike-m365.eml'), 'utf8');
  const raw = ['From: "Microsoft 365" <alerts@m365-securemail.test>', 'To: j.cole@northwind.example', 'Subject: Fwd: Your mailbox storage is full - messages are being held',
    'Date: Mon, 19 Oct 2026 12:00:00 +0000', 'Message-ID: <w1@m365-securemail.test>', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b"', '',
    '--b', 'Content-Type: text/html', '', '<p>Release your messages: <a href="https://login.micros0ft-mailbox.test/r">Release</a></p>', '--b', 'Content-Type: message/rfc822', '', lure, '--b--', ''].join('\n');
  const a = email(await analyseBytes(enc(raw)));
  assert.equal(a.reportedBy, undefined);
  assert.equal(a.subj, 'Fwd: Your mailbox storage is full - messages are being held');
  assert.equal(a.verdict.v, 'malicious');
});

test('Outlook .msg: stored headers are used, the RTF-wrapped HTML body is unwrapped, attachments carry over', async () => {
  const a = email(await load('m01-phish-with-headers.msg'));
  assert.match(a.checks.find(c => c.id === 'sender.msg')?.result || '', /kept the original internet headers/);
  assert.equal(a.auth.spf, 'pass', 'authentication results come from the stored headers');
  assert.ok(a.hops.length >= 1);
  assert.ok(a.links.some(l => l.href.startsWith('https://login.northwlnd.test/') && l.text.includes('portal.northwind.example')), 'link from the RTF-wrapped HTML');
  assert.equal(status(a, 'content.hidden'), 'warn', 'hidden text inside the wrapped HTML is found');
  assert.equal(status(a, 'att.cred-form'), 'bad');
  assert.equal(a.verdict.v, 'malicious');
});

test('Outlook .msg: a report with the phish attached as an Outlook item is analysed as the original', async () => {
  const a = email(await load('m02-report-with-attached-item.msg'));
  assert.equal(a.subj, 'Your password expires today');
  assert.match(a.reportedBy?.from || '', /j\.cole@northwind\.example/);
  assert.equal(a.verdict.v, 'malicious');
});

test('Outlook .msg without internet headers: says so, and still finds links in RTF HYPERLINK fields', async () => {
  const a = email(await load('m03-rtf-hyperlink-no-headers.msg'));
  assert.match(a.checks.find(c => c.id === 'sender.msg')?.result || '', /without internet headers/);
  assert.ok(a.links.some(l => l.href === 'https://docs-share-4471.web.app/view' && l.text === 'docs.contoso-legal.test/shared'));
  assert.equal(status(a, 'links.mismatch'), 'bad');
});

test('RTF unwrapping: escapes text outside HTML tags and decodes code-page bytes and \\u characters', async () => {
  const { rtfToHtml } = await import('../src/rtf.js');
  // The \u control word is built from parts so no tool along the way can turn it into a character.
  const u = '\\' + 'u8364?';
  const r = rtfToHtml(String.raw`{\rtf1\ansi\ansicpg1252\fromhtml1{\*\htmltag <p>}caf\'e9 <b>x</b> ` + u + String.raw`{\*\htmltag </p>}\htmlrtf {\b ignored}\htmlrtf0 }`);
  assert.equal(r.fromHtml, true);
  assert.equal(r.html, '<p>café &lt;b&gt;x&lt;/b&gt; €</p>');
  assert.equal(rtfToHtml(String.raw`{\rtf1\ansi{\fonttbl{\f0 Arial;}}Hi \par there}`).html, '<html><body><div>Hi <br>\nthere</div></body></html>');
});

test('a copy with no delivery headers (sent item, export) says so and is never high confidence', async () => {
  const a = email(await analyseBytes(enc(['From: Nata <nata@protonmail.example>', 'To: j.cole@northwind.example', 'Subject: test', 'Date: Tue, 27 Oct 2026 21:31:02 +0000',
    'Message-ID: <abc@protonmail.example>', 'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', '', '<p>hi</p><a href="https://example.org/">example.org</a>'].join('\r\n')), { ownDomains: own }));
  assert.equal(status(a, 'route.noheaders'), 'warn');
  assert.equal(a.verdict.conf, 'medium');
  assert.equal(a.verdict.score, a.checks.filter(c => c.status === 'warn' && c.id !== 'route.noheaders').length, 'shown, but adds nothing to the score');
  const b = email(await load('l03-github-password-reset.eml'));
  assert.equal(status(b, 'route.noheaders'), undefined);
});

test('without the optional QR reader, images are listed as not checked and nothing else changes', async () => {
  const { nodeEnv, qrSupport } = await import('../src/node/index.js');
  assert.ok(qrSupport().qr, 'the dev install has jsqr');
  const file = join(dir, 'example-northwind-payroll.eml');
  const withQr = email(await analyseFile(file, { ownDomains: own }));
  const without = email(await analyseFile(file, { ownDomains: own, env: nodeEnv({ qr: false }) }));
  assert.equal(status(withQr, 'links.qr'), 'bad');
  assert.equal(status(without, 'links.qr'), undefined);
  assert.equal(status(without, 'links.qr-unchecked'), 'warn');
  assert.match(without.checks.find(c => c.id === 'links.qr-unchecked')!.result, /npm install jsqr jpeg-js/);
  assert.equal(without.verdict.v, 'malicious');
  const noImages = email(await load('l03-github-password-reset.eml'));
  assert.equal(status(noImages, 'links.qr-unchecked'), undefined);
});
