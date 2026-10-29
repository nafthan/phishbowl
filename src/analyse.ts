// Entry point: analyse a raw email (or any text) and return checks, verdict and indicators.
import { buildContext } from './context.js';
import { senderChecks } from './checks/sender.js';
import { routeChecks } from './checks/route.js';
import { filterChecks } from './checks/filter.js';
import { contentChecks, images } from './checks/content.js';
import { linkChecks } from './checks/links.js';
import { attachmentChecks } from './checks/attachments.js';
import { extract } from './indicators.js';
import { binaryString, looksLikeEmail, stripMboxLine } from './mime.js';
import { verdictOf } from './verdict.js';
import { attachedEmails, MAX_DEPTH, MAX_NESTED, peek, reporterOf, reportSignals } from './nested.js';
import { defangAll } from './defang.js';
import { isOutlookMsg } from './files/sniff.js';
import { addOnline } from './online.js';
import { msgToEml } from './msg.js';
import { applyAllow } from './allow.js';
import type { AnalyseOptions, Analysis, EmailAnalysis } from './types.js';

const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/**
 * Analyse a raw email. Pass bytes when you have them (a file): each part is then decoded with the charset it
 * declares. Pass a string for pasted text. Anything that doesn't look like an email is treated as plain text and
 * only has its indicators extracted.
 */
export async function analyse(input: string | Uint8Array, opts: AnalyseOptions): Promise<Analysis> {
  const a = await analyseNested(input, opts);
  // Online lookups run once, on the email the analysis is about (the original, for a user's report).
  if (opts.online && !opts.depth && a.kind === 'email') {
    const t0 = now();
    await addOnline(a, { ownDomains: opts.ownDomains, ...opts.online });
    a.ms += Math.round(now() - t0);
  }
  if (opts.allow && !opts.depth && a.kind === 'email') applyAllow(a, opts.allow);
  return a;
}

async function analyseNested(input: string | Uint8Array, opts: AnalyseOptions): Promise<Analysis> {
  const t0 = now(), depth = opts.depth ?? 0;
  let msg: { hadHeaders: boolean; bodyFrom: string } | null = null;
  if (typeof input !== 'string' && isOutlookMsg(input)) {
    const conv = (opts.env.readMsg || msgToEml)(input);
    input = new TextEncoder().encode(conv.eml); msg = conv;
  }
  const outer = await analyseOne(input, opts);
  if (msg && outer.kind === 'email') {
    outer.checks.unshift(msg.hadHeaders
      ? { group: 'sender', id: 'sender.msg', name: 'Outlook .msg', status: 'info', result: 'Read from an Outlook .msg file. Outlook kept the original internet headers, so every check ran' }
      : { group: 'sender', id: 'sender.msg', name: 'Outlook .msg', status: 'info', result: 'Read from an Outlook .msg file without internet headers (a draft, a sent item, or saved by an export), so authentication, delivery route and spam-filter verdicts could not be checked. For a received email, save it again from the inbox' });
  }
  if (outer.kind !== 'email' || opts.unwrap === 'never' || depth >= MAX_DEPTH) return outer;
  const emails = attachedEmails(outer);
  if (!emails.length) return outer;
  const own = (opts.ownDomains || []).map(d => d.trim().toLowerCase()).filter(Boolean);
  const next = { ...opts, depth: depth + 1 };

  // A user's report: analyse the attached original instead, and say who reported it.
  const signs = reportSignals(outer, emails, own);
  if (signs.length) {
    const inner = await analyse(emails[0].bytes, next);
    if (inner.kind === 'email') {
      inner.reportedBy = reporterOf(outer, emails[0].name, signs);
      inner.checks.unshift({ group: 'sender', id: 'sender.reported', name: 'Reported email', status: 'info', result: defangAll(inner.reportedBy.note) });
      inner.ms = Math.round(now() - t0);
      return inner;
    }
  }

  // Otherwise the attached emails are part of this email: analyse each and let the worst one count.
  outer.nested = [];
  // A bounce carries your own returned message: show its verdict, but it says nothing about the bounce itself.
  const bounce = outer.checks.some(c => c.id === 'sender.bounce');
  for (const att of emails.slice(0, MAX_NESTED)) {
    const inner = await analyse(att.bytes, next);
    if (inner.kind !== 'email') continue;
    outer.nested.push({ name: att.name, subject: inner.subj, from: inner.from, verdict: inner.verdict, analysis: inner });
    const label = `${att.name}: "${inner.subj || peek(att.bytes).subject || '(no subject)'}"`;
    if (bounce) outer.checks.push({ group: 'att', id: 'att.nested-bounce', name: 'Returned message', status: 'info',
      result: defangAll(`${label}: ${inner.verdict.v === 'clean' ? 'nothing stood out' : inner.verdict.v} (score ${inner.verdict.score}). It is the message that bounced, so it doesn't count toward this verdict`) });
    else if (inner.verdict.v === 'malicious') outer.checks.push({ group: 'att', id: 'att.nested', name: 'Attached emails', status: 'bad',
      result: defangAll(`${label} is itself malicious (score ${inner.verdict.score}). Attaching an email hides its links and files from filters that don't open attachments`) });
    else if (inner.verdict.v === 'suspicious') outer.checks.push({ group: 'att', id: 'att.nested-suspicious', name: 'Attached emails', status: 'bad',
      result: defangAll(`${label} is itself suspicious (score ${inner.verdict.score})`) });
    else outer.checks.push({ group: 'att', id: 'att.nested-clean', name: 'Attached emails', status: 'info', result: defangAll(`${label}: nothing stood out (score ${inner.verdict.score})`) });
    // The attached email's indicators belong in this email's exports too.
    for (const f of inner.indicators) if (!outer.indicators.some(x => x.type === f.type && x.value === f.value))
      outer.indicators.push({ ...f, notes: [{ t: 'from the attached email ' + att.name }, ...f.notes] });
  }
  if (emails.length > MAX_NESTED) outer.checks.push({ group: 'att', id: 'att.nested-many', name: 'Attached emails', status: 'warn', result: `${emails.length} emails attached; only the first ${MAX_NESTED} were analysed` });
  outer.verdict = verdictOf(outer.checks);
  outer.ms = Math.round(now() - t0);
  return outer;
}

async function analyseOne(input: string | Uint8Array, opts: AnalyseOptions): Promise<Analysis> {
  const t0 = now(), own = (opts.ownDomains || []).map(d => d.trim().toLowerCase()).filter(Boolean);
  const binary = typeof input !== 'string';
  const raw = stripMboxLine(binary ? binaryString(input) : input);
  if (!looksLikeEmail(raw)) {
    const text = binary ? new TextDecoder('utf-8').decode(input) : raw;
    return { kind: 'text', text, indicators: extract(text, own, opts.leaveOut), ms: Math.round(now() - t0) };
  }
  const c = await buildContext(raw, binary, own, opts.env);
  senderChecks(c);
  routeChecks(c);
  filterChecks(c);
  contentChecks(c);
  linkChecks(c);
  attachmentChecks(c);

  const { remote } = images(c);
  const lines = ['From: ' + c.from, c.replyTo && 'Reply-To: ' + c.replyTo, c.rp && 'Return-Path: ' + c.rp, 'Subject: ' + c.subj, c.midDom && 'Message-ID host: ' + c.midDom,
    ...c.hops.map(h => `Received: from ${h.from} ${h.rdns && h.rdns !== h.from ? '(' + h.rdns + ') ' : ''}${h.ip ? '[' + h.ip + ']' : ''} by ${h.by}`), '',
    '[email body]', c.body.trim(), '',
    c.links.length ? '[links]' : '', ...c.links.map(l => `${l.href}   (${l.source}${l.text ? ', shows: ' + l.text : ''}${l.unwrapped ? ', unwrapped from ' + l.unwrapped : ''})`), '',
    remote.length ? '[remote images]' : '', ...remote.map(i => i.src + (i.w ? `   (${i.w}×${i.h})` : '')), '',
    c.real.length ? '[attachments]' : '', ...c.real.map(a => `${a.name}   SHA256 ${a.sha256}   SHA1 ${a.sha1}   MD5 ${a.md5}`)].filter(x => x);
  const text = lines.join('\n');

  // Indicators, with where each one came from.
  const indicators = extract(text, own, opts.leaveOut);
  for (const f of indicators) {
    const l = c.links.find(x => x.href === f.value);
    if (l) { const worst = l.findings.find(x => x[0] === 'bad') || l.findings.find(x => x[0] === 'warn'); f.notes.unshift({ t: l.source + (worst ? ': ' + worst[1] : ''), warn: !!worst }); }
    const att = c.real.find(x => [x.sha256, x.sha1, x.md5].includes(f.value));
    if (att) f.notes.unshift({ t: 'hash of attachment ' + att.name });
    if (f.type === 'email' && f.value === c.spoofed) { f.off = null; f.notes = [{ t: 'spoofed sender: kept even though it is your domain', warn: true }]; }
  }

  const result: EmailAnalysis = {
    kind: 'email', checks: c.checks, verdict: verdictOf(c.checks), headers: c.headers, auth: c.auth, spam: c.spam, hops: c.hops, entry: c.entry,
    from: c.from, fromName: c.fromName, fromAddr: c.fromAddr, fromDom: c.fromDom, replyTo: c.replyTo, rp: c.rp, to: c.to, subj: c.subj, date: c.date, mid: c.mid,
    mailer: c.mailer, spoofed: c.spoofed, authenticated: c.aligned, body: c.body, html: c.parts.html, links: c.links, atts: c.atts, real: c.real, text, indicators, ms: 0,
  };
  result.ms = Math.round(now() - t0);
  return result;
}
