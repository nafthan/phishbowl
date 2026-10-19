// Entry point: analyse a raw email (or any text) and return checks, verdict and indicators.
import { buildContext } from './context.js';
import { senderChecks } from './checks/sender.js';
import { routeChecks } from './checks/route.js';
import { filterChecks } from './checks/filter.js';
import { contentChecks, images } from './checks/content.js';
import { linkChecks } from './checks/links.js';
import { attachmentChecks } from './checks/attachments.js';
import { extract } from './indicators.js';
import { binaryString, looksLikeEmail } from './mime.js';
import { verdictOf } from './verdict.js';
import type { AnalyseOptions, Analysis, EmailAnalysis } from './types.js';

const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/**
 * Analyse a raw email. Pass bytes when you have them (a file): each part is then decoded with the charset it
 * declares. Pass a string for pasted text. Anything that doesn't look like an email is treated as plain text and
 * only has its indicators extracted.
 */
export async function analyse(input: string | Uint8Array, opts: AnalyseOptions): Promise<Analysis> {
  const t0 = now(), own = (opts.ownDomains || []).map(d => d.trim().toLowerCase()).filter(Boolean);
  const binary = typeof input !== 'string';
  const raw = binary ? binaryString(input) : input;
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
    mailer: c.mailer, spoofed: c.spoofed, body: c.body, html: c.parts.html, links: c.links, atts: c.atts, real: c.real, text, indicators, ms: 0,
  };
  result.ms = Math.round(now() - t0);
  return result;
}
