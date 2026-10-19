// Everything the checks need, worked out once: parsed headers, bodies, links, attachments, and the judgements
// several checks share (is the sender authenticated? forwarded inline? claiming to be a brand?).
import { BRANDS, FREE_MAIL } from './lists.js';
import { RE } from './defang.js';
import { addrOf, brandOwns, domOf, isOwnFactory, isPrivateIp, labelOf, orgOf, suffixMatch } from './domains.js';
import { inspectAttachment } from './files/attachment.js';
import { parseAuth, parseReceived, parseSpam } from './headers.js';
import { inspectLink, unwrapLink } from './links.js';
import { decodeWords, H, HA, splitHeaders, walk, type Parts } from './mime.js';
import { findBrand, fold } from './text.js';
import type { Attachment, Auth, Check, Env, Group, Header, Hop, Link, SpamField, Status } from './types.js';

export interface Ctx {
  env: Env;
  own: string[];
  /** Organisation labels a lookalike might imitate: your own and the brands. */
  targets: string[];
  isOwn: (d: string) => boolean;
  headers: Header[];
  parts: Parts;
  auth: Auth;
  spam: SpamField[];
  hops: Hop[];
  entry: Hop | null;
  from: string; fromAddr: string; fromDom: string; fromName: string;
  replyTo: string; rtAddr: string; rtDom: string;
  rp: string; rpDom: string;
  sender: string; to: string; subj: string; date: string; mid: string; midDom: string;
  mailer: string; unsub: string; listId: string;
  /** X-Forefront-Antispam-Report. */
  fr: string;
  /** Original sender line of an inline forward, or ''. */
  fwd: string;
  /** Exchange marked the message as internal. */
  internal: boolean;
  /** DMARC failed but Microsoft accepted it on a forwarder's ARC seal. */
  arcRescued: boolean;
  /** The From domain is authenticated (or the mail is internal). */
  aligned: boolean;
  /** Authenticated and not forwarded inline: only then does authentication vouch for the content. */
  trusted: boolean;
  dkimD: string;
  /** The From address if it spoofs one of your own domains. */
  spoofed: string;
  rtDiff: boolean; toList: boolean; rtFree: boolean;
  nameBrand: string | undefined;
  /** The display name names a brand that nothing in the sending chain belongs to. */
  brandClaim: boolean;
  sendOrgs: string[];
  freeMail: boolean;
  docs: Document[];
  htmlText: string;
  /** Plain text of the message (text part, or the HTML's text). */
  body: string;
  /** Subject, body and HTML text together, for phrase matching. */
  all: string;
  links: Link[];
  web: Link[];
  atts: Attachment[];
  real: Attachment[];
  checks: Check[];
  add: (group: Group, id: string, name: string, status: Status, result: string, extra?: Partial<Check>) => void;
}

export async function buildContext(raw: string, binary: boolean, own: string[], env: Env): Promise<Ctx> {
  const { headers } = splitHeaders(raw), parts: Parts = { text: [], html: [], attachments: [] };
  walk(raw, parts, 0, binary);
  const dw = (v: string) => decodeWords(v, binary);
  const checks: Check[] = [];
  const add: Ctx['add'] = (group, id, name, status, result, extra) => { checks.push({ group, id, name, status, result, ...(extra || {}) }); };
  const targets = [...new Set([...own.map(labelOf), ...BRANDS.map(b => b.replace(/ /g, ''))])];
  const isOwn = isOwnFactory(own);

  const from = dw(H(headers, 'from')), fromAddr = addrOf(from), fromDom = domOf(fromAddr), fromName = ((from.match(/^"?([^"<]+?)"?\s*</) || [])[1] || '').trim();
  const replyTo = dw(H(headers, 'reply-to')), rp = H(headers, 'return-path'), sender = H(headers, 'sender');
  const to = dw(H(headers, 'to')), subj = dw(H(headers, 'subject')), date = H(headers, 'date'), mid = H(headers, 'message-id');
  const mailer = H(headers, 'x-mailer') || H(headers, 'user-agent'), unsub = H(headers, 'list-unsubscribe'), listId = H(headers, 'list-id');
  const auth = parseAuth(headers), spam = parseSpam(headers);
  const hops = HA(headers, 'received').map(parseReceived).reverse();   // oldest first
  const entry = hops.find(h => h.ip && !isPrivateIp(h.ip)) || null;
  const fr = H(headers, 'x-forefront-antispam-report');

  // Forwarded inline ("Fw:" with the original pasted below): the headers describe whoever forwarded it, not the attacker.
  const quick = parts.text.join('\n') + '\n' + parts.html.map(h => h.replace(/<[^>]+>/g, ' ')).join('\n');
  const fwdBlock = /^\s*(fw|fwd|tr|wg|rv|enc)\s*:/i.test(subj) &&
    quick.match(/(?:^|\n)[ \t]*(?:from|de|von|van|da)\s*:[ \t]*([^\n]{2,160})\n(?:[^\n]*\n){0,3}?[ \t]*(?:sent|enviado|gesendet|verzonden|envoy\S*|date|inviato)\s*:/i);
  const fwd = fwdBlock ? fwdBlock[1].replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim() : '';

  // Authenticated context. Many "mismatch" checks are normal for authenticated bulk and SaaS mail, so they only count
  // as warnings when the From domain is NOT authenticated.
  const internal = /internal/i.test(H(headers, 'x-ms-exchange-organization-authas')) || /\bDIR:INT\b/i.test(fr) || /\bSFV:SKI\b/i.test(fr);
  const arcRescued = auth.dmarc === 'fail' && (auth.compauth === 'pass' || auth.arc === 'pass');
  const aligned = internal || auth.dmarc === 'pass' || arcRescued;
  const trusted = aligned && !fwd;
  const dkimD = auth.dkimD || (auth.dkimSigs[0] || { d: '' }).d || '';
  const spoofed = isOwn(fromDom) && !internal && !arcRescued && auth.dmarc && auth.dmarc !== 'pass' ? fromAddr : '';

  const rtAddr = addrOf(replyTo), rtDom = domOf(rtAddr), rtDiff = !!replyTo && orgOf(rtDom) !== orgOf(fromDom);
  const toList = !!listId && rtDiff && (rtAddr === addrOf(sender) || listId.toLowerCase().includes(rtAddr.split('@')[0]));
  const rtFree = rtDiff && suffixMatch(rtDom, FREE_MAIL) && !suffixMatch(fromDom, FREE_MAIL);
  const rpDom = domOf(addrOf(rp));
  const nameBrand = findBrand(fromName, [...own.map(labelOf), ...BRANDS]);
  const fromLabel = labelOf(fromDom);
  const nameHasSender = fromLabel.length >= 4 && fold(fromName).toLowerCase().replace(/[^a-z0-9]/g, '').includes(fromLabel.replace(/[^a-z0-9]/g, ''));
  const sendOrgs = [fromDom, dkimD, rpDom].filter(Boolean);
  const brandClaim = !!nameBrand && !sendOrgs.some(d => brandOwns(nameBrand, d)) && !isOwn(fromDom) && !nameHasSender;
  const freeMail = suffixMatch(fromDom, FREE_MAIL);

  const docs = parts.html.map(h => env.parseHtml(h));
  const htmlText = docs.map(d => (d.body ? d.body.textContent || '' : '')).join('\n');
  const body = (parts.text.join('\n') || htmlText).replace(/\r/g, '');
  const all = subj + '\n' + body + '\n' + htmlText;

  // Attachments first: QR codes and links inside them join the link list.
  const atts: Attachment[] = [];
  for (const a of parts.attachments) atts.push(await inspectAttachment(a, env));

  const links: Link[] = [];
  const linkCtx = { aligned: trusted, bulk: !!(unsub || listId), trustedOrgs: trusted ? [orgOf(fromDom), orgOf(dkimD)].filter(Boolean) : [], recipient: addrOf(to) };
  const pushLink = (hrefIn: string | null, text: string | null, source: string) => {
    const href = String(hrefIn || '').trim(); if (!href || /^cid:|^#/.test(href)) return;
    const un = unwrapLink(href);
    const l: Link = { href: un ? un.url : href, wrapped: un ? href : '', unwrapped: un ? un.by : '', text: (text || '').replace(/\s+/g, ' ').trim(), source, findings: [] };
    if (links.some(x => x.href === l.href && x.source === l.source)) return;
    l.findings = inspectLink(l, own, targets, linkCtx); links.push(l);
  };
  for (const d of docs) for (const a of d.querySelectorAll('a[href], area[href]')) pushLink(a.getAttribute('href'), a.textContent, 'email (HTML)');
  for (const t of parts.text) for (const u of t.match(RE.url) || []) pushLink(u.replace(/[.,;:!?'"]+$/, ''), '', 'email (text)');
  for (const a of atts) {
    if (a.extra.qr && /^https?:/i.test(a.extra.qr)) pushLink(a.extra.qr, '', 'QR code in ' + a.name);
    for (const u of a.extra.urls || []) pushLink(u, '', 'attachment ' + a.name);
    for (const f of (a.extra.html || { forms: [] }).forms) if (/^https?:/i.test(f.action)) pushLink(f.action, '', 'form in ' + a.name);
  }
  const web = links.filter(l => /^https?:/i.test(l.href));
  const real = atts.filter(a => !(a.inline && /^image\//.test(a.declared) && !a.extra.qr));

  return {
    env, own, targets, isOwn, headers, parts, auth, spam, hops, entry, from, fromAddr, fromDom, fromName, replyTo, rtAddr, rtDom, rp, rpDom,
    sender, to, subj, date, mid, midDom: (mid.match(/@([^>]+)>?/) || [])[1] || '', mailer, unsub, listId, fr, fwd, internal, arcRescued, aligned, trusted,
    dkimD, spoofed, rtDiff, toList, rtFree, nameBrand, brandClaim, sendOrgs, freeMail, docs, htmlText, body, all, links, web, atts, real, checks, add,
  };
}
