// Shareable reports for three audiences, built from an analysis. Everything is defanged.
import { defang, defangAll } from '../defang.js';
import { addrOf, domOf, hostOf, isKnown, labelOf, suffixMatch } from '../domains.js';
import { included, TYPE_LABEL, TYPES } from '../indicators.js';
import type { Analysis, Attachment, Check, EmailAnalysis, Link } from '../types.js';

export type Audience = 'tech' | 'mgmt' | 'staff';
export type Tlp = 'clear' | 'green' | 'amber' | 'amber-strict' | 'red';
export type ReportVerdict = 'malicious' | 'suspicious' | 'clean';

/** Actions an analyst can say were already done. Done ones move from "next steps" to "actions taken". */
export const ACTIONS = {
  'block-sender': 'Blocked the sender at the email gateway',
  purge: 'Removed the email from mailboxes',
  'block-net': 'Blocked the links, domains and IPs',
  edr: 'Added the file hashes to the endpoint blocklist',
  reset: 'Reset passwords and sessions for anyone who clicked',
} as const;
export type Action = keyof typeof ACTIONS;

export interface ReportOptions {
  audience?: Audience;
  /** Override the verdict from the checks. */
  verdict?: ReportVerdict;
  /** Sharing label (TLP 2.0). Default: AMBER, or CLEAR for a staff warning. */
  tlp?: Tlp;
  /** Reference. Default: PB-YYYYMMDD-XXXX from the Message-ID and subject. */
  ref?: string;
  preparedBy?: string;
  /** Who the customer email greets. Default: "<Recipient domain> team". */
  customer?: string;
  done?: Action[];
  ownDomains?: string[];
  /** Date printed on the report. Default: now. */
  now?: Date;
}

export const TLP_LABEL: Record<Tlp, string> = { clear: 'TLP:CLEAR', green: 'TLP:GREEN', amber: 'TLP:AMBER', 'amber-strict': 'TLP:AMBER+STRICT', red: 'TLP:RED' };
export const REPORT_VERDICT_LABEL: Record<ReportVerdict, string> = { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Not malicious' };

export type Block =
  | { verdict: ReportVerdict; label?: string; text: string }
  | { h: string } | { p: string } | { ul: string[] } | { ol: string[] }
  | { table: { head: string[]; rows: string[][] } } | { end: string };
export interface Report { meta: { tlp: Tlp; ref: string; date: string }; title: string; blocks: Block[] }

const fnv = (s: string) => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619); return (h >>> 0).toString(16).toUpperCase().padStart(8, '0'); };
export const when = (d: string | Date | null, withTime = false): string => {
  const t = d ? new Date(d) : new Date(); if (isNaN(+t)) return String(d);
  return t.toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}), timeZone: 'UTC' }) + (withTime ? ' UTC' : '');
};

export interface Details { v: ReportVerdict; tlp: Tlp; ref: string; by: string; cust: string; aud: Audience }
export function details(a: Analysis, o: ReportOptions): Details {
  const email = a.kind === 'email', aud = o.audience || 'tech';
  const v = o.verdict || (email ? a.verdict.v : included(a.indicators).length ? 'malicious' : 'clean');
  const tlp = o.tlp || (aud === 'staff' ? 'clear' : 'amber');
  const d = email && !isNaN(Date.parse(a.date)) ? new Date(a.date) : (o.now || new Date());
  const ref = o.ref || `PB-${d.toISOString().slice(0, 10).replace(/-/g, '')}-${fnv(email ? a.mid + a.subj : a.text).slice(0, 4)}`;
  const toDom = email ? domOf(addrOf(a.to)) : '', lab = toDom ? labelOf(toDom) : '';
  const cust = o.customer || (lab ? lab.charAt(0).toUpperCase() + lab.slice(1) + ' team' : 'team');
  return { v, tlp, ref, by: o.preparedBy || '', cust, aud };
}

// ── helpers over an email analysis ─────────────────────────────────────────────
export const has = (a: Analysis, id: string) => a.kind === 'email' && a.checks.some(c => c.id === id && (c.status === 'bad' || c.status === 'warn'));
const chk = (a: EmailAnalysis, id: string): Partial<Check> => a.checks.find(c => c.id === id) || {};
export const shortWhat = (x: Attachment) => x.what.replace(/\s*\(.*\)$/, '');
/** Attachments with a real problem (a QR image is reported as a link instead). */
export const badAtts = (a: EmailAnalysis) => a.real.filter(x => x.notes.some(n => (n[0] === 'bad' || n[0] === 'warn') && n[2] !== 'att.qr'));
export const mismatchLink = (a: EmailAnalysis): Link | undefined => a.links.find(l => l.findings.some(f => f[2] === 'links.mismatch'));
export const FRIENDLY: Record<string, string> = { 'application/pdf': 'PDF', 'image/png': 'image', 'image/jpeg': 'image', 'application/zip': 'zip file', 'text/plain': 'text file',
  'application/msword': 'Word document', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word document', 'application/vnd.ms-excel': 'Excel file' };
const SEVL: Record<string, string> = { bad: 'High', warn: 'Medium' };
export const ATTACK_NAMES: Record<string, string> = {
  'T1566.001': 'Phishing: Spearphishing Attachment', 'T1566.002': 'Phishing: Spearphishing Link', 'T1027.006': 'Obfuscated Files or Information: HTML Smuggling',
  T1656: 'Impersonation', 'T1056.003': 'Input Capture: Web Portal Capture', 'T1204.001': 'User Execution: Malicious Link', 'T1204.002': 'User Execution: Malicious File',
  T1221: 'Template Injection', T1078: 'Valid Accounts', 'T1114.003': 'Email Collection: Email Forwarding Rule', 'T1071.001': 'Application Layer Protocol: Web Protocols',
  'T1598.003': 'Phishing for Information: Spearphishing Link',
};

/** [id, technical step, plain-English step, technical done, plain-English done]. */
export type Step = [string, string, string, string?, string?];
export function steps(a: Analysis, o: ReportOptions): { todo: Step[]; did: Step[]; done: Set<string> } {
  const own = o.ownDomains || [], inc = included(a.indicators);
  const net = inc.filter(f => ['url', 'domain', 'ipv4', 'ipv6'].includes(f.type)), hs = inc.filter(f => ['sha256', 'sha1', 'md5'].includes(f.type));
  const S: Step[] = [];
  if (a.kind === 'email') {
    const senderDoms = [...new Set([addrOf(a.replyTo || ''), addrOf(a.rp || ''), a.spoofed ? '' : a.fromAddr].filter(x => x.includes('@')).map(domOf).filter(d => d && !suffixMatch(d, own) && !isKnown(d, own)))];
    if (senderDoms.length) S.push(['block-sender', `Block the sending domains at the email gateway: ${senderDoms.map(d => defang('domain', d)).join(', ')}.`, 'Block the sender so no more of these emails get through.',
      `Blocked the sending domains at the email gateway: ${senderDoms.map(d => defang('domain', d)).join(', ')}.`, 'Blocked the sender, so no more of these emails will get through.']);
    if (a.spoofed) S.push(['dmarc', `Review DMARC for ${defang('domain', a.fromDom)}: a spoofed message was delivered, so the policy isn't set to quarantine or reject.`, 'Tighten the email setting (DMARC) that stops outsiders sending as your domain.']);
    S.push(['purge', 'Find other recipients with the KQL hunt (subject and sender) and remove the message from every mailbox.', 'Find and remove any copies still sitting in mailboxes.',
      'Searched for other recipients (subject and sender) and removed the message from every mailbox.', 'Removed the email from everyone\'s mailbox.']);
  }
  if (net.length) S.push(['block-net', `Block the ${net.length} URLs, domains and IPs below at the web proxy, DNS filter and firewall.`, 'Block the fake website and the servers behind it.',
    `Blocked the ${net.length} URLs, domains and IPs below at the web proxy, DNS filter and firewall.`, 'Blocked the fake website and the servers behind it.']);
  if (hs.length) S.push(['edr', 'Add the file hashes below to the EDR blocklist and search endpoints for them.', 'Stop the attachment from opening on company devices.',
    'Added the file hashes below to the EDR blocklist.', 'Stopped the attachment from opening on company devices.']);
  if (a.kind === 'email' && (a.links.length || a.real.length)) S.push(['reset', 'Check proxy and sign-in logs for anyone who visited the links or opened the attachment. Reset their passwords, revoke sessions, and review their MFA methods and inbox rules.',
    'Reset the password of anyone who entered it on the fake page, straight away.', 'Reset passwords and revoked sessions for everyone who visited the link or opened the attachment.', 'Reset the passwords of everyone who entered theirs on the fake page.']);
  const done = new Set<string>(o.done || []);
  return { todo: S.filter(s => !done.has(s[0])), did: S.filter(s => done.has(s[0])), done };
}

export function techniques(a: Analysis): string[] {
  const t = new Set(included(a.indicators).filter(f => f.type === 'attack').map(f => f.value));
  if (a.kind === 'email') {
    const h = (id: string) => has(a, id);
    if (h('links.mismatch') || h('links.lookalike') || h('links.qr') || h('links.ip') || h('links.impersonation')) t.add('T1566.002');
    if (badAtts(a).length) t.add('T1566.001');
    if (h('att.smuggling') || a.real.some(x => x.fam === 'html')) t.add('T1027.006');
    if (h('att.cred-form') || (h('content.creds') && h('links.mismatch'))) t.add('T1056.003');
    if (h('att.macros')) t.add('T1204.002');
    if (h('att.remote-template')) t.add('T1221');
    if (a.spoofed || h('sender.display-brand') || h('sender.lookalike') || h('content.brand')) t.add('T1656');
  }
  return [...t].sort();
}

/** Reports are pasted into emails and tickets, so every line is defanged as a last step, whatever the wording. */
export function buildReport(a: Analysis, o: ReportOptions = {}): Report {
  const r = draftReport(a, o);
  const d = (s: string) => defangAll(s);
  return { meta: r.meta, title: d(r.title), blocks: r.blocks.map((b): Block => 'verdict' in b ? { ...b, text: d(b.text) } : 'p' in b ? { p: d(b.p) }
    : 'ul' in b ? { ul: b.ul.map(d) } : 'ol' in b ? { ol: b.ol.map(d) } : 'end' in b ? { end: d(b.end) } : b) };
}

function draftReport(a: Analysis, o: ReportOptions): Report {
  const D = details(a, o), { todo, did } = steps(a, o), inc = included(a.indicators);
  const meta = { tlp: D.tlp, ref: D.ref, date: when(o.now || null, true) }, B: Block[] = [];
  const iocRows = inc.filter(f => f.type !== 'attack').map(f => [TYPE_LABEL[f.type], defang(f.type, f.value), f.notes.filter(n => !/example data|^also /.test(n.t)).map(n => defangAll(n.t)).join('; ')]);

  if (D.aud === 'tech') {
    const title = a.kind === 'email' ? `Phishing email analysis: "${a.subj}"` : 'Indicator summary';
    if (a.kind === 'email') {
      const v = a.verdict, ml = mismatchLink(a), bad = badAtts(a);
      const flagged = a.checks.filter(c => c.status === 'bad' || c.status === 'warn').sort((x, y) => (x.status === 'bad' ? 0 : 1) - (y.status === 'bad' ? 0 : 1));
      B.push({ verdict: D.v, text: `${v.bad} red flags and ${v.warn} warnings across ${v.run} checks (score ${v.score}, ${v.conf} confidence).` });
      B.push({ h: 'Summary' }, { p: [
        `A message claiming to be from ${a.fromName ? a.fromName + ' ' : ''}<${defang('email', a.fromAddr)}> was received on ${when(a.date, true)}.`,
        a.spoofed && `The sender address was spoofed: it uses ${defang('domain', a.fromDom)} but failed DMARC.`,
        a.entry && `It entered from ${defang('domain', a.entry.from || '')} [${defang(a.entry.ip.includes(':') ? 'ipv6' : 'ipv4', a.entry.ip)}] (SPF ${a.auth.spf || 'none'}, DKIM ${a.auth.dkim || 'none'}, DMARC ${a.auth.dmarc || 'none'}${a.auth.compauth ? ', compauth ' + a.auth.compauth : ''}).`,
        a.replyTo && has(a, 'sender.replyto') && `Replies go to ${defang('email', addrOf(a.replyTo))}.`,
        ml && `A link displays ${defangAll(ml.text)} but leads to ${defang('url', ml.href)}.`,
        has(a, 'links.qr') && `A QR code in the body leads to ${defangAll((a.atts.find(x => x.extra.qr) as Attachment).extra.qr || '')}.`,
        bad.length && `It carries ${bad.length === 1 ? 'a dangerous attachment' : bad.length + ' dangerous attachments'}: ${bad.map(x => `${x.name} (declared ${x.declared}, actually ${shortWhat(x)})`).join('; ')}.`,
        has(a, 'filter.cat') && `Microsoft classified it as ${(chk(a, 'filter.cat').result || '').split(': ')[1] || 'malicious'}.`,
      ].filter(Boolean).join(' ') });
      if (flagged.length) B.push({ h: 'Findings' }, { ul: flagged.map(c => `[${SEVL[c.status]}] ${defangAll(c.name)}: ${defangAll(c.result)}${c.demo ? ' (demo data)' : ''}`) });
      if (a.real.length) B.push({ h: 'Attachments' }, { ul: a.real.map(x => `${x.name}: declared ${x.declared}, actually ${shortWhat(x)}, ${x.size} bytes. SHA256 ${x.sha256}`) });
    } else {
      B.push({ verdict: D.v, text: `${inc.length} indicators extracted from the supplied text.` });
      B.push({ h: 'Summary' }, { p: `${inc.length} indicators were extracted from the supplied text: ${TYPES.map(([k, l]) => [l, inc.filter(f => f.type === k).length] as const).filter(x => x[1]).map(([l, n]) => n + ' ' + l).join(', ')}.` });
    }
    if (iocRows.length) B.push({ h: 'Indicators of compromise' }, { table: { head: ['Type', 'Indicator (defanged)', 'Note'], rows: iocRows } });
    const tq = techniques(a); if (tq.length) B.push({ h: 'MITRE ATT&CK' }, { ul: tq.map(t => t + (ATTACK_NAMES[t] ? ' ' + ATTACK_NAMES[t] : '')) });
    if (did.length) B.push({ h: 'Actions taken' }, { ul: did.map(s => s[3] || s[1]) });
    if (todo.length) B.push({ h: 'Recommended next steps' }, { ol: todo.map(s => s[1]) });
    B.push({ end: `Prepared by ${D.by || '[your name]'} with Phishbowl. Indicators are defanged; refang them before loading into tools.` });
    return { meta, title, blocks: B };
  }

  const who = a.kind === 'email' ? (a.fromName || a.fromAddr) : '';
  if (D.aud === 'mgmt') {
    const title = a.kind === 'email' ? `Security incident summary: phishing email impersonating ${who}` : 'Threat indicator summary';
    B.push({ verdict: D.v, label: { malicious: 'High risk', suspicious: 'Medium risk', clean: 'Low risk' }[D.v],
      text: { malicious: 'This email is malicious.', suspicious: 'This email shows warning signs and is being investigated.', clean: 'No malicious indicators were found.' }[D.v] });
    B.push({ h: 'What happened' });
    if (a.kind === 'email') {
      const ml = mismatchLink(a), bad = badAtts(a);
      const shownHost = ml ? hostOf(/^https?:/i.test(ml.text) ? ml.text : 'https://' + ml.text) || ml.text : '';
      B.push({ p: [`On ${when(a.date)} a phishing email was sent to staff, pretending to come from ${who}.`, a.spoofed && 'The sender\'s address was faked to look like it came from inside the organisation.',
        ml && `It tries to get people to enter their password on a fake website made to look like ${shownHost}.`,
        has(a, 'links.qr') && 'It also includes a QR code that leads to the same kind of site, aimed at people reading on their phones.',
        bad.length && `It carries ${bad.length === 1 ? 'a file' : 'files'} disguised as ${FRIENDLY[bad[0].declared] ? 'a ' + FRIENDLY[bad[0].declared] : 'a document'}${bad[0].fam === 'html' ? ' that opens a fake sign-in page' : ''}.`].filter(Boolean).join(' ') });
    } else B.push({ p: `We have identified ${inc.length} indicators linked to malicious activity. They are listed below so your IT team can block them.` });
    B.push({ h: 'What this means' }, { p: {
      malicious: 'Anyone who entered their password on the fake page should treat their account as compromised until the password has been reset. The attachment should not be opened.',
      suspicious: 'The email should be treated with caution while it is investigated. Staff should not click its links or open its attachments.',
      clean: 'No action is needed beyond normal caution.' }[D.v] });
    B.push({ h: 'What we have done' }, did.length ? { ul: did.map(s => s[4] || s[2]) } : { p: 'The investigation is under way. We will update this summary as it progresses.' });
    if (todo.length) B.push({ h: 'What we recommend' }, { ul: todo.map(s => s[2]) });
    const top = inc.filter(f => ['url', 'domain', 'ipv4', 'ipv6', 'email', 'sha256'].includes(f.type));
    if (top.length) B.push({ h: 'Technical details for your IT team' }, { p: 'These can be blocked in your security tools. They are written in a safe, non-clickable form.' },
      { ul: top.slice(0, 12).map(f => `${TYPE_LABEL[f.type]}: ${defang(f.type, f.value)}`).concat(top.length > 12 ? [`and ${top.length - 12} more in the full technical report`] : []) });
    B.push({ end: `Prepared by ${D.by || '[your name]'}, reference ${D.ref}.` });
    return { meta, title, blocks: B };
  }

  const title = a.kind === 'email' ? `Warning: phishing email pretending to be ${who}` : 'Warning: look out for these malicious sites and senders';
  if (a.kind === 'email') {
    const ml = mismatchLink(a), bad = badAtts(a);
    B.push({ p: `We've seen a phishing email that asks you to ${ml || has(a, 'links.qr') ? 'sign in on a fake page' : bad.length ? 'open an attachment' : 'reply with information'}. Please look out for it and don't act on it.` });
    B.push({ h: 'How to spot it' }, { ul: [`Subject: "${a.subj}"`, `Appears to come from: ${a.fromName ? a.fromName + ' ' : ''}<${defang('email', a.fromAddr)}>${a.spoofed ? ' (this address was faked)' : ''}`,
      ml && `The link shows ${defangAll(ml.text)} but really goes to a different website`, has(a, 'links.qr') && 'It has a QR code asking you to scan it with your phone',
      ...bad.map(x => `Attachment: ${x.name}${FRIENDLY[x.declared] ? ` (it looks like a ${FRIENDLY[x.declared]} but isn't one)` : ''}`),
      a.replyTo && has(a, 'sender.replyto') && `Replies go to an outside address: ${defang('email', addrOf(a.replyTo))}`].filter((x): x is string => !!x) });
  } else B.push({ p: 'Please don\'t visit these websites or reply to these addresses. They are written in a safe, non-clickable form.' },
    { ul: inc.filter(f => ['url', 'domain', 'email'].includes(f.type)).slice(0, 10).map(f => defang(f.type, f.value)) });
  B.push({ h: 'What to do' }, { ul: ['Don\'t click the link, scan the QR code or open the attachment.', 'If you already did, change your password straight away and tell the IT or security team. You won\'t be in trouble.',
    'Report it with the Report phishing button in Outlook, then delete it.'] });
  if (did.length) B.push({ h: 'What we have done' }, { ul: did.map(s => s[4] || s[2]) });
  B.push({ p: 'Thanks,\n' + (D.by || 'The security team') });
  return { meta, title, blocks: B };
}

export function reportText(r: Report): string {
  const out = [[TLP_LABEL[r.meta.tlp], 'Ref ' + r.meta.ref, r.meta.date].join('  |  '), '', r.title, '='.repeat(Math.min(r.title.length, 72))];
  for (const b of r.blocks) {
    if ('verdict' in b) out.push('', `${(b.label || REPORT_VERDICT_LABEL[b.verdict]).toUpperCase()}: ${b.text}`);
    else if ('h' in b) out.push('', b.h.toUpperCase());
    else if ('p' in b) out.push(b.p);
    else if ('ul' in b) out.push(...b.ul.map(t => '- ' + t));
    else if ('ol' in b) out.push(...b.ol.map((t, i) => `${i + 1}. ${t}`));
    else if ('table' in b) out.push(...b.table.rows.map(([x, c, n]) => `- ${x}: ${c}${n ? '  (' + n + ')' : ''}`));
    else if ('end' in b) out.push('', b.end);
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n');
}

export function reportMarkdown(r: Report): string {
  const cell = (s: string) => String(s).replace(/\|/g, '\\|');
  const out = [[`**${TLP_LABEL[r.meta.tlp]}**`, 'Ref ' + r.meta.ref, r.meta.date].join(' · '), '', '## ' + r.title, ''];
  for (const b of r.blocks) {
    if ('verdict' in b) out.push(`**${b.label || REPORT_VERDICT_LABEL[b.verdict]}:** ${b.text}`, '');
    else if ('h' in b) out.push('### ' + b.h, '');
    else if ('p' in b) out.push(b.p.replace(/\n/g, '  \n'), '');
    else if ('ul' in b) out.push(...b.ul.map(t => '- ' + t), '');
    else if ('ol' in b) out.push(...b.ol.map((t, i) => `${i + 1}. ${t}`), '');
    else if ('table' in b) out.push('| ' + b.table.head.join(' | ') + ' |', '|' + b.table.head.map(() => ' --- ').join('|') + '|',
      ...b.table.rows.map(row => '| ' + row.map(c => cell(c) ? '`' + cell(c) + '`' : '').join(' | ') + ' |'), '');
    else if ('end' in b) out.push('_' + b.end + '_');
  }
  return out.join('\n').trim();
}
