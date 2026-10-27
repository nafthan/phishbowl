// A ready-to-paste email for the customer: no links, no attachments, every address defanged,
// and a final scan for anything an email client could still turn into a link.
import { TLDS } from '../lists.js';
import { defang, defangAll, RE } from '../defang.js';
import { addrOf, hostOf, tldOf } from '../domains.js';
import { included } from '../indicators.js';
import { badAtts, details, FRIENDLY, has, mismatchLink, shortWhat, steps, TLP_LABEL, when, type ReportOptions } from './report.js';
import type { Analysis } from '../types.js';

export interface CustomerEmail { subject: string; body: string; /** Anything that could still become a link. Empty means safe to send. */ hits: string[] }

/** File names ending in a real domain ending (like .zip) get a bracket, because Outlook would turn them into links. */
const safeName = (n: string) => TLDS.has(tldOf(n)) ? n.replace(/\.([^.]+)$/, '[.]$1') : n;

function liveLinks(text: string): string[] {
  const hits = new Set<string>(), scan = (re: RegExp) => { re.lastIndex = 0; let m; while ((m = re.exec(text))) hits.add(m[0]); };
  scan(RE.url); scan(RE.email); scan(RE.ipv4); scan(/\bwww\.[^\s]+/gi);
  RE.domain.lastIndex = 0; let m; while ((m = RE.domain.exec(text))) if (TLDS.has(tldOf(m[0]))) hits.add(m[0]);
  return [...hits];
}

export function buildCustomerEmail(a: Analysis, o: ReportOptions = {}): CustomerEmail {
  const inc = included(a.indicators), D = details(a, o), { did, done } = steps(a, o), L: string[] = [];
  const bullet = (arr: (string | false | null | undefined | 0)[]) => arr.filter((x): x is string => !!x).forEach(x => L.push('  • ' + x));
  const confirm = { malicious: 'We have confirmed it is malicious.', suspicious: 'It shows several warning signs and we are treating it as suspicious while we investigate.',
    clean: 'We found no malicious content, but we are sharing the details as a precaution.' }[D.v];
  let subject: string;
  L.push(`Hello ${D.cust},`, '');
  if (a.kind === 'email') {
    const ml = mismatchLink(a), bad = badAtts(a), shownHost = ml ? hostOf(/^https?:/i.test(ml.text) ? ml.text : 'https://' + ml.text) : '';
    subject = `[${TLP_LABEL[D.tlp]}] Security alert: phishing email impersonating ${a.fromName || 'a trusted sender'}`;
    L.push(`We're writing to let you know about a phishing email we identified on ${when(a.date)} that targets your organisation. ${confirm}`, '', 'WHAT THE EMAIL IS');
    bullet([`Subject: "${a.subj}"`, `Appears to come from: ${a.fromName ? a.fromName + ' ' : ''}<${defang('email', a.fromAddr)}>`, a.date && `Received: ${when(a.date, true)}`,
      (ml || has(a, 'content.creds')) && 'It asks the reader to sign in or confirm their details', has(a, 'links.qr') && 'It includes a QR code to scan with a phone',
      ...bad.map(x => `It includes an attachment named ${safeName(x.name)}`)]);
    L.push('', 'WHO REALLY SENT IT');
    bullet([a.entry && `It was sent from a server at ${defang('domain', a.entry.from || '')} (${defang(a.entry.ip.includes(':') ? 'ipv6' : 'ipv4', a.entry.ip)}), not from ${a.fromName || 'the organisation it names'}.`,
      a.spoofed && 'The sender\'s address was faked (spoofed) to look as if it came from inside your organisation.',
      a.replyTo && has(a, 'sender.replyto') && `Replies would go to an outside address: ${defang('email', addrOf(a.replyTo))}.`]);
    L.push('', 'WHY IT IS MALICIOUS');
    const lookDom = a.links.flatMap(l => l.findings.filter(f => f[2] === 'links.lookalike').map(() => hostOf(l.href)))[0];
    const qr = a.atts.find(x => x.extra.qr);
    bullet([ml && `A link in the email displays ${defang('domain', shownHost)} but leads to a look-alike site on ${defang('domain', hostOf(ml.href))}, set up to collect passwords.`,
      lookDom && lookDom !== hostOf((ml || { href: '' }).href) && `Another link uses a lookalike address (${defang('domain', lookDom)}) designed to be mistaken for a genuine one.`,
      has(a, 'links.qr') && qr && `It contains a QR code that leads to ${defang('domain', hostOf(qr.extra.qr || ''))}. QR codes are used to get past email link scanning.`,
      has(a, 'links.ip') && 'One link points straight at an IP address rather than a named website, which genuine organisations rarely do.',
      ...bad.map(x => `The attachment ${safeName(x.name)} pretends to be ${FRIENDLY[x.declared] ? 'a ' + FRIENDLY[x.declared] : 'a document'} but is ${/^([aeiou]|[FHLMNRSX][A-Z]{1,4}\b)/.test(shortWhat(x)) ? 'an' : 'a'} ${shortWhat(x)}.${x.notes.some(n => n[2] === 'att.cred-form') ? ' It contains a sign-in form that sends whatever is typed to the attackers.' : x.fam === 'html' ? ' Files like this are commonly used to show a fake sign-in page.' : ''}`),
      a.auth.dmarc && a.auth.dmarc !== 'pass' && 'It failed DMARC, the check that confirms an email really comes from the domain it claims.',
      has(a, 'filter.cat') && `Microsoft's own filter classified it as ${((a.checks.find(c => c.id === 'filter.cat') || { result: '' }).result.split(': ')[1] || 'malicious').toLowerCase()}.`,
      has(a, 'sender.display-brand') && `The sender's name claims to be ${a.fromName}, but the email doesn't come from them.`,
      has(a, 'content.seed') && 'It asks for a wallet recovery phrase, which no genuine service ever asks for.',
      has(a, 'content.urgency') && has(a, 'content.creds') && 'It uses pressure (a short deadline) to rush the reader into acting.',
      has(a, 'content.hidden') && 'It hides text from the reader to get past spam filters.',
      has(a, 'content.pixel') && 'It contains a hidden tracking image that tells the sender when the email is opened.']);
  } else {
    subject = `[${TLP_LABEL[D.tlp]}] Security advisory: indicators to block`;
    L.push(`We're sharing indicators linked to malicious activity that may affect your organisation.${D.v === 'suspicious' ? ' Some of them are still being investigated.' : ''}`, '');
    const doms = inc.filter(f => f.type === 'domain'), ips = inc.filter(f => f.type === 'ipv4' || f.type === 'ipv6'), mails = inc.filter(f => f.type === 'email');
    const hs = inc.filter(f => f.type === 'sha256'), urls = inc.filter(f => f.type === 'url');
    if (doms.length || mails.length) { L.push('DOMAINS AND SENDERS TO BLOCK'); bullet([...doms, ...mails].map(f => defang(f.type, f.value))); L.push(''); }
    if (ips.length) { L.push('IP ADDRESSES TO BLOCK'); bullet(ips.map(f => defang(f.type, f.value))); L.push(''); }
    if (hs.length) { L.push('FILE HASHES (SHA256) TO BLOCK'); bullet(hs.map(f => f.value)); L.push(''); }
    if (urls.length) L.push(`We've left out ${urls.length} full web address${urls.length > 1 ? 'es' : ''} for safety; your IT team can ask us for the technical report.`, '');
  }
  const email = a.kind === 'email';
  L.push('', 'WHAT WE HAVE DONE'); if (did.length) bullet(did.map(s => s[4] || s[2])); else L.push('  • We are investigating and will update you as we go.');
  L.push('', 'WHAT WE RECOMMEND');
  bullet([email && 'Ask staff not to reply to the email, click its link, scan its QR code or open its attachment, and to report it if they see it.',
    email && 'If anyone entered their password, reset it straight away and let us know so we can check the account.',
    !email && 'Add the domains, IP addresses and file hashes above to your blocklists.', email && !done.has('block-sender') && 'Block the sending domains at your email gateway, or let us do it for you.']);
  L.push('', 'For your safety, this message doesn\'t include the original email, its attachment or any working links. Addresses and domains are written with brackets, for example example[.]com, so they can\'t be clicked.', '',
    `If you have any questions, reply to this email quoting reference ${D.ref}.`, '', 'Kind regards,', D.by || '[your name]');
  const body = defangAll(L.join('\n')).replace(/\n{3,}/g, '\n\n');
  return { subject: defangAll(subject), body, hits: liveLinks(subject + '\n' + body) };
}
