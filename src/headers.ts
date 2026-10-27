// Received chain, authentication results, and spam filter headers (Microsoft 365 and generic).
import { H, HA } from './mime.js';
import type { Auth, Header, Hop, SpamField } from './types.js';

export function parseReceived(r: string): Hop {
  const semi = r.lastIndexOf(';');
  const main = r.slice(0, semi > 0 ? semi : r.length), date = semi > 0 ? r.slice(semi + 1).trim() : '';
  const from = (main.match(/\bfrom\s+(\S+)/i) || [])[1] || '';
  const paren = (main.match(/\bfrom\s+\S+\s+\(([^)]*)\)/i) || [])[1] || '';
  const ip = (paren.match(/\[([0-9a-f:.]+)\]/i) || main.match(/\[([0-9a-f:.]+)\]/i) || paren.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/) || [])[1] || '';
  const rdns = (paren.match(/^\s*([^\s[]+)\s*\[/) || [])[1] || '';
  const by = (main.match(/\bby\s+(\S+)/i) || [])[1] || '';
  const withp = (main.match(/\bwith\s+(.+?)(?:\s+id\s|\s+for\s|$)/i) || [])[1] || '';
  const t = Date.parse(date.replace(/\s*\([^)]*\)\s*$/, ''));
  const tls = /ESMTPS|ESMTPSA|LMTPS|TLS|HTTPS/i.test(withp + ' ' + main);
  return { raw: r, from: from.replace(/[[\]]/g, ''), rdns, ip, by, with: withp.trim(), time: isNaN(t) ? null : t, tls };
}

export function parseAuth(headers: Header[]): Auth {
  const ar = HA(headers, 'authentication-results').join(' ; ') + ' ; ' + HA(headers, 'arc-authentication-results').join(' ; ');
  const res = (k: string) => ((ar.match(new RegExp('\\b' + k + '=([a-z]+)', 'i')) || [])[1] || '').toLowerCase();
  const prop = (k: string) => ((ar.match(new RegExp('\\b' + k.replace('.', '\\.') + '=([^;\\s)]+)', 'i')) || [])[1] || '').toLowerCase();
  const rspf = H(headers, 'received-spf');
  const dkimSigs = HA(headers, 'dkim-signature').map(s => ({
    d: (s.match(/\bd=([^;\s]+)/) || [])[1] || '', s: (s.match(/\bs=([^;\s]+)/) || [])[1] || '',
    a: (s.match(/\ba=([^;\s]+)/) || [])[1] || '', h: ((s.match(/\bh=([^;]+)/) || [])[1] || '').toLowerCase().replace(/\s/g, ''),
  }));
  const dmarcAction = ((ar.match(/dmarc=\w+[^;]*?\b(?:action|p)=([a-z]+)/i) || [])[1] || '').toLowerCase();
  let dkimD = prop('header.d') || prop('header.i').replace(/^@/, '');
  if (dkimD === 'none') dkimD = '';
  return {
    spf: res('spf') || (rspf.split(/\s/)[0] || '').toLowerCase(), dkim: res('dkim'), dmarc: res('dmarc'), dmarcAction,
    compauth: res('compauth'), compReason: ((ar.match(/compauth=\w+\s+reason=(\d+)/i) || [])[1] || ''), arc: res('arc'),
    mailfrom: prop('smtp.mailfrom'), dkimD, hfrom: prop('header.from'), dkimSigs, raw: ar,
  };
}

export function parseSpam(headers: Header[]): SpamField[] {
  const out: SpamField[] = [];
  const fr = H(headers, 'x-forefront-antispam-report');
  if (fr) for (const part of fr.split(';')) { const [k, ...v] = part.split(':'); if (k && k.trim()) out.push(['X-Forefront-Antispam-Report', k.trim().toUpperCase(), v.join(':').trim()]); }
  const ms = H(headers, 'x-microsoft-antispam');
  if (ms) for (const part of ms.split(';')) { const [k, ...v] = part.split(':'); if (k && /^BCL$/i.test(k.trim())) out.push(['X-Microsoft-Antispam', 'BCL', v.join(':').trim()]); }
  const scl = H(headers, 'x-ms-exchange-organization-scl'); if (scl) out.push(['X-MS-Exchange-Organization-SCL', 'SCL', scl.trim()]);
  for (const h of ['x-spam-status', 'x-spam-flag', 'x-spam-score', 'x-spam-level']) { const v = H(headers, h); if (v) out.push([h.replace(/(^|-)\w/g, c => c.toUpperCase()), '', v.trim()]); }
  return out;
}

/** Plain-English meaning of Microsoft 365 spam filter fields. */
export const SPAM_MEANING: Record<string, (v: string) => string> = {
  SCL: v => +v === -1 ? 'Skipped filtering (sender is trusted or on an allow list)' : +v <= 1 ? 'Not spam' : +v <= 6 ? 'Spam' : 'High-confidence spam',
  SFV: v => ({ SPM: 'Marked as spam', NSPM: 'Not spam', SKN: 'Allowed by a mail flow rule', SKA: 'Allowed by an allow list', SKB: 'Matched a block list', SKS: 'Marked spam by a mail flow rule',
    SFE: 'Allowed by the user\'s safe senders', BLK: 'From a blocked sender', SKQ: 'Released from quarantine', SKI: 'Internal message' } as Record<string, string>)[v] || 'Spam filter verdict code',
  CAT: v => ({ PHSH: 'Phishing', HPHSH: 'High-confidence phishing', SPM: 'Spam', HSPM: 'High-confidence spam', BULK: 'Bulk mail', MALW: 'Malware', SPOOF: 'Spoofing',
    DIMP: 'Domain impersonation', UIMP: 'User impersonation', GIMP: 'Mailbox intelligence impersonation', AMP: 'Anti-malware', NONE: 'No category' } as Record<string, string>)[v] || 'Protection category',
  BCL: v => +v === 0 ? 'Not bulk mail' : +v <= 3 ? 'Bulk, few complaints' : +v <= 7 ? 'Bulk, some complaints' : 'Bulk, many complaints',
  CTRY: v => 'Country of the sending IP: ' + v, LANG: v => 'Language detected: ' + v, CIP: () => 'Connecting IP address',
  IPV: v => ({ CAL: 'IP is on the allow list', NLI: 'IP is not on any reputation list' } as Record<string, string>)[v] || 'IP reputation',
  PTR: v => /nonexistent/i.test(v) ? 'The sending IP has no reverse DNS (PTR) record' : 'Reverse DNS of the sending IP',
  H: () => 'Name the server gave itself (HELO)', DIR: v => ({ INB: 'Inbound', OUT: 'Outbound', INT: 'Internal' } as Record<string, string>)[v] || 'Direction',
};
