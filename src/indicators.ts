// Indicator (IOC) extraction from text: URLs, domains, IPs, addresses, hashes, CVEs, ATT&CK ids.
import { FILE_LIKE, RESERVED_TLD, TLDS } from './lists.js';
import { RE, refang, validIPv6 } from './defang.js';
import { hostOf, ipv4Class, ipv6Class, isKnown, suffixMatch, tldOf } from './domains.js';
import type { Indicator, IndicatorType, LeaveOut } from './types.js';

export const TYPES: [IndicatorType, string][] = [
  ['url', 'URL'], ['domain', 'Domain'], ['ipv4', 'IPv4'], ['ipv6', 'IPv6'], ['email', 'Email'],
  ['sha256', 'SHA256'], ['sha1', 'SHA1'], ['md5', 'MD5'], ['cve', 'CVE'], ['attack', 'ATT&CK'],
];
export const TYPE_LABEL = Object.fromEntries(TYPES) as Record<IndicatorType, string>;

function context(text: string, at: number, len: number): Indicator['ctx'] {
  const s = Math.max(0, at - 42), e = Math.min(text.length, at + len + 42);
  return { pre: (s > 0 ? '…' : '') + text.slice(s, at).replace(/\s+/g, ' '), hit: text.slice(at, at + len), post: text.slice(at + len, e).replace(/\s+/g, ' ') + (e < text.length ? '…' : '') };
}

interface Working extends Omit<Indicator, 'from'> { fromSet: Set<string> }

/** Pull indicators out of any text (a threat report, or the readable summary of an email). Defanged input is refanged first. */
export function extract(raw: string, own: string[], leaveOut: LeaveOut = {}): Indicator[] {
  const opts = { private: leaveOut.private ?? true, known: leaveOut.known ?? true, files: leaveOut.files ?? true };
  const text = refang(raw);
  const found = new Map<string, Working>();
  const add = (type: IndicatorType, value: string, idx: number, len: number, extra?: string) => {
    const key = type + '|' + value;
    let f = found.get(key);
    if (!f) { f = { type, value, count: 0, at: idx, len, notes: [], off: null, fromSet: new Set(), ctx: { pre: '', hit: '', post: '' } }; found.set(key, f); }
    f.count++; if (extra) f.fromSet.add(extra);
  };
  const scan = (re: RegExp, fn: (v: string, i: number) => void) => { re.lastIndex = 0; let m; while ((m = re.exec(text))) fn(m[0], m.index); };
  scan(RE.url, (v, i) => {
    v = v.replace(/[.,;:!?'"]+$/, '');
    add('url', v, i, v.length);
    const h = hostOf(v); if (/[a-z]/i.test(h) && !h.includes(':')) add('domain', h, i, v.length, 'in a URL');
  });
  scan(RE.email, (v, i) => { add('email', v.toLowerCase(), i, v.length); add('domain', v.split('@')[1].toLowerCase(), i, v.length, 'in an email address'); });
  scan(RE.ipv4, (v, i) => add('ipv4', v, i, v.length));
  scan(RE.ipv6, (v, i) => { if (validIPv6(v)) add('ipv6', v.toLowerCase(), i, v.length); });
  scan(RE.domain, (v, i) => {
    const d = v.toLowerCase();
    if (!TLDS.has(tldOf(d)) || /^\d+(\.\d+)+$/.test(d)) return;
    if (found.has('domain|' + d) && [...found.values()].some(f => (f.type === 'url' || f.type === 'email') && i >= f.at && i < f.at + f.len && f.value.toLowerCase().includes(d))) return;
    add('domain', d, i, v.length);
  });
  for (const t of ['sha256', 'sha1', 'md5'] as const) scan(RE[t], (v, i) => add(t, v.toLowerCase(), i, v.length));
  scan(RE.cve, (v, i) => add('cve', v.toUpperCase(), i, v.length));
  const urlSpans = [...found.values()].filter(f => f.type === 'url').map(f => [f.at, f.at + f.len]);
  scan(RE.attack, (v, i) => { if (!urlSpans.some(([a, b]) => i >= a && i < b)) add('attack', v, i, v.length); });
  for (const f of found.values()) {
    if (f.fromSet.size) f.notes.push({ t: 'also ' + [...f.fromSet].join(', ') });
    const host = f.type === 'domain' ? f.value : f.type === 'email' ? f.value.split('@')[1] : f.type === 'url' ? hostOf(f.value) : '';
    if (f.type === 'ipv4' || f.type === 'ipv6') {
      const c = f.type === 'ipv4' ? ipv4Class(f.value) : ipv6Class(f.value);
      if (c && c[0] === 'private') { f.notes.push({ t: c[1], warn: true }); if (opts.private) f.off = c[1]; }
      else if (c) f.notes.push({ t: c[1] });
    }
    if (host && isKnown(host, own)) {
      const mine = suffixMatch(host, own);
      f.notes.push({ t: mine ? 'your own domain' : 'well-known site', warn: true });
      if (opts.known) f.off = mine ? 'your own domain' : 'well-known site';
    }
    if (f.type === 'domain' && FILE_LIKE.has(tldOf(f.value)) && !f.fromSet.size) {
      f.notes.push({ t: 'probably a file name (.' + tldOf(f.value) + ' is also a domain ending)', warn: true });
      if (opts.files) f.off = 'probably a file name';
    }
    if (f.type === 'domain' && RESERVED_TLD.has(tldOf(f.value)) && !f.off) f.notes.push({ t: 'reserved ending (example data)' });
    f.ctx = context(text, f.at, f.len);
  }
  const order = Object.fromEntries(TYPES.map(([k], i) => [k, i])) as Record<IndicatorType, number>;
  return [...found.values()].sort((a, b) => order[a.type] - order[b.type] || a.at - b.at)
    .map(({ fromSet, ...f }) => ({ ...f, from: [...fromSet] }));
}

/** Indicators that go into exports: not left out by default. */
export const included = (list: Indicator[]): Indicator[] => list.filter(f => !f.off);
