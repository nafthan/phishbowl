// Domain, address and IP helpers, plus lookalike detection.
import { BRAND_OWNS, CONFUSABLE, KNOWN_GOOD, TWO_LEVEL } from './lists.js';

export const tldOf = (d: string): string => d.split('.').pop()!.toLowerCase();

/** Registrable domain ("organisation"): mail.example.co.uk → example.co.uk. */
export const orgOf = (d: string): string => {
  const p = String(d || '').toLowerCase().replace(/\.$/, '').split('.');
  if (p.length < 2) return p.join('.');
  const two = p.slice(-2).join('.');
  return TWO_LEVEL.has(two) && p.length > 2 ? p.slice(-3).join('.') : two;
};
/** First label of the registrable domain: example.co.uk → example. */
export const labelOf = (d: string): string => orgOf(d).split('.')[0];
export const hostOf = (u: string): string => { try { return new URL(u).hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch { return ''; } };
/** Address out of a header value: `"Name" <a@b.c>` → a@b.c. */
export const addrOf = (v: string): string => { const m = String(v || '').match(/<([^>]+)>/); return (m ? m[1] : String(v || '')).trim().toLowerCase(); };
export const domOf = (a: string): string => (String(a).split('@')[1] || '').replace(/>$/, '').toLowerCase();
export const suffixMatch = (d: string, list: string[]): boolean => list.some(k => d === k || d.endsWith('.' + k));
export const isKnown = (d: string, own: string[]): boolean => suffixMatch(d, [...KNOWN_GOOD, ...own]);

type IpClass = ['private' | 'doc', string] | null;
export function ipv4Class(ip: string): IpClass {
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return ['private', 'private range'];
  if (a === 127) return ['private', 'loopback'];
  if (a === 169 && b === 254) return ['private', 'link-local'];
  if (a === 100 && b >= 64 && b <= 127) return ['private', 'carrier-grade NAT'];
  if (a === 0 || a >= 224) return ['private', 'not routable'];
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return ['doc', 'documentation range (example data)'];
  return null;
}
export function ipv6Class(ip: string): IpClass {
  const s = ip.toLowerCase();
  if (s === '::1') return ['private', 'loopback'];
  if (/^fe[89ab]/.test(s)) return ['private', 'link-local'];
  if (/^f[cd]/.test(s)) return ['private', 'unique local (private)'];
  if (/^2001:0?db8:/.test(s)) return ['doc', 'documentation range (example data)'];
  return null;
}
export const isPrivateIp = (ip: string): boolean => ((ip.includes(':') ? ipv6Class(ip) : ipv4Class(ip)) || [])[0] === 'private';

/** Does this domain belong to the brand? */
export const brandOwns = (b: string, d: string): boolean => {
  const l = labelOf(d || ''), key = b.replace(/ /g, '');
  return !!l && (l === key || (BRAND_OWNS[b] || []).includes(l) || (b === 'irs' && /(^|\.)irs\.gov$/.test(d)) || (b === 'hmrc' && /(^|\.)hmrc\.gov\.uk$/.test(d)));
};

// ── lookalikes ──────────────────────────────────────────────────────────────────
function lev(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 3) return 9;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[a.length][b.length];
}
const deglyph = (s: string): string => s.toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
  .replace(/5/g, 's').replace(/\$/g, 's').replace(/@/g, 'a').replace(/[^\x00-\x7f]/g, c => (CONFUSABLE[c] || c).toLowerCase());

/** Containing a brand (outlooksecure.com, outlook.example.biz) is weaker evidence than imitating it (micros0ft, paypa1). */
export const weakLookalike = (reason: string): boolean => /inside an unrelated domain|in the subdomain of/.test(reason);

/** A reason string if `domain` looks like one of `targets` (organisation labels) without being it, else ''. */
export function lookalike(domain: string, targets: string[]): string {
  const host = String(domain || '').toLowerCase();
  if (!host) return '';
  if (/(^|\.)xn--/.test(host)) return 'uses punycode (xn--), which can hide lookalike Unicode letters';
  const org = orgOf(host), label = org.split('.')[0], sub = host.slice(0, host.length - org.length);
  for (const t of targets) {   // a brand or your name in the subdomain is the more telling sign, so check it first
    if (sub && label !== t && new RegExp('(^|[.-])' + t + '([.-]|$)').test(sub)) return `puts "${t}" in the subdomain of an unrelated domain (${org})`;
  }
  for (const t of targets) {
    if (!t || label === t) continue;
    if (deglyph(label) === t) return `imitates "${t}" with lookalike characters`;
    if (t.length >= 5 && lev(label, t) === 1) return `is one letter away from "${t}"`;
    if (t.length >= 8 && lev(label, t) === 2) return `is two letters away from "${t}"`;
    if (t.length >= 4 && (label.startsWith(t) || label.endsWith(t) || label.split('-').includes(t))) return `puts "${t}" inside an unrelated domain`;
    for (const part of label.split('-')) {   // micros0ft-mailbox, paypa1-secure: check each hyphenated part too
      if (part === t || part.length < 4) continue;
      if (deglyph(part) === t) return `imitates "${t}" with lookalike characters`;
      if (t.length >= 5 && lev(part, t) === 1) return `is one letter away from "${t}"`;
    }
  }
  return '';
}

/** A test for "is this one of my organisation's domains?" (subdomains included). */
export const isOwnFactory = (own: string[]) => { const orgs = own.map(orgOf); return (d: string): boolean => !!d && orgs.includes(orgOf(d)); };
