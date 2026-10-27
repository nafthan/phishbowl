// Defanging (making indicators unclickable), refanging, and the indicator patterns.
import { TLDS } from './lists.js';
import { tldOf } from './domains.js';
import type { IndicatorType } from './types.js';

export const RE = {
  url: /\b(?:https?|ftp):\/\/[^\s"'<>()[\]{}]+/gi,
  email: /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/g,
  ipv4: /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d]|\.\d)/g,
  ipv6: /(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])/gi,   // candidates; validIPv6() decides
  domain: /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w-])/gi,
  sha256: /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/gi,
  sha1: /(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])/gi,
  md5: /(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])/gi,
  cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
  attack: /\bT\d{4}(?:\.\d{3})?\b/g,
};

export const validIPv6 = (s: string): boolean => {
  if ((s.match(/:/g) || []).length < 2 || (s.match(/::/g) || []).length > 1) return false;
  try { new URL('http://[' + s + ']'); return true; } catch { return false; }
};

/** hxxp, [.], (dot), [@] and similar back to their real form. */
export function refang(t: string): string {
  return t
    .replace(/\bhxxp(s?)/gi, 'http$1').replace(/\bh\[tt\]p(s?)/gi, 'http$1').replace(/\bfxp\b/gi, 'ftp')
    .replace(/\[\s*:\/\/\s*\]/g, '://').replace(/\[\s*:\s*\]/g, ':')
    .replace(/\s?(\[|\(|\{)\s*(\.|dot)\s*(\]|\)|\})\s?/gi, '.')
    .replace(/\s?(\[|\(|\{)\s*(@|at)\s*(\]|\)|\})\s?/gi, '@');
}

export function defang(type: IndicatorType | string, v: string): string {
  if (type === 'url') {
    const m = v.match(/^([a-z]+):\/\/([^/?#]+)(.*)$/i);
    if (!m) return v.replace(/\./g, '[.]');
    const scheme = m[1].toLowerCase().replace(/^http/, 'hxxp').replace(/^ftp/, 'fxp');
    return scheme + '://' + m[2].replace(/\./g, '[.]') + m[3];
  }
  if (type === 'email') { const [u, d] = v.split('@'); return u + '[@]' + (d || '').replace(/\./g, '[.]'); }
  if (type === 'domain' || type === 'ipv4') return v.replace(/\./g, '[.]');
  if (type === 'ipv6') return v.replace(/:/g, '[:]');
  return v;
}

/** Defang every URL, address, IP and domain in free text. */
export function defangAll(text: string): string {
  const all = new RegExp([RE.url.source, RE.email.source, RE.ipv4.source, RE.ipv6.source, RE.domain.source].map(s => '(' + s + ')').join('|'), 'gi');
  return refang(text).replace(all, (m: string, u?: string, e?: string, ip?: string, ip6?: string) => {
    if (u) { const tail = (m.match(/[.,;:!?'"]+$/) || [''])[0]; return defang('url', m.slice(0, m.length - tail.length)) + tail; }
    if (e) return defang('email', m);
    if (ip) return defang('ipv4', m);
    if (ip6) return validIPv6(m) ? defang('ipv6', m) : m;
    return TLDS.has(tldOf(m)) ? defang('domain', m) : m;
  });
}
