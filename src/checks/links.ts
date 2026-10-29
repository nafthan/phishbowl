// Links and QR codes: one check per trick, rolled up from every link's findings.
import { defangAll } from '../defang.js';
import { hostOf, orgOf } from '../domains.js';
import type { Ctx } from '../context.js';

const LINK_CHECKS: [string, string][] = [['links.mismatch', 'Link text matches destination'], ['links.lookalike', 'Lookalike domains'], ['links.ip', 'Links to bare IP addresses'],
  ['links.at', 'user@host trick'], ['links.scheme', 'Script or data links'], ['links.shortener', 'URL shorteners'], ['links.redirect', 'Hidden redirects'], ['links.hosting', 'Free hosting services'],
  ['links.tld', 'Risky domain endings'], ['links.http', 'Unencrypted links'], ['links.subdomains', 'Subdomain chains'], ['links.tracked', 'Click-tracked links'], ['links.recipient', 'Your address in the link']];
const FLAG_TEXT: Record<string, string> = { 'links.hosting': 'a free hosting service', 'links.lookalike': 'a lookalike domain', 'links.ip': 'a bare IP address',
  'links.mismatch': 'a different site than it shows', 'links.shortener': 'a shortened URL' };

export function linkChecks(c: Ctx): void {
  const { add, links, web, checks } = c;
  const orgs = new Set(web.map(l => orgOf(hostOf(l.href)))).size;
  add('links', 'links.count', 'Links found', web.length ? 'info' : 'ok', web.length ? `${web.length} link${web.length > 1 ? 's' : ''} to ${orgs} domain${orgs > 1 ? 's' : ''}` : 'No web links');
  const scriptLinks = links.filter(l => /^(javascript|data|vbscript):/i.test(l.href));
  for (const [id, name] of LINK_CHECKS) {
    const seen = new Set<string>();
    const hits = [...web, ...scriptLinks].flatMap(l => l.findings.filter(f => f[2] === id).map(f => ({ l, f }))).filter(h => !seen.has(h.f[1]) && !!seen.add(h.f[1]));
    const worst = hits.some(h => h.f[0] === 'bad') ? 'bad' : hits.some(h => h.f[0] === 'warn') ? 'warn' : hits.length ? 'info' : web.length ? 'ok' : 'na';
    add('links', id, name, worst, hits.length
      ? hits.slice(0, 3).map(h => h.f[1] + (/QR|attachment|form/.test(h.l.source) ? ` (${h.l.source})` : '')).join('; ') + (hits.length > 3 ? `; and ${hits.length - 3} more` : '')
      : web.length ? 'None' : 'No links to check');
  }
  const linkFlags = Object.keys(FLAG_TEXT).filter(id => web.some(l => l.findings.some(f => f[2] === id && f[0] !== 'info')));
  const impersonates = c.brandClaim || checks.some(x => x.id === 'sender.lookalike' || x.id === 'content.brand') || !!c.spoofed;
  if (impersonates && linkFlags.length) add('links', 'links.impersonation', 'Impersonation with a risky link', 'bad',
    `The sender pretends to be ${c.spoofed ? 'your organisation' : c.brandClaim ? '"' + c.nameBrand + '"' : 'someone else'} and links to ${linkFlags.map(id => FLAG_TEXT[id]).join(', ')}`);
  const wrapped = links.filter(l => l.unwrapped);
  if (wrapped.length) add('links', 'links.unwrapped', 'Unwrapped links', 'info',
    `${wrapped.length} link${wrapped.length > 1 ? 's' : ''} unwrapped from ${[...new Set(wrapped.map(l => l.unwrapped))].join(', ')} so the real destination is checked`);
  const qrs = c.atts.filter(a => a.extra.qr), images = c.atts.filter(a => /^(png|jpg|gif)$/.test(a.fam)).length;
  if (!c.env.decodeQR) add('links', images ? 'links.qr-unchecked' : 'links.qr', 'QR codes', images ? 'warn' : 'na', images
    ? `${images} image${images > 1 ? 's were' : ' was'} not checked for QR codes: the optional QR reader isn't installed (npm install jsqr jpeg-js; see the README)`
    : 'No images to check');
  else add('links', 'links.qr', 'QR codes', qrs.length ? 'bad' : 'ok', qrs.length
    ? `${qrs.length > 1 ? qrs.length + ' QR codes hide links' : 'A QR code hides a link'} from email filters: ${qrs.map(a => defangAll(a.extra.qr || '')).join(', ')}`
    : 'No QR codes in images');
}
