// Links: unwrap safe-link and tracking wrappers, then look for the tricks phishing uses.
import { FREE_HOSTING, INFRA, OPEN_HOSTING, SHORTENERS, SUSPICIOUS_TLD, TLDS, TRACKERS } from './lists.js';
import { defang } from './defang.js';
import { BRANDS } from './lists.js';
import { brandOwns, hostOf, isKnown, labelOf, lookalike, orgOf, suffixMatch, tldOf, weakLookalike } from './domains.js';
import type { Finding, Link, Severity } from './types.js';

/** Real destination behind a wrapper, or null if the URL isn't wrapped. */
export function unwrapLink(u: string): { url: string; by: string } | null {
  try {
    const x = new URL(u), h = x.hostname.toLowerCase();
    if (h.endsWith('safelinks.protection.outlook.com') && x.searchParams.get('url')) return { url: x.searchParams.get('url')!, by: 'Microsoft Safe Links' };
    if (/(^|\.)google\.[a-z.]+$/.test(h) && x.pathname === '/url') { const q = x.searchParams.get('q') || x.searchParams.get('url'); if (q) return { url: q, by: 'a Google redirect' }; }
    if (h === 'click.pstmrk.it') {   // Postmark keeps the destination in the path: /3s/<encoded url>/…
      const m = x.pathname.match(/^\/\d+[a-z]*\/([^/]+)/i);
      if (m) {
        const d = decodeURIComponent(m[1]);
        if (d.startsWith('click.pstmrk.it')) { const n = unwrapLink('https://' + d); if (n) return { url: n.url, by: 'Postmark click tracking' }; }
        return { url: 'https://' + d.replace(/^https?:\/\//, ''), by: 'Postmark click tracking' };
      }
    }
    if (h === 'urldefense.proofpoint.com' && x.searchParams.get('u'))
      return { url: x.searchParams.get('u')!.replace(/-/g, '%').replace(/_/g, '/').replace(/%([0-9A-F]{2})/gi, (_m, c: string) => String.fromCharCode(parseInt(c, 16))), by: 'Proofpoint URL Defense' };
  } catch { /* not a URL */ }
  return null;
}

export interface LinkContext {
  /** The sender is authenticated and the email wasn't forwarded inline. */
  aligned?: boolean;
  /** Bulk mail (List-Unsubscribe or List-ID present). */
  bulk?: boolean;
  /** Organisations that sent the email, when authenticated: their own links aren't a mismatch. */
  trustedOrgs?: string[];
  /** Organisation of the From domain, authenticated or not. */
  fromOrg?: string;
  /** Your own domains. */
  own?: string[];
  /** The recipient's address, to spot links that carry it. */
  recipient?: string;
}

export function inspectLink(l: Pick<Link, 'href' | 'text' | 'unwrapped'>, own: string[], targets: string[], ctx: LinkContext = {}): Finding[] {
  const f: Finding[] = [], add = (sev: Severity, t: string, id: string) => f.push([sev, t, id]);
  const href = l.href.trim();
  if (/^(javascript|data|vbscript):/i.test(href)) { add('bad', 'Uses a ' + href.split(':')[0] + ': link, which runs code or hides content', 'links.scheme'); return f; }
  if (/^mailto:/i.test(href)) { add('info', 'Opens an email to ' + defang('email', href.slice(7).split('?')[0]), 'links.mailto'); return f; }
  if (/^cid:|^#/.test(href)) return f;
  const host = hostOf(href); if (!host) return f;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) add('bad', 'Points at a bare IP address instead of a domain', 'links.ip');
  try { if (new URL(href).username) add('bad', 'Uses the user@host trick: everything before @ is ignored by the browser', 'links.at'); } catch { /* ignore */ }
  if (!isKnown(host, own) && !suffixMatch(host, INFRA)) { const why = lookalike(host, targets); if (why) add(weakLookalike(why) ? 'warn' : 'bad', host + ' ' + why, 'links.lookalike'); }
  if (suffixMatch(host, SHORTENERS)) add('warn', 'URL shortener hides the real destination', 'links.shortener');
  if (suffixMatch(host, OPEN_HOSTING)) {
    const where = suffixMatch(host, ['blob.core.windows.net', 'web.core.windows.net', 'azurewebsites.net', 'storage.googleapis.com']) ? host.split('.').slice(-4).join('.') : orgOf(host);
    add(ctx.aligned && ctx.bulk ? 'warn' : 'bad', `Goes to a page on ${where}, where anyone can publish a page in minutes: a common home for phishing pages`, 'links.hosting');
  } else if (suffixMatch(host, FREE_HOSTING)) add('warn', 'Hosted on a free or shared service that is often abused (' + orgOf(host) + ')', 'links.hosting');
  if (SUSPICIOUS_TLD.has(tldOf(host))) add('warn', '.' + tldOf(host) + ' is a domain ending often used for phishing', 'links.tld');
  if (/^http:/i.test(href)) add('warn', 'Not encrypted (http)', 'links.http');
  if (host.split('.').length > 5) add('warn', 'Long chain of subdomains, used to push the real domain out of view', 'links.subdomains');
  try {
    for (const [k, v] of new URL(href).searchParams) if (/^(https?:|\/\/|%2F%2F)/i.test(v) && !l.unwrapped) { add('warn', `Redirects onward through the "${k}" parameter`, 'links.redirect'); break; }
  } catch { /* ignore */ }
  if (l.text) {
    const shown = (l.text.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i) || [])[1];
    if (shown && TLDS.has(tldOf(shown)) && orgOf(shown) !== orgOf(host)) {
      if (suffixMatch(host, TRACKERS) || (ctx.trustedOrgs || []).includes(orgOf(host)))
        add(ctx.aligned ? 'info' : 'warn', `Shows ${defang('domain', shown.toLowerCase())} but goes through ${defang('domain', orgOf(host))} (click tracking), so the final site can't be checked from the email`, 'links.tracked');
      else if (ctx.aligned && ctx.bulk && !f.some(x => x[0] === 'bad'))
        add('warn', `Shows ${defang('domain', shown.toLowerCase())} but goes to ${defang('domain', host)}: probably the newsletter's click tracking, but it can't be confirmed`, 'links.tracked');
      else {
        // Deceptive when the text shows a brand (or your own domain) the destination doesn't belong to. A newsletter showing its
        // own sister sites while linking through its own domain is click tracking, even when nothing is authenticated.
        const sl = labelOf(shown), brand = BRANDS.find(b => b.replace(/ /g, '') === sl), mine = (ctx.own || []).some(d => orgOf(d) === orgOf(shown));
        const showsBrand = (brand && !brandOwns(brand, host)) || mine;
        if (!showsBrand && ctx.fromOrg && orgOf(host) === ctx.fromOrg)
          add('warn', `Shows ${defang('domain', shown.toLowerCase())} but goes to ${defang('domain', host)}, the sender's own domain: probably click tracking, but the sender isn't authenticated`, 'links.mismatch');
        else add('bad', `Shows ${defang('domain', shown.toLowerCase())} but goes to ${defang('domain', host)}`, 'links.mismatch');
      }
    }
  }
  const rc = (ctx.recipient || '').toLowerCase();
  if (rc && rc.includes('@')) {
    const h = href.toLowerCase(); let b = '';
    try { b = btoa(rc).replace(/=+$/, '').toLowerCase(); } catch { /* non-ASCII address */ }
    if (h.includes(rc) || h.includes(encodeURIComponent(rc)) || (b && h.includes(b))) add('warn', 'The link carries your email address, which phishing kits use to pre-fill a fake sign-in page', 'links.recipient');
  }
  return f;
}
