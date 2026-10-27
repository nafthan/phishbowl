// Online lookups (opt-in). Off unless the host passes `online` options: nothing in this file runs otherwise.
//
// What leaves the machine, and to whom:
//   • RDAP (domain age): the registrable domain of the sender, Reply-To, Return-Path and link hosts, sent to the
//     domain's registry (found with IANA's RDAP bootstrap file), or to rdap.org if the bootstrap can't be read.
//   • DNS over HTTPS (MX, SPF, DMARC): the sender's registrable domain, sent to the resolver (Cloudflare by default).
//     The resolver then asks the domain's own name servers, so whoever runs the domain could see a lookup happened.
//     Only the registrable domain is queried, never a full host name, because unique per-target subdomains are a
//     common way to track who looked.
//   • Known-phishing feeds: the OpenPhish community feed is DOWNLOADED and matched here; no URL is sent anywhere.
//   • URLhaus (only with an Auth-Key): link host names, sent to abuse.ch. Full URLs are never sent: they often carry
//     the recipient's address or a token.
// Email content, addresses, subjects and attachments are never sent. Results are cached by the host.
import { hostOf, isKnown, orgOf } from './domains.js';
import { OPEN_HOSTING } from './lists.js';
import { defangAll } from './defang.js';
import { verdictOf } from './verdict.js';
import type { Check, EmailAnalysis } from './types.js';

export interface OnlineCache {
  get(key: string): unknown | undefined;
  set(key: string, value: unknown, ttlMs: number): void;
}

export interface OnlineOptions {
  /** fetch to use (globalThis.fetch in Node 18+ and browsers; inject one for tests or a proxy). */
  fetch?: typeof fetch;
  cache?: OnlineCache;
  /** Your domains: never looked up. */
  ownDomains?: string[];
  /** Domain age via RDAP. Default true. */
  rdap?: boolean;
  /** MX, SPF and DMARC of the sender's domain via DNS over HTTPS. Default true. */
  dns?: boolean;
  /** Download known-phishing feeds and match links locally. Default true. */
  feeds?: boolean;
  /** abuse.ch URLhaus host lookups. Needs a free Auth-Key (https://auth.abuse.ch/). */
  urlhausKey?: string;
  /** DNS-over-HTTPS JSON endpoint. Default https://cloudflare-dns.com/dns-query */
  dohUrl?: string;
  /** Feed of phishing URLs, one per line. Default: OpenPhish community feed (non-commercial use only). */
  feedUrl?: string;
  timeoutMs?: number;
  /** Most domains looked up per email. Default 8. */
  maxDomains?: number;
  now?: () => number;
}

export const DEFAULTS = {
  dohUrl: 'https://cloudflare-dns.com/dns-query',
  feedUrl: 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt',
  bootstrapUrl: 'https://data.iana.org/rdap/dns.json',
  rdapFallback: 'https://rdap.org/domain/',
  urlhausHost: 'https://urlhaus-api.abuse.ch/v1/host/',
};
const HOUR = 3600e3, DAY = 24 * HOUR;
const TTL = { rdap: 7 * DAY, rdapMiss: DAY, dns: HOUR, feed: 12 * HOUR, bootstrap: 7 * DAY, urlhaus: 6 * HOUR };
/** Younger than this is a red flag; younger than YOUNG_DAYS a warning. */
export const NEW_DAYS = 30, YOUNG_DAYS = 90;

/** A cache that lasts as long as the process (the Node host supplies one kept on disk). */
export function memoryCache(now = () => Date.now()): OnlineCache {
  const m = new Map<string, { v: unknown; until: number }>();
  return { get: k => { const e = m.get(k); return e && e.until > now() ? e.v : undefined; }, set: (k, v, ttl) => { m.set(k, { v, until: now() + ttl }); } };
}

class Http {
  constructor(private o: OnlineOptions) {}
  async get(url: string, init: RequestInit = {}): Promise<Response> {
    const f = this.o.fetch || globalThis.fetch;
    if (!f) throw new Error('no fetch available');
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), this.o.timeoutMs ?? 8000);
    try { return await f(url, { ...init, signal: ctl.signal, redirect: 'follow', credentials: 'omit', referrerPolicy: 'no-referrer' } as RequestInit); }
    catch (e) { throw new Error(ctl.signal.aborted ? 'timed out' : (e as Error).message || 'network error'); }
    finally { clearTimeout(t); }
  }
  async json<T>(url: string, init: RequestInit = {}): Promise<{ status: number; body: T | null }> {
    const r = await this.get(url, init);
    if (r.status === 404) return { status: 404, body: null };
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return { status: r.status, body: await r.json() as T };
  }
}

/** Memoise through the cache; errors are not cached. */
async function cached<T>(o: OnlineOptions, key: string, ttl: number | ((v: T) => number), fn: () => Promise<T>): Promise<T> {
  const hit = o.cache?.get(key); if (hit !== undefined) return hit as T;
  const v = await fn(); o.cache?.set(key, v, typeof ttl === 'function' ? ttl(v) : ttl); return v;
}

// ── RDAP ────────────────────────────────────────────────────────────────────────
type Bootstrap = { services: [string[], string[]][] };
export interface RdapResult { domain: string; found: boolean; registered: string | null; registrar: string }

async function rdapBase(http: Http, o: OnlineOptions, tld: string): Promise<string> {
  try {
    const b = await cached<Bootstrap | null>(o, 'rdap-bootstrap', TTL.bootstrap, async () => (await http.json<Bootstrap>(DEFAULTS.bootstrapUrl)).body);
    const svc = b?.services.find(s => s[0].includes(tld));
    const url = svc?.[1].find(u => u.startsWith('https://')) || svc?.[1][0];
    if (url) return url.replace(/\/?$/, '/') + 'domain/';
  } catch { /* fall back */ }
  return DEFAULTS.rdapFallback;
}

export async function rdapLookup(domain: string, o: OnlineOptions): Promise<RdapResult> {
  const http = new Http(o);
  return cached<RdapResult>(o, 'rdap:' + domain, v => v.found ? TTL.rdap : TTL.rdapMiss, async () => {
    const base = await rdapBase(http, o, domain.split('.').pop() || '');
    const r = await http.json<{ events?: { eventAction?: string; eventDate?: string }[]; entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, string, string][]] }[] }>(
      base + encodeURIComponent(domain), { headers: { accept: 'application/rdap+json, application/json' } });
    if (!r.body) return { domain, found: false, registered: null, registrar: '' };
    const reg = (r.body.events || []).find(e => /^registration$/i.test(e.eventAction || ''));
    const ent = (r.body.entities || []).find(e => (e.roles || []).includes('registrar'));
    const fn = ent?.vcardArray?.[1]?.find(x => x[0] === 'fn');
    return { domain, found: true, registered: reg?.eventDate || null, registrar: fn ? String(fn[3]) : '' };
  });
}

// ── DNS over HTTPS ──────────────────────────────────────────────────────────────
interface DohAnswer { Status: number; Answer?: { type: number; data: string }[] }
export interface DnsResult { domain: string; exists: boolean; mx: string[]; spf: string; dmarc: string }

async function doh(http: Http, o: OnlineOptions, name: string, type: string): Promise<DohAnswer> {
  const u = `${o.dohUrl || DEFAULTS.dohUrl}?name=${encodeURIComponent(name)}&type=${type}`;
  const r = await http.json<DohAnswer>(u, { headers: { accept: 'application/dns-json' } });
  if (!r.body) throw new Error('resolver returned 404');
  return r.body;
}
const txt = (a: DohAnswer) => (a.Answer || []).filter(x => x.type === 16).map(x => x.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));

export async function dnsLookup(domain: string, o: OnlineOptions): Promise<DnsResult> {
  const http = new Http(o);
  return cached<DnsResult>(o, 'dns:' + domain, TTL.dns, async () => {
    const [mx, t, d] = await Promise.all([doh(http, o, domain, 'MX'), doh(http, o, domain, 'TXT'), doh(http, o, '_dmarc.' + domain, 'TXT')]);
    const exists = !(mx.Status === 3 && t.Status === 3);   // NXDOMAIN
    return { domain, exists, mx: (mx.Answer || []).filter(x => x.type === 15).map(x => x.data.split(/\s+/).pop()!.replace(/\.$/, '')).filter(x => x && x !== ''),
      spf: txt(t).find(s => /^v=spf1\b/i.test(s)) || '', dmarc: txt(d).find(s => /^v=DMARC1\b/i.test(s)) || '' };
  });
}

// ── feeds ───────────────────────────────────────────────────────────────────────
/** Comparable form of a URL: lower-case host, no fragment, no trailing slash, default ports dropped. */
export function normUrl(u: string): string {
  try { const x = new URL(u.trim()); x.hash = ''; return (x.protocol + '//' + x.host.toLowerCase() + x.pathname.replace(/\/+$/, '') + x.search).toLowerCase(); } catch { return ''; }
}
export async function loadFeed(o: OnlineOptions): Promise<string[]> {
  const http = new Http(o), url = o.feedUrl || DEFAULTS.feedUrl;
  return cached<string[]>(o, 'feed:' + url, TTL.feed, async () => {
    const r = await http.get(url); if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return (await r.text()).split(/\r?\n/).map(s => s.trim()).filter(s => /^https?:\/\//i.test(s)).slice(0, 200000);
  });
}

export interface UrlhausResult { host: string; listed: boolean; urls: number; online: number }
export async function urlhausHost(host: string, o: OnlineOptions): Promise<UrlhausResult> {
  const http = new Http(o);
  return cached<UrlhausResult>(o, 'urlhaus:' + host, TTL.urlhaus, async () => {
    const r = await http.get(DEFAULTS.urlhausHost, { method: 'POST', headers: { 'Auth-Key': o.urlhausKey || '', 'content-type': 'application/x-www-form-urlencoded' }, body: 'host=' + encodeURIComponent(host) });
    if (!r.ok) throw new Error(r.status === 401 ? 'Auth-Key rejected' : `HTTP ${r.status}`);
    const b = await r.json() as { query_status?: string; url_count?: string | number; urls?: { url_status?: string }[] };
    if (b.query_status === 'no_results') return { host, listed: false, urls: 0, online: 0 };
    if (b.query_status !== 'ok') throw new Error(String(b.query_status || 'unexpected reply'));
    return { host, listed: true, urls: Number(b.url_count) || (b.urls || []).length, online: (b.urls || []).filter(u => u.url_status === 'online').length };
  });
}

// ── checks ──────────────────────────────────────────────────────────────────────
const IP = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)$/i;
const RESERVED = /\.(test|example|invalid|localhost|local|internal|lan|home\.arpa)$|^(example\.(com|net|org))$/i;
const shared = (h: string) => OPEN_HOSTING.some(s => h === s || h.endsWith('.' + s));

/** The domains worth looking up, sender first. */
export function lookupTargets(a: EmailAnalysis, own: string[], max = 8): { sender: string; domains: { domain: string; why: string }[]; hosts: string[] } {
  const ok = (d: string) => !!d && d.includes('.') && !IP.test(d) && !RESERVED.test(d) && !isKnown(d, own);
  const dom = (addr: string) => (addr.split('@')[1] || '').replace(/[>\s].*$/, '').toLowerCase();
  const out: { domain: string; why: string }[] = [], add = (d: string, why: string) => { const o = orgOf(d); if (ok(d) && ok(o) && !out.some(x => x.domain === o)) out.push({ domain: o, why }); };
  add(a.fromDom, 'sender'); add(dom(a.replyTo), 'Reply-To'); add(dom(a.rp.replace(/[<>]/g, '')), 'Return-Path');
  const links = [...a.links, ...(a.nested || []).flatMap(n => n.analysis.links)];
  const hosts = [...new Set(links.map(l => hostOf(l.href)).filter(h => h && !IP.test(h) && !RESERVED.test(h) && !isKnown(h, own)))];
  for (const h of hosts) if (!shared(h)) add(h, 'link');
  return { sender: ok(a.fromDom) ? orgOf(a.fromDom) : '', domains: out.slice(0, max), hosts: hosts.slice(0, max * 2) };
}

const daysBetween = (iso: string, now: number) => Math.floor((now - Date.parse(iso)) / DAY);
const ageText = (d: number) => d < 1 ? 'today' : d === 1 ? '1 day ago' : d < 60 ? `${d} days ago` : d < 730 ? `${Math.round(d / 30.4)} months ago` : `${Math.floor(d / 365.25)} years ago`;

/** Run the lookups for one analysed email. Never throws: failures become an info check. */
export async function onlineChecks(a: EmailAnalysis, o: OnlineOptions): Promise<Check[]> {
  const own = (o.ownDomains || []).map(d => d.trim().toLowerCase()).filter(Boolean), now = (o.now || Date.now)();
  const t = lookupTargets(a, own, o.maxDomains ?? 8), checks: Check[] = [], errors: string[] = [];
  const links = [...a.links, ...(a.nested || []).flatMap(n => n.analysis.links)].filter(l => /^https?:/i.test(l.href));

  const jobs: Promise<void>[] = [];
  if (o.rdap !== false && t.domains.length) jobs.push((async () => {
    const res = await Promise.all(t.domains.map(d => rdapLookup(d.domain, o).then(r => ({ ...d, r }), e => { errors.push(`RDAP ${d.domain}: ${(e as Error).message}`); return null; })));
    const got = res.filter((x): x is NonNullable<typeof x> => !!x && x.r.found && !!x.r.registered);
    const missing = res.filter(x => x && !x.r.found).map(x => x!.domain);
    if (!got.length && !missing.length) return;
    const aged = got.map(x => ({ ...x, days: daysBetween(x.r.registered!, now) })).sort((p, q) => p.days - q.days);
    const young = aged.filter(x => x.days < YOUNG_DAYS), fresh = aged.filter(x => x.days < NEW_DAYS);
    const list = (xs: typeof aged) => xs.map(x => `${x.domain} (${x.why}) registered ${ageText(x.days)}`).join('; ');
    const tail = missing.length ? `. No registration data for ${missing.join(', ')}` : '';
    checks.push(fresh.length
      ? { group: 'online', id: 'online.age', name: 'Domain age', status: 'bad', result: defangAll(list(fresh) + tail),
          why: `Phishing domains are usually registered days before use and abandoned soon after. Under ${NEW_DAYS} days is rare for a real business.` }
      : young.length
      ? { group: 'online', id: 'online.age', name: 'Domain age', status: 'warn', result: defangAll(list(young) + tail), why: `Registered within the last ${YOUNG_DAYS} days.` }
      : { group: 'online', id: 'online.age', name: 'Domain age', status: aged.length ? 'ok' : 'info',
          result: defangAll(aged.length ? `All established: ${aged.map(x => `${x.domain} ${ageText(x.days)}`).join(', ')}${tail}` : tail.slice(2)) });
  })());

  if (o.dns !== false && t.sender) jobs.push((async () => {
    try {
      const d = await dnsLookup(t.sender, o), pol = (d.dmarc.match(/\bp=(\w+)/i) || [])[1];
      if (!d.exists) checks.push({ group: 'online', id: 'online.nxdomain', name: 'Sender domain in DNS', status: 'bad', result: defangAll(`${t.sender} does not exist in DNS`),
        why: 'Replies can\'t reach a domain that doesn\'t exist. Either it was taken down or the address is made up.' });
      else checks.push({ group: 'online', id: 'online.dns', name: 'Sender domain in DNS', status: d.mx.length ? 'ok' : 'warn',
        result: defangAll(`${t.sender}: ${d.mx.length ? 'receives mail (MX ' + d.mx.slice(0, 2).join(', ') + ')' : 'no MX record, so it cannot receive replies'}; ` +
          `SPF ${d.spf ? 'published' : 'none'}; DMARC ${d.dmarc ? 'p=' + (pol || '?') : 'none'}`),
        why: d.mx.length ? undefined : 'A business domain that sends mail almost always receives it too. Throwaway sending domains often don\'t.' });
    } catch (e) { errors.push(`DNS ${t.sender}: ${(e as Error).message}`); }
  })());

  const listed: string[] = [], hostListed: string[] = []; let feedChecked = false, uhChecked = false;
  if (o.feeds !== false && links.length) jobs.push((async () => {
    try {
      const feed = await loadFeed(o), urls = new Set(feed.map(normUrl)), hosts = new Set(feed.map(u => hostOf(u)).filter(h => h && !shared(h)));
      feedChecked = true;
      for (const l of links) {
        const n = normUrl(l.href), h = hostOf(l.href);
        if (urls.has(n)) listed.push(`${l.href} is listed by OpenPhish`);
        else if (h && hosts.has(h) && !isKnown(h, own)) hostListed.push(`${h} (a different URL on it is listed by OpenPhish)`);
      }
    } catch (e) { errors.push(`Phishing feed: ${(e as Error).message}`); }
  })());
  if (o.urlhausKey && t.hosts.length) jobs.push((async () => {
    for (const h of t.hosts) {
      try { const r = await urlhausHost(h, o); uhChecked = true; if (r.listed) listed.push(`${h} is on URLhaus (${r.urls} URL${r.urls === 1 ? '' : 's'}, ${r.online} online)`); }
      catch (e) { errors.push(`URLhaus ${h}: ${(e as Error).message}`); if (/Auth-Key/.test((e as Error).message)) break; }
    }
  })());

  await Promise.all(jobs);
  if (listed.length) checks.push({ group: 'online', id: 'online.listed', name: 'Known phishing', status: 'bad', result: defangAll([...new Set(listed)].join('; ')),
    why: 'A threat feed has already reported this link as phishing or malware.' });
  if (hostListed.length) checks.push({ group: 'online', id: 'online.listed-host', name: 'Site with known phishing', status: 'bad', result: defangAll([...new Set(hostListed)].join('; ')),
    why: 'The site already hosts a reported phishing page. It may be the attacker\'s, or a hacked site being used for several campaigns.' });
  if (!listed.length && !hostListed.length && (feedChecked || uhChecked)) checks.push({ group: 'online', id: 'online.listed', name: 'Known phishing', status: 'ok',
    result: `None of ${links.length} link${links.length === 1 ? '' : 's'} on ${[feedChecked && 'OpenPhish', uhChecked && 'URLhaus'].filter(Boolean).join(' or ')}. New phishing sites often aren't listed yet` });
  if (errors.length) checks.push({ group: 'online', id: 'online.errors', name: 'Lookups that failed', status: 'info', result: defangAll(errors.join('; ')) });
  if (!checks.length) checks.push({ group: 'online', id: 'online.none', name: 'Online lookups', status: 'info', result: 'Nothing to look up: no unfamiliar domains or links' });
  return checks;
}

/** Add online checks to an analysis (and recompute its verdict). */
export async function addOnline(a: EmailAnalysis, o: OnlineOptions): Promise<EmailAnalysis> {
  a.checks = a.checks.filter(c => c.group !== 'online').concat(await onlineChecks(a, o));
  a.verdict = verdictOf(a.checks);
  return a;
}
