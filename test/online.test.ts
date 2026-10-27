// Online lookups, with recorded replies instead of the network (a fake fetch). The live OpenPhish feed is tried in
// scripts/online-live.ts, not here, so the tests never depend on the internet.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyseBytes, fileCache } from '../src/node/index.js';
import { lookupTargets, memoryCache, normUrl, type OnlineOptions } from '../src/online.js';
import type { Analysis, EmailAnalysis } from '../src/types.js';

const NOW = Date.parse('2026-10-20T12:00:00Z');
const daysAgo = (n: number) => new Date(NOW - n * 86400e3).toISOString();
const email = (a: Analysis): EmailAnalysis => { assert.equal(a.kind, 'email'); return a as EmailAnalysis; };
const check = (a: EmailAnalysis, id: string) => a.checks.find(c => c.id === id);

const phish = (from: string, link: string) => new TextEncoder().encode([
  'Received: from mail.example.net (mail.example.net [203.0.113.9]) by mx.northwind.example; Mon, 19 Oct 2026 10:00:00 +0000',
  'Authentication-Results: mx.northwind.example; spf=pass smtp.mailfrom=' + from.split('@')[1] + '; dkim=none; dmarc=none header.from=' + from.split('@')[1],
  `From: "Account Team" <${from}>`, 'To: j.cole@northwind.example', 'Subject: Action needed', 'Date: Mon, 19 Oct 2026 10:00:00 +0000',
  'Message-ID: <x1@mail.example.net>', 'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', '',
  `<p>Please review your account.</p><p><a href="${link}">Review</a></p>`].join('\r\n'));

/** A fake network: answers by URL, records what was asked. */
function fakeNet(routes: Record<string, (url: string, init?: RequestInit) => Response | Promise<Response>>) {
  const calls: { url: string; body?: string }[] = [];
  const f = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, body: init?.body ? String(init.body) : undefined });
    for (const [prefix, h] of Object.entries(routes)) if (url.startsWith(prefix)) return h(url, init);
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
  return { fetch: f, calls };
}
const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { 'content-type': 'application/json' } });
const BOOT = { services: [[['com', 'net'], ['https://rdap.verisign.example/com/v1/']], [['app'], ['https://rdap.nic.example/']]] };
const rdap = (registered: string) => json({ objectClassName: 'domain', events: [{ eventAction: 'registration', eventDate: registered }, { eventAction: 'last changed', eventDate: daysAgo(1) }],
  entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar']]] }] });
const doh = (answers: Record<string, { Status?: number; Answer?: { type: number; data: string }[] }>) => (url: string) => {
  const u = new URL(url), key = `${u.searchParams.get('name')}/${u.searchParams.get('type')}`;
  return json({ Status: 0, ...(answers[key] || { Status: 0, Answer: [] }) });
};

function net(o: { regDays: Record<string, number>; feed?: string[]; dns?: Parameters<typeof doh>[0] }) {
  return fakeNet({
    'https://data.iana.org/rdap/dns.json': () => json(BOOT),
    'https://rdap.verisign.example/com/v1/domain/': url => { const d = decodeURIComponent(url.split('/').pop()!); return d in o.regDays ? rdap(daysAgo(o.regDays[d])) : json({ errorCode: 404 }, 404); },
    'https://cloudflare-dns.com/dns-query': doh(o.dns || {}),
    'https://raw.githubusercontent.com/openphish/': () => new Response((o.feed || []).join('\n') + '\n'),
  });
}
const opts = (f: typeof fetch, extra: Partial<OnlineOptions> = {}): OnlineOptions => ({ fetch: f, cache: memoryCache(), now: () => NOW, ...extra });

test('a domain registered last week is a red flag; the link on the feed makes it malicious', async () => {
  const n = net({ regDays: { 'acct-verify-portal.com': 6 }, feed: ['https://acct-verify-portal.com/login/'],
    dns: { 'acct-verify-portal.com/MX': { Status: 0, Answer: [] }, 'acct-verify-portal.com/TXT': { Answer: [{ type: 16, data: '"v=spf1 -all"' }] } } });
  const a = email(await analyseBytes(phish('support@acct-verify-portal.com', 'https://acct-verify-portal.com/login'), { ownDomains: ['northwind.example'], online: opts(n.fetch) }));
  assert.equal(check(a, 'online.age')?.status, 'bad');
  assert.match(check(a, 'online.age')!.result, /6 days ago/);
  assert.equal(check(a, 'online.listed')?.status, 'bad', 'trailing slash and case differences still match');
  assert.equal(check(a, 'online.dns')?.status, 'warn', 'no MX');
  assert.equal(a.verdict.v, 'malicious');
});

test('an old domain with mail set up and an unlisted link adds reassurance, not alarm', async () => {
  const n = net({ regDays: { 'contoso-supplies.com': 4000 }, feed: ['https://other-bad.example.net/x'],
    dns: { 'contoso-supplies.com/MX': { Answer: [{ type: 15, data: '10 contoso-supplies-com.mail.protection.outlook.com.' }] },
      '_dmarc.contoso-supplies.com/TXT': { Answer: [{ type: 16, data: '"v=DMARC1; p=reject; rua=mailto:d@contoso-supplies.com"' }] } } });
  const before = email(await analyseBytes(phish('orders@contoso-supplies.com', 'https://contoso-supplies.com/orders/123'), { ownDomains: ['northwind.example'] }));
  const a = email(await analyseBytes(phish('orders@contoso-supplies.com', 'https://contoso-supplies.com/orders/123'), { ownDomains: ['northwind.example'], online: opts(n.fetch) }));
  assert.equal(check(a, 'online.age')?.status, 'ok');
  assert.match(check(a, 'online.age')!.result, /10 years ago/);
  assert.equal(check(a, 'online.dns')?.status, 'ok');
  assert.match(check(a, 'online.dns')!.result, /p=reject/);
  assert.equal(check(a, 'online.listed')?.status, 'ok');
  assert.equal(a.verdict.score, before.verdict.score);
});

test('only domain names leave the machine: no addresses, paths, query strings or content', async () => {
  const n = net({ regDays: { 'acct-verify-portal.com': 6 } });
  await analyseBytes(phish('support@mail.acct-verify-portal.com', 'https://track-9f3a.acct-verify-portal.com/p?u=j.cole@northwind.example&t=SECRET'),
    { ownDomains: ['northwind.example'], online: opts(n.fetch) });
  const sent = n.calls.map(c => c.url + ' ' + (c.body || '')).join('\n');
  assert.doesNotMatch(sent, /j\.cole|northwind|SECRET|track-9f3a|Action needed|Review/);
  assert.match(sent, /domain\/acct-verify-portal\.com/);
  assert.ok(n.calls.every(c => /^https:\/\/(data\.iana\.org|rdap\.verisign\.example|cloudflare-dns\.com|raw\.githubusercontent\.com)\//.test(c.url)), sent);
});

test('well-known, own, reserved and IP hosts are not looked up', async () => {
  const a = email(await analyseBytes(phish('alerts@northwind.example', 'https://login.microsoftonline.com/x'), { ownDomains: ['northwind.example'] }));
  const t = lookupTargets(a, ['northwind.example']);
  assert.deepEqual(t.domains, []);
  assert.equal(t.sender, '');
});

test('failed lookups are reported and do not change the verdict', async () => {
  const f = (async () => { throw new Error('getaddrinfo ENOTFOUND'); }) as unknown as typeof fetch;
  const before = email(await analyseBytes(phish('support@acct-verify-portal.com', 'https://acct-verify-portal.com/login'), { ownDomains: ['northwind.example'] }));
  const a = email(await analyseBytes(phish('support@acct-verify-portal.com', 'https://acct-verify-portal.com/login'), { ownDomains: ['northwind.example'], online: opts(f) }));
  assert.equal(check(a, 'online.errors')?.status, 'info');
  assert.match(check(a, 'online.errors')!.result, /ENOTFOUND/);
  assert.equal(a.verdict.v, before.verdict.v);
  assert.equal(a.verdict.score, before.verdict.score);
});

test('a sender domain that does not exist is flagged', async () => {
  const n = net({ regDays: {}, dns: { 'gone-domain-77.com/MX': { Status: 3 }, 'gone-domain-77.com/TXT': { Status: 3 }, '_dmarc.gone-domain-77.com/TXT': { Status: 3 } } });
  const a = email(await analyseBytes(phish('x@gone-domain-77.com', 'https://gone-domain-77.com/'), { online: opts(n.fetch) }));
  assert.equal(check(a, 'online.nxdomain')?.status, 'bad');
  assert.match(check(a, 'online.age')!.result, /No registration data for gone-domain-77\[\.\]com/);
});

test('a host with another URL on the feed is flagged separately; shared hosting is not', async () => {
  const n = net({ regDays: { 'acct-verify-portal.com': 900 }, feed: ['https://acct-verify-portal.com/other', 'https://someone-else.web.app/phish'] });
  const a = email(await analyseBytes(phish('support@acct-verify-portal.com', 'https://acct-verify-portal.com/login'), { online: opts(n.fetch) }));
  assert.equal(check(a, 'online.listed-host')?.status, 'bad');
  assert.equal(check(a, 'online.listed'), undefined);
  const b = email(await analyseBytes(phish('support@acct-verify-portal.com', 'https://my-site.web.app/'), { online: opts(n.fetch) }));
  assert.equal(check(b, 'online.listed-host'), undefined, 'web.app is shared by many sites');
});

test('URLhaus is asked about hosts only, with the key, and only when a key is set', async () => {
  const routes = net({ regDays: { 'acct-verify-portal.com': 900 } });
  const seen: { url: string; key: string; body: string }[] = [];
  const f = (async (u: string | URL, init?: RequestInit) => {
    const url = String(u);
    if (url.startsWith('https://urlhaus-api.abuse.ch/')) { seen.push({ url, key: String((init?.headers as Record<string, string>)['Auth-Key']), body: String(init?.body) });
      return json({ query_status: 'ok', url_count: '3', urls: [{ url_status: 'online' }, { url_status: 'offline' }, { url_status: 'offline' }] }); }
    return routes.fetch(u, init);
  }) as typeof fetch;
  const msg = phish('support@acct-verify-portal.com', 'https://dl.acct-verify-portal.com/file.zip?id=j.cole@northwind.example');
  const a = email(await analyseBytes(msg, { online: opts(f, { urlhausKey: 'K123' }) }));
  assert.deepEqual(seen, [{ url: 'https://urlhaus-api.abuse.ch/v1/host/', key: 'K123', body: 'host=dl.acct-verify-portal.com' }]);
  assert.equal(check(a, 'online.listed')?.status, 'bad');
  assert.match(check(a, 'online.listed')!.result, /URLhaus \(3 URLs, 1 online\)/);
  seen.length = 0;
  await analyseBytes(msg, { online: opts(f) });
  assert.equal(seen.length, 0);
});

test('lookups go through the cache, which persists on disk', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pb-cache-'));
  try {
    const n = net({ regDays: { 'acct-verify-portal.com': 6 }, feed: [] });
    const c1 = fileCache(join(dir, 'online.json'), () => NOW);
    await analyseBytes(phish('support@acct-verify-portal.com', 'https://acct-verify-portal.com/login'), { online: opts(n.fetch, { cache: c1 }) });
    const first = n.calls.length; c1.flush();
    assert.ok(first >= 4);
    assert.doesNotMatch(readFileSync(join(dir, 'online.json'), 'utf8'), /Action needed|northwind/);
    const c2 = fileCache(join(dir, 'online.json'), () => NOW);
    const a = email(await analyseBytes(phish('support@acct-verify-portal.com', 'https://acct-verify-portal.com/login'), { online: opts(n.fetch, { cache: c2 }) }));
    assert.equal(n.calls.length, first, 'second run answered from the cache');
    assert.equal(check(a, 'online.age')?.status, 'bad');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('without online options nothing is fetched', async () => {
  const n = net({ regDays: {} });
  const orig = globalThis.fetch; globalThis.fetch = n.fetch;
  try { const a = email(await analyseBytes(phish('support@acct-verify-portal.com', 'https://acct-verify-portal.com/login'))); assert.equal(a.checks.some(c => c.group === 'online'), false); }
  finally { globalThis.fetch = orig; }
  assert.equal(n.calls.length, 0);
});

test('normUrl', () => {
  assert.equal(normUrl('HTTPS://Evil.COM/Login/#x'), 'https://evil.com/login');
  assert.equal(normUrl('not a url'), '');
});
