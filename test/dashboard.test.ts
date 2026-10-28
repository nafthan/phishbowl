// Dashboard tests: the static file renders every email without script errors and shows nothing clickable;
// the local server answers only its own page and updates reports live.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';
import { emlFiles } from '../src/node/index.js';
import { renderDashboard, startServer, STATIC_CSP, viewOf } from '../src/node/dashboard.js';

const dir = join(import.meta.dirname, 'fixtures'), own = ['northwind.example'];
const tick = (ms = 20) => new Promise(r => setTimeout(r, ms));
const visible = (n: Node): string => { let t = ''; for (const c of n.childNodes) { if (c.nodeName === 'SCRIPT' || c.nodeName === 'STYLE') continue; t += c.nodeType === 3 ? (c.textContent || '') + ' ' : visible(c); } return t; };

async function staticPage() {
  const views = [];
  for (const f of await emlFiles(dir)) views.push((await viewOf(f, new Uint8Array(readFileSync(f)), { ownDomains: own, report: { ownDomains: own } })).view);
  return { html: renderDashboard({ mode: 'static', views }), views };
}

test('static dashboard: one file, no outside connections, every email and section renders, nothing clickable', async () => {
  const { html, views } = await staticPage();
  assert.ok(html.includes(`content="${STATIC_CSP}"`));
  assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+href="(?!data:)/i, 'no external scripts, stylesheets or icons (the icon is a data: URI)');
  assert.match(html, /@font-face\{font-family:'Geist';src:url\(data:font\/woff2;base64,/, 'fonts are embedded');
  assert.doesNotMatch(html, /url\((?!data:)/, 'no CSS url() pointing anywhere');
  const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true, url: 'file:///report.html' });
  const errors: string[] = []; dom.window.addEventListener('error', e => errors.push(e.message));
  await tick(300);
  const d = dom.window.document;
  assert.equal(d.querySelectorAll('tr.item').length, views.length, 'the queue lists every email');
  assert.ok(d.getElementById('b-snapshot')!.hidden && !d.getElementById('drop'), 'no live-only controls in a saved file');
  for (const item of [...d.querySelectorAll<HTMLElement>('tr.item')]) {
    item.click(); await tick(30);
    assert.ok(d.querySelector('.d-title'), 'detail rendered');
    // Walk every section of this email through the sidebar.
    for (const link of [...d.querySelectorAll<HTMLButtonElement>('#nav .sb-link')].filter(b => !/Queue|Add emails/.test(b.textContent || ''))) {
      link.click(); await tick(30);
      if (d.getElementById('sec-export')) continue;   // exports are raw on purpose
      assert.doesNotMatch(visible(d.getElementById('page')!), /\bhttps?:\/\//, `a live URL in visible text (${link.textContent})`);
    }
    d.querySelector<HTMLButtonElement>('#nav .sb-link')!.click(); await tick(30);   // back to the queue
  }
  assert.deepEqual(errors, []);
  assert.equal([...d.querySelectorAll('a')].filter(a => !(a.getAttribute('href') || '').startsWith('#')).length, 0, 'no links');
  dom.window.close();
});

test('email content is shown as text, never as HTML', async () => {
  const raw = 'From: a@b.example\nSubject: <img src=x onerror="window.pwned=1">\nDate: Mon, 19 Oct 2026 09:00:00 +0000\nMIME-Version: 1.0\nContent-Type: text/html\n\n<script>window.pwned=2</script><b onclick="x()">hi</b>';
  const { view } = await viewOf('xss.eml', new TextEncoder().encode(raw));
  const dom = new JSDOM(renderDashboard({ mode: 'static', views: [view] }), { runScripts: 'dangerously', pretendToBeVisual: true, url: 'file:///x.html' });
  await tick(300);
  const w = dom.window as unknown as { pwned?: number }, d = dom.window.document;
  assert.equal(w.pwned, undefined);
  assert.equal(d.querySelector('.d-title')?.textContent, '<img src=x onerror="window.pwned=1">');
  assert.equal(d.querySelectorAll('#page img, #page b[onclick]').length, 0);
  dom.window.close();
});

test('local server: own page only, custom header required, live report updates', async () => {
  const s = await startServer({ port: 0, ownDomains: own });
  try {
    const raw = (host: string) => new Promise<number>(res => request({ host: '127.0.0.1', port: s.port, path: '/api/analyses', headers: { Host: host } }, r => { r.resume(); res(r.statusCode!); }).end());
    assert.equal(await raw('evil.example:' + s.port), 421, 'foreign Host header (DNS rebinding) refused');
    assert.equal(await raw('127.0.0.1:' + s.port), 200);
    const page = await fetch(s.url);
    assert.match(page.headers.get('content-security-policy') || '', /connect-src 'self'/);
    const body = readFileSync(join(dir, 'example-northwind-payroll.eml'));
    assert.equal((await fetch(s.url + 'api/analyses', { method: 'POST', body })).status, 403, 'POST without X-Phishbowl refused');
    const r = await fetch(s.url + 'api/analyses', { method: 'POST', body, headers: { 'X-Phishbowl': '1', 'x-filename': 'payroll.eml' } });
    assert.equal(r.status, 201);
    const { summary } = await r.json() as { summary: { id: string; verdict: { v: string } } };
    assert.equal(summary.verdict.v, 'malicious');
    const rep = await (await fetch(`${s.url}api/analyses/${summary.id}/report`, { method: 'POST', headers: { 'X-Phishbowl': '1', 'content-type': 'application/json' },
      body: JSON.stringify({ done: ['purge'], preparedBy: 'Test SOC', tlp: 'red' }) })).json() as { tech: { text: string } };
    assert.match(rep.tech.text, /^TLP:RED/);
    assert.match(rep.tech.text, /ACTIONS TAKEN/);
    assert.match(rep.tech.text, /Test SOC/);
    const kql = await (await fetch(`${s.url}api/analyses/${summary.id}/export/kql`)).text();
    assert.match(kql, /union isfuzzy=true/);
    const snap = await (await fetch(s.url + 'api/snapshot.html')).text();
    assert.ok(snap.includes(STATIC_CSP) && snap.includes(summary.id));
  } finally { s.server.close(); }
});

test('local server: online lookups only when the page asks (or the server defaults to them)', async () => {
  let calls = 0;
  const fake = (async () => { calls++; return new Response('https://nothing.example.net/\n'); }) as unknown as typeof fetch;
  const s = await startServer({ port: 0, ownDomains: own, online: { fetch: fake, rdap: false, dns: false } });
  try {
    const body = readFileSync(join(dir, 'p02-compromised-sender-pages-dev.eml'));
    const post = async (h: Record<string, string>) => (await (await fetch(s.url + 'api/analyses', { method: 'POST', body, headers: { 'X-Phishbowl': '1', ...h } })).json()) as { view: { groups: { id: string; checks: unknown[] }[] } };
    const off = await post({ 'x-phishbowl-online': '0' });
    assert.equal(off.view.groups.find(g => g.id === 'online'), undefined);
    assert.equal(calls, 0);
    const on = await post({ 'x-phishbowl-online': '1' });
    assert.ok(on.view.groups.find(g => g.id === 'online')?.checks.length);
    assert.equal(calls, 1, 'feed downloaded once');
    assert.match(await (await fetch(s.url)).text(), /"online":false/);
  } finally { s.server.close(); }
});
