// The dashboard, for Node: render it as one self-contained HTML file, or serve it live from a local server.
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyseBytes, MAX_BYTES } from './index.js';
import { buildReports, buildView, summaryOf, type View } from '../view.js';
import { ACTIONS, TLP_LABEL, type ReportOptions } from '../report/report.js';
import type { Analysis } from '../types.js';
import type { OnlineOptions } from '../online.js';
import type { Allowlist } from '../allow.js';
import { recordFeedback, SAYS, type Says } from './feedback.js';

export const VERSION = '0.3.0';

/** Find assets/dashboard whether running from src/ (tsx) or dist/ (built). */
function assetDir(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 4; i++, dir = dirname(dir)) { const p = join(dir, 'assets', 'dashboard'); if (existsSync(join(p, 'index.html'))) return p; }
  throw new Error('Dashboard assets not found (assets/dashboard)');
}
let cache: { html: string; css: string; js: string } | null = null;
const assets = () => cache || (cache = { html: readFileSync(join(assetDir(), 'index.html'), 'utf8'), css: readFileSync(join(assetDir(), 'app.css'), 'utf8'), js: readFileSync(join(assetDir(), 'app.js'), 'utf8') });

/** JSON that is safe inside a <script> element. */
const scriptJson = (v: unknown) => JSON.stringify(v).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

/** The static page allows nothing to load from anywhere: no fonts, images, scripts or connections. */
export const STATIC_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";
const LIVE_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'";

export interface DashboardOptions {
  mode: 'live' | 'static';
  views?: View[];
  /** Hide the top bar (for embedding in another page). Also ?embed in the URL. */
  embed?: boolean;
  preparedBy?: string;
  /** Live mode: the "Check online" switch starts on. */
  online?: boolean;
  /** Live mode: show the "Was this right?" buttons. */
  feedback?: boolean;
}

export function renderDashboard(o: DashboardOptions): string {
  const a = assets();
  const config = { mode: o.mode, version: VERSION, embed: !!o.embed, preparedBy: o.preparedBy || '', online: !!o.online, feedback: !!o.feedback, created: new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC' };
  return a.html
    .replace('<!--PB:CSP-->', o.mode === 'static' ? `<meta http-equiv="Content-Security-Policy" content="${STATIC_CSP}">` : '')
    .replace('/*PB:CSS*/', () => a.css)
    .replace('/*PB:CONFIG*/', () => scriptJson(config))
    .replace('/*PB:DATA*/', () => scriptJson({ views: o.mode === 'static' ? o.views || [] : [] }))
    .replace('/*PB:JS*/', () => a.js.replace(/<\/script/gi, '<\\/script'));
}

/** A stable id for an email: its name plus a short hash of its bytes, so adding the same file twice doesn't duplicate it. */
export const viewId = (file: string, bytes: Uint8Array) =>
  basename(file).replace(/\.[^.]+$/, '').replace(/[^\w.-]+/g, '-').slice(0, 48) + '-' + createHash('sha256').update(bytes).digest('hex').slice(0, 8);

export async function viewOf(file: string, bytes: Uint8Array, o: { ownDomains?: string[]; report?: ReportOptions; online?: OnlineOptions; allow?: Allowlist } = {}): Promise<{ analysis: Analysis; view: View }> {
  const analysis = await analyseBytes(bytes, { ownDomains: o.ownDomains, online: o.online, allow: o.allow });
  return { analysis, view: buildView(analysis, { id: viewId(file, bytes), file: basename(file) }, { ownDomains: o.ownDomains, ...(o.report || {}) }) };
}

// ── local server ───────────────────────────────────────────────────────────────
export interface ServerOptions {
  port?: number; host?: string; ownDomains?: string[]; preparedBy?: string; files?: string[];
  /** How to do online lookups when the page asks for them (X-Phishbowl-Online: 1). Without this, it can't. */
  online?: OnlineOptions;
  /** Look things up online unless the page says not to; also how the page's switch starts. */
  onlineDefault?: boolean;
  allow?: Allowlist;
  /** Let the page record feedback (in the feedback folder, see feedback.ts). */
  feedback?: boolean;
  /** Feedback folder (default: dataDir()). */
  feedbackDir?: string;
}

export async function startServer(o: ServerOptions) {
  const host = o.host || '127.0.0.1', store = new Map<string, { analysis: Analysis; view: View; bytes: Uint8Array; file: string }>();
  const base: ReportOptions = { ownDomains: o.ownDomains, preparedBy: o.preparedBy };
  for (const f of o.files || []) { const bytes = new Uint8Array(readFileSync(f)); const r = await viewOf(f, bytes, { ownDomains: o.ownDomains, report: base, online: o.onlineDefault ? o.online : undefined, allow: o.allow }); store.set(r.view.id, { ...r, bytes, file: f }); }

  const send = (res: ServerResponse, code: number, body: string | object, type = 'application/json; charset=utf-8') => {
    res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
      ...(type.startsWith('text/html') ? { 'content-security-policy': LIVE_CSP } : {}) });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };
  const readBody = (req: IncomingMessage) => new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = []; let n = 0;
    req.on('data', (c: Buffer) => { n += c.length; if (n > MAX_BYTES) { reject(new Error(`Over ${MAX_BYTES / 1048576} MB`)); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks))); req.on('error', reject);
  });

  const server = createServer(async (req, res) => {
    try {
      // Only answer this machine's own page: blocks DNS rebinding (Host) and cross-site posts (custom header).
      const port = (server.address() as { port: number }).port;
      const allowed = new Set([`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`, `${host}:${port}`]);
      if (!allowed.has(String(req.headers.host || '').toLowerCase())) return send(res, 421, { error: 'Unexpected Host header' });
      const url = new URL(req.url || '/', `http://${req.headers.host}`), path = url.pathname, method = req.method || 'GET';
      if (method !== 'GET' && req.headers['x-phishbowl'] !== '1') return send(res, 403, { error: 'Missing X-Phishbowl header' });

      if (method === 'GET' && (path === '/' || path === '/index.html')) return send(res, 200, renderDashboard({ mode: 'live', preparedBy: o.preparedBy, online: !!(o.online && o.onlineDefault), feedback: !!o.feedback }), 'text/html; charset=utf-8');
      if (method === 'GET' && path === '/api/health') return send(res, 200, { ok: true, version: VERSION, emails: store.size, online: !!o.online });
      if (method === 'GET' && path === '/api/analyses') return send(res, 200, { items: [...store.values()].map(x => summaryOf(x.view)) });
      if (method === 'GET' && path === '/api/snapshot.html') return send(res, 200, renderDashboard({ mode: 'static', views: [...store.values()].map(x => x.view), preparedBy: o.preparedBy }), 'text/html; charset=utf-8');
      if (method === 'POST' && path === '/api/analyses') {
        const bytes = new Uint8Array(await readBody(req)); if (!bytes.length) return send(res, 400, { error: 'Empty body' });
        const name = decodeURIComponent(String(req.headers['x-filename'] || 'email.eml'));
        const ask = req.headers['x-phishbowl-online'], wantOnline = ask === undefined ? !!o.onlineDefault : ask === '1';
        const r = await viewOf(name, bytes, { ownDomains: o.ownDomains, report: base, online: wantOnline ? o.online : undefined, allow: o.allow }); store.set(r.view.id, { ...r, bytes, file: name });
        return send(res, 201, { summary: summaryOf(r.view), view: r.view });
      }
      const m = path.match(/^\/api\/analyses\/([\w.-]+)(\/report|\/feedback|\/export\/(\w+))?$/);
      if (m) {
        const item = store.get(m[1]); if (!item) return send(res, 404, { error: 'No such email' });
        if (method === 'GET' && !m[2]) return send(res, 200, item.view);
        if (method === 'GET' && m[3]) { const e = item.view.exports[m[3]]; return e ? send(res, 200, e.content, 'text/plain; charset=utf-8') : send(res, 404, { error: 'No such format' }); }
        if (method === 'DELETE' && !m[2]) { store.delete(m[1]); return send(res, 200, { ok: true }); }
        if (method === 'POST' && m[2] === '/feedback') {
          if (!o.feedback) return send(res, 404, { error: 'Feedback is off' });
          if (item.analysis.kind !== 'email') return send(res, 400, { error: 'Not an email' });
          const b = JSON.parse((await readBody(req)).toString('utf8') || '{}');
          if (!(b.says in SAYS)) return send(res, 400, { error: 'says must be one of ' + Object.keys(SAYS).join(', ') });
          const e = recordFeedback(item.analysis, item.bytes, { file: item.file, says: b.says as Says, note: typeof b.note === 'string' ? b.note : undefined, keep: !!b.keep, version: VERSION, dir: o.feedbackDir });
          return send(res, 200, { ok: true, says: e.says, kept: !!e.kept });
        }
        if (method === 'POST' && m[2] === '/report') {
          const b = JSON.parse((await readBody(req)).toString('utf8') || '{}');
          const opts: ReportOptions = { ...base,
            done: (Array.isArray(b.done) ? b.done : []).filter((x: string) => x in ACTIONS),
            tlp: b.tlp && b.tlp in TLP_LABEL ? b.tlp : undefined,
            verdict: ['malicious', 'suspicious', 'clean'].includes(b.verdict) ? b.verdict : undefined,
            ref: typeof b.ref === 'string' && b.ref ? b.ref.slice(0, 64) : undefined,
            preparedBy: typeof b.preparedBy === 'string' && b.preparedBy ? b.preparedBy.slice(0, 120) : o.preparedBy,
            customer: typeof b.customer === 'string' && b.customer ? b.customer.slice(0, 120) : undefined };
          item.view.reports = buildReports(item.analysis, opts);
          return send(res, 200, item.view.reports);
        }
      }
      return send(res, 404, { error: 'Not found' });
    } catch (e) { return send(res, 500, { error: (e as Error).message }); }
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(o.port ?? 8787, host, () => resolve()); });
  const port = (server.address() as { port: number }).port;
  return { server, port, url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/`, store };
}
