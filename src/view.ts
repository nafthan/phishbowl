// View model: an analysis turned into display-ready data for the dashboard (and any other front-end).
// Everything a person reads is defanged here, so a front-end can show it as plain text without further care.
// Exports keep raw values, because they are meant for tools.
import { defang, defangAll } from './defang.js';
import { orgOf } from './domains.js';
import { SPAM_MEANING } from './headers.js';
import { TYPE_LABEL } from './indicators.js';
import { buildCustomerEmail } from './report/customer.js';
import { EXPORTS, exportAs, type ExportFormat } from './report/exports.js';
import { buildReport, reportMarkdown, reportText, type Audience, type ReportOptions } from './report/report.js';
import { GROUPS, keyFindings, VERDICT_LABEL } from './verdict.js';
import type { Analysis, Check, EmailAnalysis, Status } from './types.js';

export interface ViewCheck { id: string; name: string; status: Status; result: string; why?: string }
export interface ViewNote { sev: string; text: string }
export interface ViewReports { tech: ViewReport; mgmt: ViewReport; staff: ViewReport; customer: { subject: string; body: string; hits: string[] } }
export interface ViewReport { title: string; text: string; markdown: string }

export interface View {
  id: string;
  file: string;
  kind: 'email' | 'text';
  analysedAt: string;
  ms: number;
  verdict: { v: string; label: string; score: number; conf: string; bad: number; warn: number; ok: number; run: number } | null;
  summary: {
    subject: string; from: string; replyTo: string; returnPath: string; to: string; date: string; sentFrom: string;
    auth: { spf: string; dkim: string; dmarc: string }; links: number; attachments: number; qr: number;
    reportedBy: string; attachedEmails: { name: string; subject: string; verdict: string; label: string; score: number }[];
  } | null;
  findings: ViewCheck[];
  groups: { id: string; name: string; flagged: number; checks: ViewCheck[] }[];
  headers: {
    hops: { n: number; from: string; rdns: string; ip: string; by: string; with: string; tls: boolean; time: string; delay: number | null; entry: boolean }[];
    auth: { check: string; result: string; domain: string; matchesFrom: boolean | null; detail: string }[];
    spam: { header: string; field: string; value: string; meaning: string }[];
    all: { name: string; value: string }[];
  } | null;
  links: { source: string; shows: string; goesTo: string; unwrapped: string; findings: ViewNote[] }[];
  attachments: {
    name: string; declared: string; what: string; size: number; entropy: number; inline: boolean; worst: 'bad' | 'warn' | 'ok'; notes: ViewNote[];
    zip?: { name: string; size: number; encrypted: boolean }[];
    html?: { title: string; forms: string[]; scripts: number; handlers: number; patterns: string[]; links: number };
    qr?: string; sha256: string; sha1: string; md5: string;
  }[];
  content: { hits: { label: string; phrases: string[] }[]; structure: { label: string; value: string }[]; body: string } | null;
  indicators: { type: string; label: string; value: string; defanged: string; count: number; notes: { t: string; warn?: boolean }[]; off: string | null; ctx: { pre: string; hit: string; post: string } }[];
  reports: ViewReports;
  exports: Record<string, { label: string; description: string; content: string }>;
  /** Plain text of a text-mode input (a threat report), defanged. */
  text?: string;
}

const d = (s: string) => defangAll(String(s || ''));
const vcheck = (c: Check): ViewCheck => ({ id: c.id, name: c.name, status: c.status, result: d(c.result), ...(c.why ? { why: c.why } : {}) });
const fmtT = (t: number | null) => t ? new Date(t).toISOString().replace('T', ' ').slice(0, 19) : '';

export function buildReports(a: Analysis, o: ReportOptions = {}): ViewReports {
  const r = (audience: Audience): ViewReport => { const rep = buildReport(a, { ...o, audience }); return { title: rep.title, text: reportText(rep), markdown: reportMarkdown(rep) }; };
  return { tech: r('tech'), mgmt: r('mgmt'), staff: r('staff'), customer: buildCustomerEmail(a, o) };
}

export function buildView(a: Analysis, meta: { id: string; file: string }, o: ReportOptions = {}): View {
  const exports = Object.fromEntries((Object.keys(EXPORTS) as ExportFormat[]).map(f => [f, { label: EXPORTS[f][0], description: EXPORTS[f][1], content: exportAs(f, a, o) }]));
  const indicators = a.indicators.map(f => ({ type: f.type, label: TYPE_LABEL[f.type], value: f.value, defanged: defang(f.type, f.value), count: f.count,
    notes: f.notes.map(n => ({ t: d(n.t), ...(n.warn ? { warn: true } : {}) })), off: f.off, ctx: { pre: d(f.ctx.pre), hit: d(f.ctx.hit), post: d(f.ctx.post) } }));
  const base = { id: meta.id, file: meta.file, analysedAt: new Date().toISOString(), ms: a.ms, indicators, reports: buildReports(a, o), exports };
  if (a.kind !== 'email') return { ...base, kind: 'text', verdict: null, summary: null, findings: [], groups: [], headers: null, links: [], attachments: [], content: null, text: d(a.text) };
  return { ...base, kind: 'email', ...emailParts(a) };
}

function emailParts(a: EmailAnalysis) {
  const v = a.verdict;
  const web = a.links.filter(l => /^https?:/i.test(l.href)).length;
  const fromOrg = orgOf(a.fromDom);
  const matches = (dom: string) => dom && a.fromDom ? orgOf(dom) === fromOrg : null;
  const sig = a.auth.dkimSigs[0];
  const hops = a.hops.map((h, i) => {
    const prev = a.hops.slice(0, i).reverse().find(p => p.time);
    return { n: i + 1, from: d(h.from), rdns: d(h.rdns), ip: d(h.ip), by: d(h.by), with: h.with, tls: h.tls, time: fmtT(h.time),
      delay: h.time && prev && prev.time ? Math.round((h.time - prev.time) / 1000) : null, entry: h === a.entry };
  });
  const auth = [
    { check: 'SPF', result: a.auth.spf, domain: d(a.auth.mailfrom), matchesFrom: matches(a.auth.mailfrom), detail: 'Is the sending server allowed to send for the bounce domain?' },
    { check: 'DKIM', result: a.auth.dkim, domain: d(a.auth.dkimD || (sig && sig.d) || ''), matchesFrom: matches(a.auth.dkimD || (sig && sig.d) || ''),
      detail: sig && sig.s ? `selector ${sig.s}, ${sig.a}, signs: ${sig.h}` : 'Was it signed and unchanged?' },
    { check: 'DMARC', result: a.auth.dmarc, domain: d(a.auth.hfrom), matchesFrom: null, detail: a.auth.dmarcAction ? 'policy/action: ' + a.auth.dmarcAction : 'Did SPF or DKIM pass for the From domain?' },
    ...(a.auth.compauth ? [{ check: 'compauth', result: a.auth.compauth, domain: '', matchesFrom: null, detail: 'Microsoft composite authentication' + (a.auth.compReason ? ', reason ' + a.auth.compReason : '') }] : []),
    ...(a.auth.arc ? [{ check: 'ARC', result: a.auth.arc, domain: '', matchesFrom: null, detail: 'Results carried over by a forwarding server' }] : []),
  ];
  const hit = (id: string) => (a.checks.find(c => c.id === id)?.hits || []).map(d);
  const res = (id: string) => d(a.checks.find(c => c.id === id)?.result || '');
  return {
    verdict: { v: v.v, label: VERDICT_LABEL[v.v], score: v.score, conf: v.conf, bad: v.bad, warn: v.warn, ok: v.ok, run: v.run },
    summary: { subject: a.subj, from: d(a.from), replyTo: d(a.replyTo), returnPath: d(a.rp), to: d(a.to), date: a.date,
      sentFrom: a.entry ? d(`${a.entry.from || '(no name)'} [${a.entry.ip}]`) : '', auth: { spf: a.auth.spf, dkim: a.auth.dkim, dmarc: a.auth.dmarc },
      links: web, attachments: a.real.length, qr: a.atts.filter(x => x.extra.qr).length,
      reportedBy: a.reportedBy ? d(`${a.reportedBy.from}${a.reportedBy.date ? ' · ' + a.reportedBy.date : ''} (this is the attached original)`) : '',
      attachedEmails: (a.nested || []).map(n => ({ name: n.name, subject: d(n.subject), verdict: n.verdict.v, label: VERDICT_LABEL[n.verdict.v], score: n.verdict.score })) },
    findings: keyFindings(a.checks, 7).map(vcheck),
    groups: GROUPS.map(([id, name]) => {
      const checks = a.checks.filter(c => c.group === id).sort((x, y) => 'bad warn ok info na'.indexOf(x.status) - 'bad warn ok info na'.indexOf(y.status));
      return { id, name, flagged: checks.filter(c => c.status === 'bad' || c.status === 'warn').length, checks: checks.map(vcheck) };
    }).filter(g => g.checks.length),
    headers: { hops, auth, spam: a.spam.map(([header, field, value]) => ({ header, field, value: d(value), meaning: SPAM_MEANING[field] ? SPAM_MEANING[field](value) : '' })),
      all: a.headers.map(([, value, name]) => ({ name, value: d(value) })) },
    links: a.links.map(l => ({ source: l.source, shows: d(l.text), goesTo: /^https?:/i.test(l.href) ? defang('url', l.href) : d(l.href), unwrapped: l.unwrapped,
      findings: l.findings.map(f => ({ sev: f[0], text: d(f[1]) })) })),
    attachments: a.atts.map(x => ({
      name: x.name, declared: x.declared, what: x.what, size: x.size, entropy: +x.extra.entropy.toFixed(2), inline: x.inline,
      worst: (x.notes.some(n => n[0] === 'bad') ? 'bad' : x.notes.some(n => n[0] === 'warn') ? 'warn' : 'ok') as 'bad' | 'warn' | 'ok',
      notes: x.notes.map(n => ({ sev: n[0], text: d(n[1]) })),
      ...(x.extra.zip ? { zip: x.extra.zip.slice(0, 100).map(e => ({ name: e.name, size: e.usize, encrypted: e.encrypted })) } : {}),
      ...(x.extra.html ? { html: { title: x.extra.html.title, forms: x.extra.html.forms.map(f => `${f.method} to ${/^https?:/i.test(f.action) ? defang('url', f.action) : f.action}${f.password ? ' (asks for a password)' : ''}`),
        scripts: x.extra.html.scripts, handlers: x.extra.html.handlers, patterns: x.extra.html.patterns, links: x.extra.html.links.length } } : {}),
      ...(x.extra.qr ? { qr: d(x.extra.qr) } : {}),
      sha256: x.sha256, sha1: x.sha1, md5: x.md5,
    })),
    content: {
      hits: [['Pressure', 'content.urgency'], ['Sign-in or details', 'content.creds'], ['Money', 'content.money'], ['Threats', 'content.threat'], ['Payment or gift-card request', 'content.bec'],
        ['Wallet recovery phrase', 'content.seed']].map(([label, id]) => ({ label, phrases: hit(id) })),
      structure: [{ label: 'Versions', value: [a.html.length ? 'HTML' : '', a.body ? 'plain text' : ''].filter(Boolean).join(' and ') || 'none' },
        { label: 'Greeting', value: res('content.greeting') }, { label: 'Hidden text', value: res('content.hidden') }, { label: 'Tracking', value: res('content.pixel') },
        { label: 'Forms and scripts', value: [res('content.forms') || 'No forms', res('content.scripts') || 'no scripts'].join('; ') }],
      body: d(a.body || '(empty)'),
    },
  };
}

/** A short summary for lists (the dashboard's queue, an API listing). */
export const summaryOf = (v: View) => ({ id: v.id, file: v.file, kind: v.kind, analysedAt: v.analysedAt, verdict: v.verdict, subject: v.summary?.subject ?? '', from: v.summary?.from ?? '', date: v.summary?.date ?? '',
  top: v.findings[0] ? v.findings[0].name : '', indicators: v.indicators.filter(i => !i.off).length });
