#!/usr/bin/env node
// phishbowl: analyse phishing emails from the command line. Everything runs locally; nothing is uploaded.
import { readFileSync, existsSync, statSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { join, basename } from 'node:path';
import { parseArgs } from 'node:util';
import { analyseBytes, analyseFile, emlFiles, fileCache, MAX_BYTES } from './node/index.js';
import type { OnlineOptions } from './online.js';
import { allowProblems, type Allowlist } from './allow.js';
import { dataDir, exportFixtures, outcome, readFeedback, recordFeedback, SAYS, summarise, type Says } from './node/feedback.js';
import { renderDashboard, startServer, VERSION, viewId } from './node/dashboard.js';
import { buildView } from './view.js';
import { buildCustomerEmail } from './report/customer.js';
import { EXPORTS, exportAs, toJSON, type ExportFormat } from './report/exports.js';
import { ACTIONS, buildReport, reportMarkdown, reportText, TLP_LABEL, type Action, type Audience, type ReportOptions, type Tlp } from './report/report.js';
import { defangAll } from './defang.js';
import { GROUPS, keyFindings, VERDICT_LABEL } from './verdict.js';
import { included } from './indicators.js';
import type { Analysis, Check, EmailAnalysis, LeaveOut, Status } from './types.js';

const EXIT = { clean: 0, error: 1, suspicious: 2, malicious: 3 } as const;

const HELP = `phishbowl ${VERSION}: phishing email analyser. Runs locally; nothing is uploaded.

Usage
  phishbowl [analyse] <file.eml | folder | -> ...   run every check and show the verdict
  phishbowl report    <file.eml | ->               write a report to share
  phishbowl iocs      <file | ->                   list indicators (an email, or any text such as a threat report)
  phishbowl ui        [file.eml | folder ...]      open the dashboard in your browser (a local server on this machine)
  phishbowl feedback  <file> --says <phish|legit|spam>   record that a verdict was right or wrong (kept on this machine)
  phishbowl feedback                               what your feedback shows: false alarms, misses, allowlist ideas

Analyse
  --all                 show every check, not just the flagged ones
  --json                print the full analysis as JSON (an array for several files)
  --html <file>         also write the dashboard as one self-contained HTML file (no outside connections;
                        attach it to a ticket or embed it in another platform)
  --embed               with --html: hide the top bar, for showing inside another page

Dashboard (ui)
  --port <n>            port to listen on (default 8787; 0 picks a free one)
  --host <addr>         address to listen on (default 127.0.0.1, this machine only)
  --no-open             don't open the browser
                        (the dashboard has its own "Check online" switch; --online turns it on to start with)

Report
  --audience <who>      tech (default), mgmt (plain English) or staff (warning to staff)
  --markdown            Markdown instead of plain text
  --customer-email      a ready-to-paste email for the customer instead (no links, everything defanged)
  --verdict <v>         override the verdict: malicious, suspicious or clean
  --tlp <label>         clear, green, amber, amber-strict or red (default amber; clear for staff)
  --ref <ref>           reference (default PB-YYYYMMDD-XXXX from the message)
  --by <name>           prepared by
  --customer <name>     who the customer email greets
  --done <actions>      already done, comma-separated: ${Object.keys(ACTIONS).join(', ')}

Indicators
  --format <f>          ${Object.keys(EXPORTS).join(', ')} (default list)
  --keep-private        keep private and internal IPs
  --keep-known          keep well-known sites and your own domains
  --keep-files          keep names that are probably files (.zip, .mov)

Feedback
  --says <what>         phish, legit or spam: what the email really is
  --note <text>         why, in your words
  --keep                also keep a copy of the email, so it can become a test fixture
  --export <folder>     copy kept emails Phishbowl got wrong into a folder, with an expected.json

Online lookups (off by default; nothing is looked up unless you turn them on)
  --online              also check domain age (RDAP), the sender's DNS (MX, SPF, DMARC) and known-phishing
                        feeds. Sends domain names only, never email content; the OpenPhish feed is downloaded
                        and matched here. Also "online": { "enabled": true } in the config, or PHISHBOWL_ONLINE=1
  --offline             turn them off even if the config turns them on
                        URLhaus host lookups need a free Auth-Key: PHISHBOWL_URLHAUS_KEY or "online.urlhausKey"

Everywhere
  --own <domains>       your organisation's domains, comma-separated. Also PHISHBOWL_OWN_DOMAINS, or
                        "ownDomains" in phishbowl.config.json (this folder) or ~/.config/phishbowl/config.json
  --no-allow            ignore the allowlist ("allow": { "senders": [...], "domains": [...] } in the config).
                        Allowlisted senders' authenticated mail doesn't raise warnings; red flags still count
  --no-color            plain output (also NO_COLOR=1)
  --exit-zero           always exit 0
  -h, --help            this help
  -v, --version         version

Exit codes: 0 likely legitimate (or text), 2 suspicious, 3 malicious, 1 error. With several files, the worst one counts.
Addresses and links in the output are defanged (hxxp, [.]) so terminals won't make them clickable.`;

interface OnlineConfig { enabled?: boolean; rdap?: boolean; dns?: boolean; feeds?: boolean; urlhausKey?: string; dohUrl?: string; feedUrl?: string }
interface Config { ownDomains?: string[]; preparedBy?: string; tlp?: Tlp; online?: OnlineConfig; allow?: Allowlist }

/** The allowlist from the config, with a warning for entries that are ignored. */
function allowFrom(cfg: Config): Allowlist | undefined {
  if (!cfg.allow) return undefined;
  for (const p of allowProblems(cfg.allow)) process.stderr.write(`phishbowl: allowlist: ${p}. Ignored.\n`);
  return cfg.allow;
}

/** Online lookup settings from config, the environment and flags; null when they are off. */
function onlineOptions(cfg: Config, o: { online?: boolean; offline?: boolean }, ownDomains: string[]): { opts: OnlineOptions; on: boolean } {
  const c = cfg.online || {}, cache = fileCache();
  process.once('exit', () => cache.flush());
  const opts: OnlineOptions = { cache, ownDomains, rdap: c.rdap, dns: c.dns, feeds: c.feeds, dohUrl: c.dohUrl || undefined, feedUrl: c.feedUrl || undefined,
    urlhausKey: process.env.PHISHBOWL_URLHAUS_KEY || c.urlhausKey || undefined };
  return { opts, on: o.offline ? false : !!(o.online || c.enabled || process.env.PHISHBOWL_ONLINE === '1') };
}
function loadConfig(): Config {
  const places = [join(process.cwd(), 'phishbowl.config.json'),
    join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'phishbowl', 'config.json'),
    ...(process.env.APPDATA ? [join(process.env.APPDATA, 'phishbowl', 'config.json')] : [])];
  for (const p of places) if (existsSync(p)) {
    try { return JSON.parse(readFileSync(p, 'utf8')) as Config; } catch (e) { throw new Error(`Can't read ${p}: ${(e as Error).message}`); }
  }
  return {};
}

// ── output helpers ─────────────────────────────────────────────────────────────
let colour = false;
const paint = (code: string) => (s: string) => colour ? `\x1b[${code}m${s}\x1b[0m` : s;
const C = { red: paint('31'), yellow: paint('33'), green: paint('32'), dim: paint('2'), bold: paint('1'), redBold: paint('1;31'), yellowBold: paint('1;33'), greenBold: paint('1;32') };
const GLYPH: Record<Status, string> = { bad: '✕', warn: '!', ok: '✓', info: '•', na: '–' };
const byStatus: Record<Status, (s: string) => string> = { bad: C.red, warn: C.yellow, ok: C.green, info: C.dim, na: C.dim };
const verdictText = (v: string) => (v === 'malicious' ? C.redBold : v === 'suspicious' ? C.yellowBold : C.greenBold)(VERDICT_LABEL[v].toUpperCase());
const out = (s = '') => process.stdout.write(s + '\n');
const safe = (s: string) => defangAll(String(s || ''));

function printCheck(c: Check, nameWidth = 30) {
  out(`  ${byStatus[c.status](GLYPH[c.status])} ${c.name.padEnd(nameWidth)} ${c.status === 'na' || c.status === 'info' ? C.dim(safe(c.result)) : safe(c.result)}`);
}

function printEmail(a: EmailAnalysis, label: string, all: boolean) {
  const v = a.verdict, row = (k: string, val: string) => { if (val) out(`  ${C.dim(k.padEnd(10))} ${val}`); };
  const pill = (k: string, r: string) => (r === 'pass' ? C.green : !r || r === 'none' ? C.dim : /fail/.test(r) ? C.red : C.yellow)(`${k} ${r || 'none'}`);
  const qr = a.atts.filter(x => x.extra.qr).length, web = a.links.filter(l => /^https?:/i.test(l.href)).length;
  out(C.bold(label));
  out(`  ${verdictText(v.v)}  ${C.dim(`${v.conf} confidence · score ${v.score} · ${v.bad + v.warn} of ${v.run} checks flagged (${v.bad} red flags)`)}`);
  if (a.reportedBy) row('Reported', C.dim(safe(`by ${a.reportedBy.from}${a.reportedBy.date ? ' · ' + a.reportedBy.date : ''} · this is the attached original`)));
  const allowed = a.checks.find(c => c.id === 'sender.allowed');
  if (allowed) row('Allowlist', C.dim(safe(allowed.result)));
  row('Subject', a.subj || '(none)');
  row('From', safe(a.from));
  row('Reply-To', safe(a.replyTo));
  row('Sent from', a.entry ? safe(`${a.entry.from || '(no name)'} [${a.entry.ip}]`) : '');
  row('Sent', a.date);
  row('Auth', [pill('SPF', a.auth.spf), pill('DKIM', a.auth.dkim), pill('DMARC', a.auth.dmarc)].join('  '));
  for (const n of a.nested || []) row('Attached', `${n.name}: ${verdictText(n.verdict.v)} ${C.dim(`score ${n.verdict.score} · "${n.subject.slice(0, 60)}"`)}`);
  row('Contains', [`${web} link${web === 1 ? '' : 's'}`, `${a.real.length} attachment${a.real.length === 1 ? '' : 's'}`, qr ? C.red(`${qr} QR code${qr > 1 ? 's' : ''}`) : ''].filter(Boolean).join(' · '));
  out();
  if (all) {
    for (const [g, name] of GROUPS) {
      const rows = a.checks.filter(c => c.group === g); if (!rows.length) continue;
      const flagged = rows.filter(c => c.status === 'bad' || c.status === 'warn').length;
      out(`  ${C.bold(name)} ${C.dim(flagged ? `${flagged} flagged` : 'nothing flagged')}`);
      const w = Math.min(36, Math.max(...a.checks.map(c => c.name.length)));
      rows.sort((x, y) => 'bad warn ok info na'.indexOf(x.status) - 'bad warn ok info na'.indexOf(y.status)).forEach(c => printCheck(c, w));
      out();
    }
  } else {
    const key = keyFindings(a.checks, 10);
    if (key.length) { const w = Math.min(36, Math.max(...key.map(c => c.name.length))); out(`  ${C.bold('Key findings')}`); key.forEach(c => printCheck(c, w)); out(); }
    else out(`  ${C.green('Nothing stood out:')} authentication passed and nothing in the links, content or attachments was flagged.\n`);
  }
  for (const att of a.real) out(`  ${C.dim('File')}       ${att.name}  ${C.dim(`${att.what} · ${att.size} bytes · SHA256 ${att.sha256}`)}`);
  if (a.real.length) out();
}

function printText(a: Analysis, label: string) {
  const n = included(a.indicators).length;
  out(C.bold(label));
  out(`  ${C.bold('TEXT')}  ${C.dim('not an email, so only its indicators were extracted')}: ${n} indicator${n === 1 ? '' : 's'}. Run \`phishbowl iocs\` to list them.`);
  out();
}

// ── input ──────────────────────────────────────────────────────────────────────
async function readStdin(): Promise<Uint8Array> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const c of process.stdin) { chunks.push(c as Buffer); size += (c as Buffer).length; if (size > MAX_BYTES) throw new Error(`Input over ${MAX_BYTES / 1048576} MB`); }
  return new Uint8Array(Buffer.concat(chunks));
}
async function expand(inputs: string[]): Promise<string[]> {
  const files: string[] = [];
  for (const p of inputs) {
    if (p === '-') { files.push(p); continue; }
    if (!existsSync(p)) throw new Error(`No such file or folder: ${p}`);
    if (statSync(p).isDirectory()) { const list = await emlFiles(p); if (!list.length) throw new Error(`No .eml files in ${p}`); files.push(...list); }
    else files.push(p);
  }
  return files;
}

// ── main ───────────────────────────────────────────────────────────────────────
async function main(argv: string[]): Promise<number> {
  const { values: o, positionals } = parseArgs({
    args: argv, allowPositionals: true, strict: true,
    options: {
      all: { type: 'boolean' }, json: { type: 'boolean' }, own: { type: 'string' }, html: { type: 'string' }, embed: { type: 'boolean' },
      port: { type: 'string' }, host: { type: 'string' }, 'no-open': { type: 'boolean' },
      audience: { type: 'string' }, markdown: { type: 'boolean' }, 'customer-email': { type: 'boolean' }, verdict: { type: 'string' },
      tlp: { type: 'string' }, ref: { type: 'string' }, by: { type: 'string' }, customer: { type: 'string' }, done: { type: 'string' },
      format: { type: 'string' }, 'keep-private': { type: 'boolean' }, 'keep-known': { type: 'boolean' }, 'keep-files': { type: 'boolean' },
      online: { type: 'boolean' }, offline: { type: 'boolean' }, 'no-allow': { type: 'boolean' },
      says: { type: 'string' }, note: { type: 'string' }, keep: { type: 'boolean' }, export: { type: 'string' },
      'no-color': { type: 'boolean' }, 'exit-zero': { type: 'boolean' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
    },
  });
  if (o.help) { out(HELP); return 0; }
  if (o.version) { out(VERSION); return 0; }
  colour = !o['no-color'] && !process.env.NO_COLOR && (!!process.env.FORCE_COLOR || !!process.stdout.isTTY);

  const commands = ['analyse', 'analyze', 'check', 'report', 'iocs', 'ui', 'feedback', 'help'];
  let cmd = 'analyse', inputs = positionals;
  if (positionals.length && commands.includes(positionals[0])) { cmd = positionals[0]; inputs = positionals.slice(1); }
  if (cmd === 'help') { out(HELP); return 0; }
  if (cmd === 'analyze' || cmd === 'check') cmd = 'analyse';
  if (cmd === 'ui') return ui(inputs, o);
  if (cmd === 'feedback') return feedback(inputs, o);
  if (!inputs.length) { process.stderr.write(`Nothing to analyse. Give a file, a folder or - for stdin.\n\n${HELP}\n`); return EXIT.error; }

  const cfg = loadConfig();
  const ownDomains = (o.own ?? process.env.PHISHBOWL_OWN_DOMAINS ?? (cfg.ownDomains || []).join(',')).split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  const leaveOut: LeaveOut = { private: !o['keep-private'], known: !o['keep-known'], files: !o['keep-files'] };
  const net = onlineOptions(cfg, o, ownDomains), online = net.on ? net.opts : undefined, allow = o['no-allow'] ? undefined : allowFrom(cfg);
  const run = async (f: string) => f === '-' ? analyseBytes(await readStdin(), { ownDomains, leaveOut, online, allow }) : analyseFile(f, { ownDomains, leaveOut, online, allow });

  const pickOne = <T extends string>(name: string, val: string | undefined, allowed: readonly T[]): T | undefined => {
    if (val === undefined) return undefined;
    if (!(allowed as readonly string[]).includes(val)) throw new Error(`--${name} must be one of: ${allowed.join(', ')}`);
    return val as T;
  };
  const done = (o.done || '').split(',').map(s => s.trim()).filter(Boolean);
  for (const d of done) if (!(d in ACTIONS)) throw new Error(`Unknown --done action "${d}". Use: ${Object.keys(ACTIONS).join(', ')}`);
  const ropts: ReportOptions = {
    audience: pickOne<Audience>('audience', o.audience, ['tech', 'mgmt', 'staff']),
    verdict: pickOne('verdict', o.verdict, ['malicious', 'suspicious', 'clean'] as const),
    tlp: pickOne<Tlp>('tlp', o.tlp ?? cfg.tlp, Object.keys(TLP_LABEL) as Tlp[]),
    ref: o.ref, preparedBy: o.by ?? cfg.preparedBy, customer: o.customer, done: done as Action[], ownDomains,
  };

  if (cmd === 'report' || cmd === 'iocs') {
    if (inputs.length !== 1) throw new Error(`${cmd} takes one file (or - for stdin)`);
    const a = await run(inputs[0]);
    if (cmd === 'iocs') {
      const format = pickOne<ExportFormat>('format', o.format, Object.keys(EXPORTS) as ExportFormat[]) || 'list';
      out(exportAs(format, a, ropts));
      return 0;
    }
    if (o['customer-email']) {
      const m = buildCustomerEmail(a, ropts);
      out(`Subject: ${m.subject}\n\n${m.body}`);
      if (m.hits.length) process.stderr.write(`\nCheck before sending: these could still become links: ${m.hits.join(', ')}\n`);
      return 0;
    }
    const r = buildReport(a, ropts);
    out(o.markdown ? reportMarkdown(r) : reportText(r));
    return 0;
  }

  // analyse
  const files = await expand(inputs);
  let worst = 0;
  const results: { file: string; a?: Analysis; error?: string }[] = [];
  for (const f of files) {
    try { results.push({ file: f, a: await run(f) }); }
    catch (e) { results.push({ file: f, error: (e as Error).message }); worst = Math.max(worst, EXIT.error); }
  }
  for (const r of results) if (r.a && r.a.kind === 'email') worst = Math.max(worst, EXIT[r.a.verdict.v]);

  if (o.html) {
    const views = [];
    for (const r of results) if (r.a) {
      const bytes = r.file === '-' ? new TextEncoder().encode(r.a.kind === 'email' ? r.a.text : r.a.text) : new Uint8Array(readFileSync(r.file));
      views.push(buildView(r.a, { id: viewId(r.file === '-' ? 'stdin' : r.file, bytes), file: r.file === '-' ? '(stdin)' : basename(r.file) }, ropts));
    }
    writeFileSync(o.html, renderDashboard({ mode: 'static', views, embed: !!o.embed, preparedBy: ropts.preparedBy }));
    process.stderr.write(`Dashboard written to ${o.html} (${views.length} email${views.length === 1 ? '' : 's'}; opens offline, makes no outside connections)\n`);
  }

  if (o.json) {
    const data = results.map(r => r.a ? { file: r.file, ...toJSON(r.a, ropts) } : { file: r.file, error: r.error });
    out(JSON.stringify(files.length === 1 ? data[0] : data, null, 2));
  } else if (files.length === 1) {
    const r = results[0], label = r.file === '-' ? '(stdin)' : basename(r.file);
    if (r.error) process.stderr.write(`${label}: ${r.error}\n`);
    else if (r.a!.kind === 'email') {
      printEmail(r.a as EmailAnalysis, label, !!o.all);
      out(C.dim(`  More: phishbowl report ${r.file === '-' ? '-' : JSON.stringify(r.file)}  ·  phishbowl iocs ${r.file === '-' ? '-' : JSON.stringify(r.file)} --format kql  ·  --all for every check`));
    } else printText(r.a!, label);
  } else {
    const tally = { malicious: 0, suspicious: 0, clean: 0, text: 0, error: 0 };
    const w = Math.min(40, Math.max(...results.map(r => basename(r.file).length)));
    for (const r of results) {
      const name = basename(r.file).padEnd(w);
      if (r.error) { tally.error++; out(`${C.red('ERROR'.padEnd(17))} ${name}  ${r.error}`); continue; }
      const a = r.a!;
      if (a.kind !== 'email') { tally.text++; out(`${'TEXT'.padEnd(17)} ${name}  not an email`); continue; }
      tally[a.verdict.v]++;
      const top = a.verdict.v === 'clean' ? undefined : keyFindings(a.checks, 1)[0];
      out(`${verdictText(a.verdict.v)}${' '.repeat(17 - VERDICT_LABEL[a.verdict.v].length)} ${name}  ${String(a.verdict.score).padStart(3)}  ${a.subj.slice(0, 50)}${top ? C.dim('  · ' + safe(top.name)) : ''}`);
    }
    out();
    out(`${files.length} files: ${tally.malicious} malicious · ${tally.suspicious} suspicious · ${tally.clean} likely legitimate${tally.text ? ` · ${tally.text} not email` : ''}${tally.error ? ` · ${tally.error} errors` : ''}`);
  }
  return o['exit-zero'] ? 0 : worst;
}

type Flags = { port?: string; host?: string; own?: string; by?: string; 'no-open'?: boolean; online?: boolean; offline?: boolean; 'no-allow'?: boolean;
  says?: string; note?: string; keep?: boolean; export?: string };

async function feedback(inputs: string[], o: Flags): Promise<number> {
  const cfg = loadConfig(), allow = o['no-allow'] ? undefined : allowFrom(cfg);
  const ownDomains = (o.own ?? process.env.PHISHBOWL_OWN_DOMAINS ?? (cfg.ownDomains || []).join(',')).split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  if (o.export) {
    const r = exportFixtures(o.export);
    out(`${r.written.length} email${r.written.length === 1 ? '' : 's'} written to ${o.export}${r.skipped ? ` (${r.skipped} kept copies missing)` : ''}. ` +
      (r.written.length ? 'Each is listed in expected.json with what it should be.' : 'Only emails Phishbowl got wrong and you kept (--keep) are exported.'));
    return 0;
  }
  if (inputs.length) {
    if (!o.says || !(o.says in SAYS)) throw new Error(`Say what it really is: --says ${Object.keys(SAYS).join(', ')}`);
    if (inputs.length !== 1 || inputs[0] === '-') throw new Error('feedback takes one file');
    const bytes = new Uint8Array(readFileSync(inputs[0]));
    const a = await analyseBytes(bytes, { ownDomains, allow });
    if (a.kind !== 'email') throw new Error(`${inputs[0]} is not an email`);
    const e = recordFeedback(a, bytes, { file: inputs[0], says: o.says as Says, note: o.note, keep: !!o.keep, version: VERSION });
    const res = outcome(e);
    out(`Recorded: you say ${SAYS[e.says]}; Phishbowl said ${VERDICT_LABEL[e.verdict].toLowerCase()} (score ${e.score}). ` +
      (res === 'false-alarm' ? C.yellow('A false alarm.') : res === 'miss' ? C.red('A miss.') : C.green('It agreed.')));
    if (e.kept) out(C.dim(`A copy was kept in ${join(dataDir(), 'emails', e.kept)}.`));
    return 0;
  }
  const entries = readFeedback(), s = summarise(entries, allow || {});
  if (!entries.length) { out(`No feedback yet. Record some with: phishbowl feedback <file> --says phish|legit|spam\nIt is kept in ${dataDir()}.`); return 0; }
  out(C.bold(`Feedback on ${s.total} email${s.total === 1 ? '' : 's'}`) + C.dim(`  (${dataDir()})`));
  out(`  ${s.total - s.falseAlarms.length - s.misses.length} agreed · ${C.yellow(`${s.falseAlarms.length} false alarm${s.falseAlarms.length === 1 ? '' : 's'}`)} · ${C.red(`${s.misses.length} missed`)}`);
  out();
  if (s.misses.length) { out(C.bold('  Missed (you said phishing, Phishbowl said likely legitimate)')); for (const e of s.misses) out(`  ${C.red('✕')} ${safe(e.file)}  ${C.dim(safe(`${e.from} · "${e.subject.slice(0, 50)}"${e.note ? ' · ' + e.note : ''}`))}`); out(); }
  if (s.falseAlarms.length) {
    out(C.bold('  False alarms (you said legitimate)')); for (const e of s.falseAlarms) out(`  ${C.yellow('!')} ${safe(e.file)}  ${C.dim(safe(`${e.verdict}, score ${e.score} · ${e.from}`))}`); out();
    out(C.bold('  Checks behind the false alarms')); for (const n of s.noisyChecks.slice(0, 10)) out(`  ${String(n.count).padStart(3)}  ${n.id}`); out();
  }
  if (s.allowSuggestions.length) {
    out(C.bold('  Allowlist ideas') + C.dim('  (authenticated senders you marked legitimate more than once)'));
    for (const x of s.allowSuggestions) out(`  ${String(x.count).padStart(3)}  ${safe(x.entry)}  ${C.dim(`add to allow.${x.kind === 'domain' ? 'domains' : 'senders'}`)}`);
    out();
  }
  const kept = entries.filter(e => e.kept && outcome(e) !== 'agree').length;
  if (kept) out(C.dim(`  ${kept} kept email${kept === 1 ? '' : 's'} can become test fixtures: phishbowl feedback --export <folder>`));
  return 0;
}

async function ui(inputs: string[], o: Flags): Promise<number> {
  const cfg = loadConfig();
  const ownDomains = (o.own ?? process.env.PHISHBOWL_OWN_DOMAINS ?? (cfg.ownDomains || []).join(',')).split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  const net = onlineOptions(cfg, o, ownDomains);
  const files = inputs.length ? await expand(inputs.filter(i => i !== '-')) : [];
  const host = o.host || '127.0.0.1', port = o.port === undefined ? 8787 : Number(o.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('--port must be a number from 0 to 65535');
  if (!/^(127\.|localhost$|::1$)/.test(host)) process.stderr.write(`Warning: listening on ${host} makes the dashboard reachable from other machines. Emails you add can be read by anyone who can reach it.\n`);
  const s = await startServer({ port, host, ownDomains, preparedBy: o.by ?? cfg.preparedBy, files, online: net.opts, onlineDefault: net.on, allow: o['no-allow'] ? undefined : allowFrom(cfg), feedback: true });
  out(`Phishbowl dashboard: ${s.url}${files.length ? `  (${files.length} email${files.length === 1 ? '' : 's'} loaded)` : ''}`);
  out(C.dim('Analysis happens on this machine. Press Ctrl+C to stop; nothing is kept after that.'));
  if (!o['no-open']) {
    const opener = process.platform === 'darwin' ? ['open', [s.url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', s.url]] : ['xdg-open', [s.url]];
    try { spawn(opener[0] as string, opener[1] as string[], { stdio: 'ignore', detached: true }).on('error', () => {}).unref(); } catch { /* no browser: the URL is printed */ }
  }
  await new Promise<void>(resolve => { process.once('SIGINT', () => { s.server.close(); resolve(); }); process.once('SIGTERM', () => { s.server.close(); resolve(); }); });
  return 0;
}

// Output piped into head, less or grep that closes early: stop quietly instead of crashing.
process.stdout.on('error', (e: NodeJS.ErrnoException) => { if (e.code === 'EPIPE') process.exit(process.exitCode ?? 0); throw e; });

main(process.argv.slice(2)).then(code => { process.exitCode = code; }, (e: Error) => {
  process.stderr.write(`phishbowl: ${e.message}\n`);
  process.exitCode = EXIT.error;
});
