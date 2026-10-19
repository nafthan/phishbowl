#!/usr/bin/env node
// phishbowl: analyse phishing emails from the command line. Everything runs locally; nothing is uploaded.
import { readFileSync, existsSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, basename } from 'node:path';
import { parseArgs } from 'node:util';
import { analyseBytes, analyseFile, emlFiles, MAX_BYTES } from './node/index.js';
import { buildCustomerEmail } from './report/customer.js';
import { EXPORTS, exportAs, toJSON, type ExportFormat } from './report/exports.js';
import { ACTIONS, buildReport, reportMarkdown, reportText, TLP_LABEL, type Action, type Audience, type ReportOptions, type Tlp } from './report/report.js';
import { defangAll } from './defang.js';
import { GROUPS, keyFindings, VERDICT_LABEL } from './verdict.js';
import { included } from './indicators.js';
import type { Analysis, Check, EmailAnalysis, LeaveOut, Status } from './types.js';

const VERSION = '0.1.0';
const EXIT = { clean: 0, error: 1, suspicious: 2, malicious: 3 } as const;

const HELP = `phishbowl ${VERSION}: phishing email analyser. Runs locally; nothing is uploaded.

Usage
  phishbowl [analyse] <file.eml | folder | -> ...   run every check and show the verdict
  phishbowl report    <file.eml | ->               write a report to share
  phishbowl iocs      <file | ->                   list indicators (an email, or any text such as a threat report)

Analyse
  --all                 show every check, not just the flagged ones
  --json                print the full analysis as JSON (an array for several files)

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

Everywhere
  --own <domains>       your organisation's domains, comma-separated. Also PHISHBOWL_OWN_DOMAINS, or
                        "ownDomains" in phishbowl.config.json (this folder) or ~/.config/phishbowl/config.json
  --no-color            plain output (also NO_COLOR=1)
  --exit-zero           always exit 0
  -h, --help            this help
  -v, --version         version

Exit codes: 0 likely legitimate (or text), 2 suspicious, 3 malicious, 1 error. With several files, the worst one counts.
Addresses and links in the output are defanged (hxxp, [.]) so terminals won't make them clickable.`;

interface Config { ownDomains?: string[]; preparedBy?: string; tlp?: Tlp }
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
  row('Subject', a.subj || '(none)');
  row('From', safe(a.from));
  row('Reply-To', safe(a.replyTo));
  row('Sent from', a.entry ? safe(`${a.entry.from || '(no name)'} [${a.entry.ip}]`) : '');
  row('Sent', a.date);
  row('Auth', [pill('SPF', a.auth.spf), pill('DKIM', a.auth.dkim), pill('DMARC', a.auth.dmarc)].join('  '));
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
      all: { type: 'boolean' }, json: { type: 'boolean' }, own: { type: 'string' },
      audience: { type: 'string' }, markdown: { type: 'boolean' }, 'customer-email': { type: 'boolean' }, verdict: { type: 'string' },
      tlp: { type: 'string' }, ref: { type: 'string' }, by: { type: 'string' }, customer: { type: 'string' }, done: { type: 'string' },
      format: { type: 'string' }, 'keep-private': { type: 'boolean' }, 'keep-known': { type: 'boolean' }, 'keep-files': { type: 'boolean' },
      'no-color': { type: 'boolean' }, 'exit-zero': { type: 'boolean' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
    },
  });
  if (o.help) { out(HELP); return 0; }
  if (o.version) { out(VERSION); return 0; }
  colour = !o['no-color'] && !process.env.NO_COLOR && (!!process.env.FORCE_COLOR || !!process.stdout.isTTY);

  const commands = ['analyse', 'analyze', 'check', 'report', 'iocs', 'help'];
  let cmd = 'analyse', inputs = positionals;
  if (positionals.length && commands.includes(positionals[0])) { cmd = positionals[0]; inputs = positionals.slice(1); }
  if (cmd === 'help') { out(HELP); return 0; }
  if (cmd === 'analyze' || cmd === 'check') cmd = 'analyse';
  if (!inputs.length) { process.stderr.write(`Nothing to analyse. Give a file, a folder or - for stdin.\n\n${HELP}\n`); return EXIT.error; }

  const cfg = loadConfig();
  const ownDomains = (o.own ?? process.env.PHISHBOWL_OWN_DOMAINS ?? (cfg.ownDomains || []).join(',')).split(/[\s,]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  const leaveOut: LeaveOut = { private: !o['keep-private'], known: !o['keep-known'], files: !o['keep-files'] };
  const run = async (f: string) => f === '-' ? analyseBytes(await readStdin(), { ownDomains, leaveOut }) : analyseFile(f, { ownDomains, leaveOut });

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

// Output piped into head, less or grep that closes early: stop quietly instead of crashing.
process.stdout.on('error', (e: NodeJS.ErrnoException) => { if (e.code === 'EPIPE') process.exit(process.exitCode ?? 0); throw e; });

main(process.argv.slice(2)).then(code => { process.exitCode = code; }, (e: Error) => {
  process.stderr.write(`phishbowl: ${e.message}\n`);
  process.exitCode = EXIT.error;
});
