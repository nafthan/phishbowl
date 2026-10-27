// Feedback: record when Phishbowl got an email wrong, on this machine, and learn from it.
//
//   feedback.jsonl  one line per email you marked: what Phishbowl said, what you said, which checks fired.
//   emails/         copies of the emails, only when you ask to keep them (to turn into test fixtures).
//
// Kept in ~/.local/share/phishbowl (XDG_DATA_HOME; %LOCALAPPDATA%\phishbowl on Windows; or PHISHBOWL_DATA_DIR).
// Nothing is sent anywhere. The summary shows which checks cause false alarms, which emails were missed, and
// which senders you keep marking as legitimate (allowlist candidates).
import { createHash } from 'node:crypto';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { orgOf } from '../domains.js';
import { allowMatch, type Allowlist } from '../allow.js';
import { FREE_MAIL } from '../lists.js';
import type { EmailAnalysis, VerdictName } from '../types.js';

export type Says = 'phish' | 'legit' | 'spam';
export const SAYS: Record<Says, string> = { phish: 'phishing or malicious', legit: 'legitimate', spam: 'unwanted but harmless (spam)' };

export interface FeedbackEntry {
  at: string;
  /** File name only, not the path. */
  file: string;
  sha256: string;
  subject: string;
  from: string;
  fromDomain: string;
  authenticated: boolean;
  verdict: VerdictName;
  score: number;
  /** Ids of the checks that were flagged (bad or warn). */
  flagged: string[];
  says: Says;
  note?: string;
  /** Copy of the email in emails/, if kept. */
  kept?: string;
  version: string;
}

export function dataDir(): string {
  return process.env.PHISHBOWL_DATA_DIR || (process.platform === 'win32' && process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, 'phishbowl')
    : join(process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'phishbowl'));
}

/** Was Phishbowl wrong? A false alarm is a flagged legitimate email; a miss is phishing it called clean. */
export function outcome(e: Pick<FeedbackEntry, 'verdict' | 'says'>): 'false-alarm' | 'miss' | 'agree' {
  if (e.says === 'legit' && e.verdict !== 'clean') return 'false-alarm';
  if (e.says === 'phish' && e.verdict === 'clean') return 'miss';
  return 'agree';
}

export function recordFeedback(a: EmailAnalysis, bytes: Uint8Array, o: { file: string; says: Says; note?: string; keep?: boolean; version: string; dir?: string }): FeedbackEntry {
  const dir = o.dir || dataDir(); mkdirSync(dir, { recursive: true, mode: 0o700 });
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const entry: FeedbackEntry = {
    at: new Date().toISOString(), file: o.file.split(/[\\/]/).pop() || o.file, sha256, subject: a.subj.slice(0, 200), from: a.fromAddr, fromDomain: a.fromDom,
    authenticated: a.authenticated, verdict: a.verdict.v, score: a.verdict.score, flagged: a.checks.filter(c => c.status === 'bad' || c.status === 'warn').map(c => c.id),
    says: o.says, ...(o.note ? { note: o.note.slice(0, 500) } : {}), version: o.version,
  };
  if (o.keep) {
    const ext = /\.msg$/i.test(o.file) ? '.msg' : '.eml', name = `${o.says}-${sha256.slice(0, 12)}${ext}`;
    mkdirSync(join(dir, 'emails'), { recursive: true, mode: 0o700 });
    writeFileSync(join(dir, 'emails', name), bytes, { mode: 0o600 });
    entry.kept = name;
  }
  appendFileSync(join(dir, 'feedback.jsonl'), JSON.stringify(entry) + '\n', { mode: 0o600 });
  return entry;
}

export function readFeedback(dir = dataDir()): FeedbackEntry[] {
  const p = join(dir, 'feedback.jsonl'); if (!existsSync(p)) return [];
  const all = readFileSync(p, 'utf8').split('\n').filter(Boolean).flatMap(l => { try { return [JSON.parse(l) as FeedbackEntry]; } catch { return []; } });
  // The latest word on each email wins.
  const last = new Map<string, FeedbackEntry>(); for (const e of all) last.set(e.sha256, e);
  return [...last.values()];
}

export interface FeedbackSummary {
  total: number;
  falseAlarms: FeedbackEntry[];
  misses: FeedbackEntry[];
  /** Checks that fired on false alarms, most often first. */
  noisyChecks: { id: string; count: number }[];
  /** Senders you marked legitimate more than once, authenticated, and not yet allowlisted. */
  allowSuggestions: { entry: string; kind: 'domain' | 'sender'; count: number }[];
}

export function summarise(entries: FeedbackEntry[], allow: Allowlist = {}): FeedbackSummary {
  const falseAlarms = entries.filter(e => outcome(e) === 'false-alarm'), misses = entries.filter(e => outcome(e) === 'miss');
  const noisy = new Map<string, number>(); for (const e of falseAlarms) for (const id of new Set(e.flagged)) noisy.set(id, (noisy.get(id) || 0) + 1);
  const legit = entries.filter(e => e.says === 'legit' && e.authenticated && e.from && !allowMatch(e.from, allow));
  const phishFrom = new Set(entries.filter(e => e.says === 'phish').map(e => orgOf(e.fromDomain)));
  const by = new Map<string, { kind: 'domain' | 'sender'; count: number }>();
  for (const e of legit) {
    const free = FREE_MAIL.some(d => e.fromDomain === d || e.fromDomain.endsWith('.' + d));
    const key = free ? e.from : orgOf(e.fromDomain);
    if (!free && phishFrom.has(key)) continue;   // you've also marked phishing from there: don't suggest it
    const x = by.get(key) || { kind: free ? 'sender' as const : 'domain' as const, count: 0 }; x.count++; by.set(key, x);
  }
  return {
    total: entries.length, falseAlarms, misses,
    noisyChecks: [...noisy].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count),
    allowSuggestions: [...by].filter(([, x]) => x.count >= 2).map(([entry, x]) => ({ entry, ...x })).sort((a, b) => b.count - a.count),
  };
}

/** Copy kept emails Phishbowl got wrong into a folder as test fixtures, with an expected.json saying what they should be. */
export function exportFixtures(outDir: string, dir = dataDir()): { written: string[]; skipped: number } {
  const entries = readFeedback(dir).filter(e => e.kept && outcome(e) !== 'agree');
  mkdirSync(outDir, { recursive: true });
  const expected: Record<string, { expect: string; note?: string; was: string }> = {}, written: string[] = [];
  let skipped = 0;
  for (const e of entries) {
    const src = join(dir, 'emails', e.kept!);
    if (!existsSync(src)) { skipped++; continue; }
    copyFileSync(src, join(outDir, e.kept!));
    expected[e.kept!] = { expect: e.says === 'legit' ? 'clean' : 'notclean', was: `${e.verdict} (score ${e.score})`, ...(e.note ? { note: e.note } : {}) };
    written.push(e.kept!);
  }
  writeFileSync(join(outDir, 'expected.json'), JSON.stringify({ emails: expected }, null, 2) + '\n');
  return { written, skipped };
}
