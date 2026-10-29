// Verdict: weighted the way a SOC analyst reads the checks.
import type { Check, Group, Verdict } from './types.js';

export const GROUPS: [Group, string][] = [['sender', 'Sender and authentication'], ['route', 'Delivery route'], ['filter', 'Spam filter verdicts'],
  ['content', 'Message content'], ['links', 'Links and QR codes'], ['att', 'Attachments'], ['online', 'Online lookups']];

/** Weight of a red flag. Unlisted red flags weigh 3; 5 or more is critical (Malicious on its own). Warnings weigh 1. */
export const WEIGHT: Record<string, number> = {
  'sender.spoof-own': 6, 'links.mismatch': 4, 'att.cred-form': 5, 'att.smuggling': 6, 'att.macros': 5, 'att.remote-template': 6, 'filter.cat': 4,
  'sender.lookalike': 4, 'links.lookalike': 4, 'att.double': 4, 'online.listed': 6, 'online.age': 3,
  'links.impersonation': 5, 'content.bec': 4, 'content.callback': 4, 'content.seed': 5, 'content.brand': 4, 'sender.script': 4,
  'att.nested': 5,
};
export const DEFAULT_BAD_WEIGHT = 3;
export const CRITICAL = 5;
/** Wording alone (urgency, "password", "invoice") appears in plenty of real mail, so content warnings add at most this much. */
export const CONTENT_WARN_CAP = 2;
/** Warnings that are weak on their own and common in legitimate mail. Each group adds at most its cap. */
export const WARN_CAPS: { name: string; cap: number; match: (c: Check) => boolean }[] = [
  { name: 'wording', cap: CONTENT_WARN_CAP, match: c => c.group === 'content' && !HYGIENE.has(c.id) },
  { name: 'delivery route', cap: 1, match: c => c.group === 'route' },
  { name: 'hygiene', cap: 1, match: c => HYGIENE.has(c.id) },
];
const HYGIENE = new Set(['links.http', 'content.pixel', 'links.recipient']);
export const MALICIOUS_SCORE = 12;
/** Six, not five: up to four points can come from capped background warnings (route, wording, link hygiene), which
 * pile up on legitimate bulk mail. Tested on 4,150 real legitimate emails and 660 real phishing emails (scripts/real-samples.ts). */
export const SUSPICIOUS_SCORE = 6;

/** Warnings shown for context that never add to the score: they say a check couldn't run (no delivery headers, no QR
 * reader installed), not that the email is bad. They lower the confidence. */
export const UNSCORED = new Set(['route.noheaders', 'links.qr-unchecked']);
export const weightOf = (c: Check): number => c.status === 'bad' ? WEIGHT[c.id] || DEFAULT_BAD_WEIGHT : c.status === 'warn' && !UNSCORED.has(c.id) ? 1 : 0;

export function verdictOf(checks: Check[]): Verdict {
  // An authenticated sender on your allowlist: warnings are shown but don't count (see allow.ts).
  const allowed = checks.some(c => c.id === 'sender.allowed' && c.status === 'ok');
  const bad = checks.filter(c => c.status === 'bad'), warn = allowed ? [] : checks.filter(c => c.status === 'warn' && !UNSCORED.has(c.id)), ok = checks.filter(c => c.status === 'ok');
  let score = 0;
  for (const c of bad) score += WEIGHT[c.id] || DEFAULT_BAD_WEIGHT;
  let capped = 0;
  for (const g of WARN_CAPS) { const n = warn.filter(c => !WARN_CAPS.slice(0, WARN_CAPS.indexOf(g)).some(x => x.match(c)) && g.match(c)).length; capped += n; score += Math.min(n, g.cap); }
  score += warn.length - capped;
  const crit = bad.some(c => (WEIGHT[c.id] || 0) >= CRITICAL);
  const v = crit || score >= MALICIOUS_SCORE ? 'malicious' : score >= SUSPICIOUS_SCORE || bad.length ? 'suspicious' : 'clean';
  const conf = v === 'malicious' ? (score >= 20 ? 'high' : 'medium') : v === 'suspicious' ? 'medium' : ok.length >= 6 && !checks.some(c => UNSCORED.has(c.id) && c.status === 'warn') ? 'high' : 'medium';
  return { v, score, conf, bad: bad.length, warn: checks.filter(c => c.status === 'warn').length, ok: ok.length, run: checks.filter(c => c.status !== 'na').length };
}

/** The flagged checks, most important first. */
export const keyFindings = (checks: Check[], n = 7): Check[] => checks.filter(c => c.status === 'bad' || c.status === 'warn')
  .sort((a, b) => ((b.status === 'bad' ? 100 : 0) + weightOf(b)) - ((a.status === 'bad' ? 100 : 0) + weightOf(a))).slice(0, n);

export const VERDICT_LABEL: Record<string, string> = { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Likely legitimate' };
