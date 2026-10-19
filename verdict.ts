// Verdict: weighted the way a SOC analyst reads the checks.
import type { Check, Group, Verdict } from './types.js';

export const GROUPS: [Group, string][] = [['sender', 'Sender and authentication'], ['route', 'Delivery route'], ['filter', 'Spam filter verdicts'],
  ['content', 'Message content'], ['links', 'Links and QR codes'], ['att', 'Attachments'], ['online', 'Online lookups']];

/** Weight of a red flag. Unlisted red flags weigh 3; 5 or more is critical (Malicious on its own). Warnings weigh 1. */
export const WEIGHT: Record<string, number> = {
  'sender.spoof-own': 6, 'links.mismatch': 4, 'att.cred-form': 5, 'att.smuggling': 6, 'att.macros': 5, 'att.remote-template': 6, 'filter.cat': 4,
  'sender.lookalike': 4, 'links.lookalike': 4, 'att.double': 4, 'online.listed': 6, 'online.age': 3,
  'links.impersonation': 5, 'content.bec': 4, 'content.callback': 4, 'content.seed': 5, 'content.brand': 4, 'sender.script': 4,
};
export const DEFAULT_BAD_WEIGHT = 3;
export const CRITICAL = 5;
/** Wording alone (urgency, "password", "invoice") appears in plenty of real mail, so content warnings add at most this much. */
export const CONTENT_WARN_CAP = 2;
export const MALICIOUS_SCORE = 12;
export const SUSPICIOUS_SCORE = 5;

export const weightOf = (c: Check): number => c.status === 'bad' ? WEIGHT[c.id] || DEFAULT_BAD_WEIGHT : c.status === 'warn' ? 1 : 0;

export function verdictOf(checks: Check[]): Verdict {
  const bad = checks.filter(c => c.status === 'bad'), warn = checks.filter(c => c.status === 'warn'), ok = checks.filter(c => c.status === 'ok');
  let score = 0;
  for (const c of bad) score += WEIGHT[c.id] || DEFAULT_BAD_WEIGHT;
  const cw = warn.filter(c => c.group === 'content').length;
  score += warn.length - cw + Math.min(cw, CONTENT_WARN_CAP);
  const crit = bad.some(c => (WEIGHT[c.id] || 0) >= CRITICAL);
  const v = crit || score >= MALICIOUS_SCORE ? 'malicious' : score >= SUSPICIOUS_SCORE || bad.length ? 'suspicious' : 'clean';
  const conf = v === 'malicious' ? (score >= 20 ? 'high' : 'medium') : v === 'suspicious' ? 'medium' : ok.length >= 6 ? 'high' : 'medium';
  return { v, score, conf, bad: bad.length, warn: warn.length, ok: ok.length, run: checks.filter(c => c.status !== 'na').length };
}

/** The flagged checks, most important first. */
export const keyFindings = (checks: Check[], n = 7): Check[] => checks.filter(c => c.status === 'bad' || c.status === 'warn')
  .sort((a, b) => ((b.status === 'bad' ? 100 : 0) + weightOf(b)) - ((a.status === 'bad' ? 100 : 0) + weightOf(a))).slice(0, n);

export const VERDICT_LABEL: Record<string, string> = { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Likely legitimate' };
