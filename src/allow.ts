// Allowlist: senders you trust, so their everyday mail stops raising false alarms.
//
// It only applies when the email is authenticated as really coming from that sender (DMARC pass, or internal mail),
// because spoofing a trusted sender is exactly what an attacker would do. And it only quiets warnings: red flags
// still count, since a trusted supplier's hacked mailbox (vendor email compromise) sends real phishing.
import { addrOf, domOf, orgOf, suffixMatch } from './domains.js';
import { defangAll } from './defang.js';
import { verdictOf } from './verdict.js';
import { FREE_MAIL, INFRA } from './lists.js';
import type { EmailAnalysis } from './types.js';

export interface Allowlist {
  /** Exact addresses, e.g. billing@supplier.com. */
  senders?: string[];
  /** Domains; subdomains match too (supplier.com covers mail.supplier.com). */
  domains?: string[];
}

const clean = (xs?: string[]) => (xs || []).map(x => String(x).trim().toLowerCase().replace(/^@/, '')).filter(Boolean);
/** Domains anyone can send from (Gmail, Outlook.com, SendGrid, Amazon SES…): allowing one would allow everyone on it. */
const shared = (d: string) => suffixMatch(d, [...FREE_MAIL, ...INFRA]);

/** Allowlist entries that are ignored, and why. */
export function allowProblems(allow: Allowlist): string[] {
  const out: string[] = [];
  for (const d of clean(allow.domains)) {
    if (d.includes('@')) out.push(`"${d}" is an address: put it under senders, not domains`);
    else if (!d.includes('.')) out.push(`"${d}" is not a domain`);
    else if (shared(d)) out.push(`"${d}" is shared by everyone who uses it, so it can't be allowlisted as a domain; list exact addresses under senders instead`);
  }
  for (const a of clean(allow.senders)) if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(a)) out.push(`"${a}" is not an email address`);
  return out;
}

/** Which allowlist entry matches this sender, if any. */
export function allowMatch(fromAddr: string, allow: Allowlist): string {
  const addr = addrOf(fromAddr), dom = domOf(addr);
  if (!addr || !dom) return '';
  const s = clean(allow.senders).find(x => x === addr);
  if (s) return s;
  return clean(allow.domains).find(d => d.includes('.') && !d.includes('@') && !shared(d) && (suffixMatch(dom, [d]) || orgOf(dom) === d)) || '';
}

/** Add the allowlist check and recompute the verdict. */
export function applyAllow(a: EmailAnalysis, allow: Allowlist): EmailAnalysis {
  a.checks = a.checks.filter(c => c.id !== 'sender.allowed' && c.id !== 'sender.allowed-unverified');
  const hit = allowMatch(a.fromAddr, allow);
  if (!hit) return a;
  if (a.authenticated && !a.spoofed) {
    a.checks.unshift({ group: 'sender', id: 'sender.allowed', name: 'Allowlist', status: 'ok',
      result: defangAll(`${a.fromAddr} is on your allowlist (${hit}) and authenticated, so warnings don't count toward the verdict. Red flags still do: a trusted sender's mailbox can be hacked`) });
  } else {
    a.checks.unshift({ group: 'sender', id: 'sender.allowed-unverified', name: 'Allowlist', status: 'warn',
      result: defangAll(`Claims to be ${a.fromAddr}, which is on your allowlist (${hit}), but isn't authenticated as coming from there, so the allowlist was not applied`),
      why: 'Attackers impersonate senders you trust. Only authenticated mail from them is let off.' });
  }
  a.verdict = verdictOf(a.checks);
  return a;
}
