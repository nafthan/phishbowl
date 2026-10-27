// Emails inside emails.
//
// Two very different situations look alike on the wire:
// - a user's report: someone forwards a suspicious email "as attachment" (Outlook's Report button, a reporting
//   mailbox). The wrapper is just an envelope; the attached original, with its own headers, is what to analyse.
// - an attack: an outside email attaches an email, because many filters never open nested messages.
// reportSignals() tells them apart; analyse() then either swaps to the original or folds the attached email's verdict in.
import { binaryString, decodeWords, H, splitHeaders } from './mime.js';
import { addrOf, isOwnFactory } from './domains.js';
import type { Attachment, EmailAnalysis } from './types.js';

/** How deep nested emails are followed. Real reports are one level; three allows a report of a forwarded report. */
export const MAX_DEPTH = 3;
/** Attached emails analysed per message, so a message with hundreds of attached emails can't stall the tool. */
export const MAX_NESTED = 5;

/** Attachments that are themselves emails, judged by content (and declared type), not by name alone. */
export const attachedEmails = (a: EmailAnalysis): Attachment[] => a.atts.filter(x => x.fam === 'eml' || x.fam === 'msg' || (x.declared === 'message/rfc822' && x.bytes.length > 0));

/** Subject and sender of an attached email, without a full analysis. */
export function peek(bytes: Uint8Array): { subject: string; from: string } {
  const { headers } = splitHeaders(binaryString(bytes.subarray(0, 256 * 1024)));
  return { subject: decodeWords(H(headers, 'subject'), true).trim(), from: decodeWords(H(headers, 'from'), true).trim() };
}

const REPORT_SUBJECT = /^\s*(\[[^\]]*\]\s*)?((fw|fwd|tr|wg|rv|enc|vs|doorst)\s*:|(phish(ing)?|spam|junk|not junk|suspicious|report(ed)?|possible phish\w*)\b)|\b(phish(ing)?|suspicious|report(ed)?)\b/i;
const normalise = (s: string) => s.toLowerCase().replace(/^((\s*(re|fw|fwd|tr|wg|rv|enc|aw|sv|vs)\s*:)|\s*\[[^\]]*\])+/i, '').replace(/\s+/g, ' ').trim();

/**
 * Is `outer` a user's report of the attached email, rather than an email that uses an attached email to attack?
 * Needs exactly one attached email, at least one sign that this is a report, and an envelope that isn't itself
 * malicious (an attacker can put "Fwd:" in a subject; they can't make the envelope look clean and still attack with it).
 */
export function reportSignals(outer: EmailAnalysis, emails: Attachment[], own: string[]): string[] {
  if (emails.length !== 1) return [];
  const inner = peek(emails[0].bytes), isOwn = isOwnFactory(own), signs: string[] = [];
  if (REPORT_SUBJECT.test(outer.subj)) signs.push('the subject says it is a forward or a report');
  const o = normalise(outer.subj), i = normalise(inner.subject);
  if (i.length >= 4 && o.includes(i)) signs.push('the subject repeats the attached email\'s subject');
  if (isOwn(outer.fromDom) && !outer.spoofed) signs.push('it was sent from your own domain');
  if (outer.verdict.v === 'malicious' && !(isOwn(outer.fromDom) && !outer.spoofed)) return [];
  return signs;
}

export const reporterOf = (outer: EmailAnalysis, name: string, signs: string[]) => ({
  from: outer.from, to: outer.to, subject: outer.subj, date: outer.date,
  note: `Reported by ${addrOf(outer.from) || outer.from || 'an unknown sender'}${outer.date ? ' on ' + outer.date : ''}: ${signs.join(', ')}. ` +
    `This analysis is of the attached original (${name}), with its own headers.`,
});

