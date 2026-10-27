// Spam filter verdicts already in the headers (Microsoft 365, SpamAssassin-style).
import { SPAM_MEANING } from '../headers.js';
import type { Ctx } from '../context.js';

export function filterChecks(c: Ctx): void {
  const { add, spam } = c;
  const sv: Record<string, string> = Object.fromEntries(spam.filter(s => s[1]).map(s => [s[1], s[2]]));
  if (sv.SCL !== undefined) add('filter', 'filter.scl', 'Spam confidence (SCL)', +sv.SCL >= 5 ? 'bad' : +sv.SCL === -1 ? 'info' : 'ok', `${sv.SCL}: ${SPAM_MEANING.SCL(sv.SCL)}`);
  if (sv.SFV) {
    const bypass = /^(SKN|SKA|SFE)$/.test(sv.SFV);
    add('filter', 'filter.sfv', 'Spam filter verdict (SFV)', /^(SPM|SKB|SKS|BLK)$/.test(sv.SFV) ? 'bad' : bypass ? 'warn' : 'ok', `${sv.SFV}: ${SPAM_MEANING.SFV(sv.SFV)}${bypass ? ' (filtering was bypassed)' : ''}`);
  }
  if (sv.CAT) add('filter', 'filter.cat', 'Protection category (CAT)', /^(PHSH|HPHSH|MALW|SPOOF|DIMP|UIMP|GIMP)$/.test(sv.CAT) ? 'bad' : /^(SPM|HSPM|BULK)$/.test(sv.CAT) ? 'warn' : 'ok', `${sv.CAT}: ${SPAM_MEANING.CAT(sv.CAT)}`);
  if (sv.BCL !== undefined) add('filter', 'filter.bcl', 'Bulk complaint level (BCL)', +sv.BCL >= 8 ? 'warn' : +sv.BCL >= 4 ? 'info' : 'ok', `${sv.BCL}: ${SPAM_MEANING.BCL(sv.BCL)}`);
  if (sv.PTR) add('filter', 'filter.ptr', 'Reverse DNS (Microsoft)', /nonexistent/i.test(sv.PTR) ? 'warn' : 'ok', SPAM_MEANING.PTR(sv.PTR));
  if (sv.CTRY) add('filter', 'filter.ctry', 'Sending country', 'info', sv.CTRY);
  if (sv.IPV) add('filter', 'filter.ipv', 'IP reputation (IPV)', sv.IPV === 'CAL' ? 'warn' : 'info', `${sv.IPV}: ${SPAM_MEANING.IPV(sv.IPV)}${sv.IPV === 'CAL' ? ' (filtering skipped for this IP)' : ''}`);
  const gen = spam.find(s => /x-spam-(status|flag)/i.test(s[0]));
  if (gen) add('filter', 'filter.generic', gen[0], /^yes/i.test(gen[2]) ? 'bad' : 'ok', gen[2].slice(0, 120));
  if (!spam.length) add('filter', 'filter.none', 'Spam filter headers', 'na', 'None found (the email may have been saved before filtering, or by a client that strips them)');
}
