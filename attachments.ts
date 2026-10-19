// Attachments: one check per trick, rolled up from every file's notes.
import type { Ctx } from '../context.js';
import type { Status } from '../types.js';

const ATT_CHECKS: [string, string][] = [['att.risky', 'Risky file type'], ['att.double', 'Double extension'], ['att.mismatch', 'Real type matches name'], ['att.cred-form', 'Password forms'],
  ['att.smuggling', 'HTML smuggling'], ['att.macros', 'Macros'], ['att.remote-template', 'Remote templates'], ['att.zip-encrypted', 'Password-protected archives'],
  ['att.zip-risky', 'Risky files in archives'], ['att.pdf-active', 'PDF actions'], ['att.svg-script', 'Script in images'], ['att.entropy', 'Encrypted or packed content']];
const EXTRA: Record<string, string> = { 'att.form': 'Forms', 'att.script': 'Scripts', 'att.refresh': 'Auto-redirects', 'att.ics': 'Calendar invites' };

export function attachmentChecks(c: Ctx): void {
  const { add, atts, real } = c;
  // Archives and invites from an authenticated sender are context, not a warning.
  if (c.trusted) for (const a of atts) for (const n of a.notes) if ((n[2] === 'att.risky' && n[0] === 'warn') || n[2] === 'att.ics') n[0] = 'info';
  add('att', 'att.count', 'Attachments', real.length ? 'info' : 'ok', real.length ? `${real.length} file${real.length > 1 ? 's' : ''}: ${real.map(a => a.name).join(', ')}` : 'No attachments');
  for (const [id, name] of ATT_CHECKS) {
    const hits = atts.flatMap(a => a.notes.filter(n => n[2] === id).map(n => ({ a, n })));
    const status: Status = hits.some(h => h.n[0] === 'bad') ? 'bad' : hits.some(h => h.n[0] === 'warn') ? 'warn' : hits.length ? 'info' : real.length ? 'ok' : 'na';
    add('att', id, name, status, hits.length ? hits.map(h => `${h.a.name}: ${h.n[1]}`).join('; ') : real.length ? 'None' : 'No attachments');
  }
  for (const [id, name] of Object.entries(EXTRA)) {
    const ns = atts.flatMap(a => a.notes.filter(n => n[2] === id).map(n => ({ a, n })));
    if (ns.length) add('att', id, name, ns.some(x => x.n[0] === 'warn') ? 'warn' : 'info', ns.map(x => `${x.a.name}: ${x.n[1]}`).join('; '));
  }
}
