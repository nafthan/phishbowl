// Delivery route: hops, the server it entered from, reverse DNS, TLS, timestamps.
import { orgOf } from '../domains.js';
import type { Ctx } from '../context.js';

export function routeChecks(c: Ctx): void {
  const { add, hops, entry } = c;
  add('route', 'route.hops', 'Servers it passed through', 'info', `${hops.length} hop${hops.length === 1 ? '' : 's'}${entry ? ', entered at ' + (entry.from || entry.ip) : ''}`);
  if (entry) {
    add('route', 'route.origin', 'Sending server', 'info', `${entry.from || '(no name)'} [${entry.ip}]`);
    if (!entry.rdns || /^unknown$/i.test(entry.rdns)) add('route', 'route.ptr', 'Reverse DNS', 'warn', `The sending IP ${entry.ip} has no reverse DNS name`);
    else if (entry.from && orgOf(entry.rdns) !== orgOf(entry.from)) add('route', 'route.helo', 'Server name check', 'warn', `Called itself ${entry.from} but its IP resolves to ${entry.rdns}`);
    else add('route', 'route.ptr', 'Reverse DNS', 'ok', entry.rdns);
    add('route', 'route.tls', 'Encryption on arrival', entry.tls ? 'ok' : 'warn', entry.tls ? 'Delivered over TLS' : 'Delivered without TLS');
  } else add('route', 'route.origin', 'Sending server', 'na', 'No outside server found in Received headers');
  // No Received, authentication or spam-filter headers at all: a sent item, a draft, or a copy exported without its
  // delivery headers. Most sender checks can't run, so a clean result means little.
  if (!hops.length && !c.auth.raw.replace(/[\s;]+/g, '') && !c.spam.length)
    add('route', 'route.noheaders', 'Delivery headers', 'warn', 'None: no Received, authentication or spam-filter headers, so who really sent it can\'t be checked. ' +
      'This is usually a sent item, a draft, or an export that dropped them. Save the email from the recipient\'s inbox (Outlook: … › Download; Gmail: Show original › Download)');

  const timed = hops.filter(h => h.time !== null) as (typeof hops[number] & { time: number })[];
  let back = 0; for (let i = 1; i < timed.length; i++) if (timed[i].time < timed[i - 1].time - 120000) back++;
  if (timed.length > 1) add('route', 'route.order', 'Timestamps in order', back ? 'warn' : 'ok',
    back ? `${back} hop${back > 1 ? 's' : ''} went back in time: headers may be forged or clocks are wrong` : 'Each server received it after the one before');
  if (timed.length > 1) {
    const total = (timed[timed.length - 1].time - timed[0].time) / 1000;
    add('route', 'route.delay', 'Delivery time', total > 3600 ? 'warn' : 'info', total < 60 ? `${Math.round(total)} seconds` : total < 3600 ? `${Math.round(total / 60)} minutes`
      : `${(total / 3600).toFixed(1)} hours (long delays can mean the message was queued or replayed)`);
  }
  const dt = Date.parse(c.date), first = timed[0] && timed[0].time;
  if (!isNaN(dt) && first) {
    const skew = (first - dt) / 60000;
    add('route', 'route.date', 'Date header', skew < -5 || skew > 60 ? 'warn' : 'ok',
      skew < -5 ? 'Dated in the future compared with when it was received' : skew > 60 ? `Dated ${Math.round(skew)} minutes before it was first received` : 'Matches when it was sent');
  }
}
