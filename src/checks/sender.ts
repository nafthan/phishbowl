// Sender and authentication: SPF, DKIM, DMARC, alignment, spoofing, Reply-To, display-name tricks, lookalikes.
import { FREE_MAIL, INFRA } from '../lists.js';
import { addrOf, domOf, isKnown, labelOf, lookalike, orgOf, suffixMatch } from '../domains.js';
import { scriptTrick } from '../text.js';
import type { Ctx } from '../context.js';

export function senderChecks(c: Ctx): void {
  const { add, auth, internal, arcRescued, fromDom, fromAddr, fromName } = c;
  // Forwarding with SRS rewrites the envelope, so alignment and Return-Path mismatches follow from the forward itself.
  const aligned = c.aligned || !!c.srs;

  add('sender', 'sender.spf', 'SPF', internal && !auth.spf ? 'na' : auth.spf === 'pass' ? 'ok' : /fail/.test(auth.spf) && auth.spf !== 'softfail' ? 'bad' : auth.spf ? 'warn' : 'na',
    auth.spf ? `${auth.spf}${auth.mailfrom ? ' for ' + auth.mailfrom : ''}` : internal ? 'Not checked: sent inside your organisation' : 'No SPF result in the headers',
    { why: 'SPF checks the sending server is allowed to send for the bounce (envelope) domain.' });
  const spfAligned = auth.mailfrom && fromDom ? orgOf(auth.mailfrom) === orgOf(fromDom) : null;
  if (auth.spf === 'pass' && spfAligned !== null) add('sender', 'sender.spf-align', 'SPF alignment', spfAligned ? 'ok' : aligned ? 'info' : 'warn',
    spfAligned ? 'Bounce domain matches the From domain' : `Passed for ${auth.mailfrom}, not for the From domain ${fromDom}${aligned ? '. Normal when a mailing service sends for the domain and DKIM matches' : ''}`,
    { why: 'A pass only helps if it is for the domain the reader sees.' });

  const unsignedInternal = internal && auth.dkim !== 'pass' && auth.dkim !== 'fail';
  add('sender', 'sender.dkim', 'DKIM', unsignedInternal ? 'info' : auth.dkim === 'pass' ? 'ok' : auth.dkim === 'fail' ? (aligned ? 'warn' : 'bad') : auth.dkim ? 'warn' : 'na',
    unsignedInternal ? 'Not signed: normal for mail sent inside your organisation' : auth.dkim ? `${auth.dkim}${auth.dkimD ? ' signed by ' + auth.dkimD : ''}` : 'No DKIM result in the headers',
    { why: 'DKIM proves the message was signed by the domain in d= and not changed in transit.' });
  if (auth.dkim === 'pass' && c.dkimD && fromDom) {
    const al = orgOf(c.dkimD) === orgOf(fromDom);
    add('sender', 'sender.dkim-align', 'DKIM alignment', al ? 'ok' : aligned ? 'info' : 'warn', al ? 'Signed by the From domain' : `Signed by ${c.dkimD}, not by the From domain ${fromDom}`);
  }
  for (const s of auth.dkimSigs) {
    if (s.a && /sha1/i.test(s.a)) add('sender', 'sender.dkim-algo', 'DKIM algorithm', 'warn', `${s.a} is outdated and weak`);
    if (s.h && !s.h.split(':').includes('from')) add('sender', 'sender.dkim-from', 'DKIM covers From', 'bad', 'The signature does not cover the From header, so From could have been changed');
  }

  const uncheckedInternal = internal && auth.dmarc !== 'pass' && auth.dmarc !== 'fail';
  add('sender', 'sender.dmarc', 'DMARC',
    uncheckedInternal ? 'info' : auth.dmarc === 'pass' ? 'ok' : arcRescued || c.dsn || c.srs ? 'warn' : auth.dmarc === 'fail' ? 'bad' : auth.dmarc ? 'warn' : 'na',
    uncheckedInternal ? 'Not checked: sent inside your organisation'
      : c.dsn && auth.dmarc === 'fail' ? `fail for ${auth.hfrom || fromDom}: this is a bounce from a mail server, so DMARC says little about who wrote the returned message`
      : c.srs && auth.dmarc === 'fail' ? `fail for ${auth.hfrom || fromDom}, after a forwarder (${c.srs}) rewrote the envelope (SRS). Forwarding often breaks DMARC; check the forwarder is expected`
      : arcRescued ? `fail for ${auth.hfrom || fromDom}, but accepted because a forwarding server (mailing list or forwarder) vouched for the original result (ARC)`
        : auth.dmarc === 'none' ? `No DMARC record for ${auth.hfrom || fromDom}, so nothing stops others sending as this domain`
          : auth.dmarc ? `${auth.dmarc}${auth.hfrom ? ' for ' + auth.hfrom : ''}${auth.dmarcAction ? ' (action ' + auth.dmarcAction + ')' : ''}` : 'No DMARC result in the headers',
    { why: 'DMARC checks SPF or DKIM passed for the same domain shown in From.' });
  if (auth.dmarc === 'fail' && !arcRescued && !c.dsn && !c.srs && /none/.test(auth.dmarcAction)) add('sender', 'sender.dmarc-policy', 'DMARC enforcement', 'warn', 'The domain\'s DMARC policy is "none", so the failing message was still delivered');
  if (auth.compauth) add('sender', 'sender.compauth', 'Microsoft composite authentication', auth.compauth === 'pass' ? 'ok' : auth.compauth === 'fail' ? 'bad' : 'warn',
    `${auth.compauth}${auth.compReason ? ' (reason ' + auth.compReason + ')' : ''}`, { why: 'Microsoft\'s own overall verdict on whether the sender is who it claims to be.' });
  if (auth.arc) add('sender', 'sender.arc', 'ARC', 'info', `${auth.arc}: authentication results carried over from a forwarding server`);

  if (c.isOwn(fromDom)) add('sender', 'sender.spoof-own', 'Sent as your own domain', c.spoofed ? 'bad' : 'ok',
    c.spoofed ? `From shows ${fromDom} but it came from outside and DMARC ${auth.dmarc === 'none' ? 'is not set up' : 'failed'}: someone outside sent this as you`
      : internal ? 'Sent inside your organisation (Exchange marked it internal)' : 'From your own domain and authenticated');

  const { replyTo, rtAddr, rtDom, rtDiff, toList, rtFree } = c;
  add('sender', 'sender.replyto', 'Reply-To', !replyTo ? 'na' : !rtDiff ? 'ok' : toList ? 'info' : rtFree || (!aligned && !!lookalike(rtDom, c.targets)) ? 'bad' : 'warn',
    !replyTo ? 'Not set' : !rtDiff ? 'Same domain as the sender' : toList ? `Replies go to the mailing list ${rtAddr}`
      : rtFree ? `Replies go to a free ${orgOf(rtDom)} account (${rtAddr}), not to the sender's domain`
        : `Replies go to ${rtAddr}, a different domain from the sender${aligned ? '. Services that send for someone (e-signature, CRM, ticketing) do this, so check it is expected' : ''}`);
  add('sender', 'sender.returnpath', 'Return-Path', !c.rpDom ? 'na' : orgOf(c.rpDom) === orgOf(fromDom) ? 'ok' : aligned ? 'info' : 'warn',
    !c.rpDom ? 'Not set' : orgOf(c.rpDom) === orgOf(fromDom) ? 'Same domain as the sender'
      : `Bounces go to ${c.rpDom}${aligned ? ': a mailing service sending for an authenticated domain, which is normal' : '. Normal for mailing services, suspicious alongside other signs'}`);
  if (c.sender && orgOf(domOf(addrOf(c.sender))) !== orgOf(fromDom)) add('sender', 'sender.sender', 'Sender header', c.listId || aligned ? 'info' : 'warn',
    `Sent on behalf of ${fromDom} by ${addrOf(c.sender)}${c.listId ? ' (a mailing list)' : ''}`);

  const nameAddr = (fromName.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i) || [])[0];
  if (nameAddr && nameAddr.toLowerCase() !== fromAddr) {
    const same = labelOf(domOf(nameAddr.toLowerCase())) === labelOf(fromDom);
    add('sender', 'sender.name-addr', 'Display name trick', same ? 'warn' : 'bad', `The display name shows ${nameAddr} but the real address is ${fromAddr}${same ? ' (same organisation)' : ''}`);
  }
  if (fromName) add('sender', 'sender.display-brand', 'Display name', c.brandClaim ? 'bad' : 'info',
    c.brandClaim ? `Claims to be "${fromName}" but the address is on ${fromDom}` : `"${fromName}"${c.nameBrand && !c.brandClaim && !c.isOwn(fromDom) ? ` (names ${c.nameBrand}, sent through ${fromDom})` : ''}`);

  const seen = new Set<string>();
  for (const [label, d] of [['From', fromDom], ['Reply-To', rtDom], ['Return-Path', c.rpDom]] as const) {
    if (!d || seen.has(orgOf(d)) || isKnown(d, c.own) || suffixMatch(d, INFRA) || suffixMatch(d, FREE_MAIL)) continue;
    seen.add(orgOf(d));
    const why = lookalike(d, c.targets); if (why) add('sender', 'sender.lookalike', label + ' domain', 'bad', `${d} ${why}`);
  }

  const none = (v: string) => !v || v === 'none';
  if (c.dsn) add('sender', 'sender.bounce', 'Bounce', 'info', `A delivery failure report from ${c.fromAddr || 'a mail server'}. The returned message inside is the original; if it is mail you never sent, your address was probably spoofed (backscatter)`);
  if (!internal && auth.raw.trim().length > 3 && none(auth.spf) && none(auth.dkim) && none(auth.dmarc))
    add('sender', 'sender.noauth', 'Any authentication', c.dsn ? 'warn' : 'bad', `Nothing vouches for ${fromDom || 'the sender'}: no SPF, no DKIM signature and no DMARC record. Anyone could have sent this`);
  const subjTrick = scriptTrick(c.subj), trick = subjTrick || scriptTrick(fromName);
  if (trick) add('sender', 'sender.script', 'Lookalike letters', 'bad', `The ${subjTrick ? 'subject' : 'sender name'} ${trick}, a trick to get past keyword filters`);
  if (c.fwd) add('sender', 'sender.forwarded', 'Forwarded inline', 'warn',
    `This is a forward of a message from ${c.fwd.slice(0, 90)}. The headers describe whoever forwarded it, so their passing checks say nothing about the original. Ask for the original as an attachment (.eml)`);
  if (c.freeMail) add('sender', 'sender.freemail', 'Free email account',
    fromName && /\b(team|support|payroll|hr|it|service|admin|billing|accounts?|security|helpdesk|bank|ceo|director|finance|office)\b/i.test(fromName) ? 'warn' : 'info',
    `Sent from a free ${orgOf(fromDom)} address${fromName ? ' while calling itself "' + fromName + '"' : ''}`);
  if (c.midDom) add('sender', 'sender.msgid', 'Message-ID domain', orgOf(c.midDom) === orgOf(fromDom) ? 'ok' : 'info',
    orgOf(c.midDom) === orgOf(fromDom) ? 'Created by the sender\'s own mail system' : `Created by ${c.midDom}, not by ${fromDom} (common: mailing services and Microsoft 365 set their own)`);
  if (c.mailer) add('sender', 'sender.mailer', 'Sending software', /phpmailer|swiftmailer|sendblaster|massmail|atomic|gammadyne|the bat/i.test(c.mailer) ? 'warn' : 'info',
    c.mailer + (/phpmailer|swiftmailer/i.test(c.mailer) ? ': a script library often used by phishing kits' : ''));
  add('sender', 'sender.unsub', 'Unsubscribe header', c.unsub ? 'ok' : 'info', c.unsub ? 'Present: typical of legitimate newsletters and bulk senders' : 'Not present');
  if (/undisclosed|^\s*$/i.test(c.to) && !c.listId) add('sender', 'sender.to', 'Recipients', 'warn', c.to ? 'Sent to "undisclosed recipients": everyone was hidden in Bcc' : 'No To address');
}
