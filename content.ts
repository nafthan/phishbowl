// Message content: pressure, credential and money language, BEC, callback scams, wallet lures, brand claims,
// hidden text, forms and scripts, tracking.
import { BRANDS } from '../lists.js';
import { brandOwns } from '../domains.js';
import { findBrand, uniq } from '../text.js';
import type { Ctx } from '../context.js';

const URGENCY = /\b(urgent(ly)?|immediately|within \d+ ?(hours?|hrs?|days?)|24 hours|48 hours|final (notice|warning|reminder)|action required|suspend(ed)?|deactivat\w*|expir(e|es|ed|ing)|last chance|as soon as possible|asap|today only)\b/gi;
const CREDS = /\b(sign[ -]?in|log[ -]?in|verify (your )?(account|identity|email|details)|confirm (your )?(details|account|identity|password|bank details)|password|re-?enter|update (your )?(account|details|information|payment)|mfa|2fa|one[- ]time (code|passcode)|security code)\b/gi;
const MONEY = /\b(bank details|account details|sort code|iban|swift|wire transfer|bank transfer|change of (bank|account)|invoice|payment|remittance|payroll|salary|refund|gift ?cards?|bitcoin|crypto|overdue|outstanding balance)\b/gi;
const BEC = /\b(gift ?cards?|itunes cards?|steam cards?|are you (at your desk|available|free|around)|quick (favou?r|task|request)|(change|update)[\w ]{0,20}(bank|payroll|direct deposit|account) details|new bank (details|account)|wire (transfer|the funds|payment) (today|urgently)|send (me )?the codes)\b/gi;
const THREAT = /\b(legal action|police|penalt(y|ies)|fine[sd]?|lawsuit|arrest|court)\b/gi;
const SEED = /\b(recovery phrase|seed phrase|secret (recovery )?phrase|(12|24)[- ]word (phrase|key)|private key|verify (your )?wallet|validate (your )?wallet|wallet (verification|validation|synchroni[sz]ation|sync)|(secure|unlock|restore) your wallet)\b/gi;
const GREETING = /^\s*(dear|hello|hi|attention)\s+(customer|user|employee|staff|member|client|valued \w+|sir|madam|sir\/madam|account holder|colleague|recipient|beneficiary)\b/im;
const ACCOUNTISH = /\b(account|wallet|security|suspend\w*|locked|unusual|verif\w+|subscription|renew\w*|refund|invoice|payment (declin|fail)\w*|password|sign[ -]?in|log[ -]?in|statement|delivery|parcel|package)\b/i;
const quoteList = (a: string[], n: number) => a.slice(0, n).map(x => `"${x}"`).join(', ');

export function contentChecks(c: Ctx): void {
  const { add, all, body, subj, trusted, docs } = c;
  const m = (re: RegExp) => uniq(all.match(re) || []);
  const urg = m(URGENCY), cred = m(CREDS), money = m(MONEY), threat = m(THREAT);
  add('content', 'content.urgency', 'Urgency or pressure', urg.length ? 'warn' : 'ok', urg.length ? 'Uses pressure: ' + quoteList(urg, 5) : 'No pressure language found', { hits: urg });
  add('content', 'content.creds', 'Asks for sign-in or details', cred.length ? 'warn' : 'ok', cred.length ? 'Mentions ' + quoteList(cred, 5) : 'Doesn\'t ask you to sign in or verify anything', { hits: cred });
  add('content', 'content.money', 'Money or bank details', money.length ? 'warn' : 'ok', money.length ? 'Mentions ' + quoteList(money, 5) : 'No payment or banking language', { hits: money });
  if (threat.length) add('content', 'content.threat', 'Threats', 'warn', 'Mentions ' + quoteList(threat, 4), { hits: threat });
  const greet = all.match(GREETING);
  add('content', 'content.greeting', 'Greeting', greet ? 'warn' : 'info', greet ? `Generic greeting "${greet[0].trim()}": the sender may not know who you are` : 'Not a generic greeting');

  const hidden = docs.flatMap(d => [...d.querySelectorAll('[style]')].filter(e =>
    /display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px)?\b|opacity\s*:\s*0(\.0+)?\b|max-height\s*:\s*0/i.test(e.getAttribute('style') || '') && (e.textContent || '').trim()));
  const preheader = hidden.length > 0 && trusted && hidden.every(e => (e.textContent || '').trim().length <= 200);
  const sample = hidden.length ? (hidden[0].textContent || '').trim().slice(0, 60) : '';
  add('content', 'content.hidden', 'Hidden text', !hidden.length ? 'ok' : preheader ? 'info' : 'warn', !hidden.length ? 'No hidden text'
    : preheader ? `Hidden preview text (preheader), normal in newsletters: "${sample}"`
      : `${hidden.length} hidden block${hidden.length > 1 ? 's' : ''} of text (used to fool spam filters): "${sample}"`);
  const forms = docs.reduce((n, d) => n + d.querySelectorAll('form').length, 0);
  if (forms) add('content', 'content.forms', 'Forms in the email', 'bad', `${forms} form${forms > 1 ? 's' : ''} inside the email body`);
  const scripts = docs.reduce((n, d) => n + d.querySelectorAll('script').length, 0);
  if (scripts) add('content', 'content.scripts', 'Scripts in the email', 'bad', `${scripts} script block${scripts > 1 ? 's' : ''} in the email body`);
  const { remote, pixels } = images(c);
  add('content', 'content.pixel', 'Tracking pixel', pixels.length ? (trusted ? 'info' : 'warn') : 'ok',
    pixels.length ? `${pixels.length} hidden 1×1 image${pixels.length > 1 ? 's tell' : ' tells'} the sender when the email is opened` : 'None found');
  if (remote.length - pixels.length > 0) add('content', 'content.remote', 'Remote images', 'info', `${remote.length - pixels.length} image${remote.length - pixels.length > 1 ? 's' : ''} load from the internet`);

  // Business email compromise: no link or file, just a request. Strong only with a sender that isn't who it seems.
  const bec = m(BEC), outsideReply = c.rtDiff && !c.toList;
  if (bec.length) add('content', 'content.bec', 'Payment or gift-card request', c.freeMail || outsideReply || !trusted ? 'bad' : 'warn',
    `Asks for ${quoteList(bec, 3)}${c.freeMail ? ' from a free email account' : outsideReply ? ' with replies going elsewhere' : ''}: the usual pattern of CEO or supplier fraud`, { hits: bec });
  // Callback phishing: a fake charge and a phone number to "cancel" it, so there is nothing for a link scanner to find.
  const phone = (all.match(/(?:call|phone|ring|contact)[^.\n]{0,40}?(\+?\d[\d\s().-]{8,}\d)/i) || [])[1];
  if (phone && (money.length || /renew|subscription|charged|debited|cancel|refund|order/i.test(all))) add('content', 'content.callback', 'Call this number', c.freeMail || c.brandClaim || !trusted ? 'bad' : 'warn',
    `Tells you to phone ${phone.trim()} about a charge or renewal: callback phishing gets you to call a fake helpdesk`);
  // Crypto-wallet lures: no genuine service ever asks for a recovery phrase.
  const seed = m(SEED);
  if (seed.length) add('content', 'content.seed', 'Wallet recovery phrase', 'bad', `Asks about ${quoteList(seed, 3)}: no real wallet or exchange ever asks for this, it is how crypto accounts are emptied`, { hits: seed });
  // A brand in the subject or opening lines, talking about the reader's account, from something the brand doesn't own.
  const opening = subj + ' ' + (c.fwd || '') + ' ' + body.replace(/\s+/g, ' ').slice(0, 400);
  const textBrand = trusted && (c.unsub || c.listId) ? '' : findBrand(opening, BRANDS);   // authenticated newsletters mention brands all the time
  if (textBrand && textBrand !== c.nameBrand && ACCOUNTISH.test(opening) && !c.sendOrgs.some(d => brandOwns(textBrand, d)) && !c.isOwn(c.fromDom))
    add('content', 'content.brand', 'Brand it talks about', 'bad', `Writes about "${textBrand}" accounts but nothing in the sending chain belongs to ${textBrand} (sent by ${c.fromDom || 'an unknown domain'})`);
  const visible = body.replace(/\s+/g, ' ').trim();
  if (visible.length < 40 && (c.parts.attachments.some(a => !/^image\//.test(a.declared || '') && !a.inline) || /<a\s/i.test(c.parts.html.join(''))))
    add('content', 'content.empty', 'Empty message', 'warn', 'Almost no text, just a link or an attachment: common in phishing, rare in real mail');
  if (c.parts.html.length && !c.parts.text.length) add('content', 'content.textpart', 'Plain-text version', 'info', 'HTML only, no plain-text version (common in phishing kits, but also in some legitimate mail)');
}

export interface Img { src: string; w: string | null; h: string | null }
export function images(c: Ctx): { remote: Img[]; pixels: Img[] } {
  const imgs: Img[] = c.docs.flatMap(d => [...d.querySelectorAll('img[src]')].map(i => ({ src: (i.getAttribute('src') || '').trim(), w: i.getAttribute('width'), h: i.getAttribute('height') })));
  const remote = imgs.filter(i => /^https?:/i.test(i.src));
  return { remote, pixels: remote.filter(i => i.w !== null && +i.w <= 2 && +(i.h || 0) <= 2) };
}
