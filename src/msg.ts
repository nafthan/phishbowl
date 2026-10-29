// Outlook .msg → a standard email (RFC 5322 + MIME), so the engine can analyse it like any .eml. Pure TypeScript:
// works in Node and browsers.
//
// A .msg is a compound file (files/cfb.ts) of MAPI properties ([MS-OXMSG]): strings and binary values in streams named
// "__substg1.0_IIIITTTT" (property id, type), fixed-size values in "__properties_version1.0", recipients and attachments
// in sub-storages, and attached Outlook items as nested message storages.
//
// When Outlook received the email over the internet, the original headers are kept (PidTagTransportMessageHeaders)
// and used as they are: authentication, route and spam-filter checks then work normally. Drafts, sent items and some
// exports have no such headers; then From/To/Subject/Date are rebuilt from properties and the analysis says so.
// Bodies: plain text, HTML (PidTagHtml), or compressed RTF, which for HTML emails wraps the original HTML (see rtf.ts).
import { readCfb, type CfbEntry } from './files/cfb.js';
export { isOutlookMsg } from './files/sniff.js';
import { decompressRtf } from './lzfu.js';
import { rtfToHtml } from './rtf.js';
import { binaryString } from './mime.js';

// Property ids used here ([MS-OXPROPS]).
const P = {
  subject: 0x0037, clientSubmitTime: 0x0039, headers: 0x007d, senderName: 0x0c1a, senderEmail: 0x0c1f, recipType: 0x0c15,
  deliveryTime: 0x0e06, body: 0x1000, rtf: 0x1009, html: 0x1013, displayName: 0x3001, email: 0x3003, creationTime: 0x3007,
  attachData: 0x3701, shortName: 0x3704, attachMethod: 0x3705, longName: 0x3707, mimeTag: 0x370e, contentId: 0x3712, smtpAddress: 0x39fe,
  localeId: 0x3ff1, messageCodepage: 0x3ffd, internetCodepage: 0x3fde, senderSmtp: 0x5d01, sentRepresentingSmtp: 0x5d02,
};
const hex4 = (n: number) => n.toString(16).padStart(4, '0');

/** One message, recipient or attachment storage: its properties. */
class Props {
  private fixed = new Map<number, DataView>();
  constructor(private e: CfbEntry, headerSize: number, private ansi: TextDecoder) {
    const s = e.children.get('__properties_version1.0')?.read();
    if (s) { const v = new DataView(s.buffer, s.byteOffset, s.byteLength); for (let o = headerSize; o + 16 <= s.length; o += 16) this.fixed.set(v.getUint32(o, true), new DataView(s.buffer, s.byteOffset + o + 8, 8)); }
  }
  private stream(id: number, type: string) { return this.e.children.get(`__substg1.0_${hex4(id)}${type}`); }
  str(id: number): string | undefined {
    const w = this.stream(id, '001f')?.read();
    if (w) return new TextDecoder('utf-16le').decode(w).replace(/\0+$/, '');
    const a = this.stream(id, '001e')?.read();
    if (a) return this.ansi.decode(a).replace(/\0+$/, '');
    return undefined;
  }
  bin(id: number): Uint8Array | undefined { return this.stream(id, '0102')?.read(); }
  object(id: number): CfbEntry | undefined { const s = this.stream(id, '000d'); return s && s.type === 1 ? s : undefined; }
  int(id: number): number | undefined { const v = this.fixed.get((id << 16 | 0x0003) >>> 0); return v ? v.getUint32(0, true) : undefined; }
  time(id: number): Date | undefined {
    const v = this.fixed.get((id << 16 | 0x0040) >>> 0); if (!v) return undefined;
    const ft = v.getUint32(0, true) + v.getUint32(4, true) * 4294967296;
    const d = new Date(ft / 10000 - 11644473600000); return isNaN(d.getTime()) ? undefined : d;
  }
  /** Sub-storages with a prefix, in their numbered order. */
  subs(prefix: string): CfbEntry[] { return [...this.e.children.entries()].filter(([k, v]) => k.startsWith(prefix) && v.type === 1).sort(([a], [b]) => a.localeCompare(b)).map(([, v]) => v); }
}

/** The Windows code page Outlook used for non-Unicode text. Internet code pages (ISO-2022-JP, KOI8-R…) map to their
 * Windows equivalent; without one, the message's locale decides. */
export function ansiCodepage(message?: number, internet?: number, locale?: number): number | undefined {
  if (message) return message;
  const fromInternet: Record<number, number> = { 50220: 932, 50221: 932, 50222: 932, 51932: 932, 20932: 932, 932: 932, 936: 936, 54936: 936, 52936: 936, 949: 949, 51949: 949,
    950: 950, 20866: 1251, 21866: 1251, 28595: 1251, 1251: 1251, 28592: 1250, 1250: 1250, 28597: 1253, 1253: 1253, 28599: 1254, 1254: 1254, 28598: 1255, 1255: 1255,
    28596: 1256, 1256: 1256, 28594: 1257, 1257: 1257, 874: 874, 1258: 1258 };
  if (internet && fromInternet[internet]) return fromInternet[internet];
  const fromLocale: Record<number, number> = { 1041: 932, 2052: 936, 4100: 936, 1042: 949, 1028: 950, 3076: 950, 1049: 1251, 1058: 1251, 1029: 1250, 1045: 1250, 1038: 1250, 1032: 1253, 1055: 1254, 1037: 1255, 1025: 1256, 1054: 874 };
  return locale ? fromLocale[locale] : undefined;
}
function decoderFor(cp: number | undefined): TextDecoder {
  const label = !cp ? 'windows-1252' : ({ 932: 'shift_jis', 936: 'gbk', 949: 'euc-kr', 950: 'big5', 65001: 'utf-8', 20127: 'us-ascii', 28591: 'iso-8859-1', 1200: 'utf-16le', 874: 'windows-874' } as Record<number, string>)[cp]
    || (cp >= 1250 && cp <= 1258 ? 'windows-' + cp : 'windows-1252');
  try { return new TextDecoder(label); } catch { return new TextDecoder('windows-1252'); }
}

/** A header value with no way to break out of its line. */
const one = (s: string | undefined) => String(s || '').replace(/[\r\n]+/g, ' ').trim();
const quote = (s: string) => '"' + one(s).replace(/["\\]/g, '') + '"';
function b64(b: Uint8Array): string {
  let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s).replace(/.{76}/g, '$&\r\n');
}
const addr = (name: string | undefined, email: string | undefined) => { const e = one(email); const n = one(name); return e && e.includes('@') ? (n && n !== e ? `${quote(n)} <${e}>` : `<${e}>`) : n ? quote(n) : ''; };
const httpDate = (d?: Date) => d ? d.toUTCString().replace('GMT', '+0000') : '';

/** Internet headers as Outlook stored them, minus the MIME structure lines (the body is rebuilt) and any blank lines. */
function storedHeaders(h: string): string {
  const lines = h.replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ').split('\n').filter(l => l.trim() && /^[\x21-\x39\x3b-\x7e]+:/.test(l));
  return lines.filter(l => !/^(content-type|content-transfer-encoding|mime-version|content-disposition):/i.test(l)).join('\r\n');
}

export interface MsgConversion { eml: string; hadHeaders: boolean; bodyFrom: 'html' | 'rtf-html' | 'rtf' | 'text' | 'none' }

/** Convert .msg bytes. Attached Outlook items are converted too, up to 3 levels. Throws if this isn't a .msg. */
export function msgToEml(bytes: Uint8Array): MsgConversion {
  let root: CfbEntry;
  try { root = readCfb(bytes); } catch { throw new Error('Not an Outlook message (.msg)'); }
  if (![...root.children.keys()].some(k => k.startsWith('__substg1.0_') || k === '__properties_version1.0')) throw new Error('Not an Outlook message (.msg)');
  return convert(root, 0, 32);
}

function convert(storage: CfbEntry, depth: number, headerSize: number): MsgConversion {
  // Older, non-Unicode .msg files store text in the sender's code page (Shift-JIS, Cyrillic…).
  const probe = new Props(storage, headerSize, decoderFor(undefined));
  const d = new Props(storage, headerSize, decoderFor(ansiCodepage(probe.int(P.messageCodepage), probe.int(P.internetCodepage), probe.int(P.localeId))));
  const boundary = (n: string) => `=_pb_${n}_${depth}`;
  const rawHeaders = d.str(P.headers);
  const hadHeaders = !!(rawHeaders && /^\s*[\w-]+:/m.test(rawHeaders));
  const head: string[] = [];
  if (hadHeaders) head.push(storedHeaders(rawHeaders as string));
  else {
    const senderEmail = d.str(P.senderEmail), senderName = d.str(P.senderName);
    head.push(`From: ${addr(senderName, d.str(P.senderSmtp) || d.str(P.sentRepresentingSmtp) || (senderEmail && senderEmail.includes('@') ? senderEmail : '')) || quote(senderName || 'unknown sender')}`);
    const to = d.subs('__recip_version1.0_').map(r => new Props(r, 8, decoderFor(undefined)))
      .filter(r => { const t = r.int(P.recipType); return t === undefined || t === 1; }).map(r => addr(r.str(P.displayName), r.str(P.smtpAddress) || r.str(P.email))).filter(Boolean);
    if (to.length) head.push(`To: ${to.join(', ')}`);
    head.push(`Subject: ${one(d.str(P.subject))}`);
    const date = httpDate(d.time(P.deliveryTime) || d.time(P.clientSubmitTime) || d.time(P.creationTime)); if (date) head.push(`Date: ${date}`);
    head.push('X-Phishbowl-Source: Outlook .msg without internet headers');
  }
  head.push('MIME-Version: 1.0');

  // Bodies
  let html = d.str(P.html) || '', bodyFrom: MsgConversion['bodyFrom'] = html ? 'html' : 'none';
  const htmlBin = d.bin(P.html), internetCp = d.int(P.internetCodepage);
  if (!html && htmlBin && htmlBin.length) { html = decoderFor(internetCp || 65001).decode(htmlBin); bodyFrom = 'html'; }
  const text = d.str(P.body) || '';
  const compressed = d.bin(P.rtf);
  if (!html && compressed && compressed.length) {
    try {
      const r = rtfToHtml(binaryString(decompressRtf(compressed)));
      if (r.fromHtml || /<a\s/i.test(r.html) || !text) { html = r.html; bodyFrom = r.fromHtml ? 'rtf-html' : 'rtf'; }
    } catch { /* unreadable RTF: fall back to the plain-text body */ }
  }
  if (bodyFrom === 'none' && text) bodyFrom = 'text';

  const parts: string[] = [];
  const alt = [text && `Content-Type: text/plain; charset="utf-8"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${text}`,
    html && `Content-Type: text/html; charset="utf-8"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${html}`].filter(Boolean) as string[];
  if (alt.length > 1) parts.push(`Content-Type: multipart/alternative; boundary="${boundary('alt')}"\r\n\r\n` + alt.map(p => `--${boundary('alt')}\r\n${p}\r\n`).join('') + `--${boundary('alt')}--`);
  else if (alt.length) parts.push(alt[0]);

  // Attachments
  for (const s of d.subs('__attach_version1.0_')) {
    const a = new Props(s, 8, decoderFor(undefined));
    const inner = a.object(P.attachData);
    if (inner) {   // an attached Outlook item: convert it into an attached email
      if (depth >= 3) continue;
      const name = one(a.str(P.displayName) || new Props(inner, 24, decoderFor(undefined)).str(P.subject) || 'attached email').replace(/["\\/:*?<>|]/g, '').slice(0, 120);
      try { parts.push(`Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename="${name}.eml"\r\n\r\n${convert(inner, depth + 1, 24).eml}`); }
      catch { /* unreadable: leave it out */ }
      continue;
    }
    const data = a.bin(P.attachData); if (!data) continue;
    const name = one(a.str(P.longName) || a.str(P.shortName) || 'attachment').replace(/"/g, '');
    const type = one(a.str(P.mimeTag)) || 'application/octet-stream', cid = one(a.str(P.contentId));
    parts.push(`Content-Type: ${type}; name="${name}"\r\nContent-Disposition: ${cid ? 'inline' : 'attachment'}; filename="${name}"\r\n` +
      (cid ? `Content-ID: <${cid}>\r\n` : '') + `Content-Transfer-Encoding: base64\r\n\r\n${b64(data)}`);
  }

  let body: string;
  if (parts.length === 0) body = 'Content-Type: text/plain; charset="utf-8"\r\n\r\n';
  else if (parts.length === 1 && alt.length) body = parts[0];
  else body = `Content-Type: multipart/mixed; boundary="${boundary('mix')}"\r\n\r\n` + parts.map(p => `--${boundary('mix')}\r\n${p}\r\n`).join('') + `--${boundary('mix')}--\r\n`;
  // The header block ends at the first blank line, so the body's own first header lines join it.
  const [bodyHead, ...bodyRest] = body.split('\r\n\r\n');
  return { eml: head.join('\r\n') + '\r\n' + bodyHead + '\r\n\r\n' + bodyRest.join('\r\n\r\n'), hadHeaders, bodyFrom };
}
