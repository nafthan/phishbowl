// Outlook .msg → a standard email (RFC 5322 + MIME), so the engine can analyse it like any .eml.
//
// A .msg is a compound file of MAPI properties. When Outlook received the email over the internet, the original
// headers are kept (PidTagTransportMessageHeaders) and used as they are: authentication, route and spam-filter
// checks then work normally. Drafts, sent items and some exports have no such headers; then From/To/Subject/Date
// are rebuilt from properties and the analysis says the headers were missing.
//
// Bodies: plain text, HTML (PidTagHtml), or compressed RTF, which for HTML emails wraps the original HTML (see rtf.ts).
// Attachments are carried over as files; attached Outlook items become attached emails (message/rfc822).
import MsgReaderModule from '@kenjiuno/msgreader';
import * as rtfModule from '@kenjiuno/decompressrtf';
import { rtfToHtml } from '../rtf.js';
import { binaryString } from '../mime.js';
export { isOutlookMsg } from '../files/sniff.js';

type Fields = {
  dataType?: string; subject?: string; senderName?: string; senderEmail?: string; senderSmtpAddress?: string; sentRepresentingSmtpAddress?: string;
  headers?: string; body?: string; bodyHtml?: string; html?: Uint8Array; compressedRtf?: Uint8Array; internetCodepage?: number;
  messageCodepage?: number; messageLocaleId?: number; messageDeliveryTime?: string; clientSubmitTime?: string; creationTime?: string;
  recipients?: { name?: string; email?: string; smtpAddress?: string; recipType?: string }[];
  attachments?: (Fields & { fileName?: string; fileNameShort?: string; attachMimeTag?: string; pidContentId?: string; innerMsgContent?: true; attachmentHidden?: boolean })[];
};
interface Reader { getFileData(): Fields; getAttachment(a: Fields): { fileName: string; content: Uint8Array }; parserConfig?: { ansiEncoding?: string } }
const MsgReader = ((MsgReaderModule as unknown as { default?: unknown }).default ?? MsgReaderModule) as unknown as new (b: Uint8Array) => Reader;
const decompressRTF = ((rtfModule as unknown as { decompressRTF?: unknown; default?: { decompressRTF?: unknown } }).decompressRTF
  ?? (rtfModule as unknown as { default: { decompressRTF: unknown } }).default.decompressRTF) as (input: number[]) => number[];

/** A header value with no way to break out of its line. */
const one = (s: string | undefined) => String(s || '').replace(/[\r\n]+/g, ' ').trim();
const quote = (s: string) => '"' + one(s).replace(/["\\]/g, '') + '"';
const b64 = (b: Uint8Array) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('base64').replace(/.{76}/g, '$&\r\n');
const addr = (name: string | undefined, email: string | undefined) => { const e = one(email); const n = one(name); return e && e.includes('@') ? (n && n !== e ? `${quote(n)} <${e}>` : `<${e}>`) : n ? quote(n) : ''; };
const httpDate = (s?: string) => { const t = s ? Date.parse(s) : NaN; return isNaN(t) ? '' : new Date(t).toUTCString().replace('GMT', '+0000'); };

/** Internet headers as Outlook stored them, minus the MIME structure lines (the body is rebuilt) and any blank lines. */
function storedHeaders(h: string): string {
  const lines = h.replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ').split('\n').filter(l => l.trim() && /^[\x21-\x39\x3b-\x7e]+:/.test(l));
  return lines.filter(l => !/^(content-type|content-transfer-encoding|mime-version|content-disposition):/i.test(l)).join('\r\n');
}

/** The Windows code page Outlook used for non-Unicode text. Internet code pages (ISO-2022-JP, KOI8-R…) map to their
 * Windows equivalent; without one, the message's locale decides. */
function ansiCodepage(message?: number, internet?: number, locale?: number): number | undefined {
  if (message) return message;
  const fromInternet: Record<number, number> = { 50220: 932, 50221: 932, 50222: 932, 51932: 932, 20932: 932, 932: 932, 936: 936, 54936: 936, 52936: 936, 949: 949, 51949: 949,
    950: 950, 20866: 1251, 21866: 1251, 28595: 1251, 1251: 1251, 28592: 1250, 1250: 1250, 28597: 1253, 1253: 1253, 28599: 1254, 1254: 1254, 28598: 1255, 1255: 1255,
    28596: 1256, 1256: 1256, 28594: 1257, 1257: 1257, 874: 874, 1258: 1258 };
  if (internet && fromInternet[internet]) return fromInternet[internet];
  const fromLocale: Record<number, number> = { 1041: 932, 2052: 936, 4100: 936, 1042: 949, 1028: 950, 3076: 950, 1049: 1251, 1058: 1251, 1029: 1250, 1045: 1250, 1038: 1250, 1032: 1253, 1055: 1254, 1037: 1255, 1025: 1256, 1054: 874 };
  return locale ? fromLocale[locale] : undefined;
}

export interface MsgConversion { eml: string; hadHeaders: boolean; bodyFrom: 'html' | 'rtf-html' | 'rtf' | 'text' | 'none' }

/** Convert .msg bytes. Attached Outlook items are converted too, up to `depth` levels. Throws if this isn't a .msg. */
export function msgToEml(bytes: Uint8Array, depth = 0): MsgConversion {
  let reader = new MsgReader(bytes), d = reader.getFileData();
  // Older, non-Unicode .msg files store text in the sender's code page (Shift-JIS, Cyrillic…): read them again with it.
  const cp = ansiCodepage(d.messageCodepage, d.internetCodepage, d.messageLocaleId);
  if (cp && ![1252, 20127, 28591, 65001, 1200].includes(cp)) {
    try { const again = new MsgReader(bytes); again.parserConfig = { ansiEncoding: String(cp) }; const d2 = again.getFileData(); if (d2.dataType === 'msg') { reader = again; d = d2; } } catch { /* keep the first reading */ }
  }
  if (d.dataType !== 'msg') throw new Error('Not an Outlook message (.msg)');
  const boundary = (n: string) => `=_pb_${n}_${depth}`;
  const hadHeaders = !!(d.headers && /^\s*[\w-]+:/m.test(d.headers));
  const head: string[] = [];
  if (hadHeaders) head.push(storedHeaders(d.headers as string));
  else {
    head.push(`From: ${addr(d.senderName, d.senderSmtpAddress || d.sentRepresentingSmtpAddress || (d.senderEmail && d.senderEmail.includes('@') ? d.senderEmail : '')) || quote(d.senderName || 'unknown sender')}`);
    const to = (d.recipients || []).filter(r => !r.recipType || r.recipType === 'to').map(r => addr(r.name, r.smtpAddress || r.email)).filter(Boolean);
    if (to.length) head.push(`To: ${to.join(', ')}`);
    head.push(`Subject: ${one(d.subject)}`);
    const date = httpDate(d.messageDeliveryTime || d.clientSubmitTime || d.creationTime); if (date) head.push(`Date: ${date}`);
    head.push('X-Phishbowl-Source: Outlook .msg without internet headers');
  }
  head.push('MIME-Version: 1.0');

  // Bodies
  let html = d.bodyHtml || '', bodyFrom: MsgConversion['bodyFrom'] = html ? 'html' : 'none';
  if (!html && d.html && d.html.length) { html = new TextDecoder(d.internetCodepage === 65001 || !d.internetCodepage ? 'utf-8' : 'windows-1252').decode(d.html); bodyFrom = 'html'; }
  if (!html && d.compressedRtf && d.compressedRtf.length) {
    try {
      const rtf = binaryString(Uint8Array.from(decompressRTF(Array.from(d.compressedRtf))));
      const r = rtfToHtml(rtf);
      if (r.fromHtml || /<a\s/i.test(r.html) || !d.body) { html = r.html; bodyFrom = r.fromHtml ? 'rtf-html' : 'rtf'; }
    } catch { /* unreadable RTF: fall back to the plain-text body */ }
  }
  const text = d.body || '';
  if (bodyFrom === 'none' && text) bodyFrom = 'text';

  const parts: string[] = [];
  const alt = [text && `Content-Type: text/plain; charset="utf-8"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${text}`,
    html && `Content-Type: text/html; charset="utf-8"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n${html}`].filter(Boolean) as string[];
  if (alt.length > 1) parts.push(`Content-Type: multipart/alternative; boundary="${boundary('alt')}"\r\n\r\n` + alt.map(p => `--${boundary('alt')}\r\n${p}\r\n`).join('') + `--${boundary('alt')}--`);
  else if (alt.length) parts.push(alt[0]);

  // Attachments
  for (const a of d.attachments || []) {
    let file: { fileName: string; content: Uint8Array };
    try { file = reader.getAttachment(a); } catch { continue; }
    const name = one(file.fileName || a.fileName || a.fileNameShort || 'attachment').replace(/"/g, '');
    if (a.innerMsgContent) {   // an attached Outlook item: convert it into an attached email
      if (depth >= 3 || !file.content) continue;
      try {
        const inner = msgToEml(file.content, depth + 1);
        parts.push(`Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename="${name.replace(/\.msg$/i, '')}.eml"\r\n\r\n${inner.eml}`);
      } catch { parts.push(`Content-Type: application/vnd.ms-outlook; name="${name}"\r\nContent-Disposition: attachment; filename="${name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(file.content)}`); }
      continue;
    }
    if (!file.content) continue;
    const type = one(a.attachMimeTag) || 'application/octet-stream', cid = one(a.pidContentId);
    parts.push(`Content-Type: ${type}; name="${name}"\r\nContent-Disposition: ${cid ? 'inline' : 'attachment'}; filename="${name}"\r\n` +
      (cid ? `Content-ID: <${cid}>\r\n` : '') + `Content-Transfer-Encoding: base64\r\n\r\n${b64(file.content)}`);
  }

  let body: string;
  if (parts.length === 0) body = 'Content-Type: text/plain; charset="utf-8"\r\n\r\n';
  else if (parts.length === 1 && alt.length) body = parts[0];
  else body = `Content-Type: multipart/mixed; boundary="${boundary('mix')}"\r\n\r\n` + parts.map(p => `--${boundary('mix')}\r\n${p}\r\n`).join('') + `--${boundary('mix')}--\r\n`;
  // The header block ends at the first blank line, so the body's own first header lines join it.
  const [bodyHead, ...bodyRest] = body.split('\r\n\r\n');
  return { eml: head.join('\r\n') + '\r\n' + bodyHead + '\r\n\r\n' + bodyRest.join('\r\n\r\n'), hadHeaders, bodyFrom };
}
