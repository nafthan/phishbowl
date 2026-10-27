// Raw .eml → headers, text and HTML bodies, attachments (RFC 5322 + MIME).
//
// The parser works on a string. Two kinds of input are supported:
// - bytes (a file read from disk): turned into a "binary string" with one character per byte, so every
//   part can be decoded with the charset it declares;
// - text (pasted into a page): already Unicode, so parts are treated as UTF-8.
import type { Header, RawAttachment } from './types.js';

/** mbox exports (Thunderbird, mail archives) put a "From sender date" separator line before the headers. */
export const stripMboxLine = (t: string): string => t.replace(/^\ufeff?From [^\r\n:]*(?::\d\d){0,2}[^\r\n]*\r?\n(?=[\w-]+:)/, '');

/** A raw email starts with a header block (which can be long: Received and ARC headers) containing From: and others. */
export const looksLikeEmail = (t: string): boolean => {
  const end = t.search(/\r?\n\r?\n/);
  if (end < 0) return false;
  const head = t.slice(0, Math.min(end, 512 * 1024));
  if (!/^[\w-]+:/.test(head.trimStart())) return false;   // must open with a header, not prose
  return /^from:/im.test(head) && /^(received|return-path|message-id|mime-version|date|subject):/im.test(head);
};

/** Bytes → one character per byte (lossless, unlike TextDecoder('latin1'), which is really windows-1252). */
export function binaryString(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return s;
}
const bytesOfBinary = (s: string): Uint8Array => { const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff; return b; };

export const utf8 = (b: Uint8Array): string => new TextDecoder('utf-8').decode(b);
export const latin = (b: Uint8Array): string => new TextDecoder('windows-1252').decode(b);
const decodeAs = (b: Uint8Array, charset: string): string => {
  try { return new TextDecoder((charset || 'utf-8').trim().toLowerCase().replace(/^(us-)?ascii$/, 'utf-8')).decode(b); } catch { return utf8(b); }
};

export function splitHeaders(raw: string): { headers: Header[]; body: string } {
  const m = raw.match(/\r?\n\r?\n/), at = m && m.index !== undefined ? m.index : raw.length;
  const headers: Header[] = [];
  for (const line of raw.slice(0, at).replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
    const k = line.indexOf(':');
    if (k > 0) headers.push([line.slice(0, k).trim().toLowerCase(), line.slice(k + 1).trim(), line.slice(0, k).trim()]);
  }
  return { headers, body: m && m.index !== undefined ? raw.slice(at + m[0].length) : '' };
}
export const H = (hs: Header[], n: string): string => (hs.find(([k]) => k === n) || [])[1] || '';
export const HA = (hs: Header[], n: string): string[] => hs.filter(([k]) => k === n).map(([, v]) => v);
export const param = (v: string, n: string): string => {
  const m = v.match(new RegExp('(?:^|;)\\s*' + n + '\\*?=\\s*(?:"([^"]*)"|([^;\\s]+))', 'i'));
  return m ? (m[1] ?? m[2]) : '';
};

export function qpBytes(s: string, binary = false): Uint8Array {
  s = s.replace(/=\r?\n/g, '');
  const out: number[] = [], enc = new TextEncoder();
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && /^[0-9A-F]{2}$/i.test(s.substr(i + 1, 2))) { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
    else { const c = s.charCodeAt(i); if (c < 128 || (binary && c < 256)) out.push(c); else out.push(...enc.encode(s[i])); }
  }
  return new Uint8Array(out);
}
export function b64Bytes(s: string): Uint8Array {
  try { const bin = atob(s.replace(/[^A-Za-z0-9+/=]/g, '')); return Uint8Array.from(bin, c => c.charCodeAt(0)); } catch { return new Uint8Array(); }
}

/** RFC 2047 encoded words (=?utf-8?B?...?=), plus raw 8-bit UTF-8 in headers when the input was bytes. */
export function decodeWords(v: string, binary = false): string {
  let s = String(v || '');
  if (binary && /[\x80-\xff]/.test(s)) { try { s = new TextDecoder('utf-8', { fatal: true }).decode(bytesOfBinary(s)); } catch { s = latin(bytesOfBinary(s)); } }
  return s.replace(/\?=\s+=\?/g, '?==?').replace(/=\?([\w-]+)(?:\*[\w-]+)?\?([BQ])\?([^?]*)\?=/gi, (m, cs: string, enc: string, txt: string) => {
    try { const b = enc.toUpperCase() === 'B' ? b64Bytes(txt) : qpBytes(txt.replace(/_/g, ' '), true); return new TextDecoder(cs).decode(b); } catch { return m; }
  });
}

export interface Parts { text: string[]; html: string[]; attachments: RawAttachment[] }

/** Walk the MIME tree and collect bodies and attachments. */
export function walk(raw: string, out: Parts, depth: number, binary: boolean): void {
  const { headers, body } = splitHeaders(raw);
  const ct = H(headers, 'content-type') || 'text/plain', type = ct.split(';')[0].trim().toLowerCase();
  if (type.startsWith('multipart/') && depth < 10) {
    const b = param(ct, 'boundary'); if (!b) return;
    for (const seg of body.split('--' + b).slice(1)) { if (seg.startsWith('--')) break; walk(seg.replace(/^\r?\n/, ''), out, depth + 1, binary); }
    return;
  }
  const cte = H(headers, 'content-transfer-encoding').toLowerCase();
  const bytes = cte === 'base64' ? b64Bytes(body) : cte === 'quoted-printable' ? qpBytes(body, binary) : binary ? bytesOfBinary(body) : new TextEncoder().encode(body);
  const disp = H(headers, 'content-disposition'), name = decodeWords(param(disp, 'filename') || param(ct, 'name'), binary);
  const text = () => binary ? decodeAs(bytes, param(ct, 'charset')) : utf8(bytes);
  if (name || /^attachment/i.test(disp) || type === 'message/rfc822' || (!type.startsWith('text/') && !type.startsWith('multipart/'))) {
    out.attachments.push({ name: name || '(no name)', declared: type, inline: /^inline/i.test(disp) || !!H(headers, 'content-id'), cid: H(headers, 'content-id').replace(/[<>]/g, ''), bytes });
  } else if (type === 'text/html') out.html.push(text());
  else if (type === 'text/calendar') out.attachments.push({ name: 'invite.ics', declared: type, inline: false, cid: '', bytes });
  else if (type.startsWith('text/')) out.text.push(text());
}
