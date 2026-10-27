// ZIP: list the central directory without extracting anything; read small text entries (Office XML) with DecompressionStream.
import { utf8 } from '../mime.js';
import type { ZipEntry } from '../types.js';

export function zipList(b: Uint8Array): ZipEntry[] | null {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength), out: ZipEntry[] = [];
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return null;
  let p = dv.getUint32(eocd + 16, true); const n = dv.getUint16(eocd + 10, true);
  for (let k = 0; k < n && p + 46 <= b.length; k++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const flags = dv.getUint16(p + 8, true), method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true), usize = dv.getUint32(p + 24, true);
    const nl = dv.getUint16(p + 28, true), el = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true), off = dv.getUint32(p + 42, true);
    out.push({ name: utf8(b.slice(p + 46, p + 46 + nl)), encrypted: !!(flags & 1), method, csize, usize, off });
    p += 46 + nl + el + cl;
  }
  return out;
}

export async function zipRead(b: Uint8Array, e: ZipEntry): Promise<string> {
  if (e.encrypted || e.usize > 2e6) return '';
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (e.off + 30 > b.length || dv.getUint32(e.off, true) !== 0x04034b50) return '';
  const start = e.off + 30 + dv.getUint16(e.off + 26, true) + dv.getUint16(e.off + 28, true), data = b.slice(start, start + e.csize);
  if (e.method === 0) return utf8(data);
  if (e.method !== 8 || typeof DecompressionStream !== 'function') return '';
  try {
    const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return utf8(new Uint8Array(await new Response(stream).arrayBuffer()));
  } catch { return ''; }
}
