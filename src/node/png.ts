// PNG → RGBA pixels, for reading QR codes. Every standard colour type and bit depth, palettes and transparency
// (tRNS), and Adam7 interlacing. The pixel data is zlib-compressed: Node's built-in zlib inflates it.
// Spec: https://www.w3.org/TR/png-3/
import { inflateSync } from 'node:zlib';

export interface Pixels { data: Uint8Array; width: number; height: number }

const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
/** Largest image decoded (pixels), so a small file can't demand gigabytes. */
export const MAX_PIXELS = 16e6;
const CHANNELS: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
const ADAM7: [number, number, number, number][] = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];

export const isPng = (b: Uint8Array) => b.length > 8 && SIG.every((x, i) => b[i] === x);

export function decodePng(b: Uint8Array): Pixels {
  if (!isPng(b)) throw new Error('Not a PNG');
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let p = 8, width = 0, height = 0, depth = 0, type = -1, interlace = 0;
  let palette: Uint8Array | null = null, trns: Uint8Array | null = null;
  const idat: Uint8Array[] = [];
  while (p + 8 <= b.length) {
    const len = v.getUint32(p), name = String.fromCharCode(b[p + 4], b[p + 5], b[p + 6], b[p + 7]), start = p + 8;
    if (start + len > b.length) break;   // truncated: use what there is
    const chunk = b.subarray(start, start + len);
    if (name === 'IHDR') {
      width = v.getUint32(start); height = v.getUint32(start + 4); depth = b[start + 8]; type = b[start + 9]; interlace = b[start + 12];
      if (!width || !height || width * height > MAX_PIXELS) throw new Error('PNG too large or empty');
      if (!(type in CHANNELS) || ![1, 2, 4, 8, 16].includes(depth)) throw new Error('Unsupported PNG');
    } else if (name === 'PLTE') palette = chunk;
    else if (name === 'tRNS') trns = chunk;
    else if (name === 'IDAT') idat.push(chunk);
    else if (name === 'IEND') break;
    p = start + len + 4;   // skip CRC
  }
  if (type < 0 || !idat.length) throw new Error('PNG has no image data');
  if (type === 3 && !palette) throw new Error('PNG palette missing');

  const ch = CHANNELS[type], bpp = Math.max(1, (ch * depth) >> 3);   // bytes per complete pixel, for filters
  const rowBytes = (w: number) => Math.ceil((w * ch * depth) / 8);
  const passes = interlace ? ADAM7.map(([x0, y0, dx, dy]) => ({ x0, y0, dx, dy, w: Math.ceil((width - x0) / dx), h: Math.ceil((height - y0) / dy) })).filter(q => q.w > 0 && q.h > 0)
    : [{ x0: 0, y0: 0, dx: 1, dy: 1, w: width, h: height }];
  const expected = passes.reduce((n, q) => n + q.h * (rowBytes(q.w) + 1), 0);
  const raw = inflateSync(Buffer.concat(idat), { maxOutputLength: expected + 1024 });
  if (raw.length < expected) throw new Error('PNG image data is short');

  const out = new Uint8Array(width * height * 4);
  const max = (1 << depth) - 1;
  // Transparent colour for grey / RGB images, in the image's own bit depth.
  const tGrey = type === 0 && trns && trns.length >= 2 ? (trns[0] << 8) | trns[1] : -1;
  const tRgb = type === 2 && trns && trns.length >= 6 ? [(trns[0] << 8) | trns[1], (trns[2] << 8) | trns[3], (trns[4] << 8) | trns[5]] : null;
  let r = 0;
  for (const q of passes) {
    const rb = rowBytes(q.w);
    let prev = new Uint8Array(rb), cur = new Uint8Array(rb);
    for (let y = 0; y < q.h; y++) {
      const f = raw[r++];
      for (let i = 0; i < rb; i++) {
        const x = raw[r + i], a = i >= bpp ? cur[i - bpp] : 0, up = prev[i], c = i >= bpp ? prev[i - bpp] : 0;
        let val: number;
        switch (f) {
          case 0: val = x; break;
          case 1: val = x + a; break;
          case 2: val = x + up; break;
          case 3: val = x + ((a + up) >> 1); break;
          case 4: { const pp = a + up - c, pa = Math.abs(pp - a), pb = Math.abs(pp - up), pc = Math.abs(pp - c); val = x + (pa <= pb && pa <= pc ? a : pb <= pc ? up : c); break; }
          default: throw new Error('Bad PNG filter');
        }
        cur[i] = val & 255;
      }
      r += rb;
      // Unpack one row of samples into RGBA.
      const sample = (i: number): number => {   // i-th sample in the row, at the image's bit depth
        if (depth === 8) return cur[i];
        if (depth === 16) return (cur[i * 2] << 8) | cur[i * 2 + 1];
        const bit = i * depth, byte = cur[bit >> 3], shift = 8 - depth - (bit & 7);
        return (byte >> shift) & max;
      };
      const to8 = (s: number) => depth === 8 ? s : Math.round((s * 255) / max);
      const yy = q.y0 + y * q.dy;
      for (let x = 0; x < q.w; x++) {
        const o = (yy * width + q.x0 + x * q.dx) * 4;
        if (type === 0) { const s = sample(x), g = to8(s); out[o] = out[o + 1] = out[o + 2] = g; out[o + 3] = s === tGrey ? 0 : 255; }
        else if (type === 2) { const s0 = sample(x * 3), s1 = sample(x * 3 + 1), s2 = sample(x * 3 + 2); out[o] = to8(s0); out[o + 1] = to8(s1); out[o + 2] = to8(s2);
          out[o + 3] = tRgb && s0 === tRgb[0] && s1 === tRgb[1] && s2 === tRgb[2] ? 0 : 255; }
        else if (type === 3) { const k = sample(x); out[o] = palette![k * 3] ?? 0; out[o + 1] = palette![k * 3 + 1] ?? 0; out[o + 2] = palette![k * 3 + 2] ?? 0; out[o + 3] = trns && k < trns.length ? trns[k] : 255; }
        else if (type === 4) { const g = to8(sample(x * 2)); out[o] = out[o + 1] = out[o + 2] = g; out[o + 3] = to8(sample(x * 2 + 1)); }
        else { out[o] = to8(sample(x * 4)); out[o + 1] = to8(sample(x * 4 + 1)); out[o + 2] = to8(sample(x * 4 + 2)); out[o + 3] = to8(sample(x * 4 + 3)); }
      }
      const t = prev; prev = cur; cur = t;
    }
  }
  return { data: out, width, height };
}
