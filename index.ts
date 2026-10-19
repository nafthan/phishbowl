// Node host for the engine: HTML parsing with linkedom, QR decoding with jsQR (PNG and JPEG), and file helpers.
import { readFile, stat, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { parseHTML } from 'linkedom';
import jsQRModule from 'jsqr';
import { PNG } from 'pngjs';
import jpeg from 'jpeg-js';
import { analyse } from '../analyse.js';

// jsqr is CommonJS with a default export; depending on the loader it arrives wrapped or not.
type JsQR = (data: Uint8ClampedArray, width: number, height: number) => { data: string } | null;
const jsQR: JsQR = ((jsQRModule as unknown as { default?: JsQR }).default ?? jsQRModule) as unknown as JsQR;
import type { AnalyseOptions, Analysis, Env } from '../types.js';

/** Largest file the CLI will read. Real emails with attachments are rarely over a few MB. */
export const MAX_BYTES = 25 * 1024 * 1024;

function decodeImage(bytes: Uint8Array, mime: string): { data: Uint8Array; width: number; height: number } | null {
  const buf = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  try {
    if (/png/i.test(mime) || (bytes[0] === 0x89 && bytes[1] === 0x50)) { const p = PNG.sync.read(buf); return { data: p.data, width: p.width, height: p.height }; }
    if (/jpe?g/i.test(mime) || (bytes[0] === 0xff && bytes[1] === 0xd8)) { const j = jpeg.decode(buf, { useTArray: true, maxMemoryUsageInMB: 256 }); return { data: j.data, width: j.width, height: j.height }; }
  } catch { /* not decodable */ }
  return null;
}

/** Small codes read better scaled up (nearest neighbour), on white so transparent pixels count as background. */
function prepare(img: { data: Uint8Array; width: number; height: number }) {
  const scale = Math.max(1, Math.min(8, Math.ceil(600 / Math.max(img.width, img.height))));
  const w = img.width * scale, h = img.height * scale, out = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const s = ((Math.floor(y / scale) * img.width) + Math.floor(x / scale)) * 4, d = (y * w + x) * 4, a = img.data[s + 3] / 255;
    for (let k = 0; k < 3; k++) out[d + k] = Math.round(img.data[s + k] * a + 255 * (1 - a));
    out[d + 3] = 255;
  }
  return { out, w, h };
}

export function nodeEnv(): Env {
  return {
    parseHtml: (html: string) => parseHTML(/<html[\s>]/i.test(html) ? html : `<!doctype html><html><body>${html}</body></html>`).document as unknown as Document,
    decodeQR: async (bytes, mime) => {
      if (bytes.length > 8 * 1024 * 1024) return null;
      const img = decodeImage(bytes, mime); if (!img || img.width * img.height > 16e6) return null;
      const { out, w, h } = prepare(img);
      const r = jsQR(out, w, h);
      return r ? r.data : null;
    },
  };
}

export type NodeAnalyseOptions = Omit<AnalyseOptions, 'env'> & { env?: Env };

export async function analyseFile(path: string, opts: NodeAnalyseOptions = {}): Promise<Analysis> {
  const s = await stat(path);
  if (s.size > MAX_BYTES) throw new Error(`${path} is ${(s.size / 1048576).toFixed(1)} MB; the limit is ${MAX_BYTES / 1048576} MB`);
  return analyse(new Uint8Array(await readFile(path)), { ...opts, env: opts.env || nodeEnv() });
}

export async function analyseBytes(bytes: Uint8Array, opts: NodeAnalyseOptions = {}): Promise<Analysis> {
  return analyse(bytes, { ...opts, env: opts.env || nodeEnv() });
}

/** .eml files in a folder (not recursive), in natural order. */
export async function emlFiles(dir: string): Promise<string[]> {
  const names = (await readdir(dir)).filter(n => /\.eml$/i.test(n)).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  return names.map(n => join(dir, n));
}

export * from '../index.js';
