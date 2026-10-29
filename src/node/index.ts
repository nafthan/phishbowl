// Node host for the engine: file helpers, and QR decoding when the optional QR reader is installed.
// HTML parsing, .msg reading and PNG decoding are Phishbowl's own code. Reading QR codes uses two optional packages,
// jsqr (and jpeg-js for JPEG images): `npm install jsqr jpeg-js` next to Phishbowl turns it on. Without them, images
// are listed as not checked for QR codes and everything else works the same.
import { readFile, stat, readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { decodePng, isPng } from './png.js';
import { analyse } from '../analyse.js';
import { msgToEml } from './msg.js';

type JsQR = (data: Uint8ClampedArray, width: number, height: number) => { data: string } | null;
type JpegDecode = (b: Uint8Array, o: { useTArray: true; maxMemoryUsageInMB: number }) => { data: Uint8Array; width: number; height: number };
const require_ = createRequire(import.meta.url);
/** Load an optional package, or undefined if it isn't installed. */
function optional<T>(name: string, pick: (m: unknown) => unknown): T | undefined {
  try { const m = require_(name) as { default?: unknown }; return (pick(m) ?? pick(m.default)) as T; } catch { return undefined; }
}
let qr: { jsQR?: JsQR; jpeg?: JpegDecode } | null = null;
/** The optional QR reader: which parts are installed. */
export function qrSupport(): { qr: boolean; jpeg: boolean } {
  qr ??= { jsQR: optional<JsQR>('jsqr', m => typeof m === 'function' ? m : undefined), jpeg: optional<JpegDecode>('jpeg-js', m => (m as { decode?: unknown })?.decode) };
  return { qr: !!qr.jsQR, jpeg: !!qr.jsQR && !!qr.jpeg };
}
import type { AnalyseOptions, Analysis, Env } from '../types.js';

/** Largest file the CLI will read. Real emails with attachments are rarely over a few MB. */
export const MAX_BYTES = 25 * 1024 * 1024;

function decodeImage(bytes: Uint8Array, mime: string): { data: Uint8Array; width: number; height: number } | null {
  try {
    if (isPng(bytes)) return decodePng(bytes);
    if (qr?.jpeg && (/jpe?g/i.test(mime) || (bytes[0] === 0xff && bytes[1] === 0xd8))) { const j = qr.jpeg(bytes, { useTArray: true, maxMemoryUsageInMB: 256 }); return { data: j.data, width: j.width, height: j.height }; }
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

/** The Node host. QR codes are read only if the optional QR reader is installed (and `o.qr` isn't false). */
export function nodeEnv(o: { qr?: boolean } = {}): Env {
  const env: Env = { readMsg: (bytes: Uint8Array) => msgToEml(bytes) };
  if (o.qr !== false && qrSupport().qr) env.decodeQR = async (bytes, mime) => {
    if (bytes.length > 8 * 1024 * 1024) return null;
    const img = decodeImage(bytes, mime); if (!img || img.width * img.height > 16e6) return null;
    const { out, w, h } = prepare(img);
    const r = qr!.jsQR!(out, w, h);
    return r ? r.data : null;
  };
  return env;
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
  const names = (await readdir(dir)).filter(n => /\.(eml|msg)$/i.test(n)).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  return names.map(n => join(dir, n));
}

export * from '../index.js';
export { fileCache, defaultCachePath } from './cache.js';
