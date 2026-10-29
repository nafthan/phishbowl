// Outlook's compressed RTF ([MS-OXRTFCP]): how a .msg stores its RTF body (PidTagRtfCompressed).
//
// A 16-byte header (compressed size, raw size, "LZFu" or "MELA", CRC), then for "LZFu" a simple LZ77 stream over a
// 4 KB ring buffer that starts pre-filled with common RTF words. Each control byte says, bit by bit from the lowest,
// whether the next item is a literal byte (0) or a 2-byte reference (1): 12 bits of buffer offset and 4 bits of
// length minus 2. A reference to the current write position ends the stream. "MELA" means stored uncompressed.

const PREBUF = '{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier' +
  '{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx';
const LZFU = 0x75465a4c, MELA = 0x414c454d;
/** Largest output accepted, so a hostile file can't claim gigabytes. */
const MAX_RAW = 64 * 1024 * 1024;

/** CRC-32 as [MS-OXRTFCP] uses it (standard polynomial, no final inversion). */
let table: Uint32Array | null = null;
export function rtfCrc(b: Uint8Array, start = 0, end = b.length): number {
  if (!table) { table = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; table[n] = c >>> 0; } }
  let crc = 0;
  for (let i = start; i < end; i++) crc = (table[(crc ^ b[i]) & 0xff] ^ (crc >>> 8)) >>> 0;
  return crc;
}

/** Decompress PidTagRtfCompressed. Throws on a malformed header. */
export function decompressRtf(input: Uint8Array): Uint8Array {
  if (input.length < 16) throw new Error('Compressed RTF is too short');
  const v = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const compSize = v.getUint32(0, true), rawSize = v.getUint32(4, true), type = v.getUint32(8, true);
  const end = Math.min(input.length, compSize + 4);
  if (rawSize > MAX_RAW) throw new Error('Compressed RTF claims to be too large');
  if (type === MELA) return input.slice(16, Math.min(end, 16 + rawSize));
  if (type !== LZFU) throw new Error('Unknown compressed RTF type');

  const dict = new Uint8Array(4096);
  for (let i = 0; i < PREBUF.length; i++) dict[i] = PREBUF.charCodeAt(i);
  let w = PREBUF.length;
  const out = new Uint8Array(rawSize);
  let o = 0, i = 16;
  while (i < end) {
    const control = input[i++];
    for (let bit = 0; bit < 8 && i < end; bit++) {
      if (!(control & (1 << bit))) {   // literal
        const b = input[i++];
        if (o < rawSize) out[o++] = b;
        dict[w] = b; w = (w + 1) & 4095;
        continue;
      }
      if (i + 1 >= end) return out.subarray(0, o);
      const token = (input[i] << 8) | input[i + 1]; i += 2;
      const offset = token >> 4, len = (token & 15) + 2;
      if (offset === w) return out.subarray(0, o);   // end of stream
      for (let k = 0; k < len; k++) {
        const b = dict[(offset + k) & 4095];
        if (o < rawSize) out[o++] = b;
        dict[w] = b; w = (w + 1) & 4095;
      }
    }
  }
  return out.subarray(0, o);
}
