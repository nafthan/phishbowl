// SHA-256 and SHA-1 through Web Crypto, MD5 in plain JavaScript (Web Crypto has no MD5), and Shannon entropy.

const hex = (buf: ArrayBuffer): string => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');

export async function hashes(bytes: Uint8Array): Promise<{ sha256: string; sha1: string; md5: string }> {
  let sha256 = '', sha1 = '';
  try {
    const copy = bytes.slice();   // a standalone buffer, as digest() needs
    sha256 = hex(await crypto.subtle.digest('SHA-256', copy));
    sha1 = hex(await crypto.subtle.digest('SHA-1', copy));
  } catch { /* no Web Crypto (very old runtime): leave empty */ }
  return { sha256, sha1, md5: md5(bytes) };
}

export function md5(bytes: Uint8Array): string {
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21], K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32);
  const len = bytes.length, n = ((len + 8) >> 6) + 1, w = new Uint32Array(n * 16);
  for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
  w[len >> 2] |= 0x80 << ((len % 4) * 8); w[n * 16 - 2] = (len * 8) >>> 0; w[n * 16 - 1] = Math.floor(len / 0x20000000);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let blk = 0; blk < n; blk++) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; } else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; } else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + w[blk * 16 + g]) >>> 0; A = D; D = C; C = B;
      const r = S[(i >> 4) * 4 + (i % 4)]; B = (B + ((F << r) | (F >>> (32 - r)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  return [a0, b0, c0, d0].map(x => [0, 8, 16, 24].map(s => ((x >>> s) & 255).toString(16).padStart(2, '0')).join('')).join('');
}

/** Bits per byte, 0–8. Encrypted or compressed data is close to 8. */
export function entropy(b: Uint8Array): number {
  if (!b.length) return 0;
  const c = new Uint32Array(256); for (const x of b) c[x]++;
  let e = 0; for (const n of c) if (n) { const p = n / b.length; e -= p * Math.log2(p); }
  return e;
}
