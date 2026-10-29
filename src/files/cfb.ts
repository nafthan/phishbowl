// Compound File Binary format ([MS-CFB]): the container inside Outlook .msg files (and old .doc/.xls).
//
// A little file system in one file: fixed-size sectors, a FAT chaining them into streams, a mini FAT for small
// streams kept inside one "mini stream", and a directory of storages (folders) and streams (files) arranged as a
// red-black tree per folder. This reader is read-only and defensive: every chain is bounded and loops are refused,
// because the file is attacker-supplied.

export interface CfbEntry {
  name: string;
  /** 1 storage, 2 stream, 5 root. */
  type: number;
  /** Children by lower-case name (storages only). */
  children: Map<string, CfbEntry>;
  /** Stream content (empty for storages). */
  read(): Uint8Array;
}

const SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END = 0xfffffffe, FREE = 0xffffffff, NOSTREAM = 0xffffffff;
/** Largest stream read (a .msg attachment can be big, but not this big). */
const MAX_STREAM = 64 * 1024 * 1024;

export const isCfb = (b: Uint8Array) => b.length >= 512 && SIG.every((x, i) => b[i] === x);

export function readCfb(b: Uint8Array): CfbEntry {
  if (!isCfb(b)) throw new Error('Not a compound file');
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u32 = (o: number) => o + 4 <= b.length ? v.getUint32(o, true) : END;
  const sectorShift = v.getUint16(0x1e, true), miniShift = v.getUint16(0x20, true);
  if ((sectorShift !== 9 && sectorShift !== 12) || miniShift !== 6) throw new Error('Unsupported compound file');
  const size = 1 << sectorShift, mini = 1 << miniShift, perSector = size / 4;
  const sectorCount = Math.floor((b.length - size) / size) + 1;
  const sector = (n: number) => { const o = (n + 1) * size; return o + size <= b.length ? b.subarray(o, o + size) : o < b.length ? b.subarray(o) : new Uint8Array(0); };
  const firstDir = u32(0x30), cutoff = u32(0x38), firstMiniFat = u32(0x3c), firstDifat = u32(0x44);

  // FAT sectors: 109 listed in the header, the rest in a chain of DIFAT sectors.
  const fatSectors: number[] = [];
  for (let i = 0; i < 109; i++) { const s = u32(0x4c + i * 4); if (s < sectorCount) fatSectors.push(s); }
  for (let s = firstDifat, guard = 0; s < sectorCount && guard < sectorCount; guard++) {
    const d = sector(s), dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
    for (let i = 0; i < perSector - 1 && i * 4 + 4 <= d.length; i++) { const f = dv.getUint32(i * 4, true); if (f < sectorCount) fatSectors.push(f); }
    s = d.length >= size ? dv.getUint32(size - 4, true) : END;
  }
  const fat = new Uint32Array(fatSectors.length * perSector);
  fatSectors.forEach((s, k) => { const d = sector(s), sv = new DataView(d.buffer, d.byteOffset, d.byteLength); for (let i = 0; i * 4 + 4 <= d.length; i++) fat[k * perSector + i] = sv.getUint32(i * 4, true); });

  /** Sector numbers of a chain, stopping at its end, a loop, or anything out of range. */
  const chain = (start: number, table: Uint32Array, limit: number): number[] => {
    const out: number[] = [], seen = new Set<number>();
    for (let s = start; s !== END && s !== FREE && s < limit && s < table.length && !seen.has(s); s = table[s]) { seen.add(s); out.push(s); }
    return out;
  };
  const readChain = (start: number, len: number): Uint8Array => {
    const out = new Uint8Array(Math.min(len, MAX_STREAM)); let o = 0;
    for (const s of chain(start, fat, sectorCount)) { if (o >= out.length) break; const d = sector(s).subarray(0, out.length - o); out.set(d, o); o += d.length; }
    return out.subarray(0, o);
  };

  // Directory: 128-byte entries.
  const dirBytes = readChain(firstDir, sectorCount * size);
  const n = Math.floor(dirBytes.length / 128), dv = new DataView(dirBytes.buffer, dirBytes.byteOffset, dirBytes.byteLength);
  interface Raw { name: string; type: number; left: number; right: number; child: number; start: number; size: number }
  const raw: Raw[] = [];
  for (let i = 0; i < n; i++) {
    const o = i * 128, nameLen = Math.min(64, dv.getUint16(o + 0x40, true));
    let name = ''; for (let k = 0; k + 1 < nameLen - 1; k += 2) name += String.fromCharCode(dv.getUint16(o + k, true));
    raw.push({ name, type: dirBytes[o + 0x42], left: dv.getUint32(o + 0x44, true), right: dv.getUint32(o + 0x48, true), child: dv.getUint32(o + 0x4c, true),
      start: dv.getUint32(o + 0x74, true), size: dv.getUint32(o + 0x78, true) });
  }
  if (!raw.length || raw[0].type !== 5) throw new Error('Compound file has no root');

  // Mini stream (the root entry's stream) and mini FAT.
  const miniStream = readChain(raw[0].start, raw[0].size);
  const miniFatBytes = readChain(firstMiniFat, sectorCount * size), miniFat = new Uint32Array(Math.floor(miniFatBytes.length / 4));
  const mv = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength);
  for (let i = 0; i < miniFat.length; i++) miniFat[i] = mv.getUint32(i * 4, true);
  const readMini = (start: number, len: number): Uint8Array => {
    const out = new Uint8Array(Math.min(len, MAX_STREAM)); let o = 0;
    for (const s of chain(start, miniFat, Math.ceil(miniStream.length / mini))) { if (o >= out.length) break; const d = miniStream.subarray(s * mini, s * mini + Math.min(mini, out.length - o)); out.set(d, o); o += d.length; }
    return out.subarray(0, o);
  };

  const built = new Map<number, CfbEntry>();
  const build = (id: number, depth: number): CfbEntry => {
    const r = raw[id];
    const e: CfbEntry = { name: r.name, type: r.type, children: new Map(),
      read: () => r.type !== 2 ? new Uint8Array(0) : r.size < cutoff ? readMini(r.start, r.size) : readChain(r.start, r.size) };
    built.set(id, e);
    if ((r.type === 1 || r.type === 5) && depth < 32) {
      // In-order walk of this storage's tree, guarding against loops and bad ids.
      const stack = [r.child], seen = new Set<number>();
      while (stack.length) {
        const c = stack.pop()!;
        if (c === NOSTREAM || c >= raw.length || seen.has(c) || built.has(c)) continue;
        seen.add(c);
        stack.push(raw[c].left, raw[c].right);
        if (raw[c].type === 1 || raw[c].type === 2) e.children.set(raw[c].name.toLowerCase(), build(c, depth + 1));
      }
    }
    return e;
  };
  return build(0, 0);
}
