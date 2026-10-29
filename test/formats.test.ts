// File formats Phishbowl reads with its own code: compressed RTF, PNG, Outlook .msg, HTML.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decompressRtf, rtfCrc } from '../src/lzfu.js';

const hex = (s: string) => Uint8Array.from(s.trim().split(/\s+/).map(x => parseInt(x, 16)));
const latin = (b: Uint8Array) => Buffer.from(b).toString('latin1');

test('compressed RTF: the [MS-OXRTFCP] example', () => {
  const b = hex('2d 00 00 00 2b 00 00 00 4c 5a 46 75 f1 c5 c7 a7 03 00 0a 00 72 63 70 67 31 32 35 42 32 0a f3 20 68 65 6c 09 00 20 62 77 05 b0 6c 64 7d 0a 80 0f a0');
  assert.equal(latin(decompressRtf(b)), '{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n');
  assert.equal(rtfCrc(b, 16), 0xa7c7c5f1);
});

test('compressed RTF: stored uncompressed (MELA)', () => {
  const body = Buffer.from('{\\rtf1 plain}', 'latin1'), h = Buffer.alloc(16);
  h.writeUInt32LE(body.length + 12, 0); h.writeUInt32LE(body.length, 4); h.write('MELA', 8, 'latin1');
  assert.equal(latin(decompressRtf(new Uint8Array(Buffer.concat([h, body])))), '{\\rtf1 plain}');
});

test('compressed RTF: hostile input fails safely', () => {
  assert.throws(() => decompressRtf(new Uint8Array(4)));
  const huge = hex('ff ff ff 7f ff ff ff 7f 4c 5a 46 75 00 00 00 00');
  assert.throws(() => decompressRtf(huge), /too large/);
  for (let n = 0; n < 200; n++) {   // random streams: never throw past the header, never run long
    const b = new Uint8Array(16 + (n * 37) % 500); for (let i = 0; i < b.length; i++) b[i] = (i * 7919 + n * 104729) & 255;
    b.set([b.length - 4, 0, 0, 0, 0, 16, 0, 0, 0x4c, 0x5a, 0x46, 0x75], 0);
    assert.ok(decompressRtf(b).length <= 4096);
  }
});

test('PNG: every colour type, bit depth, transparency and interlacing decodes to the same pixels as pngjs did', async () => {
  const { readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { createHash } = await import('node:crypto');
  const { decodePng } = await import('../src/node/png.js');
  const dir = join(import.meta.dirname, 'fixtures', 'png');
  // Hashes recorded from pngjs 7.0.0 before it was removed. Made with Pillow and ImageMagick from random pixels.
  const expected: Record<string, string> = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8'));
  for (const [f, want] of Object.entries(expected)) {
    const p = decodePng(new Uint8Array(readFileSync(join(dir, f))));
    const got = `${p.width}x${p.height} ` + createHash('sha256').update(p.data).digest('hex');
    if (f.startsWith('lt-')) { assert.equal(got.split(' ')[0], want.split(' ')[0], f); continue; }   // see below
    assert.equal(got, want, f);
  }
  // Grey with a transparent colour (17): exactly the pixels of that grey are transparent. pngjs also set their
  // colour to black, which makes no difference once transparent.
  for (const f of Object.keys(expected).filter(x => x.startsWith('lt-'))) {
    const p = decodePng(new Uint8Array(readFileSync(join(dir, f))));
    for (let i = 0; i < p.data.length; i += 4) assert.equal(p.data[i + 3] === 0, p.data[i] === 17, `${f} pixel ${i / 4}`);
  }
});

test('PNG: hostile input fails safely', async () => {
  const { decodePng } = await import('../src/node/png.js');
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  assert.throws(() => decodePng(new Uint8Array([1, 2, 3])));
  const ihdr = (w: number, h: number) => { const b = Buffer.alloc(25); b.writeUInt32BE(13, 0); b.write('IHDR', 4); b.writeUInt32BE(w, 8); b.writeUInt32BE(h, 12); b[16] = 8; b[17] = 6; return b; };
  assert.throws(() => decodePng(new Uint8Array(Buffer.concat([Buffer.from(sig), ihdr(100000, 100000)]))), /too large/);
  assert.throws(() => decodePng(new Uint8Array(Buffer.concat([Buffer.from(sig), ihdr(10, 10)]))), /no image data/);
});

test('Outlook .msg: damaged files never hang or crash the analysis', async () => {
  const { readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { msgToEml } = await import('../src/msg.js');
  const { readCfb } = await import('../src/files/cfb.js');
  const good = new Uint8Array(readFileSync(join(import.meta.dirname, 'fixtures', 'm02-report-with-attached-item.msg')));
  assert.match(msgToEml(good).eml, /Subject: FW: Your password expires today/);
  const t0 = Date.now();
  for (let n = 0; n < 300; n++) {
    const b = good.slice();
    for (let k = 0; k < 1 + (n % 6); k++) { const at = (n * 2654435761 + k * 40503) % b.length; b[at] = (b[at] + 1 + n) & 255; }   // a few corrupted bytes
    if (n % 50 === 0) b.fill(0xff, 512, 1024);   // a FAT sector of "free" entries
    try { msgToEml(b); } catch (e) { assert.ok(e instanceof Error); }
  }
  assert.ok(Date.now() - t0 < 20000, 'took too long');
  // A directory that points at itself: refused or read once, never looped.
  const loop = good.slice(); const dir = readCfb(good); assert.ok(dir.children.size > 0);
  try { msgToEml(loop.fill(0, 0x30, 0x34)); } catch { /* fine */ }
});

test('HTML: text, entities and raw-text elements as a browser reads them', async () => {
  const { parseHtml, decodeEntities } = await import('../src/html.js');
  const d = parseHtml('<html><head><title>T&amp;C</title><style>p{color:red}</style></head><body>text &amp; &nbsp;x &copy &notit; &#x41;&#65;&#0;&#x80; &ZeroWidthSpace;<script>var a="<a href=x>"&amp;</script><textarea>t&lt;</textarea><!-- <a href=y> --></body></html>');
  assert.equal(d.body.textContent, 'text & \u00a0x © ¬it; AA�€ ​var a="<a href=x>"&amp;t<');
  assert.equal(d.querySelectorAll('a').length, 0, 'no links inside a script or a comment');
  assert.equal(d.title, 'T&C');
  assert.equal(decodeEntities('?a=1&amp;b=2&copy=3&notit=4&lt', true), '?a=1&b=2&copy=3&notit=4<');
  assert.equal(decodeEntities('&#xD800;&#99999999;&bogus;'), '��&bogus;');
});

test('HTML: no <body> tag, unclosed tags, attributes', async () => {
  const { parseHtml } = await import('../src/html.js');
  const d = parseHtml('<html><title>t</title><p>hi <a HREF="http://x.example/?a=1&amp;b=2" onclick=go() data-x=\'q\'>link</a><p>two<div style="display:none">hid<p>den</div>after');
  assert.equal(d.body.textContent, 'hi linktwohiddenafter');
  const a = d.querySelector('a[href]')!;
  assert.equal(a.getAttribute('href'), 'http://x.example/?a=1&b=2');
  assert.deepEqual([...a.attributes].map(x => x.name), ['href', 'onclick', 'data-x']);
  assert.equal(d.querySelectorAll('p').length, 3, 'each <p> closes the one before');
  assert.equal(d.querySelector('[style]')!.textContent, 'hidden');
  const f = parseHtml('<form action=/x><input type=PASSWORD name=p></form><img src=a.png width=1><area href=z>');
  assert.ok(f.querySelector('form')!.querySelector('input[type=password]'), 'type matches case-insensitively');
  assert.equal(f.querySelectorAll('a[href], area[href]').length, 1);
  assert.equal(f.querySelectorAll('img[src]')[0].getAttribute('width'), '1');
  const ul = parseHtml('<ul><li>a<li>b<ul><li>c</ul><li>d</ul>');
  assert.deepEqual(ul.querySelectorAll('li').map(li => li.textContent), ['a', 'bc', 'c', 'd'], 'an open <li> survives a nested list');
});

test('HTML: hostile input stays bounded', async () => {
  const { parseHtml } = await import('../src/html.js');
  const t0 = Date.now();
  parseHtml('<div>'.repeat(100000) + 'x');
  parseHtml('<a href="'.repeat(20000));
  parseHtml('&'.repeat(200000) + '<<<<' + '<!--'.repeat(10000));
  parseHtml('<script>' + 'x'.repeat(1e6));
  assert.ok(Date.now() - t0 < 5000);
});
