// A small, tolerant HTML parser for analysis. It builds just enough of a document tree for the checks: elements with
// attributes, text, textContent, and querySelectorAll for simple selectors. Nothing is fetched, run or rendered.
//
// It follows the HTML standard where that changes what an analyst sees: entities are decoded the way browsers decode
// them; script, style, title and textarea content is raw text (a "<a href" inside a script is not a link); comments
// are dropped; content with no <body> tag still belongs to the body; and common unclosed tags (p, li, td, option…)
// close the way browsers close them. It is not a full HTML5 tree builder: unusual nesting can come out differently.
import { entities, LONGEST } from './entities.js';

export interface HtmlAttr { name: string; value: string }
export interface HtmlNode { nodeType: 1 | 3; parent: HtmlElement | null; readonly textContent: string }
export interface HtmlText extends HtmlNode { nodeType: 3; data: string }

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr', 'keygen', 'basefont', 'bgsound', 'frame']);
// iframe, noembed and noframes are raw text to a browser, but their content is parsed here, so a script or link hidden
// in an iframe's fallback still counts.
const RAW = new Set(['script', 'style', 'xmp']);
const RCDATA = new Set(['title', 'textarea']);
const HEAD = new Set(['title', 'meta', 'link', 'style', 'script', 'base', 'noscript', 'template']);
/** Opening one of these first closes the current element if it is one of the listed kinds. */
const BLOCK = ['address', 'article', 'aside', 'blockquote', 'center', 'details', 'div', 'dl', 'fieldset', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'header', 'hr', 'main', 'menu', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'ul'];
const CLOSES: Record<string, string[]> = {
  ...Object.fromEntries(BLOCK.map(t => [t, ['p']])),
  li: ['li', 'p'], dt: ['dt', 'dd', 'p'], dd: ['dt', 'dd', 'p'], option: ['option'], optgroup: ['option', 'optgroup'],
  tr: ['tr', 'td', 'th'], td: ['td', 'th'], th: ['td', 'th'], thead: ['tbody', 'tfoot', 'tr', 'td', 'th'], tbody: ['thead', 'tbody', 'tfoot', 'tr', 'td', 'th'], tfoot: ['thead', 'tbody', 'tr', 'td', 'th'],
};
/** Elements that stop the search for an element to close (an unclosed <li> inside a nested <ul> stays inside it). */
const SCOPE = new Set(['ul', 'ol', 'table', 'html', 'body', 'td', 'th', 'select', 'template']);

export class HtmlElement implements HtmlNode {
  nodeType = 1 as const;
  parent: HtmlElement | null = null;
  childNodes: (HtmlElement | HtmlText)[] = [];
  constructor(public tagName: string, public attributes: HtmlAttr[] = []) {}
  get localName() { return this.tagName; }
  getAttribute(name: string): string | null { const n = name.toLowerCase(); const a = this.attributes.find(x => x.name === n); return a ? a.value : null; }
  hasAttribute(name: string) { return this.getAttribute(name) !== null; }
  get children(): HtmlElement[] { return this.childNodes.filter((c): c is HtmlElement => c.nodeType === 1); }
  get textContent(): string {
    let s = ''; const stack: (HtmlElement | HtmlText)[] = [...this.childNodes].reverse();
    while (stack.length) { const n = stack.pop()!; if (n.nodeType === 3) s += n.data; else for (let i = n.childNodes.length - 1; i >= 0; i--) stack.push(n.childNodes[i]); }
    return s;
  }
  /** Every element below this one, in document order. */
  descendants(): HtmlElement[] {
    const out: HtmlElement[] = [], stack: HtmlElement[] = [...this.children].reverse();
    while (stack.length) { const e = stack.pop()!; out.push(e); const k = e.children; for (let i = k.length - 1; i >= 0; i--) stack.push(k[i]); }
    return out;
  }
  querySelectorAll(selector: string): HtmlElement[] { const m = compile(selector); return this.descendants().filter(m); }
  querySelector(selector: string): HtmlElement | null { const m = compile(selector); return this.descendants().find(m) || null; }
}

export class HtmlDocument {
  documentElement: HtmlElement; head: HtmlElement; body: HtmlElement;
  constructor() {
    this.documentElement = new HtmlElement('html'); this.head = new HtmlElement('head'); this.body = new HtmlElement('body');
    for (const e of [this.head, this.body]) { e.parent = this.documentElement; this.documentElement.childNodes.push(e); }
  }
  get title() { return (this.head.querySelector('title') || this.body.querySelector('title'))?.textContent.trim() || ''; }
  querySelectorAll(selector: string): HtmlElement[] { const m = compile(selector); return [this.documentElement, ...this.documentElement.descendants()].filter(m); }
  querySelector(selector: string): HtmlElement | null { return this.querySelectorAll(selector)[0] || null; }
}

// ── selectors: tag, *, [attr], [attr=value] (also ^= $= *= ~=), compound, comma lists ──────────────────────
type Matcher = (e: HtmlElement) => boolean;
const cache = new Map<string, Matcher>();
function compile(selector: string): Matcher {
  const hit = cache.get(selector); if (hit) return hit;
  const alts = selector.split(',').map(s => s.trim()).filter(Boolean).map(part => {
    const m = /^([a-zA-Z][\w-]*|\*)?((?:\[[^\]]+\])*)$/.exec(part);
    if (!m) throw new Error(`Unsupported selector: ${part}`);
    const tag = m[1] && m[1] !== '*' ? m[1].toLowerCase() : '';
    const conds = [...m[2].matchAll(/\[\s*([\w:-]+)\s*(?:([~^$*]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]*)))?\s*\]/g)].map(c => {
      const name = c[1].toLowerCase(), op = c[2], val = (c[3] ?? c[4] ?? c[5] ?? '');
      return (e: HtmlElement) => {
        const v = e.getAttribute(name); if (v === null) return false;
        if (!op) return true;
        const a = name === 'type' ? v.toLowerCase() : v, b = name === 'type' ? val.toLowerCase() : val;   // type values are case-insensitive
        return op === '=' ? a === b : op === '^=' ? !!b && a.startsWith(b) : op === '$=' ? !!b && a.endsWith(b) : op === '*=' ? !!b && a.includes(b) : a.split(/\s+/).includes(b);
      };
    });
    return (e: HtmlElement) => (!tag || e.tagName === tag) && conds.every(c => c(e));
  });
  const fn: Matcher = e => alts.some(a => a(e));
  cache.set(selector, fn); return fn;
}

// ── character references ────────────────────────────────────────────────────────
const C1: Record<number, number> = { 0x80: 0x20ac, 0x82: 0x201a, 0x83: 0x192, 0x84: 0x201e, 0x85: 0x2026, 0x86: 0x2020, 0x87: 0x2021, 0x88: 0x2c6, 0x89: 0x2030, 0x8a: 0x160,
  0x8b: 0x2039, 0x8c: 0x152, 0x8e: 0x17d, 0x91: 0x2018, 0x92: 0x2019, 0x93: 0x201c, 0x94: 0x201d, 0x95: 0x2022, 0x96: 0x2013, 0x97: 0x2014, 0x98: 0x2dc, 0x99: 0x2122,
  0x9a: 0x161, 0x9b: 0x203a, 0x9c: 0x153, 0x9e: 0x17e, 0x9f: 0x178 };

/** Decode character references the way a browser does. In attribute values, a legacy name without ";" followed by a
 * letter, digit or "=" is left alone (so "?a=1&copy=2" in a link stays as written). */
export function decodeEntities(s: string, inAttribute = false): string {
  if (!s.includes('&')) return s;
  const table = entities();
  return s.replace(/&(#[xX][0-9a-fA-F]+;?|#[0-9]+;?|[a-zA-Z][a-zA-Z0-9]*;?)/g, (whole, ref: string, at: number, all: string) => {
    if (ref[0] === '#') {
      const hex = ref[1] === 'x' || ref[1] === 'X', digits = ref.slice(hex ? 2 : 1).replace(/;$/, '');
      let n = digits.length > 8 ? 0x110000 : parseInt(digits, hex ? 16 : 10);
      if (C1[n]) n = C1[n];
      if (n === 0 || n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return '�';
      return String.fromCodePoint(n);
    }
    // Longest name that is an entity: "&notit;" is "¬" followed by "it;".
    for (let len = Math.min(ref.length, LONGEST); len > 0; len--) {
      const name = ref.slice(0, len), v = table.get(name);
      if (v === undefined) continue;
      if (!name.endsWith(';') && inAttribute) {
        const next = all[at + 1 + len];
        if (next !== undefined && /[A-Za-z0-9=]/.test(next)) return whole;
      }
      return v + ref.slice(len);
    }
    return whole;
  });
}

// ── tokenizer + tree ────────────────────────────────────────────────────────────
/** Biggest input parsed; the rest is ignored (emails are rarely over a few hundred KB of HTML). */
const MAX_HTML = 8 * 1024 * 1024;
/** Deepest nesting kept; deeper elements are added flat, so hostile nesting can't exhaust anything. */
const MAX_DEPTH = 512;

export function parseHtml(input: string): HtmlDocument {
  const html = input.length > MAX_HTML ? input.slice(0, MAX_HTML) : input;
  const doc = new HtmlDocument();
  let bodyStarted = false;
  const stack: HtmlElement[] = [];   // open elements below head/body
  const container = () => stack.length ? stack[stack.length - 1] : bodyStarted ? doc.body : doc.head;
  const append = (n: HtmlElement | HtmlText) => { const p = container(); n.parent = p; p.childNodes.push(n); };
  const text = (data: string) => {
    if (!data) return;
    if (!bodyStarted && !stack.length) { if (!data.trim()) return; bodyStarted = true; }
    const p = container(), last = p.childNodes[p.childNodes.length - 1];
    if (last && last.nodeType === 3) last.data += data;
    else append({ nodeType: 3, parent: p, data, get textContent() { return this.data; } } as HtmlText);
  };
  const close = (tag: string) => {   // pop to the nearest open <tag>, if there is one in scope
    for (let i = stack.length - 1; i >= 0; i--) { if (stack[i].tagName === tag) { stack.length = i; return; } if (SCOPE.has(stack[i].tagName) && tag !== stack[i].tagName) return; }
  };

  let i = 0; const n = html.length;
  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt < 0) { text(decodeEntities(html.slice(i))); break; }
    if (lt > i) text(decodeEntities(html.slice(i, lt)));
    i = lt;
    const c = html[i + 1];
    if (html.startsWith('<!--', i)) { const e = html.indexOf('-->', i + 4); i = e < 0 ? n : e + 3; continue; }
    if (c === '!' || c === '?') { const e = html.indexOf('>', i + 2); i = e < 0 ? n : e + 1; continue; }   // doctype, bogus comment
    if (c === '/' && /[a-zA-Z]/.test(html[i + 2] || '')) {
      const m = /^<\/([a-zA-Z][^\s/>]*)[^>]*>?/.exec(html.slice(i, i + 512)) || ['', ''];
      const tag = m[1].toLowerCase(); i += Math.max(m[0].length, 2);
      if (tag === 'body' || tag === 'html' || tag === 'head') { if (tag === 'head' && !stack.length) bodyStarted = true; continue; }
      if (tag === 'p' && !stack.some(e => e.tagName === 'p')) { append(new HtmlElement('p')); continue; }   // a stray </p> makes an empty <p>
      if (tag === 'br') { append(new HtmlElement('br')); continue; }
      close(tag); continue;
    }
    if (!/[a-zA-Z]/.test(c || '')) { text('<'); i++; continue; }

    // Start tag: name, then attributes.
    let j = i + 1; while (j < n && !/[\s/>]/.test(html[j])) j++;
    const tag = html.slice(i + 1, j).toLowerCase(), attrs: HtmlAttr[] = [];
    let selfClose = false;
    for (;;) {
      while (j < n && /[\s/]/.test(html[j])) { if (html[j] === '/' && html[j + 1] === '>') selfClose = true; j++; }
      if (j >= n || html[j] === '>') { j++; break; }
      let k = j; while (k < n && !/[\s/>=]/.test(html[k]) || k === j && html[k] === '=') k++;
      const name = html.slice(j, k).toLowerCase(); j = k;
      while (j < n && /\s/.test(html[j])) j++;
      let value = '';
      if (html[j] === '=') {
        j++; while (j < n && /\s/.test(html[j])) j++;
        const q = html[j];
        if (q === '"' || q === "'") { const e = html.indexOf(q, j + 1); value = html.slice(j + 1, e < 0 ? n : e); j = e < 0 ? n : e + 1; }
        else { k = j; while (k < n && !/[\s>]/.test(html[k])) k++; value = html.slice(j, k); j = k; }
      }
      if (name && !attrs.some(a => a.name === name)) attrs.push({ name, value: decodeEntities(value, true) });   // first one wins, as in browsers
    }
    i = j;

    if (tag === 'html') { for (const a of attrs) if (!doc.documentElement.getAttribute(a.name)) doc.documentElement.attributes.push(a); continue; }
    if (tag === 'head') continue;
    if (tag === 'body') { bodyStarted = true; for (const a of attrs) if (!doc.body.getAttribute(a.name)) doc.body.attributes.push(a); continue; }
    if (!bodyStarted && !stack.length && !HEAD.has(tag)) bodyStarted = true;
    // Implied end tags close only the current element ("<p>a<p>b" is two paragraphs), never through an open <b> or <a>:
    // a browser would re-open those, so the reader still sees one link.
    const implied = CLOSES[tag]; if (implied) while (stack.length && implied.includes(stack[stack.length - 1].tagName)) stack.pop();
    const el = new HtmlElement(tag, attrs);
    append(el);
    if (RAW.has(tag) || RCDATA.has(tag)) {   // raw text up to the matching end tag
      const re = new RegExp(`</${tag}[\\s/>]`, 'ig'); re.lastIndex = i;
      const m = re.exec(html), end = m ? m.index : n;
      const raw = html.slice(i, end);
      if (raw) el.childNodes.push({ nodeType: 3, parent: el, data: RCDATA.has(tag) ? decodeEntities(raw) : raw, get textContent() { return this.data; } } as HtmlText);
      i = m ? html.indexOf('>', m.index) + 1 || n : n;
      continue;
    }
    if (tag === 'plaintext') { el.childNodes.push({ nodeType: 3, parent: el, data: html.slice(i), get textContent() { return this.data; } } as HtmlText); break; }
    // "<div/>" is just "<div>" in HTML; only inside <svg> or <math> does "/>" close an element.
    const closesItself = VOID.has(tag) || (selfClose && (tag === 'svg' || tag === 'math' || isForeign(stack)));
    if (!closesItself && stack.length < MAX_DEPTH) stack.push(el);
  }
  return doc;
}
/** Inside <svg> or <math>, "/>" really does close an element. */
const isForeign = (stack: HtmlElement[]) => stack.some(e => e.tagName === 'svg' || e.tagName === 'math');
