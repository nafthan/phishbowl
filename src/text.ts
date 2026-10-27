// Text helpers: Unicode folding, brand matching and script tricks.
import { CONFUSABLE } from './lists.js';

const INVISIBLE = /[\u00ad\u200b-\u200f\u2060-\u206f\ufe00-\ufe0f\ufeff]|[\u{E0000}-\u{E01EF}]/gu;

/** Undo the usual disguises: invisible characters, accents, styled maths letters, Greek and Cyrillic lookalikes. */
export const fold = (s: string): string => String(s || '').replace(INVISIBLE, '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
  .replace(/[^\x00-\x7f]/g, c => CONFUSABLE[c] || c);

/** First brand from `list` that appears as a whole word (multi-word brands also match without spaces). */
export const findBrand = (text: string, list: string[]): string | undefined => {
  const t = ' ' + fold(text).toLowerCase().replace(/[^a-z0-9]+/g, ' ') + ' ';
  const words = t.trim().split(' ');
  // Brands written as one word also match when split ("Royal Mail" → royalmail), but only across whole words.
  const joined = (b: string) => b.length >= 6 && words.some((_, i) => { let s = ''; for (let j = i; j < Math.min(words.length, i + 3); j++) { s += words[j]; if (s === b) return true; } return false; });
  return list.find(b => t.includes(' ' + b + ' ') || (b.includes(' ') && t.includes(' ' + b.replace(/ /g, '') + ' ')) || (!b.includes(' ') && joined(b)));
};

/** Describes a trick used to slip past keyword filters, or ''. */
export const scriptTrick = (input: string): string => {
  const s = String(input || '');
  if (/\w[\u00ad\u200b-\u200f\u2060-\u206f\ufe00-\ufe0f]|\w(?:[\u{E0000}-\u{E01EF}])/u.test(s)) return 'hides invisible characters inside words';
  if (/[\u{1D400}-\u{1D7FF}]/u.test(s)) return 'uses styled "maths" letters instead of normal ones';
  if (/\p{L}[\u0334-\u0338\u20d2\u20d3\u20e5\u20e6]/u.test(s)) return 'strikes through letters with overlay marks (like "e̷")';
  const w = s.split(/[\s.,:;!?()[\]"'–—-]+/).find(x => /[A-Za-z]/.test(x) && /[\u0370-\u03ff\u0400-\u04ff]/.test(x));
  return w ? `mixes Latin with Cyrillic or Greek letters in "${w}"` : '';
};

export const uniq = (a: string[]): string[] => [...new Set(a.map(s => s.toLowerCase()))];
export const plural = (n: number, one: string, many = one + 's'): string => `${n} ${n === 1 ? one : many}`;
