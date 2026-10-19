// Text helpers: Unicode folding, brand matching and script tricks.
import { CONFUSABLE } from './lists.js';

const INVISIBLE = /[­​-‏⁠-⁯︀-️﻿]|[\u{E0000}-\u{E01EF}]/gu;

/** Undo the usual disguises: invisible characters, accents, styled maths letters, Greek and Cyrillic lookalikes. */
export const fold = (s: string): string => String(s || '').replace(INVISIBLE, '').normalize('NFKD').replace(/[̀-ͯ]/g, '')
  .replace(/[^\x00-\x7f]/g, c => CONFUSABLE[c] || c);

/** First brand from `list` that appears as a whole word (multi-word brands also match without spaces). */
export const findBrand = (text: string, list: string[]): string | undefined => {
  const t = ' ' + fold(text).toLowerCase().replace(/[^a-z0-9]+/g, ' ') + ' ';
  return list.find(b => t.includes(' ' + b + ' ') || (b.includes(' ') && t.includes(' ' + b.replace(/ /g, '') + ' ')));
};

/** Describes a trick used to slip past keyword filters, or ''. */
export const scriptTrick = (input: string): string => {
  const s = String(input || '');
  if (/\w[­​-‏⁠-⁯︀-️]|\w(?:[\u{E0000}-\u{E01EF}])/u.test(s)) return 'hides invisible characters inside words';
  if (/[\u{1D400}-\u{1D7FF}]/u.test(s)) return 'uses styled "maths" letters instead of normal ones';
  const w = s.split(/[\s.,:;!?()[\]"'–—-]+/).find(x => /[A-Za-z]/.test(x) && /[Ͱ-ϿЀ-ӿ]/.test(x));
  return w ? `mixes Latin with Cyrillic or Greek letters in "${w}"` : '';
};

export const uniq = (a: string[]): string[] => [...new Set(a.map(s => s.toLowerCase()))];
export const plural = (n: number, one: string, many = one + 's'): string => `${n} ${n === 1 ? one : many}`;
