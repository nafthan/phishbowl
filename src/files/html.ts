// HTML (attachment or SVG): forms, scripts and the patterns used for smuggling and redirects. Parsed inertly.
import type { Env, HtmlInfo } from '../types.js';
import { parseHtml } from '../html.js';

export function inspectHtml(text: string, env: Env): HtmlInfo {
  const doc = (env.parseHtml ?? parseHtml)(text);
  const forms = [...doc.querySelectorAll('form')].map(f => ({ action: f.getAttribute('action') || '(same page)', method: (f.getAttribute('method') || 'get').toUpperCase(), password: !!f.querySelector('input[type=password]') }));
  const scripts = [...doc.querySelectorAll('script')], inline = scripts.map(s => s.textContent || '').join('\n');
  const handlers = [...doc.querySelectorAll('*')].filter(e => [...e.attributes].some(a => /^on/i.test(a.name))).length;
  const patterns = ([
    [/\batob\s*\(/, 'decodes base64 at runtime (atob)'], [/new\s+Blob\s*\(/, 'builds a file in the browser (Blob)'], [/createObjectURL/, 'turns built data into a download link'],
    [/msSaveOrOpenBlob|navigator\.msSaveBlob/, 'saves a built file straight to disk'], [/\beval\s*\(|new\s+Function\s*\(/, 'runs code built at runtime (eval)'],
    [/unescape\s*\(|String\.fromCharCode/, 'decodes obfuscated text'], [/document\.write\s*\(/, 'writes the page at runtime'],
    [/(?:window\.|document\.)?location(?:\.href)?\s*=|location\.replace\s*\(/, 'redirects the browser'], [/fetch\s*\(|XMLHttpRequest|sendBeacon/, 'sends data to a server'],
  ] as [RegExp, string][]).filter(([re]) => re.test(inline)).map(([, t]) => t);
  const bigB64 = (text.match(/[A-Za-z0-9+/]{4000,}={0,2}/g) || []).length;
  const dl = doc.querySelectorAll('a[download]').length;
  const meta = [...doc.querySelectorAll('meta')].find(m => /^refresh$/i.test(m.getAttribute('http-equiv') || ''));
  const refresh = meta ? meta.getAttribute('content') || '' : '';
  const iframes = [...doc.querySelectorAll('iframe[src]')].map(i => i.getAttribute('src') || '');
  const extScripts = scripts.filter(s => s.getAttribute('src')).map(s => s.getAttribute('src') || '');
  const links = [...doc.querySelectorAll('a[href]')].map(a => a.getAttribute('href') || '');
  const title = ((doc.querySelector('title') || {}).textContent || '').trim();
  return { forms, scripts: scripts.length, handlers, patterns, bigB64, dl, refresh, iframes, extScripts, links, title };
}
