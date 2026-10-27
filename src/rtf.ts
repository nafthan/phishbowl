// Just enough RTF to analyse an Outlook body.
//
// Outlook usually stores an email body as compressed RTF. For HTML emails, that RTF wraps the original HTML
// ("\fromhtml1", Microsoft's [MS-OXRTFEX]): HTML markup sits in \*\htmltag groups, the text between is ordinary RTF
// text, and \htmlrtf ... \htmlrtf0 marks RTF-only formatting to drop. rtfToHtml() unwraps that.
// For plain RTF it returns the text as simple HTML, with HYPERLINK fields turned into <a> links so link checks still
// work. Nothing else is interpreted: no objects, pictures or other field codes.

/** Destinations whose content is never text. */
const SKIP = new Set(['fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'object', 'header', 'footer', 'headerl', 'headerr', 'footerl', 'footerr',
  'listtable', 'listoverridetable', 'rsidtbl', 'generator', 'themedata', 'colorschememapping', 'datastore', 'latentstyles', 'xmlnstbl', 'mmathPr', 'mhtmltag']);
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const MAX_OUT = 4 * 1024 * 1024;

/** \ansicpgN → a decoder for \'hh bytes. */
function decoderFor(cp: number): TextDecoder {
  const label = ({ 932: 'shift_jis', 936: 'gbk', 949: 'euc-kr', 950: 'big5', 65001: 'utf-8' } as Record<number, string>)[cp] || (cp >= 1250 && cp <= 1258 ? 'windows-' + cp : 'windows-1252');
  try { return new TextDecoder(label); } catch { return new TextDecoder('windows-1252'); }
}

interface State { skip: boolean; htmltag: boolean; htmlrtf: boolean; uc: number; fld: '' | 'inst' | 'rslt' }

/** RTF as a binary string (one character per byte of the decompressed RTF) → HTML for analysis. */
export function rtfToHtml(rtf: string): { html: string; fromHtml: boolean } {
  const head = rtf.slice(0, 4096), fromHtml = /\\fromhtml1/.test(head);
  const decoder = decoderFor(+((head.match(/\\ansicpg(\d+)/) || [])[1] || 1252));
  const stack: State[] = [];
  let st: State = { skip: false, htmltag: false, htmlrtf: false, uc: 1, fld: '' };
  let out = '', bytes: number[] = [], skipChars = 0, fldInst = '', fldText = '';

  const visible = () => !st.skip && (st.htmltag || !st.htmlrtf);
  /** Text: raw inside an HTML tag group, escaped everywhere else. */
  const text = (t: string) => {
    if (!t || !visible()) return;
    if (st.fld === 'inst') { fldInst += t; return; }
    if (st.fld === 'rslt') { fldText += t; return; }
    out += fromHtml && st.htmltag ? t : esc(t);
  };
  const flush = () => { if (bytes.length) { const b = bytes; bytes = []; text(decoder.decode(new Uint8Array(b))); } };

  for (let i = 0; i < rtf.length && out.length < MAX_OUT; i++) {
    const ch = rtf[i];
    if (ch === '{') { flush(); stack.push(st); st = { ...st }; continue; }
    if (ch === '}') {
      flush();
      const closing = st;
      st = stack.pop() || st;
      if (closing.fld === 'rslt' && st.fld !== 'rslt') {   // a field result just ended: write its link
        const url = (fldInst.match(/HYPERLINK\s+(?:\\[a-z]\s+)*"([^"]+)"/i) || [])[1];
        if (!st.skip) out += url ? `<a href="${esc(url)}">${esc(fldText.trim() || url)}</a>` : esc(fldText);
        fldInst = ''; fldText = '';
      }
      continue;
    }
    if (ch === '\r' || ch === '\n') continue;
    if (ch !== '\\') { if (skipChars > 0) { skipChars--; continue; } flush(); text(ch); continue; }

    const next = rtf[i + 1];
    if (next === "'") {   // \'hh: one byte in the document's code page
      const hex = rtf.substr(i + 2, 2); i += 3;
      if (skipChars > 0) { skipChars--; continue; }
      if (/^[0-9a-f]{2}$/i.test(hex) && visible()) bytes.push(parseInt(hex, 16));
      continue;
    }
    flush();
    if (next === '\\' || next === '{' || next === '}') { i++; if (skipChars > 0) skipChars--; else text(next); continue; }
    if (next === '~') { i++; text(' '); continue; }
    if (next === '*') { i++; st.skip = true; continue; }   // ignorable destination, unless a word below re-enables it
    const m = /^\\([a-zA-Z]{1,32})(-?\d{1,10})? ?/.exec(rtf.slice(i, i + 48));
    if (!m) { i++; continue; }
    i += m[0].length - 1;
    const word = m[1], arg = m[2] === undefined ? null : Number(m[2]);
    switch (word) {
      case 'htmltag': st.skip = false; st.htmltag = true; break;
      case 'htmlrtf': st.htmlrtf = arg !== 0; break;
      case 'fldinst': st.skip = false; st.fld = 'inst'; break;
      case 'fldrslt': st.skip = false; st.fld = 'rslt'; break;
      case 'par': case 'line': if (visible() && !st.fld) out += fromHtml ? '\n' : '<br>\n'; break;
      case 'tab': text('\t'); break;
      case 'uc': st.uc = Math.max(0, arg ?? 1); break;
      case 'u': text(String.fromCharCode((arg ?? 0) < 0 ? (arg as number) + 65536 : arg ?? 0)); skipChars = st.uc; break;
      case 'bin': i += Math.max(0, Math.min(arg ?? 0, rtf.length)); break;
      default: if (SKIP.has(word)) st.skip = true;
    }
  }
  flush();
  return { html: fromHtml ? out : `<html><body><div>${out}</div></body></html>`, fromHtml };
}
