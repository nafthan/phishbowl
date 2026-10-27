// One attachment: what is it really, and what is inside? Nothing is opened, run or rendered.
import { defang, defangAll, RE } from '../defang.js';
import { latin, utf8 } from '../mime.js';
import { entropy, hashes } from './hash.js';
import { inspectHtml } from './html.js';
import { DECLARED, EXT_FAMILY, RISKY, sniff } from './sniff.js';
import { zipList, zipRead } from './zip.js';
import type { Attachment, Env, Finding, RawAttachment, Severity } from '../types.js';

const art = (w: string): string => (/^([aeiou]|[FHLMNRSX][A-Z]{1,4}\b)/.test(w) ? 'an ' : 'a ') + (/^[A-Z]{2,}/.test(w) ? w : w.charAt(0).toLowerCase() + w.slice(1));

export async function inspectAttachment(a: RawAttachment, env: Env): Promise<Attachment> {
  const [what, fam] = sniff(a.bytes), notes: Finding[] = [], extra: Attachment['extra'] = { entropy: 0 };
  const exts = (a.name.toLowerCase().match(/\.([a-z0-9]{1,12})(?=\.|$)/g) || []).map(e => e.slice(1)), ext = exts[exts.length - 1] || '';
  const add = (sev: Severity, t: string, id: string) => notes.push([sev, t, id]);

  if (exts.length >= 2 && EXT_FAMILY[exts[exts.length - 2]] && exts[exts.length - 2] !== ext) add('bad', `Double extension: looks like .${exts[exts.length - 2]} but is really .${ext}`, 'att.double');
  const decl = DECLARED[a.declared];
  if (decl && fam && decl !== fam) add('bad', `Says it is ${a.declared} but the content is ${art(what)}`, 'att.mismatch');
  if (!fam && /^(pdf|docx?|xlsx?|pptx?|zip|png|jpe?g)$/.test(ext) && a.bytes.length > 512) add('bad', `Named .${ext} but the content isn't one${entropy(a.bytes) > 7.5 ? ': it looks encrypted or packed' : ''}`, 'att.mismatch');
  if (fam && EXT_FAMILY[ext] && EXT_FAMILY[ext] !== fam && !(fam === 'zip' && /^(docx|xlsx|pptx|docm|xlsm|pptm)$/.test(ext))) add('bad', `Named .${ext} but the content is ${art(what)}`, 'att.mismatch');
  const rf = /^(docx|xlsx|pptx)$/.test(ext) ? '' : fam;   // OOXML is a zip inside; judge it by its macros, not as an archive
  const risk = RISKY.high[ext] || RISKY.high[rf] ? 'bad' : RISKY.med[ext] || RISKY.med[rf] ? 'warn' : null;
  if (risk) { const list = RISKY[risk === 'bad' ? 'high' : 'med']; add(risk, 'This is ' + (list[ext] || list[rf]), 'att.risky'); }

  const ent = entropy(a.bytes); extra.entropy = ent;
  if (ent > 7.6 && !/^(zip|png|jpg|gif|pdf|7z|rar)$/.test(fam) && a.bytes.length > 2048) add('warn', `Very random content (entropy ${ent.toFixed(2)} of 8): could be encrypted or packed`, 'att.entropy');

  if (fam === 'zip') {
    const list = zipList(a.bytes) || []; extra.zip = list;
    if (list.some(e => e.encrypted)) add('bad', 'Password-protected archive: email filters and antivirus can\'t look inside', 'att.zip-encrypted');
    const inner = list.filter(e => { const x = (e.name.toLowerCase().match(/\.([a-z0-9]+)$/) || [])[1]; return !!x && !!RISKY.high[x]; });
    if (inner.length) add('bad', 'Contains risky files: ' + inner.map(e => e.name).join(', '), 'att.zip-risky');
    if (list.some(e => e.name === '[Content_Types].xml')) {
      extra.office = true;
      if (list.some(e => /vbaProject\.bin$/i.test(e.name))) add('bad', 'Office document with macros (vbaProject.bin)', 'att.macros');
      for (const e of list.filter(x => /\.rels$/i.test(x.name))) {
        const xml = await zipRead(a.bytes, e);
        for (const m of xml.matchAll(/<Relationship\b[^>]*>/gi)) {
          const tag = m[0], target = (tag.match(/Target="([^"]+)"/i) || [])[1] || '', type = (tag.match(/Type="([^"]+)"/i) || [])[1] || '';
          if (!/TargetMode="External"/i.test(tag) || !/^(https?|file|\\\\)/i.test(target)) continue;
          if (/attachedTemplate|oleObject|frame|subDocument/i.test(type)) add('bad', `Loads a remote ${type.split('/').pop()} from ${target} when opened (template injection)`, 'att.remote-template');
          else (extra.urls = extra.urls || []).push(target);
        }
      }
    }
  }
  if (fam === 'ole') { const t = latin(a.bytes); if (/_VBA_PROJECT|VBA\x00|Attribute VB_/.test(t)) add('bad', 'Older Office file with macros (VBA project found)', 'att.macros'); }
  if (fam === 'pdf') {
    const t = latin(a.bytes), hit = (k: string) => new RegExp('/' + k + '\\b').test(t);
    const act = ([['JavaScript', 'runs JavaScript'], ['JS', 'runs JavaScript'], ['OpenAction', 'does something as soon as it opens'], ['AA', 'has automatic actions'],
      ['Launch', 'can launch programs'], ['EmbeddedFile', 'has a file hidden inside'], ['SubmitForm', 'can send form data to a server'], ['XFA', 'uses XFA forms']] as [string, string][])
      .filter(([k]) => hit(k)).map(([, d]) => d);
    if (act.length) add(act.some(d => /JavaScript|launch|hidden/.test(d)) ? 'bad' : 'warn', 'PDF ' + [...new Set(act)].join(', '), 'att.pdf-active');
    extra.urls = [...t.matchAll(/\/URI\s*\(([^)]+)\)/g)].map(m => m[1]);
    if (extra.urls.length) add('info', `PDF contains ${extra.urls.length} link${extra.urls.length > 1 ? 's' : ''}`, 'att.pdf-links');
  }
  if (fam === 'html' || fam === 'svg') {
    const h = inspectHtml(utf8(a.bytes), env); extra.html = h;
    extra.urls = [...h.links, ...h.iframes, ...h.extScripts].filter(u => /^https?:/i.test(u));   // form actions are listed separately
    for (const f of h.forms) add(f.password ? 'bad' : 'warn', `${f.password ? 'Password form' : 'Form'} that sends what you type to ${/^https?:/i.test(f.action) ? defang('url', f.action) : f.action}`, f.password ? 'att.cred-form' : 'att.form');
    const smuggle = h.patterns.filter(p => /Blob|download|disk|base64/.test(p));
    if (smuggle.length >= 2 || h.bigB64 || (h.dl && smuggle.length)) add('bad', 'HTML smuggling: ' + [...smuggle, h.bigB64 ? 'carries a large base64 blob' : ''].filter(Boolean).join(', '), 'att.smuggling');
    else if (h.patterns.length) add('warn', 'Script ' + h.patterns.join(', '), 'att.script');
    if (fam === 'svg' && (h.scripts || h.handlers)) add('bad', 'SVG image that contains script', 'att.svg-script');
    if (h.refresh) add('warn', 'Redirects automatically (meta refresh) to ' + defangAll(h.refresh), 'att.refresh');
  }
  if (fam === 'ics') { const t = utf8(a.bytes); extra.urls = t.match(RE.url) || []; add('warn', 'Calendar invite: these land in the calendar even if the email is deleted', 'att.ics'); }
  if (/^(png|jpg|gif)$/.test(fam) && env.decodeQR) {
    let q: string | null = null;
    try { q = await env.decodeQR(a.bytes, a.declared || 'image/' + fam); } catch { q = null; }
    if (q) { extra.qr = q; add(/^https?:/i.test(q) ? 'warn' : 'info', 'Image contains a QR code: ' + defangAll(q), 'att.qr'); }
  }
  return { ...a, size: a.bytes.length, what, fam, ext, notes, extra, ...(await hashes(a.bytes)) };
}
