// What a file really is, judged by its content (magic bytes), not its name.
import { latin } from '../mime.js';

export function sniff(b: Uint8Array): [string, string] {
  const h = b.slice(0, 8), head = latin(b.slice(0, 512)).replace(/^﻿/, '').trimStart().toLowerCase();
  if (h[0] === 0x4d && h[1] === 0x5a) return ['Windows program (MZ)', 'exe'];
  if (h[0] === 0x50 && h[1] === 0x4b && h[2] === 3 && h[3] === 4) return ['ZIP archive', 'zip'];
  if (head.startsWith('%pdf')) return ['PDF document', 'pdf'];
  if (h[0] === 0x89 && head.slice(1, 4) === 'png') return ['PNG image', 'png'];
  if (h[0] === 0xff && h[1] === 0xd8) return ['JPEG image', 'jpg'];
  if (head.startsWith('gif8')) return ['GIF image', 'gif'];
  if (h[0] === 0xd0 && h[1] === 0xcf && h[2] === 0x11 && h[3] === 0xe0) return ['Older Office / OLE file', 'ole'];
  if (head.startsWith('rar!')) return ['RAR archive', 'rar'];
  if (h[0] === 0x37 && h[1] === 0x7a && h[2] === 0xbc && h[3] === 0xaf) return ['7-Zip archive', '7z'];
  if (h[0] === 0x4c && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 1 && h[5] === 0x14) return ['Windows shortcut (LNK)', 'lnk'];
  if (b.length > 0x8006 && latin(b.slice(0x8001, 0x8006)) === 'CD001') return ['Disk image (ISO)', 'iso'];
  if (head.startsWith('{\\rtf')) return ['Rich Text (RTF)', 'rtf'];
  if (head.startsWith('begin:vcalendar')) return ['Calendar invite (ICS)', 'ics'];
  if (/^<svg|^<\?xml[^>]*>\s*<svg/.test(head)) return ['SVG image', 'svg'];
  if (/^(<!doctype html|<html|<head|<body|<script|<meta|<form|<div|<p[ >])/.test(head)) return ['HTML page', 'html'];
  return ['Unknown or plain text', ''];
}

/** Declared MIME type → content family. */
export const DECLARED: Record<string, string> = {
  'application/pdf': 'pdf', 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'text/html': 'html', 'image/svg+xml': 'svg',
  'application/zip': 'zip', 'application/x-zip-compressed': 'zip', 'application/x-msdownload': 'exe', 'application/rtf': 'rtf', 'application/msword': 'ole', 'text/calendar': 'ics',
  'application/vnd.ms-excel': 'ole', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'zip', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'zip',
};
/** File extension → content family. */
export const EXT_FAMILY: Record<string, string> = {
  pdf: 'pdf', png: 'png', jpg: 'jpg', jpeg: 'jpg', gif: 'gif', html: 'html', htm: 'html', shtml: 'html', svg: 'svg', zip: 'zip', docx: 'zip', xlsx: 'zip', pptx: 'zip',
  docm: 'zip', xlsm: 'zip', exe: 'exe', scr: 'exe', dll: 'exe', doc: 'ole', xls: 'ole', ppt: 'ole', msg: 'ole', rar: 'rar', '7z': '7z', lnk: 'lnk', iso: 'iso', img: 'iso', rtf: 'rtf', ics: 'ics',
};
export const RISKY: { high: Record<string, string>; med: Record<string, string> } = {
  high: {
    exe: 'a Windows program', scr: 'a screensaver program', com: 'a program', pif: 'a program shortcut', bat: 'a batch script', cmd: 'a batch script', ps1: 'a PowerShell script',
    js: 'a JavaScript file that Windows runs directly', jse: 'an encoded script', vbs: 'a VBScript file', vbe: 'an encoded VBScript file', wsf: 'a Windows script', hta: 'an HTML application that runs with full rights',
    lnk: 'a shortcut that can run commands', iso: 'a disk image (often used to get round Mark-of-the-Web)', img: 'a disk image', vhd: 'a disk image', vhdx: 'a disk image', msi: 'an installer',
    dll: 'a program library', cpl: 'a Control Panel program', jar: 'a Java program', xll: 'an Excel add-in that runs code', one: 'a OneNote file (used to hide scripts)',
    mobileconfig: 'an Apple configuration profile, which can install a VPN, certificates or device management on an iPhone or Mac',
    html: 'an HTML page, common for fake sign-in pages and HTML smuggling', htm: 'an HTML page, common for fake sign-in pages and HTML smuggling', shtml: 'an HTML page', svg: 'an SVG image, which can carry script',
  },
  med: {
    zip: 'an archive', rar: 'an archive', '7z': 'an archive', docm: 'a Word document with macros', xlsm: 'an Excel workbook with macros', pptm: 'a PowerPoint with macros',
    doc: 'an older Word document (can hold macros)', xls: 'an older Excel workbook (can hold macros)', rtf: 'an RTF document (used in exploits)',
  },
};
