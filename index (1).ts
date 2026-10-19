// Phishbowl engine. Runs in browsers and Node: pass an Env that can parse HTML (and optionally decode QR codes).
// In Node, `phishbowl/node` provides a ready-made Env and file helpers.
export { analyse } from './analyse.js';
export { verdictOf, keyFindings, weightOf, WEIGHT, GROUPS, VERDICT_LABEL, CONTENT_WARN_CAP, MALICIOUS_SCORE, SUSPICIOUS_SCORE } from './verdict.js';
export { extract, included, TYPES, TYPE_LABEL } from './indicators.js';
export { defang, defangAll, refang } from './defang.js';
export { buildReport, reportText, reportMarkdown, type Audience, type ReportOptions, type Report, ACTIONS } from './report/report.js';
export { buildCustomerEmail, type CustomerEmail } from './report/customer.js';
export { EXPORTS, exportAs, toJSON, type ExportFormat } from './report/exports.js';
export { TLP_LABEL, type Tlp, type Action } from './report/report.js';
export { SPAM_MEANING } from './headers.js';
export * from './types.js';

/** An Env for browsers, using the built-in DOMParser. Supply decodeQR yourself (for example with jsQR). */
export const browserEnv = (decodeQR?: (bytes: Uint8Array, mime: string) => Promise<string | null>) => ({
  parseHtml: (html: string) => new DOMParser().parseFromString(html, 'text/html'),
  ...(decodeQR ? { decodeQR } : {}),
});
