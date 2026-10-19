// Shared types for the Phishbowl engine.

/** bad: red flag · warn: worth a look · ok: reassuring · info: context · na: not applicable */
export type Status = 'bad' | 'warn' | 'ok' | 'info' | 'na';
export type Group = 'sender' | 'route' | 'filter' | 'content' | 'links' | 'att' | 'online';

export interface Check {
  group: Group;
  /** Stable id, e.g. `sender.dmarc`. Weights and reports refer to it. */
  id: string;
  name: string;
  status: Status;
  /** Plain-English result shown to the analyst. */
  result: string;
  /** Why the check matters, shown when it is flagged. */
  why?: string;
  /** Phrases the check matched (content checks). */
  hits?: string[];
  /** Result came from demo data rather than a live lookup. */
  demo?: boolean;
}

export type Severity = 'bad' | 'warn' | 'info';
/** A finding on one link or attachment: [severity, text, id of the check it rolls up into]. */
export type Finding = [Severity, string, string];

/** [lower-case name, value, name as written]. */
export type Header = [string, string, string];

export interface Hop {
  raw: string;
  /** Name the sending server gave itself. */
  from: string;
  /** Reverse DNS name the receiving server recorded. */
  rdns: string;
  ip: string;
  by: string;
  with: string;
  time: number | null;
  tls: boolean;
}

export interface DkimSignature { d: string; s: string; a: string; h: string }

export interface Auth {
  spf: string;
  dkim: string;
  dmarc: string;
  dmarcAction: string;
  compauth: string;
  compReason: string;
  arc: string;
  mailfrom: string;
  dkimD: string;
  hfrom: string;
  dkimSigs: DkimSignature[];
  raw: string;
}

/** [header it came from, field, value]. */
export type SpamField = [string, string, string];

export interface Link {
  /** Real destination (unwrapped if it went through Safe Links and similar). */
  href: string;
  /** Original wrapped URL, if it was unwrapped. */
  wrapped: string;
  /** Name of the wrapper it was unwrapped from. */
  unwrapped: string;
  /** Text the reader sees. */
  text: string;
  /** Where it was found, e.g. "email (HTML)" or "QR code in scan.png". */
  source: string;
  findings: Finding[];
}

export interface RawAttachment {
  name: string;
  declared: string;
  inline: boolean;
  cid: string;
  bytes: Uint8Array;
}

export interface HtmlForm { action: string; method: string; password: boolean }
export interface HtmlInfo {
  forms: HtmlForm[];
  scripts: number;
  handlers: number;
  patterns: string[];
  bigB64: number;
  dl: number;
  refresh: string;
  iframes: string[];
  extScripts: string[];
  links: string[];
  title: string;
}

export interface ZipEntry { name: string; encrypted: boolean; method: number; csize: number; usize: number; off: number }

export interface Attachment extends RawAttachment {
  size: number;
  /** What the content really is, e.g. "HTML page". */
  what: string;
  /** Content family, e.g. `html`, `pdf`, `zip`; empty if unknown. */
  fam: string;
  ext: string;
  notes: Finding[];
  extra: { entropy: number; zip?: ZipEntry[]; office?: boolean; urls?: string[]; html?: HtmlInfo; qr?: string };
  sha256: string;
  sha1: string;
  md5: string;
}

export type VerdictName = 'malicious' | 'suspicious' | 'clean';
export interface Verdict {
  v: VerdictName;
  score: number;
  conf: 'high' | 'medium';
  bad: number;
  warn: number;
  ok: number;
  /** Checks that applied (everything except `na`). */
  run: number;
}

export type IndicatorType = 'url' | 'domain' | 'ipv4' | 'ipv6' | 'email' | 'sha256' | 'sha1' | 'md5' | 'cve' | 'attack';
export interface IndicatorNote { t: string; warn?: boolean }
export interface Indicator {
  type: IndicatorType;
  value: string;
  count: number;
  at: number;
  len: number;
  notes: IndicatorNote[];
  /** Reason it is left out of exports by default (private IP, well-known site…), or null if included. */
  off: string | null;
  from: string[];
  ctx: { pre: string; hit: string; post: string };
}

export interface EmailAnalysis {
  kind: 'email';
  checks: Check[];
  verdict: Verdict;
  headers: Header[];
  auth: Auth;
  spam: SpamField[];
  hops: Hop[];
  entry: Hop | null;
  from: string;
  fromName: string;
  fromAddr: string;
  fromDom: string;
  replyTo: string;
  rp: string;
  to: string;
  subj: string;
  date: string;
  mid: string;
  mailer: string;
  /** The From address if it spoofs one of your own domains. */
  spoofed: string;
  /** Plain text of the message. */
  body: string;
  html: string[];
  links: Link[];
  atts: Attachment[];
  /** Attachments a person would see (not inline images, unless they hold a QR code). */
  real: Attachment[];
  /** Readable summary the indicator extractor runs over. */
  text: string;
  indicators: Indicator[];
  ms: number;
}

export interface TextAnalysis {
  kind: 'text';
  text: string;
  indicators: Indicator[];
  ms: number;
}

export type Analysis = EmailAnalysis | TextAnalysis;

/** What the engine needs from its host. The browser and Node supply different implementations. */
export interface Env {
  /** Parse HTML inertly (no scripts run, nothing loads). */
  parseHtml(html: string): Document;
  /** Decode a QR code in an image, if the host can. */
  decodeQR?(bytes: Uint8Array, mime: string): Promise<string | null>;
}

export interface LeaveOut {
  /** Private and internal IPs. Default true. */
  private?: boolean;
  /** Well-known sites and your own domains. Default true. */
  known?: boolean;
  /** Names that are probably files (.zip, .mov). Default true. */
  files?: boolean;
}

export interface AnalyseOptions {
  env: Env;
  /** Your organisation's domains, used to spot spoofing and lookalikes. */
  ownDomains?: string[];
  leaveOut?: LeaveOut;
}
