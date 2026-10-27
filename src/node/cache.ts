// A small on-disk cache for online lookups, so repeat checks don't repeat requests (and work briefly offline).
// One JSON file: ~/.cache/phishbowl/online.json (XDG_CACHE_HOME, or %LOCALAPPDATA%\phishbowl on Windows).
// It holds domain names, lookup results and the downloaded phishing feed; never email content.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { OnlineCache } from '../online.js';

export function defaultCachePath(): string {
  const base = process.env.PHISHBOWL_CACHE_DIR || (process.platform === 'win32' && process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, 'phishbowl')
    : join(process.env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'phishbowl'));
  return join(base, 'online.json');
}

/** Most entries kept; the oldest go first. */
const MAX_ENTRIES = 5000;

export function fileCache(path = defaultCachePath(), now = () => Date.now()): OnlineCache & { flush(): void } {
  let data: Record<string, { v: unknown; until: number }> = {};
  try { data = JSON.parse(readFileSync(path, 'utf8')); } catch { /* none yet, or unreadable: start empty */ }
  let dirty = false, timer: NodeJS.Timeout | null = null;
  const flush = () => {
    if (!dirty) return; dirty = false;
    const t = now(), live = Object.entries(data).filter(([, e]) => e.until > t).sort((a, b) => b[1].until - a[1].until).slice(0, MAX_ENTRIES);
    data = Object.fromEntries(live);
    try { mkdirSync(dirname(path), { recursive: true }); const tmp = path + '.' + process.pid + '.tmp'; writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 }); renameSync(tmp, path); }
    catch { /* a read-only home is fine: the cache just doesn't persist */ }
  };
  return {
    get: k => { const e = data[k]; return e && e.until > now() ? e.v : undefined; },
    set: (k, v, ttl) => { data[k] = { v, until: now() + ttl }; dirty = true; if (!timer) { timer = setTimeout(() => { timer = null; flush(); }, 200); timer.unref(); } },
    flush: () => { if (timer) { clearTimeout(timer); timer = null; } flush(); },
  };
}
