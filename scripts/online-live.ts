// Try the online lookups against the real services: `npm run online:live`.
// Builds a harmless test email whose link is the first URL on today's OpenPhish feed (it is never opened, only
// compared), runs the analysis with lookups on, and prints the online checks. Lookups that fail are listed.
import { analyseBytes, memoryCache } from '../src/node/index.js';
import { loadFeed } from '../src/online.js';
import type { EmailAnalysis } from '../src/types.js';

const cache = memoryCache();
const feed = await loadFeed({ cache });
console.log(`OpenPhish feed: ${feed.length} URLs`);
const target = feed.find(u => /^https?:\/\/[^/]+\.[a-z]{2,}\//i.test(u)) || feed[0];
const host = new URL(target).hostname;
const eml = [`From: "Test" <test@${host}>`, 'To: you@example.com', 'Subject: online lookup test', 'Date: Mon, 19 Oct 2026 10:00:00 +0000',
  'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', '', `<a href="${target}">link</a>`].join('\r\n');
const a = await analyseBytes(new TextEncoder().encode(eml), { online: { cache } }) as EmailAnalysis;
for (const c of a.checks.filter(c => c.group === 'online')) console.log(`${c.status.padEnd(4)} ${c.id.padEnd(20)} ${c.result}`);
console.log(`verdict: ${a.verdict.v} (score ${a.verdict.score})`);
