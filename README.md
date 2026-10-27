<p align="center"><img src="assets/logo/phishbowl-logo.svg" alt="Phishbowl" width="520"></p>

# Phishbowl

[![Licence: MIT](https://img.shields.io/badge/licence-MIT-292929.svg)](LICENSE) [![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

Phishbowl analyses phishing emails the way a SOC analyst would. Give it a raw `.eml` or Outlook `.msg` and it runs about 65 checks on the sender, delivery route, spam-filter verdicts, content, links, QR codes and attachments. It gives a verdict (Malicious, Suspicious or Likely legitimate) and writes the report, the customer email and the indicator exports for you.

It is local-first. By default the engine and the CLI make no network connections: the email, its links and its attachments never leave your machine. Attachments are read as data, and nothing is opened, run or rendered. [Online lookups](#online-lookups) (domain age, the sender's DNS, known-phishing feeds) are there if you turn them on, and send domain names only.

```
$ phishbowl suspicious.eml --own northwind.example

suspicious.eml
  MALICIOUS  high confidence · score 73 · 31 of 65 checks flagged (17 red flags)
  Subject    Action required: confirm your bank details before 23 Oct payroll
  From       "Northwind Payroll" <payroll[@]northwind[.]example>
  Sent from  mail[.]northwind-hr-portal[.]test [198[.]51[.]100[.]23]
  Auth       SPF pass  DKIM pass  DMARC fail
  Contains   6 links · 2 attachments · 1 QR code

  Key findings
  ✕ Sent as your own domain          From shows northwind[.]example but it came from outside and DMARC failed …
  ✕ Impersonation with a risky link  The sender pretends to be your organisation and links to a lookalike domain …
  ✕ Password forms                   Payroll_Policy_Oct2026.pdf.html: Password form that sends what you type to …
  …
```

## Install

Phishbowl needs Node.js 22 or later.

```sh
git clone <this repo> phishbowl && cd phishbowl
npm install          # also builds dist/
npm install -g .     # puts `phishbowl` on your PATH (or run `node dist/cli.js`)
```

## Use

```sh
phishbowl email.eml                      # verdict and key findings
phishbowl email.eml --all                # every check, grouped
phishbowl reported-phish/                # a folder: one line per email, then a summary
phishbowl email.eml --json               # the full analysis as JSON
cat email.eml | phishbowl -              # from stdin

phishbowl report email.eml                         # technical report for a colleague or SOC
phishbowl report email.eml --audience mgmt         # plain English for a customer or manager
phishbowl report email.eml --audience staff        # a warning to send to staff
phishbowl report email.eml --markdown --by "SOC" --done block-sender,purge
phishbowl report email.eml --customer-email        # ready to paste: no links, everything defanged

phishbowl iocs email.eml                           # defanged indicator list
phishbowl iocs email.eml --format kql              # also csv, spl, wazuh, stix, json, text
phishbowl iocs threat-report.txt                   # any text works: hxxp and [.] are refanged first

phishbowl ui                                       # the dashboard in your browser, served from this machine
phishbowl ui reported-phish/                       # …with a folder already loaded
phishbowl reported-phish/ --html triage.html       # the dashboard as one HTML file, to attach or embed

phishbowl email.eml --online                       # also look up domain age, DNS and phishing feeds
phishbowl feedback email.eml --says legit          # tell it a verdict was wrong (kept on this machine)
phishbowl feedback                                 # false alarms, misses and allowlist ideas so far
```

**Your domains.** Use `--own northwind.example,northwind.co.uk` to say which domains are yours, so spoofing and lookalikes of them can be caught. You can also set them once, in either of these places:
- the `PHISHBOWL_OWN_DOMAINS` environment variable;
- a config file, either `phishbowl.config.json` in the current folder or `~/.config/phishbowl/config.json` (`%APPDATA%\phishbowl\config.json` on Windows):

```json
{
  "ownDomains": ["northwind.example"],
  "preparedBy": "Northwind SOC",
  "tlp": "amber",
  "allow": { "domains": ["bamboohr.com"], "senders": ["accounts@fabrikam-print.co.uk"] },
  "online": { "enabled": false, "urlhausKey": "" }
}
```

**Exit codes:**

| Code | Meaning |
| --- | --- |
| 0 | Likely legitimate, or the input was text |
| 1 | Error |
| 2 | Suspicious |
| 3 | Malicious |

With several files, the worst result counts. Use `--exit-zero` to always exit 0.

**Getting the email.** In Outlook on the web or the new Outlook, open the message, then **… › Download** for an `.eml`. In classic Outlook, drag the message out to a folder, or **File › Save As**, for a `.msg`. Outlook keeps the original internet headers in a received `.msg`, so every check runs. A `.msg` saved from Drafts or Sent Items has no such headers; Phishbowl reads it anyway and says which checks couldn't run.

**Reported emails.** When a user reports a phish by forwarding it *as an attachment* (the "Report" button, or Forward as Attachment), Phishbowl notices that the email is a report and analyses the attached original instead, noting who reported it. When an attached email is instead part of the attack (an `.eml` or Outlook item attached to hide its links from filters), it is analysed too and its verdict counts. `--json` and the dashboard show both. To treat attached emails as plain files, use the library with `unwrap: 'never'`.

An inline forward ("Fw:" with the original pasted below) loses the original headers. Phishbowl spots this and says so, but ask for the original as an attachment when you can.

### Allowlist

Some senders you trust will always trip a warning or two: an HR system that says "action required", a supplier that sends invoices. List them under `"allow"` in the config: `domains` (subdomains match too) or exact `senders`.

An allowlisted sender only gets a pass when the email is **authenticated** as really coming from them (DMARC pass, or internal mail). Otherwise it gets an extra warning, because impersonating a sender you trust is exactly what an attacker would do. The pass only stops **warnings** from counting toward the verdict; they are still shown. **Red flags still count**, because a trusted supplier's hacked mailbox sends real phishing. Shared domains such as gmail.com, outlook.com or amazonses.com can't be allowlisted as domains; list exact addresses instead. `--no-allow` ignores the list for one run.

### Feedback

When Phishbowl gets one wrong, say so: `phishbowl feedback email.eml --says legit` (or `phish`, or `spam` for unwanted but harmless). Add `--note "why"`, and `--keep` to keep a copy of the email. The dashboard has the same buttons on every email.

Feedback stays on your machine, in `~/.local/share/phishbowl/` (`%LOCALAPPDATA%\phishbowl` on Windows, or `PHISHBOWL_DATA_DIR`). `phishbowl feedback` on its own sums it up:
- the false alarms and the misses;
- which checks cause the false alarms;
- allowlist ideas: authenticated senders you marked legitimate more than once.

`phishbowl feedback --export <folder>` copies the kept emails it got wrong into a folder with an `expected.json`, ready to become test fixtures (make them harmless first if they are going into a public repository).

### Online lookups

Off by default. Turn them on with `--online`, `"online": { "enabled": true }` in the config, `PHISHBOWL_ONLINE=1`, or the **Check online** switch in the dashboard. They add an *Online lookups* group of checks:

| Check | What it asks | Sent to | Effect |
| --- | --- | --- | --- |
| Domain age | when the sender's, Reply-To's, Return-Path's and links' domains were registered (RDAP) | the domain's registry, found through IANA's bootstrap file | red flag (3) under 30 days, warning under 90 |
| Sender domain in DNS | MX, SPF and DMARC records of the sender's domain | a DNS-over-HTTPS resolver (Cloudflare by default, `online.dohUrl`) | red flag if the domain doesn't exist; warning if it can't receive mail |
| Known phishing | whether a link is on the [OpenPhish community feed](https://github.com/openphish/public_feed) | nothing: the feed is **downloaded** every 12 hours and matched here | exact link: critical red flag (6); another phishing URL on the same site: red flag (3) |
| Known phishing (URLhaus) | whether a link's host is on [URLhaus](https://urlhaus.abuse.ch/) | abuse.ch, only with a free Auth-Key (`PHISHBOWL_URLHAUS_KEY` or `online.urlhausKey`) | critical red flag (6) |

What leaves your machine is **domain and host names only**. Email content, addresses, subjects, full URLs (which often carry your address or a token) and attachments are never sent. DNS lookups use only the registrable domain (`example.com`, never `a8f3.track.example.com`), because unique subdomains are a common way to see who looked. Even so, a DNS lookup reaches the domain's own name servers through the resolver, so whoever runs the domain could notice one; leave lookups off when that matters. Your own domains, well-known sites and reserved names (`.test`, `.example`) are never looked up.

Results are cached in `~/.cache/phishbowl/online.json` (`PHISHBOWL_CACHE_DIR`): RDAP for 7 days, DNS for an hour, the feed for 12 hours. A lookup that fails is listed and doesn't change the verdict.

The OpenPhish community feed is free for non-commercial use only ([terms](https://openphish.com/terms.html)). For commercial use, turn feeds off (`"online": { "feeds": false }`) or point `online.feedUrl` at a feed you are licensed for (one URL per line).

## Dashboard

The dashboard shows the same analysis visually: a queue of emails with verdict counts, and a page per email covering the verdict, key findings, every check, headers, links, attachments, content and indicators. Each email also gets a report with "already done" ticks, the customer email, and the exports. Theme: auto, light, dark or night.

It comes in two forms, built from the same files in `assets/dashboard/`.

**Live: `phishbowl ui`.** A small server on `127.0.0.1` (port 8787, or `--port`) opens the dashboard in your browser. Drop `.eml` or `.msg` files on it or paste a raw email. Analysis runs in the server on your machine, and "Save as HTML" writes a snapshot. The **Check online** switch turns on [online lookups](#online-lookups) for the emails you add next (`--online` starts it switched on), and the buttons under each verdict record [feedback](#feedback).

The server has these safeguards:
- It only answers requests addressed to itself, which blocks DNS rebinding.
- Every change needs a custom header, so other websites can't post to it.
- Each page is sent with a strict content security policy.
- Nothing is stored after it stops.
- Leave `--host` alone unless you mean it: binding to another address exposes the server to your network.

**Static: `--html file.html`.** One self-contained file with the analyses inside it. It opens offline and makes no outside connections: its content security policy allows no fonts, images, scripts or requests from anywhere. Attach it to a ticket, or embed it in another platform:

```html
<!-- 1. Embed a saved file (?embed hides the top bar; --embed bakes that in) -->
<iframe src="phishbowl-triage.html?embed" sandbox="allow-scripts allow-downloads" style="width:100%;height:900px;border:0"></iframe>
```

```js
// 2. Or render your own analyses into the embedded page. Only its parent frame is listened to.
import { analyseFile } from 'phishbowl/node';
import { buildView } from 'phishbowl/view';               // display-ready, already defanged
const view = buildView(await analyseFile('email.eml'), { id: 'case-4411', file: 'email.eml' });
iframe.contentWindow.postMessage({ type: 'phishbowl:load', views: [view] }, '*');
// The page tells its parent what the analyst opens: { type: 'phishbowl:selected', id, verdict }
```

Email content is attacker-written, so the dashboard treats it strictly:
- Everything is added to the page as text, never as HTML.
- Every address and link is defanged.
- The email's own HTML is never displayed.

`renderDashboard` (from `phishbowl/dashboard`) builds the static file in your own code.

## What it checks

The full list, with weights, is in [docs/checks.md](docs/checks.md). In short:

- **Sender and authentication**
  - SPF, DKIM, DMARC, and whether they align with From;
  - Microsoft compauth and ARC;
  - spoofing of your own domain;
  - Reply-To and Return-Path, display-name tricks and brand claims;
  - lookalike domains: punycode, homoglyphs, edit distance, brand in subdomain;
  - lookalike letters in names and subjects: Greek or Cyrillic letters, styled maths letters, invisible characters;
  - free mail, no authentication at all, inline forwards.
- **Delivery route:** hops, the entry server, reverse DNS and HELO, TLS, timestamp order, Date skew.
- **Spam filter verdicts:** Microsoft 365 SCL, SFV, CAT, BCL, PTR and IPV, and SpamAssassin-style headers, all in plain English.
- **Content**
  - pressure, credential and money language;
  - business email compromise (gift cards, bank detail changes);
  - callback scams, crypto-wallet recovery-phrase lures;
  - a brand's accounts discussed by a sender the brand doesn't own;
  - hidden text, forms and scripts in the body, tracking pixels, empty messages.
- **Links and QR codes**
  - text vs destination, lookalikes, bare IPs, `user@host`, `javascript:`/`data:`;
  - shorteners, open redirects, free and open hosting, risky TLDs, subdomain chains;
  - your address carried in the link.
  - Safe Links, Google, Proofpoint and Postmark wrappers are unwrapped first. QR codes in PNG and JPEG images are decoded.
- **Attachments**
  - real type from the content vs the declared type vs the extension; double extensions; risky types including `.mobileconfig`; entropy;
  - ZIP listings (encrypted entries, risky files inside);
  - Office macros and remote templates; PDF actions;
  - HTML forms, smuggling patterns and redirects; SVG script; calendar invites;
  - SHA-256, SHA-1 and MD5;
  - attached emails (`.eml`, `message/rfc822`, Outlook items), analysed in their own right.
- **Online lookups** (opt-in): domain age, the sender's DNS, known-phishing feeds.

**The verdict.** A red flag adds its weight to the score (3 unless listed), and a warning adds 1, but wording alone can add at most 2. A red flag weighing 5 or more is critical and makes the email Malicious on its own. Otherwise the email is Malicious at a score of 12, and Suspicious at 6 or with any red flag. Warnings that pile up on ordinary bulk mail are capped: delivery route 1, link hygiene (http links, tracking pixels, your address in a link) 1, and wording 2. So background noise alone never reaches Suspicious.

Checks that are normal for authenticated bulk and SaaS mail relax when the sender is authenticated, such as Return-Path and Message-ID mismatches, click tracking and preview text. Brand impersonation never relaxes, because real phishing often comes through legitimate services.

## Use it as a library

The engine runs in browsers and Node. In Node:

```ts
import { analyseFile, buildReport, reportText, exportAs } from 'phishbowl/node';

const a = await analyseFile('email.eml', {
  ownDomains: ['northwind.example'],
  allow: { domains: ['bamboohr.com'] },          // optional
  online: { cache: fileCache() },                // optional: turns online lookups on (fileCache is from phishbowl/node)
});
if (a.kind === 'email') console.log(a.verdict.v, a.verdict.score, a.checks.filter(c => c.status === 'bad'));
console.log(reportText(buildReport(a, { audience: 'mgmt' })));
console.log(exportAs('stix', a));
```

In a browser, `import { analyse, browserEnv } from 'phishbowl'` and pass `browserEnv()` as `env`. Pass a QR decoder (for example jsQR) to `browserEnv` if you want QR codes read. `.msg` files need the Node host (`env.readMsg`). Online lookups work in browsers too where CORS allows; pass your own `fetch` in `online` to route them through a proxy.

## Testing

```sh
npm test                       # unit, CLI and dashboard tests on test/fixtures (made-up emails modelled on real header patterns)
npm run samples                # fetch the real test emails into samples/ (git ignores it): 1,160 phishing, about 4,170 legitimate
npm run samples -- phishing    # or only one kind
npm run test:real              # score every set; fails if any does worse than scripts/real-baseline.json allows
npm run test:real -- -v        # also list every miss and every false alarm, with their flagged checks
npm run test:real -- --update  # accept the current results as the new baseline
npm run online:live            # try online lookups against the real services (the tests use recorded replies)
```

Every real set is pinned to exact files and versions in `scripts/sample-sets.json`, so results are reproducible. The sets are fetched, never committed, so their licences are respected.

**Real phishing** comes from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot): real phishing and spam collected by honeypots, licensed CC BY-NC 4.0 (non-commercial testing with attribution, no redistribution).

**Real legitimate mail** comes from two sources:
- **The [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)**, through the npm package `@stdlib/datasets-spam-assassin`: 4,150 real legitimate emails from 2002–2006.
  - *easy* is everyday mail;
  - *hard* is legitimate mail that looks like spam (HTML newsletters and marketing), the hardest test of false alarms.
- **Modern messages** with today's authentication headers (DKIM, DMARC, ARC, bounces, calendar invites), taken from the test fixtures of open-source email libraries (MimeKit, mailauth, mailparser, postal-mime, mail; all MIT-style licences).

Current results (v0.3.0; the same as v0.2.0 apart from one more phish caught in validate):

| Set | Kind | Emails | Result |
| --- | --- | --- | --- |
| tuning | phishing | 80 | 77 flagged (96%) |
| unseen | phishing | 80 | 79 flagged (99%) |
| validate | phishing | 500 | 473 flagged (95%) |
| **holdout** | phishing | 500 | **476 flagged (95%)**: scored once with the finished engine, never looked at |
| legit-modern | legitimate | 19 | 17 clean · 2 suspicious (a bounce, an unauthenticated message) · 0 malicious |
| legit-easy-1 | legitimate | 2,500 | 2,498 clean (99.9%) · 2 suspicious · 0 malicious |
| legit-easy-2 | legitimate | 1,400 | 1,393 clean (99.5%) · 7 suspicious · 0 malicious |
| legit-hard | legitimate | 250 | 225 clean (90%) · 24 suspicious · 1 malicious (a blog-update digest of hundreds of raw links) |

How to read these numbers:
- **Use the holdout figure** as the honest estimate for new phishing. The rules were adjusted after looking at tuning, unseen and validate. Replace holdout with a fresh set after the next round of rule changes.
- **Most misses are plain spam** (dating, discounts) rather than phishing, plus brands that aren't on the list.
- **The legitimate corpus predates modern email authentication.** It has no SPF/DKIM/DMARC results, no TLS and only http links, so it understates how much context Phishbowl gets from current mail.
- **Modern legitimate mail is the thinnest set (19).** A folder of your own newsletters and notifications run through `phishbowl folder/ --html check.html` is still the best check.
- **These are offline results.** Online lookups aren't in them: the samples are months or years old, so their domains have long expired or aged and their links have dropped off the feeds.

When you change a rule:
1. Run `npm test` and `npm run test:real -- -v`.
2. Add any email that misbehaved to `test/fixtures` (as a made-up, harmless version) with its expected verdict in `expected.json`. `phishbowl feedback --export` gives you the ones you flagged.
3. Regenerate the checks reference with `npx tsx scripts/list-checks.ts > docs/checks.md`.

## Layout

```
src/
  analyse.ts        entry point: email or text → checks, verdict, indicators
  nested.ts         attached emails: user reports vs attachment attacks
  rtf.ts            Outlook's RTF bodies (and HTML wrapped in RTF) → HTML
  allow.ts          the allowlist
  online.ts         opt-in lookups: RDAP, DNS over HTTPS, phishing feeds, URLhaus
  context.ts        parses once and works out what several checks share (authenticated? forwarded? brand claim?)
  checks/           one module per group: sender, route, filter, content, links, attachments
  verdict.ts        weights and scoring
  mime.ts headers.ts links.ts domains.ts text.ts defang.ts indicators.ts lists.ts
  files/            attachment inspection: type sniffing, ZIP, HTML, hashes
  report/           reports, customer email, exports (KQL, SPL, Wazuh, STIX, CSV, JSON)
  node/             Node host (HTML parsing with linkedom, QR decoding, .msg reading), file helpers,
                    the lookup cache and feedback storage
  view.ts           view model: an analysis as display-ready, defanged data (for the dashboard or any front-end)
  node/dashboard.ts renders the static dashboard and runs the local server (phishbowl ui)
  cli.ts            the phishbowl command
assets/dashboard/   the dashboard page, styles and script (no dependencies, no outside connections)
assets/logo/        the logo: mark and wordmark as SVG (follow light/dark mode) and PNG
test/               node:test suites and fixtures
scripts/            fetch and score the real samples; regenerate docs/checks.md
prototype/          the original single-page browser prototype (superseded by the dashboard)
```

## Roadmap

1. ~~Engine extraction, tests, CI~~
2. ~~CLI~~
3. ~~Local web UI (`phishbowl ui`) and the embeddable HTML dashboard~~
4. ~~Reported-email unwrapping, `.msg`, online lookups, allowlist and feedback~~ (0.3)
5. Campaign view: group a folder of reports by sender infrastructure, links and attachment hashes, so one verdict covers fifty reports.
6. Plugin checks (your own rules in a folder), a Docker image, and the CLI on npm.
7. Opt-in AI checks. Bring your own key or use a local model (Ollama). The model can raise or explain a verdict, never lower one, and content is redacted first.
8. Outlook add-in, then triage of a reported-phishing mailbox through Microsoft Graph.
9. A demo build for the project page on nafthan.co.uk.

## Licence

[MIT](LICENSE): use, change and share it freely, including commercially, as long as the copyright notice stays. Test data fetched by the scripts keeps its own licence (see Testing) and is never committed. The OpenPhish feed used by online lookups is non-commercial only (see Online lookups).

The logo (`assets/logo/`) is part of the project and covered by the same licence.
