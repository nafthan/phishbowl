# Phishbowl

Phishbowl analyses phishing emails the way a SOC analyst would. Give it a raw `.eml` and it runs about 65 checks on the sender, delivery route, spam-filter verdicts, content, links, QR codes and attachments. It gives a verdict (Malicious, Suspicious or Likely legitimate) and writes the report, the customer email and the indicator exports for you.

It is local-first. The engine and the CLI make no network connections: the email, its links and its attachments never leave your machine. Attachments are read as data, and nothing is opened, run or rendered.

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
```

**Your domains.** Use `--own northwind.example,northwind.co.uk` to say which domains are yours, so spoofing and lookalikes of them can be caught. You can also set them once, in either of these places:
- the `PHISHBOWL_OWN_DOMAINS` environment variable;
- a config file, either `phishbowl.config.json` in the current folder or `~/.config/phishbowl/config.json` (`%APPDATA%\phishbowl\config.json` on Windows):

```json
{ "ownDomains": ["northwind.example"], "preparedBy": "Northwind SOC", "tlp": "amber" }
```

**Exit codes:**

| Code | Meaning |
| --- | --- |
| 0 | Likely legitimate, or the input was text |
| 1 | Error |
| 2 | Suspicious |
| 3 | Malicious |

With several files, the worst result counts. Use `--exit-zero` to always exit 0.

**Getting an .eml.** In Outlook on the web or the new Outlook, open the message, then **… › Download**. Classic Outlook's `.msg` files aren't supported yet.

An inline forward ("Fw:" with the original pasted below) loses the original headers. Phishbowl spots this and says so, but ask for the original as an attachment when you can.

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
  - SHA-256, SHA-1 and MD5.

**The verdict.** A red flag adds its weight to the score (3 unless listed), and a warning adds 1, but wording alone can add at most 2. A red flag weighing 5 or more is critical and makes the email Malicious on its own. Otherwise the email is Malicious at a score of 12, and Suspicious at 5 or with any red flag.

Checks that are normal for authenticated bulk and SaaS mail relax when the sender is authenticated, such as Return-Path and Message-ID mismatches, click tracking and preview text. Brand impersonation never relaxes, because real phishing often comes through legitimate services.

## Use it as a library

The engine runs in browsers and Node. In Node:

```ts
import { analyseFile, buildReport, reportText, exportAs } from 'phishbowl/node';

const a = await analyseFile('email.eml', { ownDomains: ['northwind.example'] });
if (a.kind === 'email') console.log(a.verdict.v, a.verdict.score, a.checks.filter(c => c.status === 'bad'));
console.log(reportText(buildReport(a, { audience: 'mgmt' })));
console.log(exportAs('stix', a));
```

In a browser, `import { analyse, browserEnv } from 'phishbowl'` and pass `browserEnv()` as `env`. Pass a QR decoder (for example jsQR) to `browserEnv` if you want QR codes read.

## Testing

```sh
npm test               # unit and CLI tests on test/fixtures (made-up emails modelled on real header patterns)
npm run samples        # fetch 160 real phishing emails from Phishing Pot into samples/ (git ignores it)
npm run test:real      # score them; fails if more are missed than scripts/real-baseline.json allows
npm run test:real -- -v        # list every miss with its flagged checks
npm run test:real -- --update  # accept the current results as the new baseline
```

The real samples come from [Phishing Pot](https://github.com/rf-peixoto/phishing_pot), real phishing collected by honeypots and pinned to one commit in `scripts/sample-sets.json`. They are licensed CC BY-NC 4.0: fine for non-commercial testing with attribution, but they mustn't be committed or redistributed. That's why they're fetched, not stored.

There are two sets:
- **tuning**: the rules were adjusted while looking at these;
- **unseen**: kept aside to check that changes generalise.

Current results:

| Set | Emails flagged | Missed |
| --- | --- | --- |
| tuning | 77 of 80 | 3 (low-effort spam) |
| unseen | 79 of 80 | 1 (an unlisted brand) |

The weak spot is false positives on real legitimate mail. The fixtures cover common senders (Mailchimp, Salesforce Marketing Cloud, SES, DocuSign, Substack, Google Groups, Microsoft 365, internal mail), but they're modelled, not real. A folder of genuine newsletters and notifications run through `phishbowl` is the best check.

When you change a rule:
1. Run `npm test` and `npm run test:real -- -v`.
2. Add any email that misbehaved to `test/fixtures` (as a made-up, harmless version) with its expected verdict in `expected.json`.
3. Regenerate the checks reference with `npx tsx scripts/list-checks.ts > docs/checks.md`.

## Layout

```
src/
  analyse.ts        entry point: email or text → checks, verdict, indicators
  context.ts        parses once and works out what several checks share (authenticated? forwarded? brand claim?)
  checks/           one module per group: sender, route, filter, content, links, attachments
  verdict.ts        weights and scoring
  mime.ts headers.ts links.ts domains.ts text.ts defang.ts indicators.ts lists.ts
  files/            attachment inspection: type sniffing, ZIP, HTML, hashes
  report/           reports, customer email, exports (KQL, SPL, Wazuh, STIX, CSV, JSON)
  node/             Node host (HTML parsing with linkedom, QR decoding) and file helpers
  cli.ts            the phishbowl command
test/               node:test suites and fixtures
scripts/            fetch and score the real samples; regenerate docs/checks.md
prototype/          the original single-page browser prototype, kept for the local UI work
```

## Roadmap

1. ~~Engine extraction, tests, CI~~
2. ~~CLI~~
3. Local web UI (`phishbowl ui` on localhost), with online lookups (domain age through RDAP, URLhaus), done by the local server, and `.msg` support.
4. Opt-in AI checks. Bring your own key or use a local model (Ollama). The model can raise or explain a verdict, never lower one, and content is redacted first.
5. Outlook add-in, then triage of a reported-phishing mailbox through Microsoft Graph.
6. A demo build for the project page on nafthan.co.uk.

## Licence

Not chosen yet. Add a `LICENSE` file before making the repository public.
