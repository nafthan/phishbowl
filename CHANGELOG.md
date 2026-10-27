# Changelog

## 0.3.0 (27 Oct 2026)

- **Reported emails**: a user's report (a forward with the phish attached) is recognised, and the attached original is analysed instead, with who reported it. An email attached as part of an attack is analysed too and its verdict counts (a malicious attached email is a critical red flag). Bounces show the returned message without counting it. Up to 3 levels deep and 5 attached emails.
- **Outlook `.msg`**: read directly in the CLI, the dashboard and `phishbowl/node`.
  - Uses the internet headers Outlook keeps, so every check runs. Without them (drafts, sent items) From, To, Subject and Date are rebuilt and the analysis says which checks couldn't run.
  - Bodies from HTML, from HTML wrapped in RTF, or from plain RTF with its hyperlinks; attachments and attached Outlook items; older non-Unicode files in their own code page (Japanese, Cyrillic…).
  - Tested on 19 real `.msg` files from the msgreader project.
- **Online lookups** (opt-in: `--online`, config, or the dashboard switch): domain age through RDAP, the sender's MX/SPF/DMARC through DNS over HTTPS, the OpenPhish community feed downloaded and matched locally, and URLhaus host lookups with your own key. Only domain and host names are sent; results are cached on disk.
- **Allowlist**: `"allow": { "domains": [...], "senders": [...] }`. Authenticated mail from them doesn't raise warnings; red flags still count; spoofed or unauthenticated mail claiming to be them gets a warning instead.
- **Feedback**: `phishbowl feedback <file> --says phish|legit|spam`, and buttons in the dashboard. `phishbowl feedback` lists false alarms, misses, the checks behind the false alarms and allowlist ideas; `--export` turns the kept ones into test fixtures. Stored on this machine only.
- **Detection**: more open-hosting services (Framer, Webflow, GitBook, Jimdo, GoDaddy Sites and others seen on the OpenPhish feed), and more two-level country suffixes (com.tr, co.kr, com.mx…) so the registrable domain is right. Real-sample results unchanged, apart from one more phish caught in validate (473/500).
- **Logo**: a scheming red fish in a bowl, going for an email on a hook (`assets/logo/`). Also in the dashboard header and as its icon.
- `docs/checks.md` now covers `.msg`, attached-email, allowlist and online checks.

## 0.2.0 (19 Oct 2026)

- **Dashboard**:
  - `phishbowl ui` serves a live dashboard from this machine: drop or paste emails, tick "already done" actions, save a snapshot.
  - `--html file.html` writes the same dashboard as one self-contained file that makes no outside connections, to attach to a ticket or embed in another platform (`?embed`, `postMessage` from the parent frame only).
  - The library exports `phishbowl/view` and `phishbowl/dashboard`.
  - Email content is only ever shown as defanged text.
- **Real legitimate mail in the tests**:
  - 4,150 messages from the SpamAssassin public corpus, plus 19 modern messages with current authentication headers from open-source email libraries' fixtures.
  - `npm run test:real` now checks false alarms as well as misses.
- **More real phishing**: a 500-email validation set and a 500-email holdout, scored once and never tuned on. Holdout: 476/500 flagged (95%).
- **Verdict**:
  - Suspicious now starts at a score of 6, not 5.
  - Delivery-route and link-hygiene warnings are capped like wording, so the background noise of ordinary bulk mail can't add up to Suspicious on its own.
  - On real legitimate mail this cut false alarms from 54 to 9 (of 3,900 everyday emails) and from 70 to 24 (of 250 hard ones). It cost 2 of 500 on the validation set, which the detection fixes below won back.
- **Detection**:
  - Inline forwards are judged by the original sender. A Microsoft lure forwarded from Hotmail was passing because Microsoft owns Hotmail.
  - Strike-through overlay letters ("e̷") count as a filter-evasion trick.
  - Account-lure wording is recognised in Portuguese, Spanish, French, German, Dutch and Italian, not only English.
- **Licence**: MIT.

## 0.1.0 (19 Oct 2026)

First release as a repository: the engine from the browser prototype, rebuilt as a TypeScript package with a CLI.

- **Engine** (`src/`): about 65 checks across sender, route, spam-filter verdicts, content, links/QR and attachments; weighted verdict; indicator extraction; reports for three audiences; customer email; exports (list, CSV, KQL, SPL, Wazuh, STIX 2.1, JSON, text). Runs in browsers and Node.
- **CLI** (`phishbowl`): analyse a file, folder or stdin; `report`; `iocs`; `--json`; exit codes by verdict; own domains from a flag, environment variable or config file. Output is defanged.
- **Changes from the prototype**
  - Bytes are decoded with each part's declared charset, and 8-bit UTF-8 headers are read.
  - Emails with very long header blocks (From after 8 KB) are recognised; the prototype treated them as text.
  - QR codes are decoded in Node (PNG and JPEG), not only in the browser.
  - Report text is defanged as a final pass, so no wording can leak a clickable address.
  - Closing the output pipe early (`| head`) no longer crashes the CLI.
- **Tests**: 45 unit and CLI tests on 23 fixture emails, covering every check. Real-phishing check on 160 Phishing Pot samples: 77/80 and 79/80 flagged.
