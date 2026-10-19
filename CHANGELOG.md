# Changelog

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
