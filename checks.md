# Checks

Every check Phishbowl runs, by group. A red flag (bad) adds its weight to the score; unlisted red flags weigh 3, a warning weighs 1, and content warnings add at most 2 in total.
A red flag weighing 5 or more is critical: Malicious on its own. Otherwise Malicious at a score of 12, Suspicious at 5 or with any red flag.

Statuses seen are the ones the test emails produced; some checks can produce others.

## Sender and authentication

| Check | Id | Weight as a red flag | Statuses seen |
| --- | --- | --- | --- |
| SPF | `sender.spf` | 3 | bad, warn, ok, na |
| SPF alignment | `sender.spf-align` | – | warn, ok, info |
| DKIM | `sender.dkim` | 3 | bad, warn, ok, info, na |
| DKIM alignment | `sender.dkim-align` | – | warn, ok, info |
| DMARC | `sender.dmarc` | 3 | bad, warn, ok, info, na |
| DMARC enforcement | `sender.dmarc-policy` | – | warn |
| Microsoft composite authentication | `sender.compauth` | 3 | bad, warn, ok |
| Sent as your own domain | `sender.spoof-own` | 6 (critical) | bad, ok |
| Reply-To | `sender.replyto` | 3 | bad, warn, ok, info, na |
| Return-Path | `sender.returnpath` | – | warn, ok, info, na |
| Display name | `sender.display-brand` | 3 | bad, info |
| Return-Path domain | `sender.lookalike` | 4 | bad |
| Message-ID domain | `sender.msgid` | – | ok, info |
| Sending software | `sender.mailer` | – | warn, info |
| Unsubscribe header | `sender.unsub` | – | ok, info |
| Free email account | `sender.freemail` | – | warn, info |
| ARC | `sender.arc` | – | info |
| Sender header | `sender.sender` | – | warn, info |
| Recipients | `sender.to` | – | warn |
| DKIM covers From | `sender.dkim-from` | 3 | bad |
| Display name trick | `sender.name-addr` | 3 | bad |
| Any authentication | `sender.noauth` | 3 | bad |
| Forwarded inline | `sender.forwarded` | – | warn |
| Lookalike letters | `sender.script` | 4 | bad |
| DKIM algorithm | `sender.dkim-algo` | – | warn |

## Delivery route

| Check | Id | Weight as a red flag | Statuses seen |
| --- | --- | --- | --- |
| Servers it passed through | `route.hops` | – | info |
| Sending server | `route.origin` | – | info, na |
| Reverse DNS | `route.ptr` | – | warn, ok |
| Encryption on arrival | `route.tls` | – | warn, ok |
| Timestamps in order | `route.order` | – | warn, ok |
| Delivery time | `route.delay` | – | warn, info |
| Date header | `route.date` | – | warn, ok |
| Server name check | `route.helo` | – | warn |

## Spam filter verdicts

| Check | Id | Weight as a red flag | Statuses seen |
| --- | --- | --- | --- |
| Spam confidence (SCL) | `filter.scl` | 3 | bad, ok, info |
| Spam filter verdict (SFV) | `filter.sfv` | 3 | bad, ok |
| Protection category (CAT) | `filter.cat` | 4 | bad, ok |
| Bulk complaint level (BCL) | `filter.bcl` | – | warn, ok, info |
| Reverse DNS (Microsoft) | `filter.ptr` | – | warn, ok |
| Sending country | `filter.ctry` | – | info |
| IP reputation (IPV) | `filter.ipv` | – | info |
| X-Spam-Status | `filter.generic` | 3 | bad |
| Spam filter headers | `filter.none` | – | na |

## Message content

| Check | Id | Weight as a red flag | Statuses seen |
| --- | --- | --- | --- |
| Urgency or pressure | `content.urgency` | – | warn, ok |
| Asks for sign-in or details | `content.creds` | – | warn, ok |
| Money or bank details | `content.money` | – | warn, ok |
| Greeting | `content.greeting` | – | warn, info |
| Hidden text | `content.hidden` | – | warn, ok, info |
| Tracking pixel | `content.pixel` | – | warn, ok, info |
| Plain-text version | `content.textpart` | – | info |
| Empty message | `content.empty` | – | warn |
| Remote images | `content.remote` | – | info |
| Payment or gift-card request | `content.bec` | 4 | bad |
| Threats | `content.threat` | – | warn |
| Call this number | `content.callback` | 4 | bad |
| Scripts in the email | `content.scripts` | 3 | bad |
| Wallet recovery phrase | `content.seed` | 5 (critical) | bad |
| Brand it talks about | `content.brand` | 4 | bad |
| Forms in the email | `content.forms` | 3 | bad |

## Links and QR codes

| Check | Id | Weight as a red flag | Statuses seen |
| --- | --- | --- | --- |
| Links found | `links.count` | – | ok, info |
| Link text matches destination | `links.mismatch` | 4 | bad, ok, na |
| Lookalike domains | `links.lookalike` | 4 | bad, ok, na |
| Links to bare IP addresses | `links.ip` | 3 | bad, ok, na |
| user@host trick | `links.at` | 3 | bad, ok, na |
| Script or data links | `links.scheme` | – | ok, na |
| URL shorteners | `links.shortener` | – | warn, ok, na |
| Hidden redirects | `links.redirect` | – | warn, ok, na |
| Free hosting services | `links.hosting` | 3 | bad, warn, ok, na |
| Risky domain endings | `links.tld` | – | warn, ok, na |
| Unencrypted links | `links.http` | – | warn, ok, na |
| Subdomain chains | `links.subdomains` | – | warn, ok, na |
| Click-tracked links | `links.tracked` | – | warn, ok, info, na |
| Your address in the link | `links.recipient` | – | warn, ok, na |
| Impersonation with a risky link | `links.impersonation` | 5 (critical) | bad |
| Unwrapped links | `links.unwrapped` | – | info |
| QR codes | `links.qr` | 3 | bad, ok |

## Attachments

| Check | Id | Weight as a red flag | Statuses seen |
| --- | --- | --- | --- |
| Attachments | `att.count` | – | ok, info |
| Risky file type | `att.risky` | 3 | bad, warn, ok, info, na |
| Double extension | `att.double` | 4 | bad, ok, na |
| Real type matches name | `att.mismatch` | 3 | bad, ok, na |
| Password forms | `att.cred-form` | 5 (critical) | bad, ok, na |
| HTML smuggling | `att.smuggling` | 6 (critical) | ok, na |
| Macros | `att.macros` | 5 (critical) | bad, ok, na |
| Remote templates | `att.remote-template` | 6 (critical) | ok, na |
| Password-protected archives | `att.zip-encrypted` | 3 | bad, ok, na |
| Risky files in archives | `att.zip-risky` | 3 | bad, ok, na |
| PDF actions | `att.pdf-active` | – | ok, na |
| Script in images | `att.svg-script` | – | ok, na |
| Encrypted or packed content | `att.entropy` | – | warn, ok, na |
| Calendar invites | `att.ics` | – | warn, info |
| Forms | `att.form` | – | warn |
| Scripts | `att.script` | – | warn |
| Auto-redirects | `att.refresh` | – | warn |

