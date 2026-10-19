// Reference data. Edit these lists to tune detection; the test suite will tell you what changed.

/** Domain endings recognised when pulling domains out of text. TODO: replace with the full IANA list. */
export const TLDS = new Set(('com net org info biz io co uk us de fr nl eu ru cn jp br in au ca es it pl se ch be at dk no fi ie nz za kr tw hk sg my ' +
  'xyz top online site club shop live app dev cloud tech store icu buzz cc tk ml ga cf gq pw ws me tv su click link cam rest cfd sbs lol ' +
  'space website fun cyou bond quest beauty autos mom skin hair monster bar today life world email support help news ' +
  'gov edu mil int zip mov test example invalid localhost onion').split(' '));
/** Domain endings that are also common file extensions. */
export const FILE_LIKE = new Set(['zip', 'mov']);
export const RESERVED_TLD = new Set(['test', 'example', 'invalid', 'localhost']);
export const SUSPICIOUS_TLD = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'link', 'cam', 'rest', 'cfd', 'sbs', 'icu', 'buzz', 'gq', 'tk', 'ml', 'cf', 'ga', 'lol', 'pw',
  'space', 'website', 'fun', 'cyou', 'bond', 'quest', 'beauty', 'autos', 'mom', 'skin', 'hair', 'monster', 'bar']);

export const KNOWN_GOOD = ['microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'windows.net', 'microsoftonline.com', 'google.com', 'gstatic.com', 'googleapis.com',
  'apple.com', 'amazon.com', 'amazonaws.com', 'cloudflare.com', 'github.com', 'virustotal.com', 'mitre.org', 'cisa.gov', 'nist.gov', 'abuse.ch', 'urlscan.io', 'shodan.io'];

/** Sending infrastructure owned by real brands: names like amazonses or googlegroups contain a brand but are not lookalikes. */
export const INFRA = ['amazonses.com', 'googlegroups.com', 'googlemail.com', 'googleusercontent.com', 'mcsv.net', 'mailchimp.com', 'mailchimpapp.net', 'list-manage.com', 'sendgrid.net',
  'mailgun.org', 'mailgun.net', 'mandrillapp.com', 'exacttarget.com', 'exct.net', 'sparkpostmail.com', 'hubspotemail.net', 'hubspotlinks.com', 'salesforce.com', 'docusign.net',
  'zendesk.com', 'microsoftonline.com', 'protection.outlook.com', 'office365.us', 'amazon.co.uk', 'paypal.co.uk', 'apple.co.uk', 'linkedin.com', 'facebookmail.com', 'appleid.apple.com'];

/** Click-tracking services: link text names one site, the href goes through the tracker. Not a mismatch on its own. */
export const TRACKERS = ['list-manage.com', 'ct.sendgrid.net', 'sendgrid.net', 'mandrillapp.com', 'mailchi.mp', 'mjt.lu', 'mailjet.com', 'hubspotlinks.com', 'hs-sites.com', 'mailgun.org',
  'exct.net', 'sparkpostmail.com', 'cmail19.com', 'cmail20.com', 'createsend.com', 'klclick.com', 'klclick1.com', 'clicks.aweber.com', 'rs6.net', 'constantcontact.com', 'brevo.com', 'sendibt3.com'];

/** Brands phishing impersonates. Multi-word names are matched with or without the spaces. */
export const BRANDS = ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'paypal', 'apple', 'icloud', 'amazon', 'google', 'docusign', 'dropbox', 'netflix', 'dhl', 'fedex',
  'royalmail', 'hmrc', 'linkedin', 'facebook', 'instagram', 'adobe', 'barclays', 'hsbc', 'lloyds', 'natwest', 'santander', 'coinbase', 'binance', 'wetransfer', 'zoom', 'okta',
  'ledger', 'trezor', 'metamask', 'trust wallet', 'exodus', 'kraken', 'blockchain', 'ethereum', 'irs', 'usps', 'evri', 'dpd', 'correios', 'bradesco', 'itau', 'nubank',
  'mcafee', 'norton', 'geek squad', 'openai', 'chatgpt', 'whatsapp', 'telegram', 'ebay', 'walmart', 'chase', 'wells fargo', 'bank of america', 'american express', 'amex', 'mastercard'];

/** Other domain names (registrable label) each brand really sends from. Its own name always counts. */
export const BRAND_OWNS: Record<string, string[]> = {
  microsoft: ['office', 'office365', 'outlook', 'live', 'microsoftonline', 'sharepoint', 'onedrive', 'hotmail', 'msn', 'azure', 'windows', 'xbox', 'microsoft365'],
  office365: ['microsoft', 'office', 'outlook'], outlook: ['microsoft', 'office', 'live', 'hotmail'], onedrive: ['microsoft', 'live', 'sharepoint'], sharepoint: ['microsoft'],
  google: ['gmail', 'googlemail', 'youtube', 'googlegroups', 'googleusercontent', 'withgoogle'], amazon: ['amazonses', 'amazonaws', 'aws', 'primevideo', 'audible'],
  apple: ['icloud', 'me', 'mac'], icloud: ['apple', 'me'], facebook: ['facebookmail', 'meta', 'instagram'], instagram: ['facebookmail', 'meta'], whatsapp: ['meta', 'facebookmail'],
  paypal: ['paypal-communication', 'paypal-notice'], 'trust wallet': ['trustwallet'], 'geek squad': ['bestbuy'], openai: ['chatgpt'], chatgpt: ['openai'], amex: ['americanexpress', 'aexp'],
  'american express': ['americanexpress', 'aexp'], 'bank of america': ['bankofamerica', 'bofa'], 'wells fargo': ['wellsfargo'], chase: ['jpmorgan', 'jpmorganchase'], norton: ['nortonlifelock', 'gen'],
  linkedin: ['licdn'], docusign: ['docusign'], royalmail: ['royalmail'], irs: ['irs'], hmrc: ['gov'], usps: ['usps'], blockchain: ['blockchain'],
};

export const FREE_MAIL = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'live.com', 'yahoo.com', 'yahoo.co.uk', 'aol.com', 'icloud.com', 'me.com',
  'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com', 'zoho.com', 'yandex.com', 'mail.ru'];
export const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'lnkd.in', 's.id', 'v.gd', 'qrco.de', 'shorturl.gg'];
/** Free or shared services that are often abused (file sharing stays a warning). */
export const FREE_HOSTING = ['sites.google.com', 'forms.gle', 'docs.google.com', 'storage.googleapis.com', 'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'github.io',
  'netlify.app', 'vercel.app', 'blob.core.windows.net', 'azurewebsites.net', 'web.core.windows.net', '1drv.ms', 'sharepoint.com', 'dropbox.com', 'wetransfer.com',
  'ipfs.io', 'dweb.link', 'ngrok.io', 'ngrok-free.app', 'glitch.me', 'weebly.com', 'wixsite.com', 'square.site', 'jotform.com', 'typeform.com', 'notion.site', 'canva.site'];
/** Hosts where anyone can publish a page in minutes, the usual home of phishing pages. */
export const OPEN_HOSTING = ['plesk.page', 'blogspot.com', 'wordpress.com', 'sites.google.com', 'forms.yandex.com', 'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'github.io',
  'netlify.app', 'vercel.app', 'blob.core.windows.net', 'web.core.windows.net', 'azurewebsites.net', 'ipfs.io', 'dweb.link', 'ngrok.io', 'ngrok-free.app', 'glitch.me', 'weebly.com',
  'wixsite.com', 'square.site', 'notion.site', 'canva.site', 'storage.googleapis.com'];
/** Second-level suffixes where the organisation is the third label (example.co.uk). */
export const TWO_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br', 'co.za', 'com.cn', 'co.in']);

/** Letters from other scripts that look Latin, so "LΕDGΕR" (Greek Epsilon) or "Urgеnt" (Cyrillic e) still match. */
export const CONFUSABLE: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ɡ': 'g',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
  'ο': 'o', 'ν': 'v', 'α': 'a', 'ι': 'i', 'κ': 'k', 'ρ': 'p', 'τ': 't', 'υ': 'u',
};
