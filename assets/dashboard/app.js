// Phishbowl dashboard. Renders view models built by the engine (src/view.ts).
// Two modes: "live" talks to the local server (phishbowl ui); "static" shows the data embedded in the page.
// Every value is added as text (never as HTML), and email HTML is never rendered.
(() => {
  'use strict';
  const cfg = JSON.parse(document.getElementById('pb-config').textContent || '{}');
  const embedded = JSON.parse(document.getElementById('pb-data').textContent || '{"views":[]}');
  const live = cfg.mode === 'live';
  const params = new URLSearchParams(location.search);
  const state = { items: [], views: new Map(), selected: null, filter: 'all', search: '', checkFilter: 'flagged', audience: 'tech',
    exportTab: 'list', iocType: null, showOff: false, reportOpts: { done: [], tlp: '', ref: '', preparedBy: cfg.preparedBy || '', customer: '' }, feedback: {} };

  // ── tiny DOM helpers ────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  function h(tag, props, ...kids) {
    const e = document.createElement(tag);
    if (props) for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'text') e.textContent = v;
      else e.setAttribute(k, v === true ? '' : String(v));
    }
    for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false && kid !== '') e.append(kid instanceof Node ? kid : String(kid));
    return e;
  }
  const svg = (tag, attrs) => { const e = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v)); return e; };
  const GLYPH = { bad: '✕', warn: '!', ok: '✓', info: '•', na: '–' };
  const mark = s => h('span', { class: 'mark s-' + s, 'aria-label': s }, GLYPH[s] || '•');
  const vclass = v => v ? v.v : 'text';
  const vlabel = v => v ? v.label : 'Text';
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
  const store = { get: k => { try { return localStorage.getItem(k) || ''; } catch { return ''; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } } };

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); flash(btn, 'Copied'); }
    catch { const t = h('textarea', {}, text); document.body.append(t); t.select(); try { document.execCommand('copy'); flash(btn, 'Copied'); } catch { flash(btn, 'Copy failed'); } t.remove(); }
  }
  const flash = (btn, msg) => { if (!btn) return; const old = btn.textContent; btn.textContent = msg; setTimeout(() => { btn.textContent = old; }, 1600); };
  function download(name, text, type = 'text/plain') {
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: type + ';charset=utf-8' })), download: name });
    document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  // ── data access ─────────────────────────────────────────────────────────────
  async function api(path, opts = {}) {
    const r = await fetch(path, { ...opts, headers: { 'X-Phishbowl': '1', ...(opts.headers || {}) } });
    if (!r.ok) throw new Error((await r.text()) || r.statusText);
    return r.headers.get('content-type')?.includes('json') ? r.json() : r.text();
  }
  const summaryOf = v => ({ id: v.id, file: v.file, kind: v.kind, verdict: v.verdict, subject: v.summary ? v.summary.subject : '', from: v.summary ? v.summary.from : '', top: v.findings[0] ? v.findings[0].name : '' });
  async function getView(id) {
    if (!state.views.has(id) && live) state.views.set(id, await api('/api/analyses/' + encodeURIComponent(id)));
    return state.views.get(id);
  }
  function loadViews(views) {
    for (const v of views) { state.views.set(v.id, v); if (!state.items.some(i => i.id === v.id)) state.items.push(summaryOf(v)); }
  }

  // ── queue ───────────────────────────────────────────────────────────────────
  function renderQueue() {
    const counts = { all: state.items.length, malicious: 0, suspicious: 0, clean: 0 };
    for (const i of state.items) if (i.verdict) counts[i.verdict.v]++;
    const tiles = $('tiles'); tiles.textContent = '';
    for (const [k, label] of [['all', 'All'], ['malicious', 'Malicious'], ['suspicious', 'Suspicious'], ['clean', 'Legitimate']])
      tiles.append(h('button', { type: 'button', class: 'tile ' + k, 'aria-pressed': String(state.filter === k), onclick: () => { state.filter = state.filter === k ? 'all' : k; renderQueue(); } },
        h('b', {}, counts[k]), h('span', {}, label)));
    const q = state.search.toLowerCase(), list = $('list'); list.textContent = '';
    const order = { malicious: 0, suspicious: 1, clean: 2 };
    const shown = state.items.filter(i => (state.filter === 'all' || (i.verdict && i.verdict.v === state.filter)) && (!q || `${i.subject} ${i.from} ${i.file}`.toLowerCase().includes(q)))
      .sort((a, b) => (a.verdict ? order[a.verdict.v] : 3) - (b.verdict ? order[b.verdict.v] : 3) || (b.verdict ? b.verdict.score : 0) - (a.verdict ? a.verdict.score : 0));
    if (!shown.length) list.append(h('li', { class: 'empty' }, state.items.length ? 'Nothing matches.' : live ? 'No emails yet. Drop some .eml files above.' : 'No emails in this report.'));
    for (const i of shown) list.append(h('li', { class: 'item', 'aria-current': String(i.id === state.selected), tabindex: '0',
      onclick: () => select(i.id), onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(i.id); } } },
      h('span', { class: 'bar' }),
      h('span', { class: 'main' }, h('div', { class: 'subj' }, i.subject || i.file), h('div', { class: 'meta' }, [i.from, i.top].filter(Boolean).join(' · ') || i.file)),
      h('span', { class: 'score' }, h('span', { class: 'vtag ' + vclass(i.verdict) }, vlabel(i.verdict)), h('div', { class: 'num' }, i.verdict ? 'score ' + i.verdict.score : ''))));
    document.body.classList.toggle('single', !live && state.items.length === 1);
  }

  async function select(id) {
    state.selected = id; renderQueue();
    const d = $('detail'); d.textContent = '';
    d.append(h('p', { class: 'hint' }, 'Loading…'));
    try { renderDetail(await getView(id)); } catch (e) { d.textContent = ''; d.append(h('p', { class: 'hint' }, 'Could not load: ' + e.message)); }
    if (window.parent !== window) window.parent.postMessage({ type: 'phishbowl:selected', id, verdict: state.items.find(i => i.id === id)?.verdict?.v || 'text' }, '*');
  }

  // ── detail ──────────────────────────────────────────────────────────────────
  const panel = (key, title, status, ...body) => h('section', { class: 'panel', id: 'sec-' + key }, h('div', { class: 'panel-head' }, h('span', { class: 'panel-title' }, '// ' + title), h('span', { class: 'panel-status' }, status || '')), h('div', { class: 'panel-body' }, ...body));
  const table = (head, rows) => h('div', { class: 'tbl' }, h('table', {}, h('thead', {}, h('tr', {}, head.map(c => h('th', {}, c)))), h('tbody', {}, rows)));

  function ring(v) {
    const R = 66, C = 2 * Math.PI * R, run = Math.max(1, v.run), bad = v.bad / run * C, warn = v.warn / run * C;
    const col = { malicious: 'var(--bad)', suspicious: 'var(--warn)', clean: 'var(--ok)' }[v.v];
    const s = svg('svg', { viewBox: '0 0 160 160', 'aria-hidden': 'true' });
    s.append(svg('circle', { cx: 80, cy: 80, r: R, fill: 'none', stroke: 'var(--line)', 'stroke-width': 12 }));
    s.append(svg('circle', { cx: 80, cy: 80, r: R, fill: 'none', stroke: 'var(--bad)', 'stroke-width': 12, 'stroke-dasharray': `${bad} ${C}` }));
    s.append(svg('circle', { cx: 80, cy: 80, r: R, fill: 'none', stroke: 'var(--warn)', 'stroke-width': 12, 'stroke-dasharray': `0 ${bad} ${warn} ${C}` }));
    if (!v.bad && !v.warn) s.append(svg('circle', { cx: 80, cy: 80, r: R, fill: 'none', stroke: col, 'stroke-width': 12 }));
    return h('div', {}, h('div', { class: 'ring', role: 'img', 'aria-label': `${v.bad + v.warn} of ${v.run} checks flagged` }, s,
      h('div', { class: 'ring-num' }, h('b', { style: 'color:' + col }, v.bad + v.warn), h('span', {}, `of ${v.run} checks`, h('br'), 'flagged'))),
      h('div', { class: 'legend' }, h('span', {}, h('i', { style: 'background:var(--bad)' }), plural(v.bad, 'red flag')), h('span', {}, h('i', { style: 'background:var(--warn)' }), `${v.warn} worth a look`),
        h('span', {}, h('i', { style: 'background:var(--ok)' }), `${v.ok} reassuring`)));
  }
  const authPill = (k, r) => h('span', { class: 'pill ' + (r === 'pass' ? 'ok' : !r || r === 'none' ? '' : /fail/.test(r) ? 'bad' : 'warn') }, `${k} ${r || 'none'}`);

  function renderDetail(v) {
    const d = $('detail'); d.textContent = '';
    if (!v) { d.append(h('p', { class: 'empty' }, live ? 'Drop an .eml file to analyse it, or pick one from the list.' : 'Pick an email from the list.')); return; }
    if (v.kind === 'text') return renderText(d, v);
    const s = v.summary, vd = v.verdict;
    d.append(h('div', { class: 'd-head' }, ring(vd), h('div', {},
      h('h1', { class: 'd-title' }, s.subject || '(no subject)'), h('p', { class: 'd-file' }, `${v.file} · analysed in ${v.ms} ms`),
      h('div', { class: 'vline' }, h('span', { class: 'vtag big ' + vd.v }, vd.label), h('span', { class: 'num' }, `${vd.conf} confidence · score ${vd.score}`)),
      v.findings.length ? h('ul', { class: 'findings' }, v.findings.map(c => h('li', {}, mark(c.status), h('span', {}, h('span', { class: 'cname' }, c.name + ': '), c.result))))
        : h('p', { class: 'hint' }, 'Nothing stood out: authentication passed and nothing in the links, content or attachments was flagged.'),
      h('dl', { class: 'kv' }, ...[['Reported by', s.reportedBy || ''], ...(s.attachedEmails || []).map(n => ['Attached email', `${n.name}: ${n.label} (score ${n.score}) · "${n.subject}"`]), ['From', s.from], ['Reply-To', s.replyTo], ['Return-Path', s.returnPath], ['To', s.to], ['Sent', s.date], ['Sent from', s.sentFrom]]
        .filter(([, x]) => x).flatMap(([k, x]) => [h('dt', {}, k), h('dd', {}, x)])),
      h('div', { class: 'chips' }, authPill('SPF', s.auth.spf), authPill('DKIM', s.auth.dkim), authPill('DMARC', s.auth.dmarc), h('span', { class: 'pill' }, plural(s.links, 'link')),
        h('span', { class: 'pill' }, plural(s.attachments, 'attachment')), s.qr ? h('span', { class: 'pill bad' }, plural(s.qr, 'QR code')) : null),
      live && cfg.feedback ? feedbackRow(v) : null)));
    const flagged = v.groups.reduce((n, g) => n + g.flagged, 0);
    d.append(h('nav', { class: 'jump', 'aria-label': 'Sections' }, [['checks', 'Checks', h('b', { class: vd.bad ? 'bad' : '' }, flagged)], ['headers', 'Headers'], ['links', 'Links', h('b', {}, v.links.length)],
      ['atts', 'Attachments', h('b', {}, v.attachments.length)], ['content', 'Content'], ['iocs', 'Indicators', h('b', {}, v.indicators.filter(i => !i.off).length)],
      ['report', 'Report'], ['cust', 'Customer email'], ['export', 'Export']].map(([k, label, count]) => h('a', { href: '#sec-' + k }, label, count || ''))));
    d.append(checksPanel(v), headersPanel(v), linksPanel(v), attsPanel(v), contentPanel(v), iocsPanel(v), reportPanel(v), customerPanel(v), exportPanel(v));
    d.append(h('p', { class: 'foot' }, 'Addresses and links are defanged (hxxp, [.]) so nothing here can be clicked by accident. The email\'s own HTML is never displayed.'));
  }

  // "Was this right?" Records your answer on this machine (phishbowl feedback shows what it adds up to).
  function feedbackRow(v) {
    const st = h('span', { class: 'hint', role: 'status' }, state.feedback[v.id] ? 'Recorded: ' + state.feedback[v.id] : '');
    const keep = h('input', { type: 'checkbox' });
    const say = (says, label) => h('button', { class: 'btn ghost small', type: 'button', onclick: async () => {
      try { await api(`/api/analyses/${v.id}/feedback`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ says, keep: keep.checked }) });
        state.feedback[v.id] = label; st.textContent = 'Recorded: ' + label + (keep.checked ? ' (copy kept)' : ''); }
      catch (e) { st.textContent = 'Not recorded: ' + e.message; } } }, label);
    return h('div', { class: 'feedback' }, h('span', { class: 'cname' }, 'Is it really? '), say('phish', 'Phishing'), say('legit', 'Legitimate'), say('spam', 'Spam'),
      h('label', { class: 'hint' }, keep, ' keep a copy for tests'), st);
  }

  function renderText(d, v) {
    d.append(h('h1', { class: 'd-title' }, v.file), h('div', { class: 'vline' }, h('span', { class: 'vtag big text' }, 'Text'),
      h('span', { class: 'num' }, `not an email, so only its indicators were extracted: ${v.indicators.filter(i => !i.off).length}`)));
    d.append(h('nav', { class: 'jump' }, [['iocs', 'Indicators'], ['report', 'Report'], ['cust', 'Customer email'], ['export', 'Export']].map(([k, l]) => h('a', { href: '#sec-' + k }, l))));
    d.append(iocsPanel(v), reportPanel(v), customerPanel(v), exportPanel(v), panel('text', 'Text', 'defanged', h('pre', { class: 'out' }, v.text || '')));
  }

  function checksPanel(v) {
    const all = v.groups.flatMap(g => g.checks), F = { flagged: [c => c.status === 'bad' || c.status === 'warn', 'Flagged'], all: [c => c.status !== 'na', 'All'],
      ok: [c => c.status === 'ok', 'Reassuring'], info: [c => c.status === 'info' || c.status === 'na', 'Context'] };
    const body = h('div');
    const draw = () => {
      body.textContent = '';
      body.append(h('div', { class: 'filters' }, Object.entries(F).map(([k, [f, l]]) => h('button', { type: 'button', class: 'chip', 'aria-pressed': String(state.checkFilter === k),
        onclick: () => { state.checkFilter = k; draw(); } }, l, h('b', {}, all.filter(f).length)))));
      for (const g of v.groups) {
        const rows = g.checks.filter(F[state.checkFilter][0]); if (!rows.length) continue;
        body.append(h('div', { class: 'group' }, h('h3', {}, g.name, h('span', {}, g.flagged ? g.flagged + ' flagged' : 'nothing flagged')),
          rows.map(c => h('div', { class: 'chk ' + c.status }, mark(c.status), h('span', { class: 'cname' }, c.name),
            h('span', { class: 'cres' }, c.result, c.why && (c.status === 'bad' || c.status === 'warn') ? h('small', {}, c.why) : null)))));
      }
      if (!all.some(F[state.checkFilter][0])) body.append(h('p', { class: 'hint' }, 'Nothing in this filter.'));
    };
    draw();
    return panel('checks', 'Checks', `${v.verdict.run} checks · ${v.groups.reduce((n, g) => n + g.flagged, 0)} flagged`, body);
  }

  function headersPanel(v) {
    const x = v.headers, q = h('input', { class: 'input', type: 'search', placeholder: 'Filter headers', 'aria-label': 'Filter headers', style: 'max-width:260px' });
    const allRows = x.all.map(r => h('tr', {}, h('td', { class: 'm', style: 'white-space:nowrap' }, r.name), h('td', { class: 'm' }, r.value)));
    q.addEventListener('input', () => { const t = q.value.toLowerCase(); allRows.forEach(tr => { tr.hidden = !!t && !tr.textContent.toLowerCase().includes(t); }); });
    return panel('headers', 'Headers', 'route, authentication and filter verdicts',
      h('div', { class: 'sub' }, h('span', {}, 'Delivery route, oldest first'), h('span', {}, plural(x.hops.length, 'hop'))),
      table(['#', 'From (name it gave)', 'Reverse DNS', 'IP', 'Received by', 'With', 'Time (UTC)', 'Delay'], x.hops.map(r => h('tr', {},
        h('td', { class: 'n' }, r.n), h('td', { class: 'm' }, r.from, r.entry ? h('span', { class: 'note warn' }, 'entered here') : null), h('td', { class: 'm' }, r.rdns), h('td', { class: 'm' }, r.ip),
        h('td', { class: 'm' }, r.by), h('td', { class: 'm' }, r.with, r.tls ? h('span', { class: 'note' }, 'TLS') : null), h('td', { class: 'm' }, r.time),
        h('td', { class: 'n' }, r.delay == null ? '' : r.delay < 0 ? h('span', { class: 'note bad' }, r.delay + 's') : '+' + r.delay + 's')))),
      h('div', { class: 'sub' }, 'Authentication'),
      table(['Check', 'Result', 'For domain', 'Matches From', 'Detail'], x.auth.map(r => h('tr', {}, h('td', { class: 'm' }, r.check), h('td', {}, authPill('', r.result)), h('td', { class: 'm' }, r.domain),
        h('td', {}, r.matchesFrom == null ? '' : h('span', { class: 'note ' + (r.matchesFrom ? '' : 'bad') }, r.matchesFrom ? 'yes' : 'no')), h('td', {}, r.detail)))),
      x.spam.length ? [h('div', { class: 'sub' }, 'Spam filter verdicts'), table(['Header', 'Field', 'Value', 'Meaning'], x.spam.map(r => h('tr', {}, h('td', { class: 'm' }, r.header), h('td', { class: 'm' }, r.field),
        h('td', { class: 'm' }, r.value), h('td', {}, r.meaning))))] : null,
      h('div', { class: 'sub' }, h('span', {}, 'All headers'), q), table(['Name', 'Value'], allRows));
  }

  function linksPanel(v) {
    if (!v.links.length) return panel('links', 'Links', 'none', h('p', { class: 'hint' }, 'No links in this email.'));
    return panel('links', 'Links', 'from the body, QR codes and attachments',
      h('p', { class: 'hint' }, 'Wrapped links (Safe Links, Proofpoint, Postmark…) are unwrapped so the real destination is checked. Nothing here is clickable.'),
      table(['#', 'Found in', 'Shows', 'Goes to', 'Findings'], v.links.map((l, i) => h('tr', {}, h('td', { class: 'n' }, i + 1), h('td', { class: 'm' }, l.source), h('td', {}, l.shows),
        h('td', { class: 'm' }, l.goesTo, l.unwrapped ? h('span', { class: 'note' }, 'unwrapped from ' + l.unwrapped) : null),
        h('td', {}, l.findings.length ? l.findings.map(f => h('span', { class: 'note ' + (f.sev === 'info' ? '' : f.sev) }, f.text)) : h('span', { class: 'note' }, 'nothing found'))))));
  }

  function attsPanel(v) {
    if (!v.attachments.length) return panel('atts', 'Attachments', 'none', h('p', { class: 'hint' }, 'No attachments or embedded images.'));
    return panel('atts', 'Attachments', 'checked by content, not by name', h('p', { class: 'hint' }, 'Files are read as data only. Nothing is opened, run or previewed.'),
      v.attachments.map(a => h('div', { class: 'att' }, h('h3', {}, h('span', {}, a.name), h('span', { class: 'pill ' + a.worst }, a.worst === 'bad' ? 'dangerous' : a.worst === 'warn' ? 'check' : 'nothing found')),
        h('div', { class: 'att-body' },
          h('div', { class: 'meta-row' }, h('span', {}, 'Says ', h('b', {}, a.declared)), h('span', {}, 'Is ', h('b', {}, a.what)), h('span', {}, a.size < 1024 ? a.size + ' bytes' : (a.size / 1024).toFixed(1) + ' KB'),
            h('span', {}, 'Entropy ', h('b', {}, a.entropy), ' / 8'), a.inline ? h('span', {}, 'shown inline') : null),
          a.notes.length ? h('ul', { class: 'notes' }, a.notes.map(n => h('li', {}, mark(n.sev), h('span', {}, n.text)))) : null,
          a.zip ? [h('div', { class: 'sub' }, `Inside the archive (${a.zip.length})`), table(['Name', 'Size', 'Encrypted'], a.zip.map(z => h('tr', {}, h('td', { class: 'm' }, z.name), h('td', { class: 'n' }, z.size), h('td', {}, z.encrypted ? h('span', { class: 'note bad' }, 'yes') : ''))))] : null,
          a.html ? h('dl', { class: 'kv' }, h('dt', {}, 'Page title'), h('dd', {}, a.html.title || '(none)'), h('dt', {}, 'Forms'), h('dd', {}, a.html.forms.length ? a.html.forms.join('; ') : 'none'),
            h('dt', {}, 'Scripts'), h('dd', {}, `${plural(a.html.scripts, 'block')}, ${plural(a.html.handlers, 'event handler')}${a.html.patterns.length ? ': ' + a.html.patterns.join(', ') : ''}`), h('dt', {}, 'Links'), h('dd', {}, a.html.links)) : null,
          a.qr ? h('dl', { class: 'kv' }, h('dt', {}, 'QR code says'), h('dd', {}, a.qr)) : null,
          h('div', { class: 'hash' }, 'SHA256 ', h('span', {}, a.sha256), h('br'), 'SHA1 ', h('span', {}, a.sha1), h('br'), 'MD5 ', h('span', {}, a.md5))))));
  }

  function contentPanel(v) {
    const c = v.content;
    return panel('content', 'Content', 'language and structure', h('div', { class: 'sub' }, 'Language'),
      h('dl', { class: 'kv' }, c.hits.flatMap(x => [h('dt', {}, x.label), h('dd', {}, x.phrases.length ? x.phrases.map(p => h('span', { class: 'phr' }, p)) : h('span', { class: 'num' }, 'none'))])),
      h('div', { class: 'sub' }, 'Structure'), h('dl', { class: 'kv' }, c.structure.flatMap(x => [h('dt', {}, x.label), h('dd', {}, x.value)])),
      h('div', { class: 'sub' }, h('span', {}, 'Message text'), h('span', {}, 'defanged')), h('pre', { class: 'out' }, c.body));
  }

  function iocsPanel(v) {
    const body = h('div');
    const draw = () => {
      body.textContent = '';
      const types = [...new Set(v.indicators.map(i => i.label))];
      body.append(h('div', { class: 'bar-row' }, h('div', { class: 'filters' },
        h('button', { type: 'button', class: 'chip', 'aria-pressed': String(!state.iocType), onclick: () => { state.iocType = null; draw(); } }, 'All', h('b', {}, v.indicators.filter(i => !i.off).length)),
        types.map(t => h('button', { type: 'button', class: 'chip', 'aria-pressed': String(state.iocType === t), onclick: () => { state.iocType = state.iocType === t ? null : t; draw(); } },
          t, h('b', {}, v.indicators.filter(i => i.label === t && !i.off).length)))),
        h('label', { class: 'num' }, h('input', { type: 'checkbox', checked: state.showOff || null, onchange: e => { state.showOff = e.target.checked; draw(); } }), ' show left-out')));
      const rows = v.indicators.filter(i => (!state.iocType || i.label === state.iocType) && (state.showOff || !i.off));
      body.append(rows.length ? table(['Type', 'Indicator (defanged)', 'Seen', 'Where it appears'], rows.map(i => h('tr', { class: i.off ? 'off' : '' }, h('td', {}, h('span', { class: 'type' }, i.label)),
        h('td', { class: 'm' }, i.defanged, i.off ? h('span', { class: 'note warn' }, 'left out: ' + i.off) : null, i.notes.map(n => h('span', { class: 'note' + (n.warn ? ' warn' : '') }, n.t))),
        h('td', { class: 'n' }, '×' + i.count), h('td', { class: 'ctx' }, i.ctx.pre, h('mark', {}, i.ctx.hit), i.ctx.post)))) : h('p', { class: 'hint' }, 'No indicators.'));
    };
    draw();
    return panel('iocs', 'Indicators', `${v.indicators.filter(i => !i.off).length} to export · ${v.indicators.filter(i => i.off).length} left out`, body);
  }

  const ACTIONS = { 'block-sender': 'Blocked the sender', purge: 'Removed it from mailboxes', 'block-net': 'Blocked links, domains and IPs', edr: 'Blocked the file hashes', reset: 'Reset passwords for anyone who clicked' };
  function reportPanel(v) {
    const out = h('pre', { class: 'out' }), status = h('span', { class: 'toast', role: 'status' });
    let fmt = 'text';
    const show = () => { const r = v.reports[state.audience]; out.textContent = fmt === 'markdown' ? r.markdown : r.text; };
    const refresh = async () => {
      if (!live) return show();
      status.textContent = 'Updating…';
      try { v.reports = await api(`/api/analyses/${encodeURIComponent(v.id)}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(state.reportOpts) }); status.textContent = ''; }
      catch (e) { status.textContent = 'Could not update: ' + e.message; }
      show(); const c = document.getElementById('sec-cust'); if (c) c.replaceWith(customerPanel(v));
    };
    const aud = h('select', { class: 'input', onchange: e => { state.audience = e.target.value; show(); } },
      [['tech', 'Colleague or SOC (technical)'], ['mgmt', 'Customer or manager (plain English)'], ['staff', 'Staff warning']].map(([k, l]) => h('option', { value: k, selected: state.audience === k || null }, l)));
    const fmtSel = h('select', { class: 'input', onchange: e => { fmt = e.target.value; show(); } }, h('option', { value: 'text' }, 'Plain text'), h('option', { value: 'markdown' }, 'Markdown'));
    const o = state.reportOpts, text = (key, label, ph) => h('label', {}, label, h('input', { class: 'input', value: o[key] || '', placeholder: ph || '', onchange: e => { o[key] = e.target.value.trim(); if (key === 'preparedBy') store.set('pb-by', o[key]); refresh(); } }));
    const controls = h('div', { class: 'controls' }, h('label', {}, 'Written for', aud), h('label', {}, 'Format', fmtSel),
      live ? [h('label', {}, 'Sharing (TLP)', h('select', { class: 'input', onchange: e => { o.tlp = e.target.value; refresh(); } }, [['', 'Suggested'], ['clear', 'TLP:CLEAR'], ['green', 'TLP:GREEN'], ['amber', 'TLP:AMBER'], ['amber-strict', 'TLP:AMBER+STRICT'], ['red', 'TLP:RED']]
        .map(([k, l]) => h('option', { value: k, selected: o.tlp === k || null }, l)))), text('preparedBy', 'Prepared by', 'Your name or team'), text('ref', 'Reference', 'Automatic')] : null);
    const done = live ? h('fieldset', { class: 'done' }, h('legend', {}, 'Already done (moves them to "actions taken")'), Object.entries(ACTIONS).map(([k, l]) => h('label', {},
      h('input', { type: 'checkbox', checked: o.done.includes(k) || null, onchange: e => { o.done = e.target.checked ? [...o.done, k] : o.done.filter(x => x !== k); refresh(); } }), l)))
      : h('p', { class: 'hint' }, 'Saved report: the text is fixed. Open the email in phishbowl ui to tick actions or change the sharing label.');
    const copyBtn = h('button', { class: 'btn', type: 'button', onclick: e => copy(out.textContent, e.target) }, 'Copy');
    const dl = h('button', { class: 'btn ghost', type: 'button', onclick: () => download(`${v.id}-report-${state.audience}.${fmt === 'markdown' ? 'md' : 'txt'}`, out.textContent) }, 'Download');
    show();
    return panel('report', 'Report', 'a draft to share · check it before sending', controls, done, h('div', { class: 'bar-row' }, h('span', { class: 'hint' }, 'Everything is defanged.'), h('div', { class: 'btns' }, status, dl, copyBtn)), out);
  }

  function customerPanel(v) {
    const c = v.reports.customer;
    return panel('cust', 'Customer email', 'no links · no attachments · ready to paste',
      h('div', { class: 'safe ' + (c.hits.length ? 's-bad' : 's-ok') }, c.hits.length ? 'Check before sending: these could still become links: ' + c.hits.join(', ') : 'Safe to send: no links, no attachments, and every address and domain is defanged.'),
      h('div', { class: 'bar-row' }, h('span', { class: 'hint' }, 'Paste into a new email to the customer. Don\'t forward the original.'),
        h('div', { class: 'btns' }, h('button', { class: 'btn ghost', type: 'button', onclick: e => copy(c.subject, e.target) }, 'Copy subject'), h('button', { class: 'btn', type: 'button', onclick: e => copy(c.body, e.target) }, 'Copy email'))),
      h('dl', { class: 'kv' }, h('dt', {}, 'Subject'), h('dd', {}, c.subject)), h('pre', { class: 'out', style: 'margin-top:10px' }, c.body));
  }

  function exportPanel(v) {
    const body = h('div');
    const ext = { list: 'txt', csv: 'csv', kql: 'kql', spl: 'spl', wazuh: 'xml', stix: 'json', json: 'json', text: 'txt' };
    const draw = () => {
      body.textContent = '';
      const e = v.exports[state.exportTab];
      body.append(h('div', { class: 'tabs' }, Object.entries(v.exports).map(([k, x]) => h('button', { type: 'button', class: 'chip', 'aria-pressed': String(state.exportTab === k), onclick: () => { state.exportTab = k; draw(); } }, x.label))),
        h('div', { class: 'bar-row' }, h('span', { class: 'hint' }, e.description), h('div', { class: 'btns' },
          h('button', { class: 'btn ghost', type: 'button', onclick: () => download(`${v.id}.${ext[state.exportTab] || 'txt'}`, e.content) }, 'Download'),
          h('button', { class: 'btn', type: 'button', onclick: ev => copy(e.content, ev.target) }, 'Copy'))),
        h('pre', { class: 'out code' }, e.content));
    };
    draw();
    return panel('export', 'Export', 'indicators for your tools (not defanged where tools need raw values)', body);
  }

  // ── live mode: adding emails ────────────────────────────────────────────────
  async function analyse(name, body) {
    const st = $('drop-status');
    st.textContent = `Analysing ${name}…`;
    try {
      const r = await api('/api/analyses', { method: 'POST', headers: { 'content-type': 'message/rfc822', 'x-filename': encodeURIComponent(name), 'x-phishbowl-online': $('online').checked ? '1' : '0' }, body });
      state.views.set(r.view.id, r.view); state.items = state.items.filter(i => i.id !== r.view.id); state.items.push(r.summary);
      st.textContent = `${name}: ${r.summary.verdict ? r.summary.verdict.label : 'text'}`;
      return r.view.id;
    } catch (e) { st.textContent = `${name}: ${e.message}`; return null; }
  }
  async function addFiles(files) {
    let last = null;
    for (const f of files) last = (await analyse(f.name, await f.arrayBuffer())) || last;
    renderQueue(); if (last) select(last);
  }
  function setupLive() {
    $('drop').hidden = false; $('b-snapshot').hidden = false;
    const drop = $('drop');
    for (const ev of ['dragenter', 'dragover']) document.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); });
    for (const ev of ['dragleave', 'drop']) document.addEventListener(ev, e => { e.preventDefault(); if (ev === 'drop' || e.target === document.documentElement) drop.classList.remove('over'); });
    document.addEventListener('drop', e => { if (e.dataTransfer && e.dataTransfer.files.length) addFiles([...e.dataTransfer.files]); });
    $('online').checked = !!cfg.online;
    $('b-pick').onclick = () => $('file').click();
    $('file').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('b-paste').onclick = async () => { const t = $('paste').value; if (!t.trim()) return; const id = await analyse('pasted-' + new Date().toISOString().slice(11, 19).replace(/:/g, '') + '.eml', new TextEncoder().encode(t)); $('paste').value = ''; renderQueue(); if (id) select(id); };
    $('b-snapshot').onclick = async e => { try { download(`phishbowl-${new Date().toISOString().slice(0, 10)}.html`, await api('/api/snapshot.html'), 'text/html'); } catch (err) { flash(e.target, 'Failed'); } };
  }

  // ── start ───────────────────────────────────────────────────────────────────
  const theme = $('theme'), saved = store.get('pb-theme');
  const applyTheme = t => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; };
  theme.value = saved; applyTheme(saved);
  theme.onchange = () => { store.set('pb-theme', theme.value); applyTheme(theme.value); };
  if (params.has('embed') || cfg.embed) document.body.classList.add('embed');
  if (!state.reportOpts.preparedBy) state.reportOpts.preparedBy = store.get('pb-by');
  $('search').addEventListener('input', e => { state.search = e.target.value; renderQueue(); });
  $('mode').append(...(live ? [h('b', {}, '● Local'), ` · analysed on this machine${cfg.version ? ' · v' + cfg.version : ''}`] : [`Saved report · ${cfg.created || ''}`]));
  // A platform embedding the page can push views in: { type: 'phishbowl:load', views: [...] }. Only the page that
  // contains this one (its parent frame) is listened to; other windows and frames are ignored.
  window.addEventListener('message', e => {
    if (window.parent === window || e.source !== window.parent) return;
    const m = e.data;
    if (m && m.type === 'phishbowl:load' && Array.isArray(m.views)) { loadViews(m.views.filter(v => v && typeof v.id === 'string')); renderQueue(); if (m.views[0]) select(m.views[0].id); }
  });

  (async () => {
    if (live) {
      setupLive();
      try { const r = await api('/api/analyses'); state.items = r.items; } catch (e) { $('drop-status').textContent = 'Can\'t reach the local server: ' + e.message; }
    } else loadViews(embedded.views || []);
    renderQueue();
    const first = params.get('id') || (state.items.length ? [...state.items].sort((a, b) => (b.verdict ? b.verdict.score : -1) - (a.verdict ? a.verdict.score : -1))[0].id : null);
    if (first) select(first); else renderDetail(null);
  })();
})();
