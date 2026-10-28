// Phishbowl dashboard. Renders view models built by the engine (src/view.ts).
// Two modes: "live" talks to the local server (phishbowl ui); "static" shows the data embedded in the page.
// Pages: the queue (stats, intake, a table of emails) and one page per section of an email (overview, checks,
// headers, links, attachments, content, indicators, report, customer email, export), chosen in the sidebar.
// Every value is added as text (never as HTML), and email HTML is never rendered.
(() => {
  'use strict';
  const cfg = JSON.parse(document.getElementById('pb-config').textContent || '{}');
  const embedded = JSON.parse(document.getElementById('pb-data').textContent || '{"views":[]}');
  const live = cfg.mode === 'live';
  const params = new URLSearchParams(location.search);
  const state = { items: [], views: new Map(), route: { page: 'queue', id: null, section: 'overview' }, filter: 'all', search: '', sort: { by: 'score', dir: -1 },
    checkFilter: 'flagged', audience: 'tech', reportFmt: 'text', exportTab: 'list', iocType: null, showOff: false,
    reportOpts: { done: [], tlp: '', ref: '', preparedBy: cfg.preparedBy || '', customer: '' }, feedback: {} };

  // ── small helpers ───────────────────────────────────────────────────────────
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
  /** Thin-stroke icons, drawn here so nothing is loaded. */
  const ICONS = {
    inbox: 'M3 13h5l2 3h4l2-3h5M5 5h14l2 8v6H3v-6z', plus: 'M12 5v14M5 12h14', eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
    checks: 'M4 6h2m3 0h11M4 12h2m3 0h11M4 18h2m3 0h11', headers: 'M4 5h16v14H4zM4 10h16M9 10v9', link: 'M10 14a4 4 0 0 0 5.6 0l3-3a4 4 0 0 0-5.6-5.6l-1 1M14 10a4 4 0 0 0-5.6 0l-3 3a4 4 0 0 0 5.6 5.6l1-1',
    clip: 'M20 11.5 11.5 20a5 5 0 0 1-7-7L13 4.5a3.3 3.3 0 0 1 4.7 4.7L9.6 17.3a1.6 1.6 0 0 1-2.3-2.3l7.6-7.6', text: 'M4 6h16M4 11h16M4 16h10', ioc: 'M12 3a9 9 0 0 1 9 9c0 3-1 5-3 7M12 7a5 5 0 0 1 5 5c0 2-1 3-2 4M12 11a1 1 0 0 1 1 1c0 3-2 6-5 8M3 12a9 9 0 0 1 4-7.5M7 12a5 5 0 0 1 1-3',
    report: 'M6 3h9l4 4v14H6zM14 3v5h5M9 13h6M9 17h6', mail: 'M3 6h18v12H3zM3 7l9 6 9-6', export: 'M12 4v11M7 10l5 5 5-5M4 19h16', search: 'M11 4a7 7 0 1 1 0 14 7 7 0 0 1 0-14zM20 20l-3.5-3.5',
    upload: 'M12 16V5M7 10l5-5 5 5M4 19h16', sun: 'M12 4v2m0 12v2M4 12h2m12 0h2M6.3 6.3l1.4 1.4m8.6 8.6 1.4 1.4M6.3 17.7l1.4-1.4m8.6-8.6 1.4-1.4M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8z', file: 'M6 3h9l4 4v14H6zM14 3v5h5',
    back: 'M15 6l-6 6 6 6', fwd: 'M9 6l6 6-6 6', save: 'M4 4h13l3 3v13H4zM8 4v5h8V4M8 20v-6h8v6',
  };
  const icon = name => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('aria-hidden', 'true'); const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', ICONS[name]); s.append(p); return s; };
  const GLYPH = { bad: '✕', warn: '!', ok: '✓', info: 'i', na: '–' };
  const SAYS = { bad: 'red flag', warn: 'worth a look', ok: 'reassuring', info: 'context', na: 'not applicable' };
  const mark = s => h('span', { class: 'mark s-' + s, role: 'img', 'aria-label': SAYS[s] || s }, GLYPH[s] || 'i');
  const vclass = v => v ? v.v : 'text';
  const vlabel = v => v ? v.label : 'Text';
  const vbadge = (v, cls = '') => h('span', { class: `badge ${vclass(v)} ${cls}` }, h('i', { class: 'dot' }), vlabel(v));
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
  const size = n => n < 1024 ? plural(n, 'byte') : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
  const store = { get: k => { try { return localStorage.getItem(k) || ''; } catch { return ''; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } } };
  const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); flash(btn, 'Copied'); }
    catch { const t = h('textarea', {}, text); document.body.append(t); t.select(); try { document.execCommand('copy'); flash(btn, 'Copied'); } catch { flash(btn, 'Copy failed'); } t.remove(); }
  }
  const flash = (btn, msg) => { if (!btn) return; const old = btn.textContent; btn.textContent = msg; setTimeout(() => { btn.textContent = old; }, 1600); };
  function download(name, text, type = 'text/plain') {
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: type + ';charset=utf-8' })), download: name });
    document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  const btn = (label, onclick, cls = 'outline') => h('button', { class: 'btn ' + cls, type: 'button', onclick }, label);
  const tabs = (label, options, current, pick) => h('div', { class: 'tabs', role: 'group', 'aria-label': label },
    options.map(([k, l, n]) => h('button', { type: 'button', 'aria-pressed': String(current === k), onclick: () => pick(k) }, l, n == null ? null : h('b', {}, n))));
  const card = (title, desc, body, actions, cls = '') => h('section', { class: 'card ' + cls, 'aria-label': title },
    title ? h('div', { class: 'card-head' }, h('h2', {}, title), actions ? h('div', { class: 'actions' }, actions) : null, desc ? h('p', {}, desc) : null) : null,
    h('div', { class: 'card-body' }, body));
  const table = (head, rows, cls = 'bordered') => h('div', { class: 'tbl ' + cls }, h('table', {}, h('thead', {}, h('tr', {}, head.map(c => h('th', { scope: 'col' }, c)))), h('tbody', {}, rows)));

  // ── data ────────────────────────────────────────────────────────────────────
  async function api(path, opts = {}) {
    const r = await fetch(path, { ...opts, headers: { 'X-Phishbowl': '1', ...(opts.headers || {}) } });
    if (!r.ok) throw new Error((await r.text()) || r.statusText);
    return r.headers.get('content-type')?.includes('json') ? r.json() : r.text();
  }
  const summaryOf = v => ({ id: v.id, file: v.file, kind: v.kind, verdict: v.verdict, subject: v.summary ? v.summary.subject : '', from: v.summary ? v.summary.from : '', date: v.summary ? v.summary.date : '', top: v.findings[0] ? v.findings[0].name : '' });
  async function getView(id) {
    if (!state.views.has(id) && live) state.views.set(id, await api('/api/analyses/' + encodeURIComponent(id)));
    return state.views.get(id);
  }
  function loadViews(views) {
    for (const v of views) { state.views.set(v.id, v); if (!state.items.some(i => i.id === v.id)) state.items.push(summaryOf(v)); }
  }
  const itemOf = id => state.items.find(i => i.id === id);

  // ── routing ─────────────────────────────────────────────────────────────────
  const SECTIONS = [['overview', 'Overview', 'eye'], ['checks', 'Checks', 'checks'], ['headers', 'Headers', 'headers'], ['links', 'Links', 'link'], ['atts', 'Attachments', 'clip'],
    ['content', 'Content', 'text'], ['iocs', 'Indicators', 'ioc'], ['report', 'Report', 'report'], ['cust', 'Customer email', 'mail'], ['export', 'Export', 'export']];
  const TEXT_SECTIONS = ['overview', 'iocs', 'report', 'cust', 'export'];
  const sectionsFor = v => v && v.kind === 'text' ? SECTIONS.filter(([k]) => TEXT_SECTIONS.includes(k)) : SECTIONS;
  const hashOf = r => r.page === 'queue' ? '#/queue' : `#/email/${encodeURIComponent(r.id)}/${r.section}`;
  function parseHash() {
    const m = /^#\/email\/([^/]+)(?:\/([a-z]+))?/.exec(location.hash);
    if (m) return { page: 'email', id: decodeURIComponent(m[1]), section: SECTIONS.some(([k]) => k === m[2]) ? m[2] : 'overview' };
    return { page: 'queue', id: null, section: 'overview' };
  }
  // Navigation is the URL hash, so the back button works and a link can point at one email's section. The hash is
  // set through location (not history.pushState), which also works for a saved file opened from disk.
  function go(route, replace) {
    const target = hashOf(route);
    if (location.hash === target) return render();
    if (replace) location.replace(target); else location.hash = target;
  }
  const openEmail = (id, section = 'overview') => go({ page: 'email', id, section });
  window.addEventListener('hashchange', () => render());

  // ── queue helpers ───────────────────────────────────────────────────────────
  const ORDER = { malicious: 0, suspicious: 1, clean: 2 };
  function shownItems() {
    const q = state.search.toLowerCase(), { by, dir } = state.sort;
    const val = i => by === 'score' ? (i.verdict ? i.verdict.score : -1) : by === 'verdict' ? (i.verdict ? ORDER[i.verdict.v] : 3) : by === 'date' ? Date.parse(i.date) || 0 : String(i[by] || '').toLowerCase();
    return state.items.filter(i => (state.filter === 'all' || (i.verdict && i.verdict.v === state.filter)) && (!q || `${i.subject} ${i.from} ${i.file}`.toLowerCase().includes(q)))
      .sort((a, b) => { const x = val(a), y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * dir || (b.verdict ? b.verdict.score : 0) - (a.verdict ? a.verdict.score : 0); });
  }
  function step(n) {
    const shown = shownItems(); if (!shown.length) return;
    const at = shown.findIndex(i => i.id === state.route.id);
    const next = shown[Math.max(0, Math.min(shown.length - 1, at < 0 ? 0 : at + n))];
    if (next && next.id !== state.route.id) openEmail(next.id, state.route.page === 'email' ? state.route.section : 'overview');
  }

  // ── sidebar ─────────────────────────────────────────────────────────────────
  function renderNav() {
    const nav = $('nav'); nav.textContent = '';
    const r = state.route, v = r.id ? state.views.get(r.id) : null, item = r.id ? itemOf(r.id) : null;
    const link = (label, name, active, onclick, count, extra = {}) => h('button', { class: 'sb-link', type: 'button', 'aria-current': active ? 'page' : null, onclick, ...extra }, icon(name), h('span', {}, label), count == null ? null : h('span', { class: 'n' + (count && extra.bad ? ' bad' : '') }, count));
    const single = !live && state.items.length === 1;
    if (!single) {
      nav.append(h('div', { class: 'sb-group' }, 'Workspace'));
      nav.append(link('Queue', 'inbox', r.page === 'queue', () => go({ page: 'queue' }), state.items.length));
      if (live) nav.append(link('Add emails', 'plus', false, () => { go({ page: 'queue' }); setTimeout(() => $('b-pick')?.focus(), 50); }));
    }
    nav.append(h('div', { class: 'sb-group' }, item ? 'This email' : 'Email'));
    if (!item) nav.append(h('p', { class: 'muted', style: 'font-size:12.5px;padding:2px 10px 0;margin:0' }, 'Open an email from the queue to see its sections here.'));
    else {
      const flagged = v ? v.groups.reduce((n, g) => n + g.flagged, 0) : null;
      const counts = v ? { checks: flagged, links: v.links.length, atts: v.attachments.length, iocs: v.indicators.filter(i => !i.off).length } : {};
      for (const [k, label, name] of sectionsFor(v)) nav.append(link(label, name, r.page === 'email' && r.section === k, () => openEmail(r.id, k), counts[k], { bad: k === 'checks' && v && v.verdict && v.verdict.bad }));
    }
    document.body.classList.remove('nav-open'); $('scrim').hidden = true;
  }
  function renderCrumbs() {
    const c = $('crumbs'); c.textContent = '';
    const r = state.route, item = r.id ? itemOf(r.id) : null;
    const single = !live && state.items.length === 1;
    const parts = [];
    if (!single) parts.push(r.page === 'queue' ? h('span', { class: 'cur' }, 'Queue') : h('button', { type: 'button', onclick: () => go({ page: 'queue' }) }, 'Queue'));
    if (r.page === 'email' && item) {
      const name = item.subject || item.file;
      parts.push(r.section === 'overview' ? h('span', { class: 'cur' }, name) : h('button', { type: 'button', onclick: () => openEmail(r.id, 'overview'), class: 'cur', style: 'font-weight:400;color:var(--mid)' }, name));
      if (r.section !== 'overview') parts.push(h('span', { class: 'cur' }, SECTIONS.find(([k]) => k === r.section)[1]));
    }
    parts.forEach((p, i) => { if (i) c.append(h('span', { class: 'sep', 'aria-hidden': 'true' }, '/')); c.append(p); });
  }

  // ── render ──────────────────────────────────────────────────────────────────
  async function render() {
    state.route = parseHash();
    if (state.route.page === 'email' && !itemOf(state.route.id)) state.route = { page: 'queue', id: null, section: 'overview' };
    renderNav(); renderCrumbs();
    const page = $('page'); page.textContent = '';
    if (state.route.page === 'queue') return renderQueue(page);
    page.append(h('p', { class: 'hint' }, 'Loading…'));
    let v;
    try { v = await getView(state.route.id); } catch (e) { page.textContent = ''; page.append(card('Could not load this email', e.message, '')); return; }
    if (v.kind === 'text' && !TEXT_SECTIONS.includes(state.route.section)) { state.route.section = 'overview'; location.replace(hashOf(state.route)); renderNav(); renderCrumbs(); }
    page.textContent = '';
    renderEmail(page, v);
    window.scrollTo({ top: 0 });
    if (window.parent !== window) window.parent.postMessage({ type: 'phishbowl:selected', id: v.id, verdict: v.verdict ? v.verdict.v : 'text' }, '*');
  }

  // ── queue page ──────────────────────────────────────────────────────────────
  function renderQueue(page) {
    const counts = { all: state.items.length, malicious: 0, suspicious: 0, clean: 0, text: 0 };
    for (const i of state.items) if (i.verdict) counts[i.verdict.v]++; else counts.text++;
    page.append(h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Queue'), h('p', {}, live ? 'Emails analysed on this machine during this session. Nothing is kept after the server stops.' : `Saved report${cfg.created ? ', ' + cfg.created : ''}.`))));
    const pct = n => counts.all ? Math.round(n / counts.all * 100) + '%' : '';
    page.append(h('div', { class: 'grid cols-4', id: 'tiles' }, [['all', 'All emails', ''], ['malicious', 'Malicious', 'Act on these first'], ['suspicious', 'Suspicious', 'Need a second look'], ['clean', 'Likely legitimate', 'Nothing stood out']].map(([k, label, sub]) =>
      h('button', { type: 'button', class: 'card stat ' + k, 'aria-pressed': String(state.filter === k), onclick: () => { state.filter = state.filter === k ? 'all' : k; render(); } },
        h('span', { class: 'lbl' }, label), h('span', { class: 'val' + (counts[k] ? '' : ' zero') }, counts[k]),
        h('span', { class: 'sub' }, k === 'all' ? (counts.text ? plural(counts.text, 'text file') + ' included' : 'in the queue') : counts[k] ? `${pct(counts[k])} of the queue · ${sub}` : sub)))));
    if (live) page.append(intakeCard());

    const sortBtn = (by, label) => h('button', { type: 'button', 'aria-sort': state.sort.by === by ? (state.sort.dir > 0 ? 'ascending' : 'descending') : null,
      onclick: () => { state.sort = state.sort.by === by ? { by, dir: -state.sort.dir } : { by, dir: by === 'score' || by === 'date' ? -1 : 1 }; render(); } }, label, state.sort.by === by ? (state.sort.dir > 0 ? ' ↑' : ' ↓') : '');
    const shown = shownItems();
    const search = h('input', { class: 'input', id: 'search', type: 'search', value: state.search, placeholder: 'Filter by subject, sender or file', 'aria-label': 'Filter emails',
      oninput: e => { state.search = e.target.value; const tb = page.querySelector('#list'); if (tb) { tb.replaceWith(tableBody()); } } });
    const tableBody = () => {
      const rows = shownItems();
      return h('tbody', { id: 'list' }, rows.length ? rows.map(i => h('tr', { class: 'item', 'data-id': i.id, tabindex: '0', 'aria-current': String(i.id === state.route.id),
        onclick: () => openEmail(i.id), onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openEmail(i.id); } } },
        h('td', {}, h('span', { class: 'primary' }, i.subject || i.file), h('span', { class: 'second' }, i.from || (i.kind === 'text' ? 'Text, not an email' : ''))),
        h('td', {}, vbadge(i.verdict)), h('td', { class: 'n', style: 'color:var(--ink);font-weight:500' }, i.verdict ? i.verdict.score : ''),
        h('td', {}, i.top || h('span', { class: 'none' }, '—')), h('td', { class: 'n' }, i.date ? i.date.replace(/\s[+-]\d{4}$/, '') : ''), h('td', { class: 'm' }, i.file)))
        : h('tr', { class: 'empty-row' }, h('td', { colspan: 6 }, state.items.length ? 'No emails match this filter.' : live ? 'No emails yet. Add some above, or drop files anywhere on this page.' : 'No emails in this report.')));
    };
    page.append(h('section', { class: 'card flush', 'aria-label': 'Emails' },
      h('div', { class: 'table-tools' }, search,
        tabs('Verdict', [['all', 'All', counts.all], ['malicious', 'Malicious', counts.malicious], ['suspicious', 'Suspicious', counts.suspicious], ['clean', 'Legitimate', counts.clean]], state.filter, k => { state.filter = k; render(); }),
        h('div', { class: 'end' }, h('span', { class: 'muted', style: 'font-size:13px' }, `${shown.length} of ${state.items.length}`))),
      h('div', { class: 'tbl' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, sortBtn('subject', 'Email')), h('th', {}, sortBtn('verdict', 'Verdict')), h('th', {}, sortBtn('score', 'Score')), h('th', {}, 'Top finding'), h('th', {}, sortBtn('date', 'Sent')), h('th', {}, sortBtn('file', 'File')))), tableBody()))));
    page.append(h('p', { class: 'foot' }, 'Keys: ', h('kbd', {}, 'j'), ' ', h('kbd', {}, 'k'), ' open the next or previous email, ', h('kbd', {}, '/'), ' filter, ', h('kbd', {}, '⌘K'), ' search everything.'));
  }

  function intakeCard() {
    const status = h('p', { class: 'status', id: 'drop-status', role: 'status' }, state.lastStatus || '');
    const online = h('input', { type: 'checkbox', id: 'online', checked: state.online ?? !!cfg.online ? true : null, onchange: e => { state.online = e.target.checked; } });
    const paste = h('textarea', { id: 'paste', spellcheck: 'false', placeholder: 'Paste the raw email, headers included' });
    return h('section', { class: 'card', id: 'drop', 'aria-label': 'Add emails' },
      h('div', { class: 'card-head' }, h('h2', {}, 'Add emails'), h('p', {}, 'Analysed here on this machine. Nothing is uploaded anywhere.')),
      h('div', { class: 'card-body intake' },
        h('button', { class: 'dropzone', type: 'button', id: 'b-pick', onclick: () => $('file').click() }, icon('upload'), h('b', {}, 'Drop .eml or .msg files here'), h('span', {}, 'or click to choose files. Text files such as threat reports work too: only their indicators are extracted.')),
        h('div', { class: 'intake-side' },
          h('details', { class: 'paste' }, h('summary', {}, 'Paste a raw email or a threat report'), paste, h('button', { class: 'btn', type: 'button', id: 'b-paste', onclick: async () => { const t = paste.value; if (!t.trim()) return; const id = await analyse('pasted-' + new Date().toISOString().slice(11, 19).replace(/:/g, '') + '.eml', new TextEncoder().encode(t)); paste.value = ''; if (id) openEmail(id); else render(); } }, 'Analyse')),
          h('label', { class: 'switch' }, online, h('span', { class: 'sw', 'aria-hidden': 'true' }), h('span', { class: 'sw-text' }, h('b', {}, 'Check online'), h('span', {}, 'Domain age, the sender\'s DNS and phishing feeds. Sends domain names only.'))),
          status)));
  }

  // ── email pages ─────────────────────────────────────────────────────────────
  function renderEmail(page, v) {
    const r = state.route, s = v.summary, vd = v.verdict, sections = sectionsFor(v);
    const at = sections.findIndex(([k]) => k === r.section), prev = sections[at - 1], next = sections[at + 1];
    const title = v.kind === 'text' ? v.file : (s.subject || '(no subject)');
    const flagged = v.kind === 'text' ? 0 : v.groups.reduce((n, g) => n + g.flagged, 0);
    page.append(h('div', { class: 'page-head' },
      h('div', { style: 'min-width:0' }, h('h1', { class: 'd-title' }, title),
        h('p', {}, h('span', { class: 'mono' }, v.file), v.kind === 'email' ? ` · analysed in ${v.ms} ms · ${flagged} of ${vd.run} checks flagged` : ' · not an email, so only its indicators were extracted')),
      h('div', { class: 'actions' }, v.verdict ? vbadge(vd, 'lg') : h('span', { class: 'badge text lg' }, 'Text'),
        btn('Copy report', e => copy(v.reports[state.audience].text, e.target), 'outline'))));
    const panels = { overview: overviewPage, checks: checksPanel, headers: headersPanel, links: linksPanel, atts: attsPanel, content: contentPanel, iocs: iocsPanel, report: reportPanel, cust: customerPanel, export: exportPanel };
    page.append(panels[r.section](v));
    page.append(h('div', { class: 'pager' },
      prev ? h('button', { class: 'btn outline', type: 'button', onclick: () => openEmail(v.id, prev[0]) }, icon('back'), prev[1]) : h('span'),
      next ? h('button', { class: 'btn outline', type: 'button', onclick: () => openEmail(v.id, next[0]) }, next[1], icon('fwd')) : h('span')));
    page.append(h('p', { class: 'foot' }, 'Addresses and links are defanged (hxxp, [.]) so nothing here can be clicked by accident. The email\'s own HTML is never displayed.'));
  }

  function meter(v) {
    const run = Math.max(1, v.run), pct = n => (n / run * 100).toFixed(2) + '%';
    return h('div', { class: 'meter', role: 'img', 'aria-label': `${v.bad} red flags, ${v.warn} worth a look, ${v.ok} reassuring, of ${v.run} checks` },
      h('i', { class: 'b', style: 'width:' + pct(v.bad) }), h('i', { class: 'w', style: 'width:' + pct(v.warn) }), h('i', { class: 'o', style: 'width:' + pct(v.ok) }));
  }
  const authBadge = (k, r) => h('span', { class: 'badge ' + (r === 'pass' ? 'ok' : !r || r === 'none' ? 'soft' : /fail/.test(r) ? 'bad' : 'warn') }, k ? h('b', {}, k) : null, r || 'none');

  function overviewPage(v) {
    const left = h('div', { class: 'grid' }), right = h('div', { class: 'grid' });
    const wrap = h('div', { class: 'two-col', id: 'sec-overview' }, left, right);
    const nextCard = () => card('Next', '', h('div', { class: 'counts', style: 'grid-template-columns:1fr' }, [['report', 'Report'], ['cust', 'Customer email'], ['export', 'Export']].map(([k, l]) => h('button', { class: 'count', type: 'button', onclick: () => openEmail(v.id, k) }, h('b', { style: 'font-size:14px' }, l)))));
    if (v.kind === 'text') {
      const n = v.indicators.filter(i => !i.off).length;
      left.append(card('What this is', '', h('p', { style: 'margin:0' }, 'A text file rather than an email, so there are no sender, route or content checks. Its indicators (URLs, domains, IPs, hashes, CVEs, ATT&CK ids) were extracted and can be exported.')),
        card('Text', 'Defanged', h('pre', { class: 'out' }, v.text || '')));
      right.append(card('Indicators', '', h('div', { class: 'scoreblock', style: 'justify-items:start;text-align:left' }, h('span', { class: 'val' }, n), h('span', { class: 'lbl' }, 'to export')), btn('Open', () => openEmail(v.id, 'iocs'), 'outline sm')), nextCard());
      return wrap;
    }
    const s = v.summary, vd = v.verdict;
    left.append(h('section', { class: 'card verdict-card', 'aria-label': 'Verdict' }, h('div', { class: 'card-body' },
      h('div', {}, h('div', { class: 'verdict-word ' + vd.v }, h('i', { class: 'dotbig' }), vd.label), h('p', { class: 'verdict-sub' }, `${cap(vd.conf)} confidence. ${vd.bad + vd.warn} of ${vd.run} checks flagged.`)),
      h('div', { class: 'scoreblock' }, h('span', { class: 'val' }, vd.score), h('span', { class: 'lbl' }, 'Score'), h('span', { class: 'thr' }, 'Suspicious from 6, malicious from 12')),
      meter(vd), h('div', { class: 'legend' }, h('span', { style: '--c:var(--bad)' }, h('b', {}, vd.bad), ' red flags'), h('span', { style: '--c:var(--warn)' }, h('b', {}, vd.warn), ' worth a look'), h('span', { style: '--c:var(--ok)' }, h('b', {}, vd.ok), ' reassuring')))));
    left.append(card('Key findings', v.findings.length ? 'What matters most, in order' : '', v.findings.length
      ? h('ul', { class: 'findings' }, v.findings.map(c => h('li', {}, mark(c.status), h('span', {}, h('span', { class: 'cname' }, c.name), ' ', h('span', { class: 'res' }, c.result)))))
      : h('p', { class: 'hint', style: 'margin:0' }, 'Nothing stood out: authentication passed and nothing in the links, content or attachments was flagged.'), btn('All checks', () => openEmail(v.id, 'checks'), 'ghost sm')));
    left.append(card('Contents', '', h('div', { class: 'counts' },
      h('button', { class: 'count', type: 'button', onclick: () => openEmail(v.id, 'links') }, h('b', {}, s.links), h('span', {}, s.links === 1 ? 'link' : 'links')),
      h('button', { class: 'count', type: 'button', onclick: () => openEmail(v.id, 'atts') }, h('b', {}, s.attachments), h('span', {}, s.attachments === 1 ? 'attachment' : 'attachments')),
      h('button', { class: 'count' + (s.qr ? ' alert' : ''), type: 'button', onclick: () => openEmail(v.id, 'atts') }, h('b', {}, s.qr), h('span', {}, s.qr === 1 ? 'QR code' : 'QR codes')))));
    if (live && cfg.feedback) left.append(card('Is it really?', 'Your answer stays on this machine. phishbowl feedback shows what it adds up to.', feedbackRow(v)));
    right.append(card('Authentication', '', h('div', { class: 'rows' },
      [['SPF', s.auth.spf], ['DKIM', s.auth.dkim], ['DMARC', s.auth.dmarc]].map(([k, r]) => h('div', { class: 'row' }, h('span', { class: 'k' }, k), h('span', { class: 'end' }, authBadge('', r)))),
      h('div', { class: 'row' }, h('span', { class: 'k' }, 'Sent from'), h('span', { class: 'mono', style: 'overflow-wrap:anywhere' }, s.sentFrom || '—'))),
      btn('Headers', () => openEmail(v.id, 'headers'), 'ghost sm')));
    const facts = [['Reported by', s.reportedBy || ''], ...(s.attachedEmails || []).map(n => ['Attached email', `${n.name}: ${n.label}, score ${n.score}, "${n.subject}"`]),
      ['From', s.from], ['Reply-To', s.replyTo], ['Return-Path', s.returnPath], ['To', s.to], ['Sent', s.date]].filter(([, x]) => x);
    right.append(card('Message', '', h('dl', { class: 'kv' }, facts.flatMap(([k, x]) => [h('dt', {}, k), h('dd', { class: /From|Reply|Return|To/.test(k) ? 'm' : '' }, x)]))));
    right.append(nextCard());
    return wrap;
  }

  function feedbackRow(v) {
    const said = h('span', { class: 'said', role: 'status' }, state.feedback[v.id] ? 'Recorded: ' + state.feedback[v.id] : '');
    const keep = h('input', { type: 'checkbox' });
    const say = (says, label) => btn(label, async () => {
      try { await api(`/api/analyses/${v.id}/feedback`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ says, keep: keep.checked }) });
        state.feedback[v.id] = label; said.textContent = 'Recorded: ' + label + (keep.checked ? ', with a copy kept' : ''); }
      catch (e) { said.textContent = 'Not recorded: ' + e.message; } }, 'outline sm');
    return h('div', { class: 'feedback' }, say('phish', 'Phishing'), say('legit', 'Legitimate'), say('spam', 'Spam'), h('label', { class: 'check', style: 'margin-left:4px' }, keep, 'Keep a copy for tests'), said);
  }

  function checksPanel(v) {
    const all = v.groups.flatMap(g => g.checks), F = { flagged: [c => c.status === 'bad' || c.status === 'warn', 'Flagged'], all: [c => c.status !== 'na', 'All'],
      ok: [c => c.status === 'ok', 'Reassuring'], info: [c => c.status === 'info' || c.status === 'na', 'Context'] };
    const body = h('div');
    const draw = () => {
      body.textContent = '';
      body.append(h('div', { class: 'toolbar' }, tabs('Show checks', Object.entries(F).map(([k, [f, l]]) => [k, l, all.filter(f).length]), state.checkFilter, k => { state.checkFilter = k; draw(); })));
      for (const g of v.groups) {
        const rows = g.checks.filter(F[state.checkFilter][0]); if (!rows.length) continue;
        body.append(h('div', { class: 'group' }, h('h3', {}, g.name, h('span', { class: g.flagged ? 'has' : '' }, g.flagged ? g.flagged + ' flagged' : 'Nothing flagged')),
          rows.map(c => h('div', { class: 'chk ' + c.status }, mark(c.status), h('span', { class: 'cname' }, c.name),
            h('span', { class: 'cres' }, c.result, c.why && (c.status === 'bad' || c.status === 'warn') ? h('span', { class: 'why' }, c.why) : null)))));
      }
      if (!all.some(F[state.checkFilter][0])) body.append(h('p', { class: 'hint' }, 'No checks in this filter.'));
    };
    draw();
    return h('div', { id: 'sec-checks' }, card('Checks', `${v.verdict.run} checks ran. A red flag adds its weight to the score; a warning adds one.`, body));
  }

  function headersPanel(v) {
    const x = v.headers, q = h('input', { class: 'input', type: 'search', placeholder: 'Filter headers', 'aria-label': 'Filter headers', style: 'width:240px' });
    const allRows = x.all.map(r => h('tr', {}, h('td', { class: 'm nw' }, r.name), h('td', { class: 'm' }, r.value)));
    const shown = h('span', { class: 'count' }, plural(x.all.length, 'header'));
    q.addEventListener('input', () => { const t = q.value.toLowerCase(); let n = 0; allRows.forEach(tr => { tr.hidden = !!t && !tr.textContent.toLowerCase().includes(t); if (!tr.hidden) n++; }); shown.textContent = t ? `${n} of ${x.all.length}` : plural(x.all.length, 'header'); });
    return h('div', { id: 'sec-headers', class: 'grid' },
      card('Delivery route', 'Oldest hop first. The entry hop is where the email came in from outside.', x.hops.length ? table(['#', 'From (name it gave)', 'Reverse DNS', 'IP', 'Received by', 'With', 'Time (UTC)', 'Delay'], x.hops.map(r => h('tr', {},
        h('td', { class: 'n' }, r.n), h('td', { class: 'm' }, r.from, r.entry ? h('span', { class: 'chip warn' }, 'Entered here') : null), h('td', { class: 'm' }, r.rdns), h('td', { class: 'm nw' }, r.ip),
        h('td', { class: 'm' }, r.by), h('td', { class: 'm' }, r.with, r.tls ? h('span', { class: 'chip' }, 'TLS') : null), h('td', { class: 'm nw' }, r.time),
        h('td', { class: 'n' }, r.delay == null ? '' : r.delay < 0 ? h('span', { class: 'chip bad' }, r.delay + 's') : '+' + r.delay + 's'))))
        : h('p', { class: 'hint', style: 'margin:0' }, 'No Received headers, so the route can\'t be traced.'), h('span', { class: 'badge soft' }, plural(x.hops.length, 'hop'))),
      card('Authentication', '', table(['Check', 'Result', 'For domain', 'Matches From', 'Detail'], x.auth.map(r => h('tr', {}, h('td', { class: 'nw' }, r.check), h('td', {}, authBadge('', r.result)), h('td', { class: 'm' }, r.domain),
        h('td', {}, r.matchesFrom == null ? '' : h('span', { class: 'chip ' + (r.matchesFrom ? 'ok' : 'bad') }, r.matchesFrom ? 'Yes' : 'No')), h('td', {}, r.detail))))),
      x.spam.length ? card('Spam filter verdicts', 'What the receiving filter decided, in plain English.', table(['Header', 'Field', 'Value', 'Meaning'], x.spam.map(r => h('tr', {}, h('td', { class: 'm' }, r.header), h('td', { class: 'm nw' }, r.field), h('td', { class: 'm' }, r.value), h('td', {}, r.meaning))))) : null,
      card('All headers', '', table(['Name', 'Value'], allRows), [shown, q]));
  }

  function linksPanel(v) {
    if (!v.links.length) return h('div', { id: 'sec-links' }, card('Links', '', h('p', { class: 'hint', style: 'margin:0' }, 'No links in this email.')));
    const bad = v.links.filter(l => l.findings.some(f => f.sev === 'bad')).length;
    return h('div', { id: 'sec-links' }, card('Links', 'From the body, QR codes and attachments. Wrapped links (Safe Links, Proofpoint, Postmark and others) are unwrapped so the real destination is checked. Nothing here is clickable.',
      table(['#', 'Found in', 'Shows', 'Goes to', 'Findings'], v.links.map((l, i) => h('tr', {}, h('td', { class: 'n' }, i + 1), h('td', { class: 'nw' }, l.source), h('td', {}, l.shows),
        h('td', { class: 'm' }, l.goesTo, l.unwrapped ? h('div', {}, h('span', { class: 'chip' }, 'Unwrapped from ' + l.unwrapped)) : null),
        h('td', {}, l.findings.length ? l.findings.map(f => h('span', { class: 'chip ' + (f.sev === 'info' ? '' : f.sev) }, f.text)) : h('span', { class: 'none' }, 'Nothing found'))))),
      [h('span', { class: 'badge soft' }, plural(v.links.length, 'link')), bad ? h('span', { class: 'badge bad' }, `${bad} with red flags`) : null]));
  }

  function attsPanel(v) {
    if (!v.attachments.length) return h('div', { id: 'sec-atts' }, card('Attachments', '', h('p', { class: 'hint', style: 'margin:0' }, 'No attachments or embedded images.')));
    const fact = (k, val) => h('div', { class: 'fact' }, h('span', {}, k), h('b', {}, val));
    return h('div', { id: 'sec-atts' }, card('Attachments', 'Checked by content, not by name. Files are read as data only: nothing is opened, run or previewed.',
      h('div', { class: 'atts' }, v.attachments.map(a => h('article', { class: 'att' },
        h('h3', {}, h('span', {}, a.name), h('span', { class: 'badge ' + (a.worst === 'bad' ? 'bad' : a.worst === 'warn' ? 'warn' : 'ok') }, a.worst === 'bad' ? 'Dangerous' : a.worst === 'warn' ? 'Check it' : 'Nothing found')),
        h('div', { class: 'att-body' },
          h('div', { class: 'facts' }, fact('Says it is', a.declared), fact('Really is', a.what), fact('Size', size(a.size)), fact('Entropy', `${a.entropy} of 8`), a.inline ? fact('Shown', 'Inline in the body') : null),
          a.notes.length ? h('ul', { class: 'notes' }, a.notes.map(n => h('li', {}, mark(n.sev), h('span', {}, n.text)))) : null,
          a.zip ? [h('div', { class: 'sub' }, h('span', {}, 'Inside the archive'), h('span', { class: 'count' }, plural(a.zip.length, 'file'))),
            table(['Name', 'Size', 'Encrypted'], a.zip.map(z => h('tr', {}, h('td', { class: 'm' }, z.name), h('td', { class: 'n' }, z.size), h('td', {}, z.encrypted ? h('span', { class: 'chip bad' }, 'Yes') : ''))))] : null,
          a.html ? h('dl', { class: 'kv' }, h('dt', {}, 'Page title'), h('dd', {}, a.html.title || '(none)'), h('dt', {}, 'Forms'), h('dd', {}, a.html.forms.length ? a.html.forms.join('; ') : 'None'),
            h('dt', {}, 'Scripts'), h('dd', {}, `${plural(a.html.scripts, 'block')}, ${plural(a.html.handlers, 'event handler')}${a.html.patterns.length ? ': ' + a.html.patterns.join(', ') : ''}`), h('dt', {}, 'Links'), h('dd', {}, a.html.links)) : null,
          a.qr ? h('dl', { class: 'kv' }, h('dt', {}, 'QR code says'), h('dd', { class: 'm' }, a.qr)) : null,
          h('dl', { class: 'hash' }, h('dt', {}, 'SHA256'), h('dd', {}, a.sha256), h('dt', {}, 'SHA1'), h('dd', {}, a.sha1), h('dt', {}, 'MD5'), h('dd', {}, a.md5)))))),
      h('span', { class: 'badge soft' }, plural(v.attachments.length, 'file'))));
  }

  function contentPanel(v) {
    const c = v.content;
    return h('div', { id: 'sec-content', class: 'grid cols-2' },
      card('Language', 'Phrases the checks matched, by category.', h('dl', { class: 'kv' }, c.hits.flatMap(x => [h('dt', {}, x.label), h('dd', {}, x.phrases.length ? x.phrases.map(p => h('span', { class: 'phr' }, p)) : h('span', { class: 'none' }, 'None'))]))),
      card('Structure', '', h('dl', { class: 'kv' }, c.structure.flatMap(x => [h('dt', {}, x.label), h('dd', {}, x.value)]))),
      card('Message text', 'Defanged plain text of the email.', h('pre', { class: 'out' }, c.body), null, 'span-2'));
  }

  function iocsPanel(v) {
    const body = h('div');
    const draw = () => {
      body.textContent = '';
      const types = [...new Set(v.indicators.map(i => i.label))];
      body.append(h('div', { class: 'toolbar' },
        tabs('Indicator type', [[null, 'All', v.indicators.filter(i => !i.off).length], ...types.map(t => [t, t, v.indicators.filter(i => i.label === t && !i.off).length])], state.iocType,
          k => { state.iocType = state.iocType === k ? null : k; draw(); }),
        h('div', { class: 'end' }, h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: state.showOff || null, onchange: e => { state.showOff = e.target.checked; draw(); } }), 'Show left-out'))));
      const rows = v.indicators.filter(i => (!state.iocType || i.label === state.iocType) && (state.showOff || !i.off));
      body.append(rows.length ? table(['Type', 'Indicator (defanged)', 'Seen', 'Where it appears'], rows.map(i => h('tr', { class: i.off ? 'off' : '' }, h('td', { class: 'nw' }, h('span', { class: 'badge soft' }, i.label)),
        h('td', { class: 'm' }, i.defanged, h('div', {}, i.off ? h('span', { class: 'chip warn' }, 'Left out: ' + i.off) : null, i.notes.map(n => h('span', { class: 'chip' + (n.warn ? ' warn' : '') }, n.t)))),
        h('td', { class: 'n' }, '×' + i.count), h('td', { class: 'ctx' }, i.ctx.pre, h('mark', {}, i.ctx.hit), i.ctx.post)))) : h('p', { class: 'hint' }, 'No indicators.'));
    };
    draw();
    return h('div', { id: 'sec-iocs' }, card('Indicators', `${v.indicators.filter(i => !i.off).length} to export, ${v.indicators.filter(i => i.off).length} left out (private IPs, well-known sites, file names).`, body, btn('Export', () => openEmail(v.id, 'export'), 'outline sm')));
  }

  const ACTIONS = { 'block-sender': 'Blocked the sender', purge: 'Removed it from mailboxes', 'block-net': 'Blocked links, domains and IPs', edr: 'Blocked the file hashes', reset: 'Reset passwords for anyone who clicked' };
  function reportPanel(v) {
    const out = h('pre', { class: 'out' }), status = h('span', { class: 'toast', role: 'status' });
    const show = () => { const r = v.reports[state.audience]; out.textContent = state.reportFmt === 'markdown' ? r.markdown : r.text; };
    const refresh = async () => {
      if (!live) return show();
      status.textContent = 'Updating…';
      try { v.reports = await api(`/api/analyses/${encodeURIComponent(v.id)}/report`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(state.reportOpts) }); status.textContent = ''; }
      catch (e) { status.textContent = 'Could not update: ' + e.message; }
      show();
    };
    const audSeg = h('div');
    const drawAud = () => { audSeg.textContent = ''; audSeg.append(tabs('Written for', [['tech', 'Colleague or SOC'], ['mgmt', 'Customer or manager'], ['staff', 'Staff warning']], state.audience, k => { state.audience = k; drawAud(); show(); })); };
    drawAud();
    const fmtSel = h('select', { class: 'select', style: 'width:auto', onchange: e => { state.reportFmt = e.target.value; show(); }, 'aria-label': 'Format' }, h('option', { value: 'text', selected: state.reportFmt === 'text' || null }, 'Plain text'), h('option', { value: 'markdown', selected: state.reportFmt === 'markdown' || null }, 'Markdown'));
    const o = state.reportOpts, text = (key, label, ph) => h('label', {}, label, h('input', { class: 'input', value: o[key] || '', placeholder: ph || '', onchange: e => { o[key] = e.target.value.trim(); if (key === 'preparedBy') store.set('pb-by', o[key]); refresh(); } }));
    const fields = live ? h('div', { class: 'fields' },
      h('label', {}, 'Sharing (TLP)', h('select', { class: 'select', onchange: e => { o.tlp = e.target.value; refresh(); } }, [['', 'Suggested'], ['clear', 'TLP:CLEAR'], ['green', 'TLP:GREEN'], ['amber', 'TLP:AMBER'], ['amber-strict', 'TLP:AMBER+STRICT'], ['red', 'TLP:RED']]
        .map(([k, l]) => h('option', { value: k, selected: o.tlp === k || null }, l)))), text('preparedBy', 'Prepared by', 'Your name or team'), text('ref', 'Reference', 'Automatic')) : null;
    const done = live ? h('fieldset', { class: 'done' }, h('legend', {}, 'Already done: these move to "actions taken"'), Object.entries(ACTIONS).map(([k, l]) => h('label', {},
      h('input', { type: 'checkbox', checked: o.done.includes(k) || null, onchange: e => { o.done = e.target.checked ? [...o.done, k] : o.done.filter(x => x !== k); refresh(); } }), l)))
      : h('p', { class: 'hint' }, 'This is a saved report, so its text is fixed. Open the email in phishbowl ui to tick actions or change the sharing label.');
    show();
    return h('div', { id: 'sec-report' }, card('Report', 'A draft to share. Read it before sending; everything in it is defanged.',
      [h('div', { class: 'toolbar' }, audSeg, fmtSel, h('div', { class: 'end' }, status)), fields, done, out],
      [btn('Download', () => download(`${v.id}-report-${state.audience}.${state.reportFmt === 'markdown' ? 'md' : 'txt'}`, out.textContent)), btn('Copy report', e => copy(out.textContent, e.target), '')]));
  }

  function customerPanel(v) {
    const c = v.reports.customer;
    return h('div', { id: 'sec-cust' }, card('Customer email', 'Paste it into a new email to the customer. Don\'t forward the original.',
      [h('div', { class: 'callout ' + (c.hits.length ? 'bad' : 'ok') }, mark(c.hits.length ? 'bad' : 'ok'),
        h('span', {}, c.hits.length ? 'Check before sending: these could still become links: ' + c.hits.join(', ') : 'Safe to send: no links, no attachments, and every address and domain is defanged.')),
      h('div', { class: 'subject-line' }, h('span', {}, 'Subject'), h('b', {}, c.subject)), h('pre', { class: 'out' }, c.body)],
      [btn('Copy subject', e => copy(c.subject, e.target)), btn('Copy email', e => copy(c.body, e.target), '')]));
  }

  function exportPanel(v) {
    const body = h('div'), actions = h('div', { class: 'actions' });
    const ext = { list: 'txt', csv: 'csv', kql: 'kql', spl: 'spl', wazuh: 'xml', stix: 'json', json: 'json', text: 'txt' };
    const draw = () => {
      body.textContent = ''; actions.textContent = '';
      const e = v.exports[state.exportTab];
      body.append(h('div', { class: 'toolbar' }, tabs('Format', Object.entries(v.exports).map(([k, x]) => [k, x.label]), state.exportTab, k => { state.exportTab = k; draw(); })),
        h('p', { class: 'hint' }, e.description), h('pre', { class: 'out code' }, e.content));
      actions.append(btn('Download', () => download(`${v.id}.${ext[state.exportTab] || 'txt'}`, e.content)), btn('Copy', ev => copy(e.content, ev.target), ''));
    };
    draw();
    const c = card('Export', 'Indicators for your tools, raw where tools need raw values.', body);
    c.querySelector('.card-head').insertBefore(actions, c.querySelector('.card-head p'));
    return h('div', { id: 'sec-export' }, c);
  }

  // ── command palette ─────────────────────────────────────────────────────────
  const pal = { open: false, sel: 0, items: [] };
  function palItems(q) {
    q = q.trim().toLowerCase();
    const out = [], hit = s => !q || String(s || '').toLowerCase().includes(q);
    const emails = state.items.filter(i => hit(i.subject + ' ' + i.from + ' ' + i.file)).slice(0, 8);
    if (emails.length) { out.push({ group: 'Emails' }); for (const i of emails) out.push({ label: i.subject || i.file, sub: i.from || i.file, icon: 'mail', badge: i.verdict, run: () => openEmail(i.id) }); }
    const cur = state.route.id, v = cur ? state.views.get(cur) : null;
    if (cur) { const secs = sectionsFor(v).filter(([, l]) => hit(l)); if (secs.length) { out.push({ group: 'This email' }); for (const [k, l, ic] of secs) out.push({ label: l, icon: ic, run: () => openEmail(cur, k) }); } }
    const actions = [{ label: 'Go to the queue', icon: 'inbox', run: () => go({ page: 'queue' }) }];
    if (live) actions.push({ label: 'Add emails', icon: 'plus', run: () => $('file').click() }, { label: 'Save as HTML', icon: 'save', run: () => $('b-snapshot').click() });
    for (const [t, l] of [['', 'System'], ['light', 'Light'], ['dark', 'Dark'], ['night', 'Night']]) actions.push({ label: 'Appearance: ' + l, icon: 'sun', run: () => { $('theme').value = t; $('theme').dispatchEvent(new Event('change')); } });
    const acts = actions.filter(a => hit(a.label)); if (acts.length) { out.push({ group: 'Actions' }); out.push(...acts); }
    return out;
  }
  function drawPal() {
    const list = $('pal-list'); list.textContent = '';
    pal.items = palItems($('pal-q').value); const runnable = pal.items.filter(i => i.run);
    if (!runnable.length) { list.append(h('div', { class: 'pal-empty' }, 'Nothing matches.')); return; }
    pal.sel = Math.max(0, Math.min(pal.sel, runnable.length - 1));
    let n = 0;
    for (const it of pal.items) {
      if (it.group) { list.append(h('div', { class: 'pal-group' }, it.group)); continue; }
      const idx = n++;
      list.append(h('button', { class: 'pal-item', type: 'button', role: 'option', 'aria-selected': String(idx === pal.sel), onmouseenter: () => { pal.sel = idx; drawPal(); }, onclick: () => { closePal(); it.run(); } },
        icon(it.icon), h('span', {}, it.label), it.sub ? h('span', { class: 'sub' }, it.sub) : null, it.badge !== undefined ? vbadge(it.badge) : null));
    }
    const selEl = list.querySelector('[aria-selected="true"]'); if (selEl) selEl.scrollIntoView({ block: 'nearest' });
  }
  function openPal() { pal.open = true; pal.sel = 0; $('palette').hidden = false; $('pal-q').value = ''; drawPal(); $('pal-q').focus(); }
  function closePal() { pal.open = false; $('palette').hidden = true; }
  $('palette').addEventListener('click', e => { if (e.target === $('palette')) closePal(); });
  $('pal-q').addEventListener('input', () => { pal.sel = 0; drawPal(); });
  $('pal-q').addEventListener('keydown', e => {
    const runnable = pal.items.filter(i => i.run);
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.sel = Math.min(runnable.length - 1, pal.sel + 1); drawPal(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.sel = Math.max(0, pal.sel - 1); drawPal(); }
    else if (e.key === 'Enter') { e.preventDefault(); const it = runnable[pal.sel]; if (it) { closePal(); it.run(); } }
  });
  $('b-search').onclick = openPal;

  // ── live mode: adding emails ────────────────────────────────────────────────
  const setStatus = t => { state.lastStatus = t; const el = $('drop-status'); if (el) el.textContent = t; };
  async function analyse(name, body) {
    setStatus(`Analysing ${name}…`);
    try {
      const r = await api('/api/analyses', { method: 'POST', headers: { 'content-type': 'message/rfc822', 'x-filename': encodeURIComponent(name), 'x-phishbowl-online': (state.online ?? !!cfg.online) ? '1' : '0' }, body });
      state.views.set(r.view.id, r.view); state.items = state.items.filter(i => i.id !== r.view.id); state.items.push(r.summary);
      setStatus(`${name}: ${r.summary.verdict ? r.summary.verdict.label : 'text'}`);
      return r.view.id;
    } catch (e) { setStatus(`${name}: ${e.message}`); return null; }
  }
  async function addFiles(files) {
    let last = null;
    for (const f of files) last = (await analyse(f.name, await f.arrayBuffer())) || last;
    if (last) openEmail(last); else render();
  }
  function setupLive() {
    $('b-snapshot').hidden = false;
    let depth = 0;
    const over = on => document.body.classList.toggle('over', on);
    document.addEventListener('dragenter', e => { if ([...(e.dataTransfer?.types || [])].includes('Files')) { e.preventDefault(); depth++; over(true); } });
    document.addEventListener('dragover', e => { e.preventDefault(); });
    document.addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) over(false); });
    document.addEventListener('drop', e => { e.preventDefault(); depth = 0; over(false); if (e.dataTransfer && e.dataTransfer.files.length) addFiles([...e.dataTransfer.files]); });
    $('file').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
    $('b-snapshot').onclick = async e => { try { download(`phishbowl-${new Date().toISOString().slice(0, 10)}.html`, await api('/api/snapshot.html'), 'text/html'); } catch { flash(e.target, 'Save failed'); } };
  }

  // ── start ───────────────────────────────────────────────────────────────────
  const theme = $('theme'), saved = store.get('pb-theme');
  const applyTheme = t => { if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme; };
  theme.value = saved; applyTheme(saved);
  theme.onchange = () => { store.set('pb-theme', theme.value); applyTheme(theme.value); };
  if (params.has('embed') || cfg.embed) document.body.classList.add('embed');
  if (!state.reportOpts.preparedBy) state.reportOpts.preparedBy = store.get('pb-by');
  $('mode').append(live ? (cfg.version ? 'v' + cfg.version : '') : 'Saved report');
  $('b-menu').onclick = () => { document.body.classList.add('nav-open'); $('scrim').hidden = false; };
  $('scrim').onclick = () => { document.body.classList.remove('nav-open'); $('scrim').hidden = true; };
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal.open ? closePal() : openPal(); return; }
    if (e.key === 'Escape') { if (pal.open) closePal(); else if (document.body.classList.contains('nav-open')) $('scrim').click(); return; }
    if (pal.open) return;
    const typing = /^(input|textarea|select)$/i.test(e.target.tagName || '') || e.target.isContentEditable;
    if (e.key === '/' && !typing) { e.preventDefault(); const s = $('search'); if (s) s.focus(); else openPal(); }
    else if (!typing && !e.metaKey && !e.ctrlKey && !e.altKey && (e.key === 'j' || e.key === 'k')) step(e.key === 'j' ? 1 : -1);
  });
  // A platform embedding the page can push views in: { type: 'phishbowl:load', views: [...] }. Only the page that
  // contains this one (its parent frame) is listened to; other windows and frames are ignored.
  window.addEventListener('message', e => {
    if (window.parent === window || e.source !== window.parent) return;
    const m = e.data;
    if (m && m.type === 'phishbowl:load' && Array.isArray(m.views)) { loadViews(m.views.filter(v => v && typeof v.id === 'string')); if (m.views[0]) openEmail(m.views[0].id); else render(); }
  });

  (async () => {
    if (live) {
      setupLive();
      try { const r = await api('/api/analyses'); state.items = r.items; } catch (e) { state.lastStatus = 'Can\'t reach the local server: ' + e.message; }
    } else loadViews(embedded.views || []);
    const wanted = params.get('id');
    if (!location.hash && wanted && itemOf(wanted)) return go({ page: 'email', id: wanted, section: 'overview' }, true);
    if (!location.hash && !live && state.items.length === 1) return go({ page: 'email', id: state.items[0].id, section: 'overview' }, true);
    render();
  })();
})();
