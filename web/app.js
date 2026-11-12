"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Persian / Arabic digits and the Persian comma (a Persian keypad types ۱۴۰۰ and ۴۴۳،۸۰) become
// Latin as they are typed in number, port and id fields: the server reads Latin digits only
const latinDigits = (s) => String(s).replace(/[۰-۹]/g, d => d.charCodeAt(0) - 0x06F0).replace(/[٠-٩]/g, d => d.charCodeAt(0) - 0x0660).replace(/،/g, ',');
document.addEventListener('input', (e) => {
  const el = e.target;
  if (!el || !el.matches || el.type === 'password' || !el.matches('input.mono, input[inputmode="numeric"], input[type="number"]')) return;
  const v = latinDigits(el.value);
  if (v === el.value) return;
  const p = el.selectionStart;
  el.value = v;
  try { el.setSelectionRange(p, p); } catch (er) {} // number inputs have no selection
}, true);
const STATE = { user: null, methods: [], servers: [], tunnels: [], settings: {}, agentPin: '', view: 'tunnels' };
// the page and (admin) the account being viewed survive a refresh: kept in this browser only
const remember = (k, v) => { try { localStorage.setItem(k, v || ''); } catch (e) {} };
const recall = (k) => { try { return localStorage.getItem(k) || ''; } catch (e) { return ''; } };
const setOwnerFilter = (v) => { STATE.ownerFilter = v || ''; remember('tp-viewas', STATE.ownerFilter); };
const setView = (v) => { STATE.view = v; remember('tp-page', v); };

async function api(path, body, method) {
  const opt = { method: method || (body ? 'POST' : 'GET'), headers: {} };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch('/api' + path, opt);
  const txt = await r.text();
  let data = {}; try { data = txt ? JSON.parse(txt) : {}; } catch (e) { data = { error: txt }; }
  // the session ended (expired, signed out elsewhere, password changed): back to the sign-in
  // page once — only while signed in, so the login page's own calls and late timers don't loop
  if (r.status === 401 && STATE.user && !['/login', '/register', '/logout'].includes(path)) {
    STATE.user = null; STATE.view = 'auth'; // every page timer stops on its own once the view is gone
    renderAuth('login', STATE.settings.panelName);
  }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}
// a user-given name (tunnel, server, account) inside translated text: the Persian page leaves it as it is
const nm = (s) => `<bdi data-notr>${esc(s)}</bdi>`;
function toast(msg) {
  let box = $('#toasts');
  if (!box) { box = h('<div id="toasts" role="status" aria-live="polite"></div>'); document.body.appendChild(box); }
  const t = h(`<div class="toast">${esc(msg)}</div>`); box.appendChild(t);
  while (box.children.length > 3) box.firstElementChild.remove();
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 200); }, 2600 + Math.min(4000, String(msg).length * 30));
}
function copy(text, el) {
  // a second press within the 1.2 s keeps the button's own label (it used to stay "Copied")
  const done = () => { if (el) { const o = el.dataset.copyLabel ?? el.textContent; el.dataset.copyLabel = o; el.textContent = 'Copied'; clearTimeout(el._copyT); el._copyT = setTimeout(() => { el.textContent = o; delete el.dataset.copyLabel; }, 1200); } };
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done) { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); } catch (e) {} t.remove(); done && done(); }

/* ---------------- boot ---------------- */
async function boot() {
  let s = {};
  try {
    s = await api('/setup-state');
    document.title = s.panelName || 'Tunnel Panel';
    if (!s.configured) return renderAuth('register', s.panelName);
    const me = await api('/me');
    if (!me.user) return renderAuth('login', s.panelName);
    STATE.user = me.user; STATE.role = me.role || 'admin'; STATE.version = me.version || "";
    await loadAll();
    renderShell();
  } catch (e) { renderAuth('login', s.panelName); } // signed out: /me answers 401
}
async function loadAll() {
  const [methods, servers, tunnels, settings, helpers] = await Promise.all([
    api('/methods'), api('/servers'), api('/tunnels'), api('/settings'), api('/helpers').catch(() => [])]);
  STATE.helperLost = Object.fromEntries((helpers || []).filter(x => x.source === 'missing').map(x => [x.name, x.note || '']));
  STATE.hostArch = (settings && settings.hostArch) || 'amd64';
  STATE.methods = methods || []; STATE.tunnels = tunnels || [];
  // a user also gets the admin's servers that carry their tunnels (shared, read-only): they
  // name where a tunnel runs but aren't the user's to manage
  STATE.servers = (servers || []).filter(s => !s.shared); STATE.shared = (servers || []).filter(s => s.shared);
  STATE.settings = (settings && settings.settings) || {}; STATE.agentPin = settings.agentPin || ''; STATE.agentPort = settings.agentPort || 7020;
  STATE.users = isAdmin() ? await api('/users').catch(() => []) : [];
  if (STATE.restored === undefined) { // once per page load: back to the page and account viewed before the refresh
    STATE.restored = true;
    const pg = recall('tp-page');
    if (['tunnels', 'servers', 'routes', 'usage', 'igproxy', 'bench', 'settings'].includes(pg) || (pg === 'users' && isAdmin())) STATE.view = pg;
    const va = recall('tp-viewas');
    if (isAdmin() && va && (va === '-' || STATE.users.some(u => u.username === va))) STATE.ownerFilter = va;
  }
  paintSide();
}
// the sidebar's panel name and running/all badge follow every reload of the state (they were
// drawn once per shell, so they kept the old numbers until the next full redraw)
function paintSide() {
  const side = $('#side'); if (!side) return;
  const b = $('.brand b', side); if (b) b.textContent = STATE.settings.panelName || 'Tunnel Panel';
  const nb = $('.nav button[data-v="tunnels"]', side); if (!nb) return;
  let em = $('.nb', nb);
  if (!STATE.tunnels.length) { if (em) em.remove(); return; }
  if (!em) { em = h('<em class="nb" title="running / all"></em>'); nb.appendChild(em); }
  const txt = `${STATE.tunnels.filter(t => t.active && shownOwner(t.owner)).length}/${STATE.tunnels.filter(t => shownOwner(t.owner)).length}`;
  if (em.textContent !== txt) em.textContent = txt;
}
const iranServers = () => STATE.servers.filter(s => (s.role || 'iran') === 'iran');
const foreignServers = () => STATE.servers.filter(s => s.role === 'foreign');
const methodsFor = (fam) => STATE.methods.filter(m => m.families.includes(fam));
// method families, in the order the UI lists them (all Backhaul cores together)
const GROUPS = ['Backhaul', 'BackPack', 'Kernel GRE / IPsec / WireGuard', 'TP', 'Other'];
const GROUP_ICON = { 'Backhaul': '🚀', 'BackPack': '🎒', 'Kernel GRE / IPsec / WireGuard': '🧩', 'TP': '🛰', 'Other': '🔧' };
const groupOf = (m) => (m && m.group) || 'Other';
const groupRank = (g) => { const i = GROUPS.indexOf(g); return i < 0 ? GROUPS.length : i; };
const groupIcon = (m) => GROUP_ICON[groupOf(m)] || '🔧';
// <optgroup>s of methods, one per family; opt(m) renders one <option>
function groupedOptions(ms, opt) {
  const by = {};
  ms.forEach(m => (by[groupOf(m)] = by[groupOf(m)] || []).push(m));
  return Object.keys(by).sort((a, b) => groupRank(a) - groupRank(b))
    .map(g => `<optgroup label="${esc((GROUP_ICON[g] || '🔧') + ' ' + g)}">${by[g].map(opt).join('')}</optgroup>`).join('');
}
// uname -m → release arch, as the server does (goArch)
const archOf = (u) => /^(aarch64|arm64)$/.test(u || '') ? 'arm64' : /^(x86_64|amd64)$/.test(u || '') ? 'amd64' : (u || '');
// why a method's core can't be installed ("" = fine). The panel gets its helper binaries by
// itself (vendor download, or copied back from a server); only a lost one it couldn't
// recover has a note.
function methodMissing(m, t) {
  if (!m || !m.helper) return '';
  const ir = serverById(t.serverId), fg = t.foreignId ? serverById(t.foreignId) : null;
  const arches = m.helperArch ? [m.helperArch] : [archOf(ir && ir.arch), fg ? archOf(fg.arch) : STATE.hostArch].filter(Boolean);
  const lost = [...new Set(arches)].map(a => (STATE.helperLost || {})[m.helper + '-' + a]).filter(x => x !== undefined);
  return lost.length ? (lost[0] || m.helper + ' is missing on the panel') : '';
}
const serverById = (id) => STATE.servers.find(s => s.id === id) || (STATE.shared || []).find(s => s.id === id);
// the tunnel's own servers when they're shared ones (the pickers list only the user's servers)
const sharedOpts = (role, cur) => (STATE.shared || []).filter(s => s.id === cur && (s.role || 'iran') === role).map(s => `<option value="${s.id}" selected>${esc(serverLabel(s))} · shared</option>`).join('');
// accounts: the admin sees everything (and can narrow the view to one account); a user only
// ever gets their own servers and tunnels from the panel
const isAdmin = () => STATE.role !== 'user';
// a route a user's tunnel runs on the admin's servers (shared, or the panel host): its
// method switches are the admin's — the server neither shows a user them nor lets them change
const sharedPair = (iran, foreign) => !isAdmin() && (!foreign || !!serverById(iran)?.shared || !!serverById(foreign)?.shared);
// the admin's account filter: '' = everything, '-' = the admin's own, else a username
const shownOwner = (o) => !isAdmin() || !STATE.ownerFilter || (STATE.ownerFilter === '-' ? !o : o === STATE.ownerFilter);
const ownerChip = (o) => isAdmin() && o ? `<span class="chip own" title="belongs to the account ${esc(o)}">👤 ${nm(o)}</span>` : '';
const panelHostOpt = () => isAdmin() ? '<option value="">this panel host</option>' : '';
const serverName = (id) => id ? (serverById(id)?.name || '(deleted)') : 'this panel host';
// serverName as HTML: a server's own name is left untranslated, "this panel host" / "(deleted)" are translated
const srvNm = (id, host) => { const s = id ? serverById(id) : null; return s ? nm(s.name) : esc(id ? '(deleted)' : host || 'this panel host'); };
// flag emoji from an ISO-3166 alpha-2 country code (regional indicator letters)
function flag(cc) {
  if (!cc || cc.length !== 2) return '';
  cc = cc.toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}
const serverFlag = (id) => { const s = serverById(id); return s && s.country ? flag(s.country) + ' ' : ''; };
const serverLabel = (s) => (s.country ? flag(s.country) + ' ' : '') + s.name;

/* ---------------- auth ---------------- */
// 👁 show/hide on password fields, and a strength hint under new passwords
function wirePasswordUX(root) {
  $$('[data-eye]', root).forEach(b => b.onclick = () => { const i = b.previousElementSibling; i.type = i.type === 'password' ? 'text' : 'password'; });
  $$('[data-strength]', root).forEach(i => {
    const meter = $('[data-meter]', i.closest('label'));
    if (!meter) return;
    i.oninput = () => {
      const v = i.value;
      if (!v) { meter.textContent = ''; return; }
      const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => r.test(v)).length;
      const score = v.length < 8 ? 0 : (v.length >= 14 ? 2 : 1) + (kinds >= 3 ? 1 : 0);
      meter.textContent = ['too short (min 8)', 'okay', 'good', 'strong'][score];
      meter.style.color = ['var(--crit)', 'var(--warn)', 'var(--good)', 'var(--good)'][score];
    };
  });
}
function renderAuth(mode, name) {
  const reg = mode === 'register';
  document.body.innerHTML = '';
  const el = h(`<div class="auth"><div class="card">
    <div class="brand"><div class="dot"></div><div><b>${esc(name || 'Tunnel Panel')}</b><small>server link manager</small></div></div>
    <h2 style="text-align:center;margin-bottom:6px">${reg ? 'Create admin account' : 'Sign in'}</h2>
    <p class="muted" style="text-align:center;margin:0 0 18px">${reg ? 'First run — set your panel login.' : 'Enter your credentials.'}</p>
      ${reg ? `<div class="mdesc" style="margin-bottom:12px">Enter the <b>setup code</b> the installer printed. Lost it? On the server run <span class="mono">tunnel-panel setup-code</span></div>` : ''}
    <form class="ff" id="af">
      <label class="f">Username<input name="u" autocomplete="username" required></label>
      <label class="f">Password<span class="pw"><input name="p" type="password" autocomplete="${reg ? 'new-password' : 'current-password'}" required${reg ? ' minlength="8" data-strength' : ''}><button type="button" class="btn sm ghost" data-eye title="show / hide">👁</button></span>${reg ? '<small class="fhelp" data-meter></small>' : ''}</label>
      ${reg ? '<label class="f">Setup code<input name="c" class="mono" autocomplete="one-time-code" placeholder="xxxx-xxxx-xxxx" required></label>' : ''}
      <button class="btn pri" style="justify-content:center;padding:11px">${reg ? 'Create account' : 'Sign in'}</button>
      <div id="aerr" style="color:var(--crit);min-height:16px;font-size:13px"></div>
    </form></div></div>`);
  document.body.appendChild(el);
  wirePasswordUX(el);
  $('#af').onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api(reg ? '/register' : '/login', { username: ev.target.u.value, password: ev.target.p.value, code: reg ? ev.target.c.value : '' }); location.reload(); }
    catch (e) { $('#aerr').textContent = e.message; }
  };
}

/* ---------------- shell ---------------- */
function renderShell() {
  // the View filter names an account that is gone (deleted), or there's no selector to change it: everything
  if (isAdmin() && STATE.ownerFilter && ((STATE.users || []).length <= 1 || (STATE.ownerFilter !== '-' && !(STATE.users || []).some(u => u.username === STATE.ownerFilter)))) setOwnerFilter('');
  document.body.innerHTML = '';
  const nav = [['servers', 'Servers', '🖥'], ['tunnels', 'Tunnels', '🛰'], ['routes', 'Routes', '🔀'], ['usage', 'Usage', '📈'], ['igproxy', 'IG Routing', '🌐'], ['bench', 'Benchmark', '📊'],
    ...(isAdmin() ? [['users', 'Users', '👥'], ['settings', 'Settings', '⚙']] : [['settings', 'Account', '👤']])];
  const shell = h(`<div class="shell">
    <aside class="side" id="side">
      <div class="brand"><div class="dot"></div><div><b>${esc(STATE.settings.panelName || 'Tunnel Panel')}</b><small>server link manager</small></div></div>
      <nav class="nav">${nav.map(n => `<button data-v="${n[0]}"><span class="ni">${n[2]}</span><span class="nl">${n[1]}</span>${n[0] === 'tunnels' && STATE.tunnels.length ? `<em class="nb" title="running / all">${STATE.tunnels.filter(t => t.active && shownOwner(t.owner)).length}/${STATE.tunnels.filter(t => shownOwner(t.owner)).length}</em>` : ''}</button>`).join('')}</nav>
      <div class="foot">
        ${isAdmin() && (STATE.users || []).length > 1 ? `<label class="f vf" title="show the servers and tunnels of one account">👁 View<select id="ownerSel"><option value="">All accounts</option><option value="-">My own</option>${STATE.users.filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}" data-notr>${esc(u.username)}</option>`).join('')}</select></label>` : ''}
        ${isAdmin() ? '' : '<!--'}<a class="btn ghost sm bkbtn" href="/api/backup" download title="Download a backup of the whole panel: servers, tunnels, settings, users (keep the file private). Restore it under Settings.">💾 Backup</a>${isAdmin() ? '' : '-->'}
        <div class="sep"></div>
        <div class="look"><button class="btn ghost sm" id="themeBtn" title="Light / dark">◐</button><button class="btn ghost sm" id="langBtn" data-notr title="${window.tpLang === 'fa' ? 'English' : 'فارسی'}">${window.tpLang === 'fa' ? 'EN' : 'فا'}</button><div class="swatches" title="Accent colour">${ACCENTS.map(c => `<button type="button" class="sw" data-acc="${c}" style="--c:${c}" aria-label="accent ${c}"></button>`).join('')}</div></div>
        <div class="who"><span class="faint"><b data-notr>${esc(STATE.user)}</b>${isAdmin() ? ' <span class="chip own">admin</span>' : ''}${STATE.version ? ` · <span class="mono" title="version">${esc(STATE.version)}</span>` : ''}</span><button class="btn ghost sm" id="logout">Sign out</button></div>
      </div></aside>
    <div class="sidebg" id="sidebg"></div>
    <main class="main" id="work"></main></div>`);
  document.body.appendChild(shell);
  $$('.nav button', shell).forEach(b => b.onclick = () => { setView(b.dataset.v); paintNav(); renderView(); $('#side').classList.remove('open'); });
  $('#sidebg').onclick = () => $('#side').classList.remove('open');
  $('#logout').onclick = async () => { await api('/logout', {}); location.reload(); };
  $('#themeBtn').onclick = toggleTheme;
  $('#langBtn').onclick = () => window.tpSetLang && window.tpSetLang(window.tpLang === 'fa' ? 'en' : 'fa');
  const os = $('#ownerSel', shell);
  if (os) { os.value = STATE.ownerFilter || ''; os.onchange = () => { setOwnerFilter(os.value); renderShell(); }; } // the sidebar's counts follow it too
  $$('[data-acc]', shell).forEach(b => b.onclick = () => setAccent(b.dataset.acc));
  paintAccent();
  paintNav(); renderView();
}
function paintNav() { $$('.nav button').forEach(b => b.classList.toggle('on', b.dataset.v === STATE.view)); }
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('tp-theme', next); } catch (e) {}
}
try { const t = localStorage.getItem('tp-theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch (e) {}
// accent colour (per browser): the theme's own, or one of these
const ACCENTS = ['', '#6d5dfc', '#0ea5e9', '#10b981', '#f59e0b', '#ec4899'];
function setAccent(c) {
  const r = document.documentElement.style;
  if (c) { r.setProperty('--accent', c); r.setProperty('--accent-soft', `color-mix(in srgb, ${c} 16%, var(--panel))`); r.setProperty('--accent-fg', accentFg(c)); }
  else { r.removeProperty('--accent'); r.removeProperty('--accent-soft'); r.removeProperty('--accent-fg'); }
  try { localStorage.setItem('tp-accent', c); } catch (e) {}
  paintAccent();
}
// the text colour on an accent: white where it reads (WCAG contrast ≥ 4.5), else near-black
function accentFg(c) {
  const lin = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  const [r, g, b] = [1, 3, 5].map(i => lin(parseInt(c.slice(i, i + 2), 16)));
  const L = 0.2126 * r + 0.7152 * g + 0.0722 * b;
  return 1.05 / (L + 0.05) >= 4.5 ? '#ffffff' : '#0c0f1a';
}
function paintAccent() {
  let c = ''; try { c = localStorage.getItem('tp-accent') || ''; } catch (e) {}
  $$('[data-acc]').forEach(b => b.classList.toggle('on', b.dataset.acc === c));
}
try { const a = localStorage.getItem('tp-accent'); if (a && /^#[0-9a-f]{6}$/i.test(a)) setAccent(a); } catch (e) {}

// numbers in [data-cu] count up from 0 (once per page draw)
function countUp(root) {
  const reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  $$('[data-cu]', root).forEach(el => {
    const to = +el.dataset.cu || 0;
    if (reduce || to < 2) { el.textContent = to; return; }
    const t0 = performance.now(), dur = 600;
    const step = (now) => { const k = Math.min(1, (now - t0) / dur); el.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  });
}
function renderView() {
  const w = $('#work'); w.innerHTML = '';
  w.classList.remove('enter'); void w.offsetWidth; w.classList.add('enter'); // replay the page-in animation
  clearTimeout(renderView.t); renderView.t = setTimeout(() => w.classList.remove('enter'), 400); // …once: later redraws don't fade again
  w.classList.remove('igp');
  ({ tunnels: viewTunnels, servers: viewServers, routes: viewRoutes, usage: viewUsage, igproxy: viewIg, bench: viewBench, settings: viewSettings, users: viewUsers }[STATE.view])(w);
  trafficWatch();
  healthWatch();
}

/* ---------------- usage ---------------- */
// Bytes per tunnel over the last 1 / 7 / 30 days (usage.go reads the counters every 5 min,
// always) and what of it costs: Iran's upload is free, so a tunnel pays what its Iran server
// received for it — its users' upload plus what its foreign server sent (usage.go usagePaid).
async function viewUsage(w) {
  const custom = recall('tp-usage-d') === 'c';
  const days = custom ? 1 : [1, 7, 30].includes(+recall('tp-usage-d')) ? +recall('tp-usage-d') : 1;
  // a chosen span, in Tehran time (UTC+3:30 all year) to the hour: the counters are kept hour by hour
  const thrIn = (u) => new Date((u + 12600) * 1000).toISOString().slice(0, 14) + '00';
  const thrOut = (v) => Math.floor(Date.parse(v.slice(0, 13) + ':00Z') / 1000) - 12600;
  const nowU = Math.floor(Date.now() / 1000), today = nowU - (nowU + 12600) % 86400;
  // a quick range ("today") and a span that ends now are kept as such, so they move with the clock
  const quick = { today: [today, nowU], yesterday: [today - 86400, today], d3: [today - 2 * 86400, nowU], week: [today - 6 * 86400, nowU] };
  let rng = {}; try { rng = JSON.parse(recall('tp-usage-rng') || '{}') || {}; } catch (e) {}
  if (quick[rng.q]) rng = { q: rng.q, f: quick[rng.q][0], t: quick[rng.q][1] };
  else if (rng.live && rng.f > 0) rng.t = nowU;
  if (!(rng.f > 0 && rng.t > rng.f)) rng = { q: 'today', f: today, t: nowU };
  w.innerHTML = topbar('Usage', 'Download, upload and what you pay for, per tunnel — hour by hour.',
    `<div class="seg">${[[1, '24 hours'], [7, '7 days'], [30, '30 days'], ['c', '📅 Date & time']].map(x => `<button class="${(custom ? x[0] === 'c' : x[0] === days) ? 'on' : ''}" data-ud="${x[0]}">${x[1]}</button>`).join('')}</div>`);
  $$('[data-ud]', w).forEach(b => b.onclick = () => { remember('tp-usage-d', b.dataset.ud); renderView(); });
  if (custom) {
    const pick = h(`<div class="card pad urange">
      <label>From<input type="datetime-local" step="3600" data-rf min="${thrIn(today - 399 * 86400)}" value="${thrIn(rng.f)}"></label>
      <label>To<input type="datetime-local" step="3600" data-rt min="${thrIn(today - 399 * 86400)}" value="${thrIn(rng.t - 1)}"></label>
      <button class="btn pri" data-rgo>Show</button>
      <span class="ugo">${[['Today', 'today'], ['Yesterday', 'yesterday'], ['Last 3 days', 'd3'], ['This week', 'week']].map(x => `<button class="btn sm ${rng.q === x[1] ? 'pri' : 'ghost'}" data-rq="${x[1]}">${x[0]}</button>`).join('')}</span>
      <small class="faint">Tehran time, to the hour.</small></div>`);
    w.appendChild(pick);
    const go = (v) => { remember('tp-usage-rng', JSON.stringify(v)); renderView(); };
    $('[data-rgo]', pick).onclick = () => {
      const fv = $('[data-rf]', pick).value, tv = $('[data-rt]', pick).value;
      const f = thrOut(fv), t = thrOut(tv) + 3600;   // (Chrome reads an empty field as the year 2000)
      if (!fv || !tv || !(f > 0 && t > 0)) return toast('Fill in both From and To');
      if (t <= f) return toast('"To" must be after "From"');
      if (f >= nowU) return toast('"From" is in the future');
      go(t >= nowU ? { f, t: nowU, live: true } : { f, t });
    };
    $$('[data-rq]', pick).forEach(b => b.onclick = () => go({ q: b.dataset.rq }));
  }
  const box = h('<div class="srvsplit usplit"><div class="card skel" style="height:320px"></div><div class="skel" style="height:320px"></div></div>');
  w.appendChild(box);
  let r;
  try { r = await api(custom ? `/usage?from=${rng.f}&to=${rng.t}` : '/usage?days=' + days); } catch (e) { box.outerHTML = `<div class="card pad errtxt">${esc(e.message)}</div>`; return; }
  const T = Object.fromEntries((r.tunnels || []).map(x => [x.id, x]));
  const S = Object.fromEntries((r.servers || []).map(x => [x.id, x]));
  const z = { down: 0, up: 0, paid: 0, series: [] };
  const tot = (x) => x.down + x.up;
  // deleted tunnels whose bytes are in this window still count (their route as it was)
  // (one deleted before its route was kept has none: '~', shown as "route unknown", paid at ×1)
  const gone = Object.entries(r.gone || {}).map(([id, g]) => { const p = (g.pair || '').split('|'); const k = p.length === 2; return { id, name: g.name || 'deleted ' + id.slice(0, 6), owner: g.owner || '', serverId: k ? p[0] : '~', foreignId: k ? p[1] : '~', active: '', deleted: true }; });
  const tunnels = STATE.tunnels.concat(gone).filter(t => shownOwner(t.owner)).sort((a, b) => tot(T[b.id] || z) - tot(T[a.id] || z));
  const routeOf = Object.fromEntries(STATE.tunnels.concat(gone).map(t => [t.id, t.serverId]));
  const stopTag = (t) => t.deleted ? ' <span class="faint">(deleted)</span>' : t.active ? '' : ' <span class="faint">(stopped)</span>';
  // one physical server may be in the list twice (two accounts added it): its card counts once
  const all = STATE.servers.concat(STATE.shared || []);
  const nicOf = (id) => {
    if (id === '~') return { key: '~', u: z };
    const s = id ? serverById(id) : null;
    const ip = s ? (s.ipv4 || s.ipv6 || id) : 'panel';
    const u = S[id] || (s ? all.filter(o => (o.ipv4 || o.ipv6) === ip).map(o => S[o.id]).find(Boolean) : null) || z;
    return { key: ip, u };
  };
  const srvOf = (id) => id && id !== '~' ? serverById(id) : null;
  const flagOf = (id) => { if (id === '~') return '❔'; const s = srvOf(id); return s ? (s.country ? flag(s.country) : '🌍') : '🏠'; };
  const nameOf = (id) => { if (id === '~') return '❔ route unknown'; const s = srvOf(id); return s ? `${s.country ? flag(s.country) : ''} ${nm(s.name)}` : '🏠 panel host'; };
  // the count line: what the total sums (live tunnels, deleted ones with bytes here, the Iran servers they ran on)
  const countTxt = (list, gs) => { const d = list.filter(t => t.deleted).length, n = list.length - d, k = gs.filter(g => g.id !== '~').length;
    return `${n} tunnel${n === 1 ? '' : 's'}${d ? ` + ${d} deleted` : ''} on ${k} Iran server${k === 1 ? '' : 's'}`; };
  const coef = (paid, used) => used > 1 << 20 && paid > 0 ? '×' + (paid / used).toFixed(2) : '—';
  const coefCls = (paid, used) => used > 1 << 20 ? (paid / used > 1.3 ? ' class="ucoef bad"' : paid / used > 1.1 ? ' class="ucoef warn"' : ' class="ucoef"') : '';
  const since = r.started ? Math.floor((Date.now() / 1000 - r.started) / 3600) : 0;
  const sum = (list) => list.reduce((a, t) => { const x = T[t.id] || z; return { down: a.down + x.down, up: a.up + x.up, paid: a.paid + (x.paid || 0), est: a.est || !!x.est }; }, { down: 0, up: 0, paid: 0, est: false });

  // the list: everything, then each Iran server (its whole bill) with its tunnels under it
  const groups = [];
  const seen = new Map();
  tunnels.forEach(t => {
    const k = t.serverId === '~' ? '~' : nicOf(t.serverId).key;
    if (!seen.has(k)) { const g = { id: t.serverId, key: k, tunnels: [] }; seen.set(k, g); groups.push(g); }
    seen.get(k).tunnels.push(t);
  });
  const total = sum(tunnels);
  const meta = (x) => `<span class="smeta"><small><b>${fmtBytes(tot(x))}</b></small><small${coefCls(x.paid, tot(x))}>💰 ${x.est ? '≈' : ''}${fmtBytes(x.paid)} · ${coef(x.paid, tot(x))}</small></span>`;
  const tRow = (t) => { const x = T[t.id] || z; return `<button class="srow" data-pick="t:${t.id}">
      <span class="sflag">${flagOf(t.foreignId)}</span>
      <span class="sinfo"><b>${nm(t.name)}${stopTag(t)}</b><small>→ ${nameOf(t.foreignId)}</small></span>
      ${meta({ down: x.down, up: x.up, paid: x.paid || 0, est: !!x.est })}</button>`; };
  let cur = recall('tp-usage-sel') || '';
  if (cur === '' || (cur.startsWith('t:') && !tunnels.some(t => 't:' + t.id === cur)) || (cur.startsWith('s:') && !groups.some(g => 's:' + g.id === cur))) cur = 'all';
  box.innerHTML = `<aside class="card srvlist">
      ${tunnels.length > 6 ? '<input class="sq" type="search" placeholder="Filter by name…" data-sq>' : ''}
      <button class="srow" data-pick="all"><span class="sflag">Σ</span><span class="sinfo"><b>All tunnels</b><small>${countTxt(tunnels, groups)}</small></span>${meta(total)}</button>
      ${groups.map(g => { const x = sum(g.tunnels); return `<div class="sgrp"><button class="srow sgh2" data-pick="s:${g.id}"><span class="sflag">${flagOf(g.id)}</span><span class="sinfo"><b>${g.id === '~' ? 'Route unknown' : srvOf(g.id) ? nm(srvOf(g.id).name) : 'panel host'}</b><small>${g.id === '~' ? 'deleted before routes were kept · ×1' : 'Iran server'} · ${g.tunnels.length} tunnel${g.tunnels.length > 1 ? 's' : ''}</small></span>${meta(x)}</button>
        <div class="usub">${g.tunnels.map(tRow).join('')}</div></div>`; }).join('') || '<div class="faint sempty">No tunnels yet.</div>'}
    </aside>
    <div class="srvdetail" data-detail></div>`;
  const det = $('[data-detail]', box);

  const kpi = (x) => `<div class="ukpi">
    <div class="card pad"><small>⬇ Download</small><b>${fmtBytes(x.down)}</b><span class="faint">users received</span></div>
    <div class="card pad"><small>⬆ Upload</small><b>${fmtBytes(x.up)}</b><span class="faint">users sent</span></div>
    <div class="card pad"><small>Σ Total traffic</small><b>${fmtBytes(x.down + x.up)}</b><span class="faint">download + upload</span></div>
    <div class="card pad paid"><small>💰 You pay for</small><b>${x.est ? '≈ ' : ''}${fmtBytes(x.paid)}</b><span>coefficient <b${coefCls(x.paid, x.down + x.up)} style="font-size:14px">${coef(x.paid, x.down + x.up)}</b></span></div></div>`;
  const legend = `<div class="card pad ulegend">
    <div><b>💰 You pay for</b> = what the Iran server <b>received</b> for the tunnel: the users' upload + what the foreign server sent it. Sending from Iran is free.</div>
    <div><b>Coefficient</b> = paid ÷ total traffic. ×1.00 means you pay exactly what the users used; ×1.15 means 15 % more (tunnel headers, health checks, tests).</div>
    <div class="faint">Each Iran server's intake is counted separately per foreign server, so an Iran server with two foreign servers is split between them.${total.est ? ' Hours before this was counted (marked ≈) are estimated from the whole Iran server.' : ''}${tunnels.some(t => t.serverId === '~') ? ' Tunnels deleted before their route was kept (route unknown) are counted at ×1: the panel cannot tell which Iran server they ran on.' : ''}${r.started > r.from ? ` Counting started ${since < 1 ? 'less than an hour' : since < 48 ? since + ' h' : Math.floor(since / 24) + ' days'} ago.` : ''}</div></div>`;
  // one Iran server's bill: what its cards received, how much the tunnels explain (the ones
  // shown, and others on the same card: another account's, or hidden by the account filter), the rest
  const otherPaid = (g) => (r.tunnels || []).reduce((a, x) => routeOf[x.id] !== undefined && nicOf(routeOf[x.id]).key === g.key && !g.tunnels.some(t => t.id === x.id) ? a + (x.paid || 0) : a, 0);
  const bill = (g, withOther) => {
    const n = nicOf(g.id), x = sum(g.tunnels), used = tot(x), o = otherPaid(g);
    return `<tr><td><b>${nameOf(g.id)}</b></td><td>${fmtBytes(used)}</td><td>${fmtBytes(x.paid)}</td>${withOther ? `<td>${fmtBytes(o)}</td>` : ''}<td>${fmtBytes(Math.max(0, n.u.down - x.paid - o))}</td><td><b>${fmtBytes(n.u.down)}</b></td><td><b${coefCls(n.u.down, used)}>${coef(n.u.down, used)}</b></td></tr>`;
  };
  // only servers whose card this account sees (a user's tunnels on the admin's servers have no bill here)
  const billTbl = (all) => {
    const gs = all.filter(g => nicOf(g.id).u !== z);
    if (!gs.length) return '';
    const wo = gs.some(g => otherPaid(g) > 0);
    return `<div class="card pad"><h3 style="margin:0 0 6px">${gs.length > 1 ? 'Iran servers — the whole bill' : 'The whole bill of this server'}</h3><div class="uscroll"><table class="tbl utbl"><thead><tr><th>Iran server</th><th>Σ Tunnels' traffic</th><th>💰 Tunnels' paid</th>${wo ? "<th>💰 Other tunnels on this server</th>" : ''}<th>Other (updates, tests…)</th><th>💰 Server received (bill)</th><th>Coefficient</th></tr></thead><tbody>${gs.map(g => bill(g, wo)).join('')}</tbody></table></div></div>`;
  };
  const rounded = custom && r.step === 86400 ? `<div class="card pad faint">${r.from > rng.f + 86400 ? 'Only the last 400 days are kept: the range starts at the oldest day kept. ' : ''}Hours are kept 35 days: a range that starts earlier is shown day by day, whole Tehran days.</div>` : '';
  const tunTbl = (list) => `<div class="card pad"><h3 style="margin:0 0 6px">Per tunnel</h3><div class="uscroll"><table class="tbl utbl"><thead><tr><th>Tunnel</th><th>⬇ Download</th><th>⬆ Upload</th><th>Σ Total</th><th>💰 Paid</th><th>Coefficient</th></tr></thead><tbody>${list.map(t => { const x = T[t.id] || z; return `<tr class="urow" data-pick="t:${t.id}"><td><b>${nm(t.name)}</b><div class="faint" style="font-size:11.5px">${nameOf(t.serverId)} → ${nameOf(t.foreignId)}</div></td><td>${fmtBytes(x.down)}</td><td>${fmtBytes(x.up)}</td><td><b>${fmtBytes(tot(x))}</b></td><td><b>${x.est ? '≈ ' : ''}${fmtBytes(x.paid || 0)}</b></td><td><b${coefCls(x.paid || 0, tot(x))}>${coef(x.paid || 0, tot(x))}</b></td></tr>`; }).join('')}</tbody></table></div></div>`;

  // hour by hour for the tunnels picked: the last 24 hours, or a past Tehran day
  let date = 0, hr = days === 1 || custom ? r : null;
  const dayOpts = () => { const o = ['<option value="0">Last 24 hours</option>']; for (let i = 0; i < 35; i++) { const d = new Date(Date.now() - i * 864e5); const ds = d.toLocaleDateString('fa-IR-u-nu-latn', { timeZone: 'Asia/Tehran', year: 'numeric', month: '2-digit', day: '2-digit' }); const en = d.toLocaleDateString('en-GB', { timeZone: 'Asia/Tehran', day: '2-digit', month: 'short' }); o.push(`<option value="${i + 1}"${date === i + 1 ? ' selected' : ''}>${i === 0 ? 'Today' : i === 1 ? 'Yesterday' : en} · ${ds}</option>`); } return o.join(''); };
  let seq = 0; // the latest draw wins: an older request that answers later is dropped
  const drawHours = async (hb, ids) => {
    const my = ++seq;
    hb.innerHTML = `<div class="uhrow"><h3 style="margin:0">${hr && hr.step === 86400 ? 'Day by day' : 'Hour by hour'}</h3>${custom ? '' : `<select data-uhd>${dayOpts()}</select>`}</div><div class="skel" style="height:120px"></div>`;
    if (!custom) $('[data-uhd]', hb).onchange = (e) => { date = +e.target.value; hr = null; drawHours(hb, ids); };
    if (!hr) {
      let x;
      try { x = await api(date ? '/usage?date=' + Math.floor(Date.now() / 1000 - (date - 1) * 86400) : '/usage?days=1'); } catch (e) { if (my === seq && hb.isConnected) hb.lastChild.outerHTML = `<div class="errtxt">${esc(e.message)}</div>`; return; }
      if (my !== seq) return;
      hr = x;
    }
    if (my !== seq || !hb.isConnected) return;
    const pick = (hr.tunnels || []).filter(x => ids.includes(x.id));
    const rows = [];
    let mx = 1;
    for (let i = 0; i < (hr.n || 24); i++) {
      const s = { d: 0, u: 0, p: 0 }; pick.forEach(x => { const v = (x.series || [])[i]; if (v) { s.d += v.d || 0; s.u += v.u || 0; s.p += v.p || 0; } });
      mx = Math.max(mx, s.d + s.u); rows.push(s);
    }
    const lbl = (i) => { const t = new Date((hr.from + i * hr.step) * 1000); const f = (x) => x.toLocaleTimeString('en-GB', { timeZone: 'Asia/Tehran', hour: '2-digit', minute: '2-digit' }); if (hr.step === 86400) return t.toLocaleDateString('en-GB', { timeZone: 'Asia/Tehran', day: '2-digit', month: 'short' }) + ' · ' + t.toLocaleDateString('fa-IR-u-nu-latn', { timeZone: 'Asia/Tehran', month: '2-digit', day: '2-digit' }); const d = hr.n > 24 ? t.toLocaleDateString('en-GB', { timeZone: 'Asia/Tehran', day: '2-digit', month: 'short' }) + ' ' : ''; return d + f(t) + '–' + f(new Date(t.getTime() + 3600e3)); };
    const now = Date.now() / 1000;
    const body = rows.map((s, i) => hr.from + i * hr.step > now ? '' : `<tr><td class="mono">${lbl(i)}</td><td>${fmtBytes(s.d)}</td><td>${fmtBytes(s.u)}</td><td><b>${fmtBytes(s.d + s.u)}</b></td>
      <td><span class="ubar"><i style="width:${Math.round((s.d + s.u) / mx * 100)}%"></i></span></td><td>${fmtBytes(s.p)}</td><td><b${coefCls(s.p, s.d + s.u)}>${coef(s.p, s.d + s.u)}</b></td></tr>`).reverse().join('');
    const t = rows.reduce((a, s) => ({ d: a.d + s.d, u: a.u + s.u, p: a.p + s.p }), { d: 0, u: 0, p: 0 });
    hb.lastChild.outerHTML = `<div class="uscroll uhours"><table class="tbl utbl"><thead><tr><th>${hr.step === 86400 ? 'Day (Tehran)' : 'Hour (Tehran)'}</th><th>⬇ Download</th><th>⬆ Upload</th><th>Σ Total</th><th></th><th>💰 Paid</th><th>Coefficient</th></tr></thead><tbody>${body}</tbody>
      <tfoot><tr><td><b>${custom ? 'Total' : 'Day total'}</b></td><td>${fmtBytes(t.d)}</td><td>${fmtBytes(t.u)}</td><td><b>${fmtBytes(t.d + t.u)}</b></td><td></td><td><b>${fmtBytes(t.p)}</b></td><td><b${coefCls(t.p, t.d + t.u)}>${coef(t.p, t.d + t.u)}</b></td></tr></tfoot></table></div>`;
  };

  const show = (id, scroll) => {
    cur = id; remember('tp-usage-sel', id);
    $$('.srow', box).forEach(b => b.classList.toggle('on', b.dataset.pick === id));
    let head, list, gs;
    if (id.startsWith('t:')) {
      const t = tunnels.find(x => 't:' + x.id === id); list = [t];
      head = `<div class="card pad uhead"><h2>${nm(t.name)}${stopTag(t)}</h2><div class="muted">${nameOf(t.serverId)} → ${nameOf(t.foreignId)}${t.active ? ` · <span class="mono">${esc(t.active)}</span>` : ''}</div></div>`;
    } else if (id.startsWith('s:')) {
      const g = groups.find(x => 's:' + x.id === id); list = g.tunnels; gs = [g];
      head = `<div class="card pad uhead"><h2>${nameOf(g.id)}</h2><div class="muted">Iran server · ${g.tunnels.map(t => nm(t.name) + ' → ' + nameOf(t.foreignId)).join(' · ')}</div></div>`;
    } else {
      list = tunnels; gs = groups;
      head = `<div class="card pad uhead"><h2>All tunnels</h2><div class="muted">${countTxt(tunnels, groups)}</div></div>`;
    }
    det.innerHTML = head + rounded + kpi(sum(list)) + '<div class="card pad" data-uh></div>' + (list.length > 1 ? tunTbl(list) : '') + (gs ? billTbl(gs) : '') + legend;
    $$('.urow', det).forEach(tr => tr.onclick = () => show(tr.dataset.pick, true));
    drawHours($('[data-uh]', det), list.map(t => t.id));
    if (scroll && window.innerWidth <= 860) det.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  $$('.srvlist [data-pick]', box).forEach(b => b.onclick = () => show(b.dataset.pick, true));
  const q = $('[data-sq]', box);
  if (q) q.oninput = () => { const v = q.value.trim().toLowerCase(); $$('.usub .srow', box).forEach(b => b.hidden = !!v && !b.textContent.toLowerCase().includes(v)); };
  show(cur, false);
}

/* ---------------- routes ---------------- */
// One card per Iran ⇄ foreign pair: its tunnels and every path they run (hot standby: each
// path ✓/✕ and the one users are on), and the order the next Re-apply / hot standby /
// failover uses — the pair's latest benchmark ranking, per address family.
const ageTxt = (u) => { const s = Math.floor(Date.now() / 1000) - u; return s < 3600 ? `${Math.max(1, Math.floor(s / 60))} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
let routesTok = 0;
async function viewRoutes(w) {
  const tok = ++routesTok; // a newer draw of the page wins (an older one finishing later took its timer)
  w.innerHTML = topbar('Routes', 'Each tunnel: the paths its users are on, and which methods it may use — switch them on or off, and measure them.');
  const box = h('<div class="grid" style="gap:18px"><div class="skel" style="height:120px"></div><div class="skel" style="height:220px"></div></div>');
  w.appendChild(box);
  let hist = [], skip = {};
  try { [hist, skip] = await Promise.all([api('/bench/history'), api('/routes/skip')]); } catch (e) {}
  if (tok !== routesTok || !box.isConnected) return;
  const pairs = new Map();
  const key = (i, f) => i + '|' + (f || '');
  STATE.tunnels.filter(t => shownOwner(t.owner)).forEach(t => { const k = key(t.serverId, t.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: t.serverId, foreign: t.foreignId || '', tunnels: [] }); pairs.get(k).tunnels.push(t); });
  hist.filter(r => shownOwner((serverById(r.iranId) || {}).owner)).forEach(r => { const k = key(r.iranId, r.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: r.iranId, foreign: r.foreignId || '', tunnels: [] }); });
  box.innerHTML = '';
  if (!pairs.size) { box.appendChild(h('<div class="card empty"><div class="big">🔀</div>No tunnels or benchmarks yet.</div>')); return; }
  const srvLabel = (id, fb) => { const s = id ? serverById(id) : null; return s ? `${s.country ? flag(s.country) : ''} ${nm(s.name)}` : fb; };  const hasFam = (id, f) => { const s = id ? serverById(id) : null; const st = STATE.settings; return f === 'v4' ? !!(s ? s.ipv4 : st.localIPv4 || true) : !!(s ? s.ipv6 : st.localIPv6); };
  // one card per tunnel (a measured pair with no tunnel gets one too); a switch re-draws the
  // cards in place (the page keeps its scroll)
  let repaint = () => {};
  const buildCard = (p) => {
    const fams = ['v4', 'v6'].filter(f => hasFam(p.iran, f) && hasFam(p.foreign, f));
    const off = skip[key(p.iran, p.foreign)] || [];
    const adminPair = sharedPair(p.iran, p.foreign);
    const bench = {};
    ['v4', 'v6'].forEach(f => { bench[f] = hist.find(x => x.iranId === p.iran && (x.foreignId || '') === p.foreign && x.family === f); });

    // 1. tunnels: one line each; a hot-standby tunnel folds its paths away
    let up = 0, down = 0;
    const tunnels = p.tunnels.map(t => {
      let st, cls;
      if (!t.active) { st = 'stopped'; cls = 'off'; }
      else if (t.health === null || t.health === undefined) { st = 'not checked yet'; cls = 'unk'; }
      else if (t.health) { st = t.health; cls = 'bad'; down++; }
      else { st = 'connected'; cls = 'ok'; up++; }
      let hs = '';
      if (t.hotStandby && t.hs && t.hs.paths) {
        t.hs.ok = t.hs.ok || []; // a switcher state read only in part has no ok list
        const n = t.hs.ok.filter(Boolean).length;
        hs = `<details class="rt-hs"${p.tunnel ? ' open' : ''}><summary>⚡ users on <b>${esc(t.hs.paths[t.hs.active] || '—')}</b> · ${n}/${t.hs.paths.length} paths working${t.hsAuto ? ' · 🤖 auto' : ''} <span class="faint">▸ paths</span></summary><div class="hsl">${t.hs.paths.map((x, i) => `<div class="${t.hs.ok[i] ? 'ok' : 'bad'}${i === t.hs.active ? ' cur' : ''}">${t.hs.ok[i] ? '✓' : '✕'} ${esc(x)}${i === t.hs.active ? ' <b>← users</b>' : ''}</div>`).join('')}</div></details>`;
      } else if (t.hotStandby) {
        // running with paths but no switcher state read yet (just after a panel restart): say so
        hs = t.active && (t.paths || []).length
          ? `<div class="faint rt-hs">⚡ hot standby: ${t.paths.length} paths — reading which one the users are on…</div>`
          : '<div class="faint rt-hs">⚡ hot standby: its paths start on the next Start/Re-apply</div>';
      }
      return `<div class="rt-row ${cls}"><span class="sd ${cls === 'ok' ? 'ok' : cls === 'bad' ? 'bad' : ''}"></span>
        ${p.tunnel ? '<span class="faint">now</span>' : `<b class="rt-name" data-notr>${esc(t.name)}</b><span class="faint mono">:${esc(t.ports)}</span>`}
        <span class="rt-mth">${esc(methodTitle(t.active || t.selected) || '—')} · ${famName(t.family)}</span>
        <span class="rt-st ${cls}">${esc(st)}</span>${hs}</div>`;
    }).join('') || '<div class="faint" style="font-size:12.5px">no tunnel on this pair yet</div>';

    // 2. methods: one row each, IPv4 and IPv6 side by side, best first
    const rank = {}; // method -> {fam: {pos, r}}
    fams.forEach(f => {
      const r = bench[f]; if (!r) return;
      let pos = 0;
      r.results.forEach(x => { (rank[x.method] = rank[x.method] || {})[f] = { pos: x.ok ? ++pos : 0, r: x }; });
    });
    off.forEach(v => { const [mid, f] = v.split('|'); if (fams.includes(f)) (rank[mid] = rank[mid] || {})[f] = (rank[mid] || {})[f] || { pos: 0, r: null }; });
    // every method the route can carry is listed, measured or not: the choice of what this route
    // uses must not wait for a benchmark
    STATE.methods.filter(m => m.id !== 'spoof' && fams.some(f => m.families.includes(f))).forEach(m => { rank[m.id] = rank[m.id] || {}; });
    // a method's best position on either family (left out or failed: at the end)
    const best = (mid) => Math.min(999, ...fams.filter(f => !off.includes(mid + '|' + f)).map(f => (rank[mid][f] && rank[mid][f].pos) || 999));
    // grouped by method family (all Backhaul cores together), best first within a family
    const gOf = (mid) => groupOf(STATE.methods.find(x => x.id === mid));
    const mids = Object.keys(rank).sort((a, b) => groupRank(gOf(a)) - groupRank(gOf(b)) || best(a) - best(b) || methodTitle(a).localeCompare(methodTitle(b)));
    // a cell = an on/off switch (does this route use the method on this family?) + what the
    // last benchmark measured
    const cell = (mid, f) => {
      const m = STATE.methods.find(x => x.id === mid);
      if (m && !m.families.includes(f)) return `<td class="rt-c na" data-f="${famName(f)}"><span class="faint">—</span></td>`;
      const isOff = off.includes(mid + '|' + f);
      const sw = adminPair ? '' : `<label class="rt-sw" title="${isOff ? 'not used on this route — turn on to let hot standby and failover use it' : 'used on this route (hot standby, failover, benchmark) — turn off to leave it out'}"><input type="checkbox" data-use="${esc(mid)}|${f}"${isOff ? '' : ' checked'}><i></i></label>`;
      const c = rank[mid][f], x = c && c.r;
      let body;
      if (isOff) body = '<span class="faint">off</span>';
      else if (!x) body = '<span class="faint">not measured</span>';
      else if (x.skipped) body = '<span class="faint">not measurable</span>';
      else if (x.ok) {
        const carrier = x.opts ? Object.entries(x.opts).map(([k, v]) => `${k} ${v}`).join(', ') : '';
        body = `<span class="rt-rank${x.recommended ? ' top' : ''}">${x.recommended ? '★' : c.pos}</span><span class="rt-num">↓${x.downMbps.toFixed(0)} ↑${x.upMbps.toFixed(0)} <small>Mbps</small> · ${x.rttMs.toFixed(0)} <small>ms</small></span>${carrier ? `<span class="chip rt-car" title="the default carrier passes nothing here; this one does">${esc(carrier)}</span>` : ''}`;
      } else body = `<button type="button" class="rt-err" data-err="${esc(x.error || 'failed')}" title="${esc(x.error || 'failed')}">✕ ${esc(shortErr(x.error))}</button>`;
      return `<td class="rt-c ${isOff ? 'left' : x && x.ok ? 'good' : x && !x.skipped ? 'bad' : ''}" data-f="${famName(f)}"><div class="rt-cv">${sw}${body}</div></td>`;
    };
    const methodsTbl = mids.length ? `<table class="rt-tbl"><thead><tr><th>Method</th>${fams.map(f => `<th>${famName(f)}${bench[f] ? ` <span class="faint">· measured ${ageTxt(bench[f].at)}</span>` : ' <span class="faint">· not measured yet</span>'}</th>`).join('')}</tr></thead>
      <tbody>${mids.map((mid, i) => (i === 0 || gOf(mids[i - 1]) !== gOf(mid) ? `<tr class="rt-grp"><td colspan="${fams.length + 1}">${GROUP_ICON[gOf(mid)] || '🔧'} ${esc(gOf(mid))}</td></tr>` : '') +
        `<tr><td class="rt-mn">${esc(methodTitle(mid))}</td>${fams.map(f => cell(mid, f)).join('')}</tr>`).join('')}</tbody></table>
      ${adminPair ? '<div class="faint rt-leg">These servers belong to the admin, who decides which methods this route uses.</div>' : ''}<div class="faint rt-leg">Switch on = the route's tunnels may use it (hot standby keeps it ready, failover can move users to it); off = never used here. ★ best measured · numbers = the order they're tried · tap ✕ for the whole error · 📊 measures the running ones (every method when none runs)${fams.some(f => !bench[f]) ? ' — not measured yet: you can still choose' : ''}</div>`
      : '<div class="faint" style="font-size:12.5px">No method can run between these two servers over the address families they have.</div>';

    const cells = mids.flatMap(mid => { const m = STATE.methods.find(x => x.id === mid); return fams.filter(f => !m || m.families.includes(f)).map(f => mid + '|' + f); });
    const cellCount = cells.length, onCount = cells.filter(c => !off.includes(c)).length;
    const summary = [`${p.tunnels.length} tunnel${p.tunnels.length === 1 ? '' : 's'}`];
    if (up) summary.push(`<span class="ok">● ${up} connected</span>`);
    if (down) summary.push(`<span class="bad">● ${down} down</span>`);
    // a tunnel's card is titled with the tunnel (what people look for); a measured pair with no
    // tunnel keeps the servers as its title
    const route = `${srvLabel(p.iran, 'Iran')} <span class="faint">→</span> ${srvLabel(p.foreign, '🖥 this panel host')}`;
    const title = p.tunnel ? `<h3 data-notr>${esc(p.tunnel.name)}</h3><div class="rt-sum">${route} · <span class="mono">:${esc(p.tunnel.ports)}</span></div>`
      : `<h3>${route}</h3><div class="rt-sum">${summary.join(' · ')} · measured, no tunnel yet</div>`;
    const sharedNote = p.shared && p.shared.length ? `<div class="faint rt-leg" style="margin:0 0 6px">These switches belong to the server pair, so they also apply to ${p.shared.map(nm).join(', ')}.</div>` : '';
    const card = h(`<div class="card rt-card">
      <div class="rt-head"><div>${title}</div>
        <div class="actions">${fams.map(f => `<button class="btn sm" data-rb="${f}" title="measure the methods the tunnels run over ${famName(f)} between these two servers, or every method when none runs (each on a temporary tunnel; live tunnels are not touched)">📊 Measure ${famName(f)}</button>`).join('')}</div></div>
      ${p.tunnel ? '' : '<div class="lbl">Tunnels</div>'}<div class="rt-rows">${tunnels}</div>
      <details class="rt-more"${p.tunnel || STATE.routeSel ? ' open' : ''}><summary><span class="lbl">Methods this tunnel may use</span> <span class="faint">${onCount} of ${cellCount} on — speeds and order</span></summary>${sharedNote}${methodsTbl}</details></div>`);
    // sections opened or closed by hand stay that way through the 30 s repaint
    const rtOpen = (STATE.rtOpen = STATE.rtOpen || {});
    $$('details', card).forEach((d, i) => { const k = p.id + '|' + i; if (k in rtOpen) d.open = rtOpen[k]; d.addEventListener('toggle', () => { rtOpen[k] = d.open; }); });
    const setSkip = async (v, on) => {
      const [method, family] = v.split('|');
      try {
        skip = await api('/routes/skip', { iran: p.iran, foreign: p.foreign, method, family, skip: on });
        repaint(); // the other tunnels on this pair show the same switches
        toast(on ? `${methodTitle(method)} (${famName(family)}) left out on this route — running hot-standby tunnels stop it within seconds` : `${methodTitle(method)} (${famName(family)}) is back on this route — running hot-standby tunnels start it within seconds`);
      } catch (er) { repaint(); alertModal('Routes', er.message); } // the switch goes back to what is saved
    };
    $$('[data-use]', card).forEach(b => b.onchange = () => setSkip(b.dataset.use, !b.checked));
    $$('[data-err]', card).forEach(b => b.onclick = () => alertModal('Why it failed', b.dataset.err));
    $$('[data-rb]', card).forEach(b => b.onclick = async () => {
      try { const r = await api('/bench/start', { iranId: p.iran, foreignId: p.foreign, family: b.dataset.rb, running: true, seconds: 3 }); toast('Benchmark started'); openLog({ id: 'bench', name: 'Benchmark · ' + famName(b.dataset.rb) }, r.job); } catch (er) { alertModal('Benchmark', er.message); }
    });
    return card;
  };
  // one item per tunnel, in the Tunnels page's order (tunnels on the same pair share its
  // switches); measured pairs with no tunnel come last, under "Other routes"
  const items = [], others = [];
  [...pairs.values()].forEach(p => {
    if (!p.tunnels.length) { others.push({ ...p, id: 'p:' + key(p.iran, p.foreign) }); return; }
    p.tunnels.forEach(t => items.push({ ...p, tunnels: [t], tunnel: t, id: t.id, shared: p.tunnels.filter(x => x !== t).map(x => x.name) }));
  });
  items.sort((a, b) => tunnelOrder(a.tunnel, b.tunnel));
  const valid = (id) => id === '' || id === 'other' || items.some(x => x.id === id);
  if (STATE.routeSel === undefined) { try { STATE.routeSel = localStorage.getItem('tp-routesel') || ''; } catch (e) { STATE.routeSel = ''; } }
  if (!valid(STATE.routeSel)) STATE.routeSel = '';
  const dot = (t) => !t.active ? '' : t.health ? '<i class="bad">●</i>' : t.health === '' ? '<i class="ok">●</i>' : '';
  // like the Servers page: the routes listed by Iran server on the side, the picked one beside it
  const row = (it) => {
    const t = it.tunnel, s = serverById(it.foreign);
    return `<button type="button" class="srow${STATE.routeSel === it.id ? ' on' : ''}" data-rsel="${it.id}" title="${esc(serverName(it.iran))} → ${esc(it.foreign ? serverName(it.foreign) : 'this panel host')}">
      <span class="sflag">${s && s.country ? flag(s.country) : '🛰'}</span>
      <span class="sinfo"><b data-notr>${esc(t.name)}</b><small>→ ${srvNm(it.foreign, 'panel host')} · ${t.active ? esc(methodTitle(t.active)) : 'stopped'}</small></span>
      <span class="smeta rt-dots">${dot(t)}</span></button>`;
  };
  const rgroups = [];
  items.forEach(it => { let g = rgroups.find(x => x.id === it.iran); if (!g) rgroups.push(g = { id: it.iran, items: [] }); g.items.push(it); });
  rgroups.sort((x, y) => serverName(x.id).localeCompare(serverName(y.id)));
  const picker = h(`<aside class="card srvlist">
    <button type="button" class="srow${STATE.routeSel === '' ? ' on' : ''}" data-rsel=""><span class="sflag">🌐</span><span class="sinfo"><b>All tunnels</b><small>${items.length} tunnel${items.length === 1 ? '' : 's'}</small></span></button>
    ${rgroups.map(g => { const s = serverById(g.id); return `<div class="sgrp"><div class="sgh"><span>${s && s.country ? flag(s.country) : '🇮🇷'} ${srvNm(g.id)} <span class="count">${g.items.length}</span></span></div>${g.items.map(row).join('')}</div>`; }).join('')}
    ${others.length ? `<button type="button" class="srow${STATE.routeSel === 'other' ? ' on' : ''}" data-rsel="other"><span class="sflag">📊</span><span class="sinfo"><b>Other routes</b><small>measured, no tunnel</small></span></button>` : ''}</aside>`);
  const split = h('<div class="srvsplit usplit"><div class="srvdetail"></div></div>');
  box.replaceWith(split);
  split.prepend(picker);
  $('.srvdetail', split).appendChild(box);
  const paint = () => {
    $$('[data-rsel]', picker).forEach(b => b.classList.toggle('on', b.dataset.rsel === STATE.routeSel));
    items.forEach(it => { const d = $(`[data-rsel="${it.id}"] .rt-dots`, picker); if (d) d.innerHTML = dot(it.tunnel); }); // the list's ● follow the refresh too
    // on a phone the tiles are one row: keep the chosen one in sight
    box.innerHTML = '';
    const shown = STATE.routeSel === '' ? items : STATE.routeSel === 'other' ? others : items.filter(x => x.id === STATE.routeSel);
    shown.forEach(p => {
      // one route that can't be drawn must not hide the ones after it
      try { box.appendChild(buildCard(p)); }
      catch (e) { box.appendChild(h(`<div class="card rt-card"><h3>${srvNm(p.iran)} → ${srvNm(p.foreign)}</h3><div class="faint">${p.tunnels.map(t => nm(t.name)).join(' · ')} — this route couldn't be drawn (${esc(e.message)})</div></div>`)); console.error(e); }
    });
  };
  $$('[data-rsel]', picker).forEach(b => b.onclick = () => { STATE.routeSel = b.dataset.rsel; try { localStorage.setItem('tp-routesel', STATE.routeSel); } catch (e) {} paint(); if (window.innerWidth <= 860) box.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
  repaint = paint;
  paint();
  // health, the users' path and new benchmark results come in while the page is open (it
  // showed what was true when it was opened); not while a field or switch is being used
  if (routesTimer) clearInterval(routesTimer);
  const timer = setInterval(async () => {
    if (tok !== routesTok || STATE.view !== 'routes' || !box.isConnected) { clearInterval(timer); if (routesTimer === timer) routesTimer = null; return; }
    if (document.hidden || (document.activeElement && box.contains(document.activeElement) && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName))) return;
    try {
      const [list, h2] = await Promise.all([api('/tunnels'), api('/bench/history')]);
      if (tok !== routesTok || !box.isConnected) return;
      (Array.isArray(list) ? list : []).forEach(n => { const t = STATE.tunnels.find(x => x.id === n.id); if (t) Object.assign(t, { hs: n.hs, failover: n.failover, health: n.health, active: n.active }); });
      // a reload of the state elsewhere (a job ending, a save) replaced STATE.tunnels' objects:
      // the cards follow the current ones, not the ones the page was opened with
      items.forEach(it => { const t = STATE.tunnels.find(x => x.id === it.tunnel.id); if (t) { it.tunnel = t; it.tunnels = [t]; } });
      hist = h2 || hist;
      const y = window.scrollY; paint(); window.scrollTo(0, y);
    } catch (e) {}
  }, 30000);
  routesTimer = timer;
}
let routesTimer = null;
// the Tunnels page's order (running first, then the ones with a problem, then by name), the
// Routes page uses it too
function tunnelOrder(x, y) { return (!!y.active - !!x.active) || (!!(y.active && y.health) - !!(x.active && x.health)) || x.name.localeCompare(y.name); }
// the gist of a benchmark error, for a table cell
function shortErr(e) {
  e = e || 'failed';
  if (/excluded on this route/.test(e)) return 'left out (not measured)';
  if (/no traffic passes/.test(e)) return /also tried/.test(e) ? 'no traffic (other carriers too)' : 'no traffic passes';
  if (/no bulk data passes/.test(e)) return 'pings pass, data stalls (MTU?)';
  if (/not tested: tunnel/.test(e)) return 'busy: a live tunnel uses it';
  if (/deploy/.test(e)) return 'could not start';
  return e.length > 34 ? e.slice(0, 34) + '…' : e;
}

/* ---------------- live traffic ---------------- */
// Polls /api/traffic while the tunnels or servers page is open; the server only reads
// counters while someone polls, and stops ~20 s after the page goes away.
let trafficTimer = null;
const trafficMem = { since: 0, at: 0, h: { tunnels: {}, servers: {}, res: {} } };
const fmtRate = (bps) => bps >= 1e9 ? (bps / 1e9).toFixed(2) + ' Gbps' : bps >= 1e6 ? (bps / 1e6).toFixed(1) + ' Mbps' : bps >= 1e3 ? (bps / 1e3).toFixed(0) + ' Kbps' : Math.round(bps) + ' bps';
// a value that rounds to 1024 of its unit is shown in the next one ("1.0 MB", never "1024 KB")
const fmtBytes = (b) => {
  const us = [[1, 'B', 0], [1024, 'KB', 0], [2 ** 20, 'MB', 1], [2 ** 30, 'GB', 2], [2 ** 40, 'TB', 2]];
  let i = 0;
  while (i + 1 < us.length && b >= us[i + 1][0]) i++;
  if (i + 1 < us.length && +(b / us[i][0]).toFixed(us[i][2]) >= 1024) i++;
  return i === 0 ? b + ' B' : (b / us[i][0]).toFixed(us[i][2]) + ' ' + us[i][1];
};
const ago = (ts) => { const s = Math.max(0, Date.now() / 1000 - ts); return s < 60 ? 'just now' : s < 3600 ? Math.round(s / 60) + ' min ago' : s < 86400 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; };
function trafficWatch() {
  const want = STATE.view === 'tunnels' || STATE.view === 'servers';
  if (!want) { if (trafficTimer) clearInterval(trafficTimer); trafficTimer = null; return; }
  if (trafficTimer) { trafficTick(); return; }
  trafficTick(); trafficTimer = setInterval(trafficTick, 2000);
}
async function trafficTick() {
  if (STATE.view !== 'tunnels' && STATE.view !== 'servers') { clearInterval(trafficTimer); trafficTimer = null; return; }
  if (document.hidden) return;
  // after the first poll only the new chart points come (?since); the history is kept here
  const fresh = !trafficMem.since || Date.now() / 1000 - trafficMem.at > 20;
  let d; try { d = await api('/traffic' + (fresh ? '' : '?since=' + (trafficMem.since - 1))); } catch (e) { return; }
  if (fresh) trafficMem.h = { tunnels: {}, servers: {}, res: {} };
  for (const k of ['tunnels', 'servers', 'res']) for (const [id, x] of Object.entries(d[k] || {})) {
    if (!x || !x.hist) continue;
    const old = trafficMem.h[k][id] || [], first = x.hist.length ? x.hist[0].t : Infinity;
    x.hist = trafficMem.h[k][id] = old.filter(p => p.t < first).concat(x.hist).slice(-90);
  }
  trafficMem.since = d.now || 0; trafficMem.at = Date.now() / 1000;
  const tun = d.tunnels || {}, srv = d.servers || {}, speed = d.speed || {};
  $$('[data-res]').forEach(el => renderRes(el, (d.res || {})[el.dataset.res]));
  // the server list's CPU · RAM
  $$('[data-mini]').forEach(el => { const r = (d.res || {})[el.dataset.mini]; el.textContent = r && !r.error ? `${r.cpu.toFixed(0)}% · ${(r.memTotal ? 100 * r.memUsed / r.memTotal : 0).toFixed(0)}%` : ''; });
  // the totals follow the View selector, like the cards
  const shownIds = new Set(STATE.tunnels.filter(t => shownOwner(t.owner)).map(t => t.id));
  const sum = Object.entries(tun).reduce((a, [id, x]) => (x.error || !shownIds.has(id) ? a : [a[0] + x.down, a[1] + x.up]), [0, 0]);
  const sd = $('[data-sum-dn]'), su = $('[data-sum-up]');
  if (sd) sd.textContent = fmtRate(sum[0]);
  if (su) su.textContent = fmtRate(sum[1]);
  $$('[data-lr]').forEach(el => { const x = tun[el.dataset.lr]; el.textContent = x && !x.error && (x.down || x.up) ? `↓${fmtRate(x.down)}` : ''; });
  $$('[data-traf]').forEach(el => {
    const id = el.dataset.traf, s = tun[id], sp = speed[id];
    const rd = $('[data-rd]', el), ru = $('[data-ru]', el), src = $('[data-src]', el), tot = $('[data-tot]', el);
    el.classList.toggle('err', !!(s && s.error));
    if (!s) { rd.textContent = '…'; ru.textContent = '…'; src.textContent = 'reading counters…'; }
    else if (s.error) { rd.textContent = '—'; ru.textContent = '—'; src.textContent = s.error; src.style.color = 'var(--crit)'; }
    else {
      src.style.color = ''; rd.textContent = fmtRate(s.down); ru.textContent = fmtRate(s.up);
      src.textContent = s.source === 'iface' ? 'tunnel interface' : 'forwarded ports';
      tot.innerHTML = `<span>total ↓</span> <bdi>${fmtBytes(s.totalDown)}</bdi> · ↑ <bdi>${fmtBytes(s.totalUp)}</bdi>`;
      drawSpark($('svg', el), s.hist || []);
    }
    const se = $('[data-speed]', el);
    if (sp) se.innerHTML = sp.ok ? `<span>speed test</span> <span>${ago(sp.at)}</span>: <bdi><b style="color:var(--accent)">↓ ${sp.downMbps.toFixed(1)}</b> / <b style="color:var(--good)">↑ ${sp.upMbps.toFixed(1)}</b> Mbps · ${sp.rttMs.toFixed(0)} ms</bdi>` : `<span style="color:var(--crit)" title="${esc(sp.error || '')}">speed test failed ${ago(sp.at)}</span>`;
  });
  $$('[data-nic]').forEach(el => {
    const s = srv[el.dataset.nic];
    if (!s) { el.innerHTML = el.dataset.nic === '' ? 'live traffic…' : ''; return; }
    if (s.error) { el.innerHTML = `<span class="faint">traffic: ${esc(s.error)}</span>`; return; }
    el.innerHTML = `<span class="faint">${esc((s.source || '').replace('nic ', 'NIC '))}</span> <span class="dn">↓ <bdi>${fmtRate(s.down)}</bdi></span> <span class="up">↑ <bdi>${fmtRate(s.up)}</bdi></span> <span class="faint"><span>· since boot</span> ↓ <bdi>${fmtBytes(s.totalDown)}</bdi> ↑ <bdi>${fmtBytes(s.totalUp)}</bdi></span>`;
  });
}
// a server's live CPU / RAM / disk, load, sockets and busiest programs
const kbTxt = (kb) => kb >= 2 ** 30 ? (kb / 2 ** 30).toFixed(1) + ' TB' : kb >= 2 ** 20 ? (kb / 2 ** 20).toFixed(1) + ' GB' : (kb / 1024).toFixed(0) + ' MB';
const upTxt = (s) => s >= 86400 ? `${Math.floor(s / 86400)}d ${Math.floor(s % 86400 / 3600)}h` : `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m`;
// "Top programs" stays open across the 2-second refreshes (the box is redrawn each time)
const procsOpen = new Set();
document.addEventListener('toggle', (e) => {
  const d = e.target;
  if (!d.matches || !d.matches('details.rprocs')) return;
  const id = d.closest('[data-res]') && d.closest('[data-res]').dataset.res;
  if (id === undefined || d.dataset.redraw) return;
  d.open ? procsOpen.add(id) : procsOpen.delete(id);
}, true);
function renderRes(el, r) {
  if (!r) { el.innerHTML = ''; return; }
  if (r.error) { el.innerHTML = `<span class="faint" style="font-size:12px" title="${esc(r.error)}"><span>⚠ live load unavailable</span> — <span>${esc(r.error.split(/[:;—]/)[0].trim())}</span></span>`; return; }
  const p = (a, b) => b ? 100 * a / b : 0;
  const bar = (label, v, txt, title) => `<div class="rbar${v >= 90 ? ' crit' : v >= 70 ? ' warn' : ''}" title="${esc(title || '')}"><span class="rl">${label}</span><span class="rt"><i style="width:${Math.min(100, v).toFixed(1)}%"></i></span><span class="rv">${v.toFixed(0)}%</span><span class="rx faint">${txt}</span></div>`;
  const mem = p(r.memUsed, r.memTotal), disk = p(r.diskUsed, r.diskTotal);
  const extra = [`load ${r.load.map(x => x.toFixed(2)).join(' ')}`, `${r.cores} cores`, `up ${upTxt(r.uptime)}`, `TCP ${r.tcp}`];
  if (r.ctMax > 0 && r.conntrack >= 0) extra.push(`conntrack ${r.conntrack}/${r.ctMax}`);
  const warn = [];
  if (r.steal >= 5) warn.push(`steal ${r.steal.toFixed(0)}% — the host is oversold, this VPS waits for CPU`);
  if (r.iowait >= 10) warn.push(`iowait ${r.iowait.toFixed(0)}% — waiting on the disk`);
  if (r.swapUsed > 0 && mem > 80) warn.push(`swap in use: ${kbTxt(r.swapUsed)}`);
  if ((r.softirq || 0) >= 15) warn.push(`${r.softirq.toFixed(0)}% of the CPU is the kernel moving packets — no program shows it`);
  if (r.irqHint) warn.push(r.irqHint);
  const perCore = (r.coreIrq || []).map((v, i) => `core ${i}: ${v.toFixed(0)}%`).join(' · ');
  if ((r.softirq || 0) >= 15 && r.coreIrq && r.coreIrq.length > 1) extra.push(`packets per core ${r.coreIrq.map(v => v.toFixed(0) + '%').join(' ')}`);
  const procs = (r.procs || []).filter(x => x.cpu >= 0.1 || x.rssMB >= 20).slice(0, 12);
  el.innerHTML = bar('CPU', r.cpu, `iowait ${r.iowait.toFixed(0)}% · steal ${r.steal.toFixed(0)}% · kernel ${(r.sys || 0).toFixed(0)}% · packets ${(r.softirq || 0).toFixed(0)}%`, 'all cores together; "packets" is the kernel moving network traffic (irq + softirq)' + (perCore ? '\npackets per core — ' + perCore : '') + (r.nic ? `\n${r.nic}: ${r.rxQueues} receive queue${r.rxQueues === 1 ? '' : 's'}, RPS ${(r.rps || '').replace(/0/g, '') ? r.rps : 'off'}` : ''))
    + bar('RAM', mem, `${kbTxt(r.memUsed)} / ${kbTxt(r.memTotal)}${r.swapTotal ? ` · swap ${kbTxt(r.swapUsed)}` : ''}`)
    + bar('Disk', disk, `${kbTxt(r.diskUsed)} / ${kbTxt(r.diskTotal)}`, 'the root filesystem')
    + `<svg class="rspark" viewBox="0 0 100 24" preserveAspectRatio="none"><path class="pc" d="${resLine(r.hist, 'cpu')}"/><path class="pm" d="${resLine(r.hist, 'mem')}"/></svg>`
    + `<div class="faint rinfo">${extra.join(' · ')} <span class="rleg"><b class="pc">━</b> CPU <b class="pm">━</b> RAM · last 3 min</span></div>`
    + warn.map(w => `<div class="rwarn">⚠ ${esc(w)}</div>`).join('')
    + (procs.length ? `<details class="rprocs"${procsOpen.has(el.dataset.res) ? ' open' : ''}><summary>Top programs</summary><table>${procs.map(x => `<tr><td class="mono">${esc(x.name)}${x.n > 1 ? ` <span class="faint">×${x.n}</span>` : ''}${x.path ? ` <span class="faint">${esc(x.path)}</span>` : ''}</td><td>${x.cpu.toFixed(1)}%</td><td class="faint">${x.rssMB.toFixed(0)} MB</td></tr>`).join('')}</table></details>` : '');
}
// a long error: the start, and the whole of it on click
function errMore(e, n) {
  if (e.length <= n) return `<span class="faint">${esc(e)}</span>`;
  return `<details class="emore"><summary class="faint">${esc(e.slice(0, n))}… <u>more</u></summary><div class="faint">${esc(e)}</div></details>`;
}
function resLine(hist, k) {
  const pts = (hist || []).slice(-90), n = pts.length;
  if (n < 2) return '';
  return pts.map((p, i) => `${i ? 'L' : 'M'}${(i / (n - 1) * 100).toFixed(2)},${(23 - Math.min(100, p[k]) / 100 * 22).toFixed(2)}`).join('');
}
function drawSpark(svg, hist) {
  if (!svg) return;
  const pts = hist.slice(-60), n = pts.length;
  const [ad, pd, pu] = ['.ad', '.pd', '.pu'].map(c => $(c, svg));
  if (n < 2) { [ad, pd, pu].forEach(p => p.setAttribute('d', '')); return; }
  const max = Math.max(1, ...pts.map(p => Math.max(p.down, p.up)));
  const x = (i) => (i / (n - 1)) * 100, y = (v) => 36 - (v / max) * 33;
  const line = (k) => pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(2)},${y(p[k]).toFixed(2)}`).join('');
  pd.setAttribute('d', line('down')); pu.setAttribute('d', line('up'));
  ad.setAttribute('d', line('down') + `L100,38L0,38Z`);
}
function topbar(title, sub, actions) {
  return `<div class="topbar"><div style="display:flex;align-items:center;gap:12px">
    <button class="btn ghost sm menu-toggle">☰</button>
    <div><h1>${esc(title)}</h1><p>${esc(sub)}</p></div></div><div class="actions">${actions || ''}</div></div>`;
}
function modal(inner, wide) {
  // closes only with its ✕ (or its own buttons): a click beside it no longer throws away a half-filled form
  const m = h(`<div class="modal"><div class="card"${wide ? ' style="max-width:640px"' : ''}><button class="mclose" title="Close" aria-label="Close">✕</button>${inner}</div></div>`);
  document.body.appendChild(m);
  $('.mclose', m).onclick = () => m.remove();
  return m;
}
function alertModal(title, msg) {
  const m = modal(`<h2>${esc(title)}</h2><pre class="pre">${esc(msg)}</pre><div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn pri" id="ok">OK</button></div>`);
  $('#ok', m).onclick = () => m.remove();
}
// a form's submit runs once at a time: its submit button stays disabled until the request
// settles (a double press used to save twice — two servers, two tunnels)
const oneAtATime = (form, fn) => async (ev) => {
  ev.preventDefault();
  if (form._busy) return;
  form._busy = true;
  const bs = $$('button:not([type=button])', form); bs.forEach(b => b.disabled = true);
  try { await fn(ev); } finally { form._busy = false; bs.forEach(b => b.disabled = false); }
};
function confirmInline(btn, msg) { if (btn.dataset.armed) return true; btn.dataset.armed = '1'; const o = btn.textContent; btn.textContent = msg; setTimeout(() => { if (btn.isConnected) { btn.textContent = o; delete btn.dataset.armed; } }, 2500); return false; }

/* ---------------- settings ---------------- */
// the signed-in account: username and/or password (every role)
function accountFormHTML() {
  return `<form class="card pad ff" id="pf">
      <h3>👤 Account</h3>
      <p class="muted" style="font-size:13px;margin:0">Change the panel login — the username, the password, or both. Every other signed-in browser is signed out.</p>
      <label class="f">Username<input name="user" autocomplete="username" value="${esc(STATE.user || '')}" maxlength="32"></label>
      <label class="f">New password <span class="faint">(min 8 — leave empty to keep it)</span><span class="pw"><input name="new" type="password" autocomplete="new-password" data-strength><button type="button" class="btn sm ghost" data-eye title="show / hide">👁</button></span><small class="fhelp" data-meter></small></label>
      <label class="f">Current password <span class="faint">(required)</span><span class="pw"><input name="old" type="password" autocomplete="current-password" required><button type="button" class="btn sm ghost" data-eye title="show / hide">👁</button></span></label>
      <div class="actions"><button class="btn pri">Save account</button><button type="button" class="btn ghost" data-genpw title="fill in a strong random password (shown so you can copy it)">🎲 Generate a strong password</button></div>
    </form>`;
}
function wireAccount(pf) {
  wirePasswordUX(pf);
  $('[data-genpw]', pf).onclick = () => {
    const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.';
    const pw = Array.from(crypto.getRandomValues(new Uint8Array(18)), b => abc[b % abc.length]).join('');
    const el = pf.new; el.value = pw; el.type = 'text'; el.dispatchEvent(new Event('input')); el.select();
    toast('Strong password filled in — copy it before you save');
  };
  pf.onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    const newUser = (fd.user || '').trim() !== STATE.user ? (fd.user || '').trim() : '';
    try {
      const r = await api('/password', { Old: fd.old, New: fd.new, NewUser: newUser });
      STATE.user = r.user || STATE.user; pf.old.value = ''; pf.new.value = '';
      toast(newUser && fd.new ? 'Username and password updated' : newUser ? 'Username updated' : 'Password updated');
      // a renamed admin: the account list (View selector, Users page, "(you)") is read again first
      await loadAll().catch(() => {});
      renderShell();
    } catch (e) { alertModal('Error', e.message); }
  };
}
// a user's own Telegram bot: it shows and alerts only their services
function myBotHTML() {
  return `<form class="card pad ff" id="mbf">
      <h3>🤖 Your Telegram bot</h3>
      <p class="muted" style="font-size:13px;margin:0">Run your tunnels from Telegram and get alerts about them — your services only.
      <b>1.</b> Create a bot with <a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a> (/newbot) and paste its token here.
      <b>2.</b> Save, send your bot <b>/start</b>: it answers with your chat id. <b>3.</b> Put the chat id here and save again.</p>
      <label class="f">Bot token<input name="token" class="mono" autocomplete="off" placeholder="123456789:AAH…" data-tok></label>
      <label class="f">Your chat id(s) <span class="faint">(comma-separated)</span><input name="chats" class="mono" placeholder="123456789" data-chats></label>
      <div class="actions"><button class="btn pri">Save bot</button><button type="button" class="btn ghost" data-rm hidden>Remove bot</button><span class="faint" data-st style="font-size:12px"></span></div>
    </form>`;
}
function wireMyBot(f) {
  const show = (r) => {
    $('[data-chats]', f).value = r.chats || '';
    $('[data-tok]', f).placeholder = r.set ? 'saved — leave empty to keep it' : '123456789:AAH…';
    $('[data-rm]', f).hidden = !r.set;
    const st = r.state || '';
    $('[data-st]', f).textContent = !r.set ? 'no bot yet' : st.startsWith('error') ? '🔴 Telegram refused it — ' + st.slice(7) : !st ? 'starting…'
      : r.chats ? '🟢 ' + st + ' is running' : '🟢 ' + st + ' is running — send it /start and add your chat id';
  };
  const load = () => api('/mybot').then(show).catch(() => {});
  load();
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    try { show(await api('/mybot', { Token: f.token.value.trim(), Chats: f.chats.value.trim() })); f.token.value = ''; toast('Bot saved'); setTimeout(load, 4000); }
    catch (e) { alertModal('Telegram bot', e.message); }
  };
  $('[data-rm]', f).onclick = async () => {
    try { show(await api('/mybot', { Remove: true })); toast('Bot removed'); } catch (e) { alertModal('Telegram bot', e.message); }
  };
}
function viewSettings(w) {
  if (!isAdmin()) {
    w.innerHTML = topbar('Account', 'Your panel login. You see and run only your own servers and tunnels.');
    const c = h(`<div class="grid" style="max-width:560px;gap:16px">${accountFormHTML()}${myBotHTML()}</div>`);
    w.appendChild(c); wireAccount($('#pf', c)); wireMyBot($('#mbf', c));
    return;
  }
  const s = STATE.settings;
  w.innerHTML = topbar('Settings', 'This panel host, downloads, the dial-back agent and Telegram.');
  const card = h(`<div class="grid" style="max-width:660px;gap:16px">
    <form class="card pad ff" id="sf">
      <h3>Panel & this host</h3>
      <label class="f">Panel name<input name="panelName" value="${esc(s.panelName || '')}"></label>
      <div class="two">
        <label class="f">This host · public IPv4<input name="localIPv4" class="mono" placeholder="auto-detected if blank" value="${esc(s.localIPv4 || '')}"></label>
        <label class="f">This host · public IPv6<input name="localIPv6" class="mono" placeholder="auto-detected if blank" value="${esc(s.localIPv6 || '')}"></label>
      </div>
      <label class="f">Agent dial-back address <span class="faint">host:port Iran agents connect to (blank = this host's IPv4 : ${STATE.agentPort})</span><input name="agentConnect" class="mono" value="${esc(s.agentConnect || '')}" placeholder="203.0.113.5:${STATE.agentPort}"></label>
      <div class="two">
        <label class="f">FRP version <span class="faint">(blank = 0.72.0, pinned)</span><input name="frpVersion" class="mono" value="${esc(s.frpVersion || '')}"></label>
        <label class="f">GitHub download prefix<input name="githubProxy" class="mono" value="${esc(s.githubProxy || '')}" placeholder="https://ghproxy.net/"></label>
        <label class="f">Automatic benchmark every … hours <span class="faint">(only the methods running on each route, on the spare slot — live tunnels aren't touched; blank = 24, 0 = off; each method moves at most 3 MB each way)</span><input name="autoBench" class="mono" inputmode="numeric" value="${esc(s.autoBench || '')}" placeholder="24"></label>
      </div>
      <h3 style="margin-top:6px">Telegram bot</h3>
      <div class="two">
        <label class="f">Bot token<input name="telegramTok" class="mono" value="${esc(s.telegramTok || '')}" placeholder="123456:ABC..."></label>
        <label class="f">Admin chat id(s)<input name="telegramAdmin" class="mono" value="${esc(s.telegramAdmin || '')}" placeholder="comma-separated"></label>
      </div>
      <div class="faint" style="font-size:12px">Message your bot <b>/start</b>; it replies with your chat id if you're not yet an admin. The bot can start, stop and switch every tunnel.</div>
      <label class="f">📣 Alert channel <span class="faint">(tunnel &amp; server up/down alerts go here instead of the admin chat — add the bot to your channel as an admin and it fills this in by itself; -100… id or @name, blank = admin chat. WARP / Instagram / Gemini alerts stay in the admin chat: only the important ones, one short summary every 10 min)</span><input name="telegramChannel" class="mono" placeholder="-1001234567890" value="${esc(s.telegramChannel || '')}"></label>
      <label class="row f"><input type="checkbox" name="botAll" value="on" ${s.botAll === 'on' ? 'checked' : ''}> Send every event to Telegram <span class="faint">(hot-standby switches, finished benchmarks, 'now runs …', re-applies… — off: only outages, failures, warnings and the AI analysis)</span></label>
      <label class="row f"><input type="checkbox" name="telegramBackup" value="on" ${s.telegramBackup === 'on' ? 'checked' : ''}> Send the daily backup to the admin chat too</label>
      <h3 style="margin-top:6px">🧠 AI analysis (Claude)</h3>
      <label class="f">Claude API key <span class="faint">(from console.anthropic.com — the Tunnels page's 🧠 AI analysis sends the tunnels' state to Claude: names, paths, measurements, outages and alerts; no server addresses, passwords or keys. Blank = off)</span><input name="claudeKey" class="mono" type="password" autocomplete="off" value="${esc(s.claudeKey || '')}" placeholder="sk-ant-..."></label>
      <label class="f">🧠 Daily AI analysis at <span class="faint">(HH:MM, Tehran time — the panel runs the analysis by itself, even with no page open, and sends the summary to the admin chat; blank = 09:30 while a key is set, off = never)</span><input name="aiDaily" class="mono" placeholder="09:30" maxlength="5" value="${esc(s.aiDaily || '')}"></label>
      <label class="row f"><input type="checkbox" name="aiAuto" value="off" ${s.aiAuto === 'off' ? 'checked' : ''}> The daily run only reports — it doesn't apply its suggested changes (moving users to a working path, the switcher's auto/manual mode)</label>
      <label class="f">☀️ Daily report at <span class="faint">(HH:MM, Tehran time — tunnels, their paths and the last day's outages; blank = off)</span><input name="telegramReport" class="mono" placeholder="09:00" maxlength="5" value="${esc(s.telegramReport || '')}"></label>
      <div><button class="btn pri">Save settings</button></div>
    </form>
    <form class="card pad ff" id="domf">
      <h3>🌐 Panel address (HTTPS)</h3>
      <p class="muted" style="font-size:13px;margin:0">Domains the panel answers on, comma-separated — each gets a free Let's Encrypt certificate on its first visit, renewed automatically before it expires. Point each domain's DNS (A record) at this server; behind Cloudflare use <b>DNS only</b> (grey cloud) or let port 80 through. Saving restarts the panel (tunnels keep running).</p>
      <label class="f">Domains<input name="Domains" class="mono" placeholder="panel.example.com, 1-2-3-4.sslip.io" data-dom></label>
      <div class="actions"><button class="btn pri">Save &amp; restart the panel</button><span class="faint" data-domnow style="font-size:12px"></span></div>
    </form>
    <div class="card pad" id="bkCard">
      <h3>Backup &amp; restore</h3>
      <p class="muted" style="font-size:13px;margin:6px 0">One file with everything: servers (with their SSH passwords/keys), tunnels and their secrets, settings, users and history. A copy is also kept every day on this host (the last 14, next to the panel's state in <span class="mono">backups/</span>). Keep the file private.</p>
      <div class="actions"><a class="btn pri" href="/api/backup" download>⬇ Download backup</a>
        <input type="file" id="bkfile" accept=".json,application/json" hidden><button class="btn" id="bkpick">⬆ Restore from file…</button></div>
      <div class="faint" id="bkstat" style="font-size:12px;margin-top:6px">Restoring replaces the whole panel state (the current one is saved first). Tunnels already running on the servers keep running; Apply them again if the backup's settings differ. You may have to log in again with the backup's password.</div>
    </div>
    <div class="card pad">
      <h3>Agent certificate pin</h3>
      <p class="muted" style="font-size:13px;margin:6px 0">Agents verify the panel with this pin. It never changes unless you delete the panel's agent key.</p>
      <div class="codebox"><code>${esc(STATE.agentPin)}</code></div>
    </div>
    ${accountFormHTML()}
  </div>`);
  w.appendChild(card);
  $('#sf').onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try { await api('/settings', fd); await loadAll(); toast('Settings saved'); renderView(); } catch (e) { alertModal('Error', e.message); }
  };
  wireAccount($('#pf', card));
  const domf = $('#domf', card);
  api('/domain').then(r => {
    const cur = r.tls === 'self' ? '' : r.tls || '';
    $('[data-dom]', domf).value = cur;
    $('[data-domnow]', domf).textContent = r.tls === 'self' ? 'now: self-signed HTTPS' : r.tls ? 'now: ' + r.tls : 'now: plain HTTP';
  }).catch(() => {});
  domf.onsubmit = async (ev) => {
    ev.preventDefault();
    try {
      const r = await api('/domain', { Domains: $('[data-dom]', domf).value });
      alertModal('Panel address', `Saved — the panel restarts in a few seconds.\n\nOpen it at ${r.url}\n(the first visit fetches the certificate, which can take a few seconds)${r.note ? '\n\n⚠ ' + r.note : ''}`);
    } catch (e) { alertModal('Panel address', e.message); }
  };
  const bkf = $('#bkfile', card);
  $('#bkpick', card).onclick = () => bkf.click();
  bkf.onchange = async () => {
    const f = bkf.files[0]; bkf.value = '';
    if (!f) return;
    if (!confirm('Replace the whole panel state with ' + f.name + '?')) return;
    $('#bkstat', card).textContent = 'Restoring…';
    try { const r = await api('/backup', { data: await f.text() }); alertModal('Restored', r.ok); await loadAll(); renderView(); }
    catch (e) { $('#bkstat', card).textContent = ''; alertModal('Restore failed', e.message); }
  };
}

/* ---------------- users (admin) ---------------- */
// Accounts: an admin sees and runs everything; a user only the servers and tunnels given to
// it (or that it adds itself). Give an account its servers with 👤 Account… on a server card.
function viewUsers(w) {
  w.innerHTML = topbar('Users', 'Panel accounts. A user sees and runs only its own servers and tunnels; admins see the whole network.',
    '<button class="btn pri" id="addUser">+ New user</button>');
  const list = h('<div class="grid cards"></div>');
  w.appendChild(list);
  const paint = () => {
    list.innerHTML = '';
    (STATE.users || []).forEach(u => list.appendChild(h(`<div class="card ucard${u.username === STATE.user ? ' me' : ''}">
      <div class="uav">${esc((u.username[0] || '?').toUpperCase())}</div>
      <div class="ubody"><h3>${nm(u.username)} ${u.role === 'admin' ? '<span class="chip own">admin</span>' : '<span class="chip">user</span>'}${u.username === STATE.user ? ' <span class="faint">(you)</span>' : ''}</h3>
        <div class="faint" style="font-size:12.5px">${u.servers} server${u.servers === 1 ? '' : 's'} · ${u.tunnels} tunnel${u.tunnels === 1 ? '' : 's'}${u.role === 'admin' ? ' <span title="servers and tunnels with no account belong to the admins">· shared by the admins</span>' : ''}</div></div>
      <div class="uact">${u.username === STATE.user ? '' : `<button class="btn sm" data-view="${esc(u.username)}" title="show only this account's servers and tunnels">👁 View</button>
        <button class="btn sm" data-edit="${esc(u.username)}">✎ Edit</button><button class="btn sm ghost danger" data-del="${esc(u.username)}">🗑</button>`}</div></div>`)));
    $$('[data-view]', list).forEach(b => b.onclick = () => { setOwnerFilter(b.dataset.view); setView('tunnels'); renderShell(); });
    $$('[data-edit]', list).forEach(b => b.onclick = () => userModal(STATE.users.find(u => u.username === b.dataset.edit)));
    $$('[data-del]', list).forEach(b => b.onclick = async () => {
      if (!confirmInline(b, 'Delete?')) return;
      try {
        await api('/users/delete', { Username: b.dataset.del });
        // its servers and tunnels moved, and a View set to it would show nothing with no way back:
        // renderShell drops a View naming a missing account and redraws the selector
        await loadAll().catch(async () => { STATE.users = await api('/users').catch(() => STATE.users); });
        if (STATE.ownerFilter === b.dataset.del) setOwnerFilter('');
        renderShell(); toast('Account deleted');
      } catch (e) { alertModal('Delete account', e.message); }
    });
  };
  paint();
  $('#addUser').onclick = () => userModal(null);
}
function userModal(u) {
  const m = modal(`<h2>${u ? '<span>Edit</span> ' + nm(u.username) : 'New user'}</h2>
    <form class="ff" id="uf">
      <label class="f">Username<input name="Username" value="${esc(u ? u.username : '')}" ${u ? 'readonly' : 'required'} maxlength="32" autocomplete="off"></label>
      <label class="f">Role<select name="Role"><option value="user"${!u || u.role === 'user' ? ' selected' : ''}>👤 User — only its own servers and tunnels</option><option value="admin"${u && u.role === 'admin' ? ' selected' : ''}>🛡 Admin — the whole network</option></select></label>
      <label class="f">Password ${u ? '<span class="faint">(leave empty to keep it; a new one signs the user out)</span>' : '<span class="faint">(min 8)</span>'}<span class="pw"><input name="Password" type="password" autocomplete="new-password" data-strength${u ? '' : ' required minlength="8"'}><button type="button" class="btn sm ghost" data-eye title="show / hide">👁</button></span><small class="fhelp" data-meter></small></label>
      <div class="actions" style="justify-content:space-between"><button type="button" class="btn ghost" data-gen>🎲 Generate</button><div class="actions"><button type="button" class="btn ghost" data-x>Cancel</button><button class="btn pri">Save</button></div></div>
    </form>`);
  wirePasswordUX(m);
  $('[data-x]', m).onclick = () => m.remove();
  $('[data-gen]', m).onclick = () => {
    const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const el = $('[name=Password]', m); el.value = Array.from(crypto.getRandomValues(new Uint8Array(14)), b => abc[b % abc.length]).join(''); el.type = 'text'; el.dispatchEvent(new Event('input')); el.select();
  };
  $('#uf', m).onsubmit = oneAtATime($('#uf', m), async (ev) => {
    const fd = Object.fromEntries(new FormData(ev.target));
    try { STATE.users = await api('/users', fd); m.remove(); toast(u ? 'Account saved' : 'Account created — give the user its servers with 👤 Account… on a server card'); renderShell(); }
    catch (e) { alertModal('Account', e.message); }
  });
}
// the admin moves a server or tunnel to another account
function ownerModal(kind, id) {
  const x = kind === 'server' ? serverById(id) : STATE.tunnels.find(t => t.id === id);
  if (!x) return;
  const m = modal(`<h2><span>👤 Account of</span> ${nm(x.name)}</h2>
    <p class="muted" style="font-size:13px">That account sees it and can run it; other users don't see it. Admins always see everything.${kind === 'server' ? ' Its tunnels keep their own account — move them too.' : ''}</p>
    <label class="f">Account<select data-o><option value="">me (admin)</option>${(STATE.users || []).filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}"${x.owner === u.username ? ' selected' : ''} data-notr>${esc(u.username)}${u.role === 'admin' ? ' (admin)' : ''}</option>`).join('')}</select></label>
    <div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn ghost" data-x>Cancel</button><button class="btn pri" data-s>Save</button></div>`);
  $('[data-x]', m).onclick = () => m.remove();
  $('[data-s]', m).onclick = async () => {
    try { await api('/owner', { Kind: kind, ID: id, Owner: $('[data-o]', m).value }); m.remove(); await loadAll(); renderView(); toast('Saved'); } catch (e) { alertModal('Account', e.message); }
  };
}

/* ---------------- servers ---------------- */
// Two clearly separate groups: Iran (entry) and foreign (exit, incl. this panel host).
// A compact list of every server on the left; the chosen one's details, live load and
// actions on the right (on a phone: the list, then the details under it).
function viewServers(w) {
  w.innerHTML = topbar('Servers', 'Iran servers (users connect here) and foreign servers (traffic exits there), with their live load.');
  const ir = iranServers().filter(x => shownOwner(x.owner)), fg = foreignServers().filter(x => shownOwner(x.owner));
  const hostShown = isAdmin() && (!STATE.ownerFilter || STATE.ownerFilter === '-'); // the panel host is the admin's
  const all = [...ir, ...fg];
  let cur = recall('tp-srv');
  if (!(cur === 'host' && hostShown) && !all.some(x => x.id === cur)) cur = all.length ? all[0].id : hostShown ? 'host' : '';
  const row = (s) => {
    const host = s === 'host', id = host ? 'host' : s.id;
    const led = host || s.agentOnline ? 'on' : s.prepared ? 'ok2' : 'off';
    const tip = host ? 'local' : s.agentOnline ? 'agent online' : s.prepared ? 'reachable' : 'not tested';
    const n = host ? STATE.tunnels.filter(t => !t.foreignId).length : STATE.tunnels.filter(t => t.serverId === s.id || t.foreignId === s.id).length;
    const fl = host ? '🖥' : s.country ? flag(s.country) : ((s.role || 'iran') === 'iran' ? '🇮🇷' : '🌍');
    const ip = host ? STATE.settings.localIPv4 : (s.ipv4 || s.ipv6);
    return `<button class="srow${id === cur ? ' on' : ''}" data-pick="${id}">
      <span class="sflag">${fl}</span>
      <span class="sinfo"><b>${host ? 'This panel host' : s.name ? nm(s.name) : '(unnamed)'}${host ? '' : ' ' + ownerChip(s.owner)}</b><small class="mono">${esc(ip || '—')}</small></span>
      <span class="smeta"><span class="led ${led}" title="${tip}"></span><small class="faint" title="tunnels">🛰 ${n}</small><small class="faint mono" data-mini="${host ? '' : s.id}" title="CPU · RAM"></small></span>
    </button>`;
  };
  const grp = (key, title, items, add) => `<div class="sgrp"><div class="sgh"><span>${title} <span class="count">${items.length}</span></span><button class="btn sm" data-add="${key}">${add}</button></div>
    ${items.length ? items.map(row).join('') : `<div class="faint sempty">${key === 'iran' ? 'No Iran server yet — add one to start building tunnels.' : 'No foreign server yet.'}</div>`}</div>`;
  const split = h(`<div class="srvsplit">
    <aside class="card srvlist">
      ${all.length > 6 ? '<input class="sq" type="search" placeholder="Filter by name or IP…" data-sq>' : ''}
      ${grp('iran', '🇮🇷 Iran · entry', ir, '+ Add')}
      ${grp('foreign', '🌍 Foreign · exit', hostShown ? ['host', ...fg] : fg, '+ Add')}
    </aside>
    <div class="srvdetail" data-detail></div>
  </div>`);
  w.appendChild(split);
  if (isAdmin()) w.appendChild(outageSection());
  const det = $('[data-detail]', split);
  const show = (id, scroll) => {
    cur = id; remember('tp-srv', id);
    $$('.srow', split).forEach(r => r.classList.toggle('on', r.dataset.pick === id));
    const s = STATE.servers.find(x => x.id === id);
    det.innerHTML = '';
    if (id === 'host' && hostShown) det.appendChild(panelHostCard());
    else if (s) det.appendChild(serverCard(s));
    else det.innerHTML = '<div class="card empty"><div class="big">🖥</div><h3>No servers here yet</h3><p class="muted">Add an Iran server (entry) and a foreign server (exit), then build a tunnel between them.</p></div>';
    bindServerActions(det);
    if (scroll && window.innerWidth <= 860) det.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  $$('[data-pick]', split).forEach(b => b.onclick = () => show(b.dataset.pick, true));
  $$('[data-add]', split).forEach(b => b.onclick = () => serverModal({ role: b.dataset.add }));
  const q = $('[data-sq]', split);
  if (q) q.oninput = () => { const v = q.value.trim().toLowerCase(); $$('.srow', split).forEach(r => r.hidden = !!v && !r.textContent.toLowerCase().includes(v)); };
  show(cur, false);
}
function bindServerActions(w) {
  $$('[data-con]', w).forEach(b => b.onclick = () => consoleModal(b.dataset.con));
  $$('[data-edit]', w).forEach(b => b.onclick = () => serverModal(STATE.servers.find(x => x.id === b.dataset.edit)));
  $$('[data-del]', w).forEach(b => b.onclick = async () => { if (!confirmInline(b, 'Click again to delete')) return; try { await api('/servers/delete', { ID: b.dataset.del }); await loadAll(); renderView(); } catch (e) { alertModal('Error', e.message); } });
  $$('[data-test]', w).forEach(b => b.onclick = () => testServer(b.dataset.test, b));
  $$('[data-agent]', w).forEach(b => b.onclick = () => agentModal(b.dataset.agent));
  $$('[data-bridge]', w).forEach(b => b.onclick = () => bridgeModal(b.dataset.bridge));
  $$('[data-optz]', w).forEach(b => b.onclick = () => optimizeModal(b.dataset.optz));
  $$('[data-own]', w).forEach(b => b.onclick = () => ownerModal('server', b.dataset.own));
  $$('[data-prep]', w).forEach(b => b.onclick = () => prepareServer(b.dataset.prep));
}
// Outage log: every server (SSH port checked every few seconds) and tunnel outage, with
// exact times in Tehran time and, for tunnels, whether their servers answered.
const tehranTime = (u) => new Date(u * 1000).toLocaleString('en-GB', { timeZone: 'Asia/Tehran', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const durTxt = (s) => s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s` : `${Math.floor(s / 3600)}h${String(Math.floor(s / 60) % 60).padStart(2, '0')}m`;
function outageSection() {
  const sec = h(`<section class="group"><div class="ghd"><div><h2>📉 Outage log</h2><p>Every server's SSH port is checked every few seconds (a miss is retried twice), so short drops show up too; tunnel outages say whether their servers answered at the time — the tunnel or the server. Times are Tehran time.</p></div>
    <div><button class="btn sm" data-oref>⟳</button> <button class="btn sm ghost" data-oclr>Clear</button></div></div><div class="card" style="padding:0;overflow-x:auto" data-olist><div class="muted" style="padding:14px">loading…</div></div></section>`);
  const load = async () => {
    try {
      const r = await api('/outages'); const list = $('[data-olist]', sec);
      if (!r.outages.length) { list.innerHTML = '<div class="muted" style="padding:14px">No outage recorded yet. ✅</div>'; return; }
      list.innerHTML = `<table class="otab"><thead><tr><th>Start</th><th>Duration</th><th>What</th><th>Reason</th></tr></thead><tbody>${r.outages.slice(0, 100).map(o => {
        const open = !o.end, d = (o.end || r.now) - o.start;
        const icon = o.kind === 'tunnel' ? '🛰' : o.kind === 'panel' ? '🖥' : '🖧';
        return `<tr class="${open ? 'open' : ''}"><td class="mono">${tehranTime(o.start)}</td><td>${open ? `<b>ongoing</b> · ${durTxt(d)}` : `${durTxt(d)}<div class="faint mono" style="font-size:11px">→ ${tehranTime(o.end).split(', ')[1] || ''}</div>`}</td>
          <td>${icon} ${nm(o.name)}<div class="faint" style="font-size:11px">${o.kind}</div></td><td>${esc(o.reason)}${o.cause ? `<div class="faint" style="font-size:12px">${esc(o.cause)}</div>` : ''}</td></tr>`;
      }).join('')}</tbody></table>`;
    } catch (e) { $('[data-olist]', sec).innerHTML = `<div style="padding:14px;color:var(--crit)">${esc(e.message)}</div>`; }
  };
  $('[data-oref]', sec).onclick = load;
  $('[data-oclr]', sec).onclick = async (e) => { if (!confirmInline(e.target, 'Click again to clear')) return; try { await api('/outages', { Clear: true }); load(); } catch (er) { alertModal('Error', er.message); } };
  load();
  return sec;
}
// the panel's own machine, shown as the first foreign server
function panelHostCard() {
  const st = STATE.settings, n = STATE.tunnels.filter(t => !t.foreignId).length;
  return h(`<div class="card scard host">
    <div class="sh"><div class="sname"><span class="sflag">🖥</span><div><h3>This panel host</h3><small>the machine running this panel</small></div></div><span class="pill on"><span class="led"></span>local</span></div>
    <dl class="kvt">
      <div><dt>IPv4</dt><dd><span class="mono">${esc(st.localIPv4 || 'auto-detecting…')}</span></dd></div>
      ${st.localIPv6 ? `<div class="wide"><dt>IPv6</dt><dd><span class="mono">${esc(st.localIPv6)}</span></dd></div>` : ''}
      <div><dt>Tunnels</dt><dd>${n}</dd></div>
    </dl>
    <div class="nic" data-nic=""></div>
    <div class="res" data-res=""></div>
    <div class="sfoot"><button class="btn sm" data-prep="" title="Pre-install the binaries every method needs">Install packages</button><span class="grow"></span><span class="faint" style="font-size:12px">edit in Settings</span></div>
  </div>`);
}
async function prepareServer(id) {
  const s = STATE.servers.find(x => x.id === id);
  try { const r = await api('/servers/prepare', { ID: id }); openLog({ id: '', name: 'Install packages · ' + (s ? s.name : 'this panel host') }, r.job); }
  catch (e) { alertModal('Error', e.message); }
}
function optimizeModal(id) {
  const m = modal(`<h2>Optimize kernel</h2>
    <p class="muted" style="font-size:13px">Detects this server and recommends sysctl tuning (BBR, buffers, forwarding, file limits) scaled to its RAM and kernel. Applies it over the active path, or gives you the command to run by hand.</p>
    <div id="ozbody" style="margin-top:12px"><div class="muted">Detecting…</div></div>`, true);
  const render = (r, applied) => {
    if (r.error) { $('#ozbody', m).innerHTML = `<div style="color:var(--crit)">${esc(r.error)}</div>`; return; }
    const info = [['Kernel', r.kernel], ['Virtualization', r.virt], ['RAM', r.ramMB + ' MB'], ['CPUs', r.cpus], ['Current', (r.cc || '?') + ' / ' + (r.qdisc || '?')], ['BBR', r.bbr ? 'available' : 'not available']];
    $('#ozbody', m).innerHTML = `
      <table class="tbl">${info.map(x => `<tr><td class="faint">${x[0]}</td><td class="mono">${esc(String(x[1]))}</td></tr>`).join('')}</table>
      ${(r.notes || []).map(n => `<div class="mdesc" style="margin-top:8px">${esc(n)}</div>`).join('')}
      ${applied ? `<div class="mdesc" style="border-color:var(--good);margin-top:8px"><b>${r.applied ? '✓ Applied' : '⚠ Apply failed'}</b>${r.output ? '\n' + esc(r.output) : ''}</div>` : ''}
      <h3 style="margin-top:14px">Recommended /etc/sysctl.d/zzz-tunnel-panel-optz.conf</h3>
      <div class="codebox" style="margin-top:6px"><code>${esc(r.sysctlConf)}</code></div>
      <h3 style="margin-top:14px">Run it manually (as root)</h3>
      <div class="codebox" style="margin-top:6px"><code id="ozman">${esc(r.manual)}</code></div>
      <div class="actions" style="justify-content:space-between;margin-top:14px">
        <button class="btn sm" id="ozcopy">Copy manual command</button>
        <div><button class="btn ghost" id="ozclose">Close</button><button class="btn pri" id="ozapply">${applied ? 'Re-apply' : 'Apply now'}</button></div>
      </div>`;
    $('#ozcopy', m).onclick = (e) => copy(r.manual, e.target);
    $('#ozclose', m).onclick = () => m.remove();
    $('#ozapply', m).onclick = () => run(true);
  };
  const run = async (apply) => {
    $('#ozbody', m).innerHTML = `<div class="muted">${apply ? 'Applying…' : 'Detecting…'}</div>`;
    try { const r = await api('/servers/optimize', { ID: id, Apply: !!apply }); render(r, apply); if (apply && r.applied) { toast('Kernel optimized'); loadAll(); } }
    catch (e) { $('#ozbody', m).innerHTML = `<div style="color:var(--crit)">${esc(e.message)}</div>`; }
  };
  run(false);
}
// "⋯" menu for the less common actions, so each card has one clear row of buttons
function moreMenu(items) {
  return `<details class="more"><summary class="btn sm ghost" title="More actions">⋯</summary><div class="pop">${items.filter(Boolean).map(i =>
    `<button class="mi${i.danger ? ' danger' : ''}" ${i.attr}>${i.label}</button>`).join('')}</div></details>`;
}
document.addEventListener('click', (e) => { $$('details.more[open]').forEach(d => { if (!d.contains(e.target)) d.removeAttribute('open'); }); });
// the phone menu button (no inline handlers: the page runs under a CSP without 'unsafe-inline' scripts)
// phone menu: the toggle opens it, a tap outside closes it (before, only picking a page did)
document.addEventListener('click', (e) => {
  const side = $('#side');
  if (!side || !e.target.closest) return;
  if (e.target.closest('.menu-toggle')) side.classList.toggle('open');
  else if (side.classList.contains('open') && !e.target.closest('.side')) side.classList.remove('open');
});
// keep an open ⋯ menu above the next card (browsers without :has()), and close it once an item is picked
document.addEventListener('toggle', (e) => {
  const d = e.target; if (!d.matches || !d.matches('details.more')) return;
  const c = d.closest('.card'); if (c) c.classList.toggle('raised', d.open);
  // and its page section: each one is a layer (page-in animation), so the next one covered the menu's lower items
  const sec = [...$$('.main > *')].find(x => x.contains(d)); if (sec) sec.classList.toggle('raised', d.open);
}, true);
document.addEventListener('click', (e) => { const mi = e.target.closest && e.target.closest('details.more .mi'); if (mi) setTimeout(() => { const d = mi.closest('details.more'); if (d && !mi.dataset.armed) d.removeAttribute('open'); }, 0); });
function serverCard(s) {
  const isIran = (s.role || 'iran') === 'iran';
  const status = s.agentOnline ? `<span class="pill on"><span class="led"></span>agent online</span>`
    : s.prepared ? `<span class="pill ok2"><span class="led"></span>reachable</span>`
    : `<span class="pill off"><span class="led"></span>not tested</span>`;
  const tl = STATE.tunnels.filter(t => t.serverId === s.id || t.foreignId === s.id);
  const sub = [s.city, s.os && s.arch ? `${s.os} ${s.arch}` : ''].filter(Boolean).join(' · ');
  return h(`<div class="card scard ${isIran ? 'ir' : 'fg'}">
    <div class="sh"><div class="sname"><span class="sflag">${s.country ? flag(s.country) : (isIran ? '🇮🇷' : '🌍')}</span><div><h3>${s.name ? nm(s.name) : '(unnamed)'} ${ownerChip(s.owner)}</h3><small><span class="srole">${isIran ? 'Iran · entry' : 'foreign · exit'}</span>${sub ? ' ' + esc(sub) : ''}</small></div></div>${status}</div>
    <div class="sfoot">
      <button class="btn sm pri" data-con="${s.id}" title="A shell on this server in the browser, over the panel's own path to it">&gt;_ Console</button>
      <button class="btn sm" data-test="${s.id}">Test connection</button>
      <button class="btn sm" data-prep="${s.id}" title="Pre-install every method's binaries and packages once, so switching methods is instant">${s.provisioned ? '📦 Update packages' : 'Install packages'}</button>
      <span class="grow"></span>
      ${moreMenu([
        { label: '⚡ Optimize kernel', attr: `data-optz="${s.id}"` },
        isIran ? { label: '📡 Agent install command', attr: `data-agent="${s.id}"` } : null,
        isAdmin() ? { label: '🔑 SSH bridge', attr: `data-bridge="${s.id}"` } : null,
        isAdmin() ? { label: '👤 Account…', attr: `data-own="${s.id}"` } : null,
        { label: '✎ Edit', attr: `data-edit="${s.id}"` },
        { label: '🗑 Delete', attr: `data-del="${s.id}"`, danger: true },
      ])}
    </div>
    <div data-paths="${s.id}"></div>
    <dl class="kvt">
      <div><dt>IPv4</dt><dd><span class="mono">${esc(s.ipv4 || '—')}</span></dd></div>
      <div class="wide"><dt>IPv6</dt><dd><span class="mono">${esc(s.ipv6 || (s.prepared ? 'none' : 'reading over SSH…'))}</span></dd></div>
      <div><dt>SSH</dt><dd><span class="mono">${esc(s.sshUser || 'root')}@${esc(s.sshHost || s.ipv4 || s.ipv6 || '?')}:${s.sshPort || 22}</span></dd></div>
      <div><dt>Packages</dt><dd>${s.provisioned ? '<span style="color:var(--good)">✓ installed</span>' : '<span class="faint">not installed yet</span>'}</dd></div>
      ${s.lastPath ? `<div><dt>Reached via</dt><dd>${esc(s.lastPath)}</dd></div>` : ''}
      ${s.proxy ? `<div><dt>Proxy</dt><dd><span class="mono">${esc(s.proxy)}</span></dd></div>` : ''}
      <div class="wide"><dt>Tunnels</dt><dd>${tl.length ? tl.map(t => `<span class="tchip${t.active ? '' : ' off'}" data-notr>${esc(t.name || t.id)}</span>`).join(' ') : '<span class="faint">none</span>'}</dd></div>
    </dl>
    <div class="nic" data-nic="${s.id}"></div>
    <div class="res" data-res="${s.id}"></div></div>`);
}
async function testServer(id, btn) {
  btn.disabled = true; const o = btn.textContent; btn.textContent = 'Testing… (up to ~30 s)';
  try {
    const r = await api('/servers/test', { ID: id });
    const html = `<div class="paths">${r.paths.map(p => `<div class="path ${p.ok ? 'ok' : 'bad'}"><span>${p.ok ? '✓' : '✕'} ${esc(p.path)}</span><span class="faint">${esc(p.info)}</span></div>`).join('')}</div>`;
    if (r.ok) {
      toast('Best path: ' + r.best);
      // the test may have read the server's addresses: redraw so the card shows them, then
      // put the path list back under the redrawn card
      await loadAll(); renderView();
    }
    const box = $(`[data-paths="${id}"]`);
    if (box) box.innerHTML = html;
  } catch (e) { alertModal('Test failed', e.message); }
  const b = $(`[data-test="${id}"]`) || btn; b.disabled = false; b.textContent = o;
}
function agentModal(id) {
  const m = modal(`<h2>Agent install (Iran)</h2>
    <p class="muted" style="font-size:13px">Run this on the Iran server. It dials back to the panel, so no inbound SSH or open port is needed on Iran. The panel then reaches it through the agent.</p>
    <div class="codebox" id="acmd"><code>loading…</code></div>
    <div class="actions" style="justify-content:space-between;margin-top:14px">
      <button class="btn ghost sm" id="rot">Rotate token</button>
      <div><button class="btn" id="cp">Copy</button><button class="btn pri" id="close">Done</button></div>
    </div>`, true);
  const load = async (rotate) => {
    try { const r = await api('/servers/agent', { ID: id, Rotate: !!rotate }); $('#acmd code', m).textContent = r.command; m._cmd = r.command; }
    catch (e) { $('#acmd code', m).textContent = e.message; }
  };
  $('#rot', m).onclick = () => load(true);
  $('#cp', m).onclick = (e) => copy(m._cmd || '', e.target);
  $('#close', m).onclick = () => m.remove();
  load(false);
}
function bridgeModal(id) {
  const m = modal(`<h2>SSH bridge</h2>
    <p class="muted" style="font-size:13px">Opens a port on the panel that proxies SSH to this Iran server over the active path (agent/jump/direct). Use it to log in manually when Iran blocks inbound SSH.</p>
    <label class="row f" style="margin:10px 0"><input type="checkbox" id="pub"> Expose on the panel's public IP (otherwise localhost only)</label>
    <div class="codebox" id="bcmd" hidden><code></code></div>
    <div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn ghost" id="close">Close</button><button class="btn pri" id="open">Open bridge</button></div>`, true);
  $('#close', m).onclick = () => m.remove();
  $('#open', m).onclick = async () => {
    try {
      const r = await api('/servers/bridge', { ID: id, Public: $('#pub', m).checked });
      const box = $('#bcmd', m); box.hidden = false; box.querySelector('code').textContent = r.command + '\n# ' + r.note;
    } catch (e) { alertModal('Error', e.message); }
  };
}
// The web SSH console (console.go): xterm.js, loaded the first time it is opened
let xtermLoad;
function loadXterm() {
  const add = (tag, attrs) => new Promise((ok, bad) => { const el = Object.assign(document.createElement(tag), attrs); el.onload = ok; el.onerror = () => bad(new Error('could not load ' + (attrs.src || attrs.href))); document.head.appendChild(el); });
  xtermLoad = xtermLoad || Promise.all([add('link', { rel: 'stylesheet', href: '/vendor/xterm.css' }), add('script', { src: '/vendor/xterm.js' })])
    .then(() => add('script', { src: '/vendor/addon-fit.js' }))
    .catch(e => { xtermLoad = null; throw e; });
  return xtermLoad;
}
async function consoleModal(id) {
  const s = STATE.servers.find(x => x.id === id); if (!s) return;
  const m = h(`<div class="modal conm"><div class="card">
    <div class="conhd"><b data-notr>&gt;_ ${esc(s.name)}</b><span class="faint mono" style="font-size:12px">${esc(s.sshUser || 'root')}@${esc(s.ipv4 || s.sshHost || s.ipv6 || '')}</span><span class="pill off" data-cst><span class="led"></span>connecting</span><span class="grow"></span>
      <button class="btn sm ghost" data-crec title="Open a new session">⟳ Reconnect</button><button class="btn sm ghost" data-cmax title="Full screen">⤢</button><button class="btn sm" data-cclose>Close</button></div>
    <div class="term" data-term data-notr dir="ltr"></div></div></div>`);
  document.body.appendChild(m);
  const st = $('[data-cst]', m), setSt = (cls, txt) => { st.className = 'pill ' + cls; st.innerHTML = `<span class="led"></span>${txt}`; };
  // Close works while xterm loads, and when it can't be loaded (the window used to stay up for good)
  $('[data-cclose]', m).onclick = () => m.remove();
  try { await loadXterm(); } catch (e) { setSt('off', esc(e.message)); return; }
  if (!m.isConnected) return; // closed while loading
  const dark = getComputedStyle(document.documentElement).colorScheme.includes('dark');
  const term = new Terminal({ cursorBlink: true, fontSize: 13, fontFamily: 'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace', scrollback: 5000,
    theme: dark ? { background: '#0d1117', foreground: '#d6dbe4' } : { background: '#fbfcfe', foreground: '#1b2030', cursor: '#1b2030', selectionBackground: '#c9d4f5' } });
  const fit = new FitAddon.FitAddon(); term.loadAddon(fit);
  const box = $('[data-term]', m); box.style.background = term.options.theme.background;
  term.open(box); fit.fit(); term.focus();
  let ws, ping;
  const send = (o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
  const connect = () => {
    if (ws) ws.close();
    clearInterval(ping); setSt('off', 'connecting');
    ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/servers/console?id=${encodeURIComponent(id)}&c=${term.cols}&r=${term.rows}`);
    ws.binaryType = 'arraybuffer';
    const me = ws;
    ws.onopen = () => { setSt('on', 'connected'); ping = setInterval(() => send({ t: 'p' }), 30000); };
    ws.onmessage = (e) => term.write(typeof e.data === 'string' ? e.data : new Uint8Array(e.data));
    ws.onclose = () => { if (me !== ws) return; clearInterval(ping); setSt('off', 'closed'); };
  };
  term.onData(d => send({ t: 'i', d }));
  term.onResize(({ cols, rows }) => send({ t: 'r', c: cols, r: rows }));
  const ro = new ResizeObserver(() => { try { fit.fit(); } catch (e) {} }); ro.observe($('[data-term]', m));
  const close = () => { ro.disconnect(); clearInterval(ping); if (ws) { const x = ws; ws = null; x.close(); } term.dispose(); m.remove(); };
  $('[data-cclose]', m).onclick = close;
  $('[data-crec]', m).onclick = () => { term.reset(); connect(); term.focus(); };
  $('[data-cmax]', m).onclick = () => { m.classList.toggle('full'); term.focus(); };
  connect();
}
function serverModal(s) {
  s = s || {};
  const m = modal(`<h2>${s.id ? 'Edit server' : (s.role === 'foreign' ? 'Add foreign server' : 'Add Iran server')}</h2>
    <form class="ff" id="srvf">
      <div class="two">
        <label class="f">Name<input name="name" value="${esc(s.name || '')}" required></label>
        <label class="f">Role<select name="role"><option value="iran"${s.role === 'foreign' ? '' : ' selected'}>🇮🇷 Iran (entry)</option><option value="foreign"${s.role === 'foreign' ? ' selected' : ''}>🌍 Foreign (exit)</option></select></label>
      </div>
      <div class="two">
        <label class="f">Public IPv4<input name="ipv4" class="mono" placeholder="blank = read from the server over SSH" value="${esc(s.ipv4 || '')}"></label>
        <label class="f">Public IPv6<input name="ipv6" class="mono" placeholder="blank = read from the server over SSH, automatically" value="${esc(s.ipv6 || '')}"></label>
      </div>
      <div class="two">
        <label class="f">SSH host <span class="faint">(blank=IPv4)</span><input name="sshHost" class="mono" value="${esc(s.sshHost || '')}"></label>
        <label class="f">SSH port<input name="sshPort" type="number" class="mono" value="${s.sshPort || 22}"></label>
      </div>
      <div class="two"><label class="f">SSH user<input name="sshUser" class="mono" value="${esc(s.sshUser || 'root')}"></label><label class="f">Country <span class="faint">(auto; 2-letter override)</span><input name="country" class="mono" maxlength="2" value="${esc(s.country || '')}" placeholder="auto"></label></div>
      ${isAdmin() && !s.id && (STATE.users || []).length > 1 ? `<label class="f">Account <span class="faint">(who sees and runs it)</span><select name="owner"><option value="">me (admin)</option>${STATE.users.filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}"${STATE.ownerFilter === u.username ? ' selected' : ''} data-notr>${esc(u.username)}</option>`).join('')}</select></label>` : ''}
      <label class="f">Password <span class="faint">(leave blank to keep)</span><input name="password" type="password" value="${esc(s.password || '')}"></label>
      <label class="f">or Private key (PEM)<textarea name="privateKey" rows="2" class="mono">${esc(s.privateKey || '')}</textarea></label>
      <details><summary class="muted" style="font-size:13px;cursor:pointer">Advanced reach options</summary>
        <div class="ff" style="margin-top:10px">
          <label class="f">Proxy for SSH <span class="faint">socks5:// or http://</span><input name="proxy" class="mono" value="${esc(s.proxy || '')}"></label>
          <label class="f">Force jump via<select name="via"><option value="">auto (try all servers)</option>${STATE.servers.filter(x => x.id !== s.id && (x.owner || '') === (s.owner || (isAdmin() ? '' : STATE.user))).map(x => `<option value="${x.id}"${s.via === x.id ? ' selected' : ''} data-notr>${esc(x.name)}</option>`).join('')}</select></label>
        </div></details>
      <div class="actions" style="justify-content:flex-end"><button type="button" class="btn ghost" id="cancel">Cancel</button><button class="btn pri">Save</button></div>
    </form>`, true);
  $('#cancel', m).onclick = () => m.remove();
  $('#srvf', m).onsubmit = oneAtATime($('#srvf', m), async (ev) => {
    const fd = Object.fromEntries(new FormData(ev.target));
    fd.sshPort = parseInt(fd.sshPort || '22', 10);
    if (s.id) fd.ID = s.id;
    try { const r = await api('/servers', fd); m.remove(); await loadAll(); renderView(); toast('Server saved'); if (s.onSaved) s.onSaved(r.id || s.id, fd.name); } catch (e) { alertModal('Error', e.message); }
  });
}

/* ---------------- tunnels ---------------- */
// Summary strip, then tunnels grouped by their Iran server.
function viewTunnels(w) {
  w.innerHTML = topbar('Tunnels', 'Each tunnel links one Iran server to one foreign server. Pick a connection method and switch any time.',
    `${isAdmin() ? '' : '<!--'}<button class="btn" id="aiTun" title="Claude reviews the tunnels, their paths, outages and the servers' load, and says what to improve">🧠 AI analysis</button><button class="btn" id="repairTun" title="Apply again every running tunnel that has a problem (down, dead hot-standby paths, an older switcher or Golden relay); servers that are down are left alone">🛠 Repair</button>${isAdmin() ? '' : '-->'}<button class="btn pri" id="addTun"${iranServers().length ? '' : ' disabled title="Add an Iran server first"'}>+ New tunnel</button>`);
  // everything on this page follows the View selector (an admin looking at one account sees
  // that account's numbers and chips, not the whole panel's)
  const mine = STATE.tunnels.filter(t => shownOwner(t.owner));
  const run = mine.filter(t => t.active).length;
  const hostShown = isAdmin() && (!STATE.ownerFilter || STATE.ownerFilter === '-'); // the panel host is the admin's
  w.appendChild(h(`<div class="summary">
    <div class="stat"><i class="si">🛰</i><small>Running tunnels</small><b><span class="ltr"><span class="cu" data-cu="${run}">0</span><span> / ${mine.length}</span></span> <span class="downtxt" data-sum-down></span></b></div>
    <div class="stat"><i class="si">⬇</i><small>Live download</small><b class="dn" data-sum-dn>—</b></div>
    <div class="stat"><i class="si">⬆</i><small>Live upload</small><b class="up" data-sum-up>—</b></div>
    <div class="stat"><i class="si">🖥</i><small>Servers</small><b>${iranServers().filter(s => shownOwner(s.owner)).length}<span> Iran · </span>${foreignServers().filter(s => shownOwner(s.owner)).length + (hostShown ? 1 : 0)}<span> foreign</span></b></div>
  </div>`));
  countUp(w);
  if (!mine.length) {
    w.appendChild(h(`<div class="card empty"><div class="big">🛰</div>${iranServers().length ? 'No tunnels yet — press <b>+ New tunnel</b>.' : 'Start on the <b>Servers</b> page: add an Iran server, then create a tunnel here.'}</div>`));
  }
  // like the Servers page: the tunnels listed by Iran server on the side, the picked one's card
  // beside it. Every card is built (hidden but the picked one) so the status checks, the live
  // traffic and the down count keep covering all of them.
  if (mine.length) {
    const list = mine.slice().sort(tunnelOrder);
    const groups = [];
    list.forEach(t => { let g = groups.find(x => x.id === t.serverId); if (!g) groups.push(g = { id: t.serverId, tunnels: [] }); g.tunnels.push(t); });
    groups.sort((x, y) => serverName(x.id).localeCompare(serverName(y.id)));
    let cur = STATE.tunSel && list.some(t => t.id === STATE.tunSel) ? STATE.tunSel : recall('tp-tun');
    if (!list.some(t => t.id === cur)) cur = list[0].id;
    const fl = (id, d) => { const s = id ? serverById(id) : null; return s && s.country ? flag(s.country) : d; };
    const row = (t) => `<button class="srow" data-pick="${t.id}">
      <span class="sflag">${fl(t.foreignId, t.foreignId ? '🌍' : '🖥')}</span>
      <span class="sinfo"><b data-notr>${esc(t.name)}</b><small>→ ${srvNm(t.foreignId, 'panel host')} · ${esc(methodTitle(t.active || t.selected) || '—')}</small></span>
      <span class="smeta"><span class="sbadges">${t.hotStandby ? '<span class="sbadge hs" title="hot standby">⚡</span>' : ''}<span class="sbadge fo" data-tfo="${t.id}" title="on a backup path"${t.failover ? '' : ' hidden'}>🔁</span><span class="led ${t.active ? (t._down || t.health ? 'bad' : 'on') : 'off'}" data-tled="${t.id}" title="${t.active ? 'running' : 'stopped'}"></span></span><small class="faint mono" data-lr="${t.id}"></small></span></button>`;
    const split = h(`<div class="srvsplit usplit">
      <aside class="card srvlist">
        <input class="sq" type="search" data-q placeholder="🔍 Search name, server, port, method…" value="${esc(STATE.tunSearch || '')}">
        <button class="fchip${STATE.tunRunning ? ' on' : ''}" data-run title="show only running tunnels">● Running <b>${run}</b></button>
        ${groups.map(g => `<div class="sgrp" data-g="${g.id}"><div class="sgh"><span>${fl(g.id, '🇮🇷')} ${srvNm(g.id)} <span class="count">${g.tunnels.length}</span></span></div>${g.tunnels.map(row).join('')}</div>`).join('')}
        <div class="faint sempty nomatch" hidden>No tunnel matches this search.</div>
      </aside>
      <div class="srvdetail tdet" data-detail></div>
    </div>`);
    const det = $('[data-detail]', split);
    list.forEach(t => det.appendChild(tunnelCard(t)));
    w.appendChild(split);
    const show = (id, scroll) => {
      cur = id; STATE.tunSel = id; remember('tp-tun', id);
      $$('.srow', split).forEach(r => r.classList.toggle('on', r.dataset.pick === id));
      $$('.tc', det).forEach(c => c.classList.toggle('sel', c.dataset.id === id));
      if (scroll && window.innerWidth <= 860) det.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
    // the search and Running filter the list in place (no redraw: the live traffic keeps running)
    const hay = (t) => [t.name, t.ports, serverName(t.serverId), serverName(t.foreignId), methodTitle(t.active || t.selected), groupOf(STATE.methods.find(x => x.id === (t.active || t.selected))), famName(t.family)].join(' ').toLowerCase();
    const applySearch = () => {
      const q = (STATE.tunSearch || '').trim().toLowerCase();
      let shown = 0;
      $$('.srow', split).forEach(r => {
        const t = STATE.tunnels.find(x => x.id === r.dataset.pick);
        const ok = !!t && (!q || hay(t).includes(q)) && (!STATE.tunRunning || t.active);
        r.hidden = !ok; if (ok) shown++;
      });
      $$('.sgrp', split).forEach(g => g.hidden = !$$('.srow', g).some(r => !r.hidden));
      $('.nomatch', split).hidden = !!shown;
    };
    $$('.srow', split).forEach(r => r.onclick = () => show(r.dataset.pick, true));
    $('[data-q]', split).oninput = (e) => { STATE.tunSearch = e.target.value; applySearch(); };
    $('[data-run]', split).onclick = (e) => { STATE.tunRunning = !STATE.tunRunning; e.currentTarget.classList.toggle('on', STATE.tunRunning); applySearch(); };
    applySearch();
    show(cur, false);
  }
  $('#addTun').onclick = () => { if (iranServers().length) tunnelModal(); };
  if ($('#aiTun')) $('#aiTun').onclick = () => aiModal();
  if ($('#repairTun')) $('#repairTun').onclick = async () => {
    try { const r = await api('/repair', {}); openLog({ id: 'repair', name: 'Repair' }, r.job); } catch (e) { alertModal('Repair', e.message); }
  };
}
// Compact card: who ⇄ who, state, live traffic and the three everyday buttons.
// Everything else (method, options, tests) lives in the Manage window.
function tunnelCard(t) {
  const avail = methodsFor(t.family);
  const active = STATE.methods.find(m => m.id === t.active);
  const selId = (t.selected && avail.find(m => m.id === t.selected)) ? t.selected : (t.active || avail[0]?.id || '');
  const selM = STATE.methods.find(m => m.id === selId);
  const ir = serverById(t.serverId), fg = t.foreignId ? serverById(t.foreignId) : null;
  const fl = (s, d) => s && s.country ? flag(s.country) : d;
  const miss = methodMissing(active || selM, t);
  // a hot-standby tunnel's users may be on another of its paths than the tunnel's own method
  // (it failed on this route, or the switcher moved them): the method chip shows what the users
  // are on — the same path the ⚡ chip names — and a failed own method says why it didn't start
  const mainFail = t.hotStandby && t.active ? (t.paths || []).find(p => p.method === t.active && p.family === t.family && p.failed) : null;
  const onKey = t.hotStandby && t.active && t.hs && t.hs.keys ? (t.hs.keys[t.hs.active] || '') : '';
  const onM = onKey && onKey !== t.active + '|' + t.family ? STATE.methods.find(m => m.id === onKey.split('|')[0]) : null;
  const shownM = onM || active || selM, shownFam = onM ? onKey.split('|')[1] : t.family;
  // what happens when the users' path fails: hot standby, the plain failover, or nothing
  const keep = t.hotStandby ? `<span class="tc-keep hs">⚡ <span>Hot standby</span> · <span>${t.hsAuto ? 'auto switching' : 'manual switching'}</span></span>`
    : t.noFailover ? '<span class="tc-keep off">Off: nothing switches.</span>' : '<span class="tc-keep">🔁 <span>Failover after 5 min down</span></span>';
  const chips = tcChips(t, mainFail, miss);
  const card = h(`<div class="card tc${t.active ? ' live' : ''}" data-id="${t.id}">
    <div class="tc-h"><div class="tc-t"><span class="sflag" aria-hidden="true">🛰</span><div class="tc-tn"><h3 title="${esc(t.name)}" data-notr>${esc(t.name)}</h3>${ownerChip(t.owner)}</div></div>${active ? `<span class="pill on"><span class="led"></span>running</span>` : `<span class="pill off"><span class="led"></span>stopped</span>`}</div>
    <div class="tc-r" title="${esc(serverName(t.serverId))} → ${esc(fg ? fg.name : 'this panel host')}">
      <span class="tc-end"><span class="ef">${fl(ir, '🇮🇷')}</span><span class="en"><small>Iran server</small><b class="nm">${srvNm(t.serverId)}</b></span><span class="sd" data-ir></span></span>
      <span class="ln${t.active ? ' on' : ''}"></span>
      <span class="tc-end r"><span class="sd" data-fg></span><span class="en"><small>Foreign server</small><b class="nm">${fg ? nm(fg.name) : 'panel host'}</b></span><span class="ef">${fl(fg, fg ? '🌍' : '🖥')}</span></span>
    </div>
    <dl class="kvt">
      <div><dt>Method</dt><dd title="${esc(groupOf(shownM) + ' · ' + (shownM?.title || ''))}">${shownM ? groupIcon(shownM) + ' ' : ''}<b>${esc(shownM?.title || '—')}</b></dd></div>
      <div><dt>IP</dt><dd>${famName(shownFam)}</dd></div>
      <div><dt>Ports</dt><dd><span class="mono">${esc(t.ports)}</span></dd></div>
      <div><dt>If it fails</dt><dd>${keep}</dd></div>
      ${t.note ? `<div class="wide"><dt>Note</dt><dd>${esc(t.note)}</dd></div>` : ''}
    </dl>
    <div class="tc-m">${chips}</div>
    ${t.active ? `<div class="traf" data-traf="${t.id}">
      <div class="rates"><span class="dn" title="foreign → Iran (download)">↓ <b data-rd>…</b></span><span class="up" title="Iran → foreign (upload)">↑ <b data-ru>…</b></span></div>
      <svg class="spark" viewBox="0 0 100 38" preserveAspectRatio="none" aria-hidden="true"><path class="ad"/><path class="pd"/><path class="pu"/></svg>
      <div class="meta"><span data-tot></span><span data-src></span></div><div class="meta" data-speed></div></div>`
      : `<div class="tc-idle">Not running${selM ? ` · selected: <b>${esc(selM.title)}</b>` : ''}</div>`}
    ${t.hotStandby && t.active ? `<div class="tc-hs"><div class="lbl">⚡ Hot standby paths</div><div data-hsl>${hsRows(t) || '<div class="faint">paths — reading which one the users are on…</div>'}</div></div>` : ''}
    <div class="tc-f">
      <button class="btn sm pri" data-manage>⚙ Manage</button>
      ${t.active ? `<button class="btn sm ghost" data-stop>■ Stop</button>` : `<button class="btn sm" data-start>▶ Start</button>`}
      <button class="btn sm ghost" data-log>Logs</button>
      <span class="grow"></span>
      ${moreMenu([
        t.active ? { label: '🚀 Speed test', attr: 'data-speedtest' } : null,
        t.active ? { label: '🩺 Diagnose', attr: 'data-diag' } : null,
        t.active ? { label: '🔎 Trace connections (30 s)', attr: 'data-trace' } : null,
        isAdmin() ? { label: '👤 Account…', attr: 'data-own' } : null,
        { label: '✎ Edit tunnel', attr: 'data-edit' },
        { label: '🗑 Delete tunnel', attr: 'data-del', danger: true }])}
    </div></div>`);
  // what was drawn, in English: healthWatch compares with this (the Persian page rewrites the DOM)
  $('.tc-m', card).dataset.was = chips;
  const on = (sel, fn) => { const el = $(sel, card); if (el) el.onclick = fn; };
  on('[data-manage]', () => manageTunnel(t));
  on('[data-start]', () => { if (!selM || miss) { manageTunnel(t); return; } applyMethod(t, selM.id, t.family); });
  on('[data-stop]', async () => { try { const r = await api('/tunnels/stop', { ID: t.id }); openLog(t, r.job); } catch (e) { alertModal('Error', e.message); } });
  on('[data-log]', () => openLog(t, null));
  on('[data-speedtest]', () => tunnelJob(t, '/tunnels/speedtest', 'Speed test'));
  on('[data-diag]', () => tunnelJob(t, '/tunnels/diagnose', 'Diagnose'));
  on('[data-trace]', () => tunnelJob(t, '/tunnels/trace', 'Trace — connect your client now'));
  on('[data-edit]', () => tunnelModal(t));
  on('[data-own]', () => ownerModal('tunnel', t.id));
  hsWire(t, card);
  on('[data-del]', async (e) => { if (!confirmInline(e.target, 'Click again to delete')) return; try { const r = await api('/tunnels/delete', { ID: t.id }); await loadAll(); renderView(); if (r.warning) alertModal('Deleted — with a warning', r.warning); } catch (er) { alertModal('Error', er.message); } });
  // the monitor's last verdict at once: a broken tunnel no longer shows green until its check returns
  if (t.active && t.health) paintDown(t, card, t.health);
  refreshStatus(t, card);
  return card;
}
// AI analysis: the last report, a button for a new one (1-3 min), and the safe actions it suggests
async function aiModal() {
  const m = modal(`<h2>🧠 AI analysis</h2><div data-ai><div class="muted">Loading…</div></div>`, true);
  const box = $('[data-ai]', m);
  const sev = { high: 'bad', medium: 'warn', low: '' };
  const paint = (r) => {
    if (!box.isConnected) return;
    const rep = r.report;
    const tname = (id) => (STATE.tunnels.find(t => t.id === id) || {}).name || id;
    const head = !r.hasKey ? `<div class="muted">Set the Claude API key in Settings first.</div>`
      : `<div class="actions" style="margin-bottom:10px"><button class="btn pri" data-airun${r.running ? ' disabled' : ''}>${r.running ? '⏳ Analysing… (1-3 min)' : rep ? '↻ Analyse again' : '▶ Analyse now'}</button>${rep ? `<span class="faint" style="font-size:12px">last: ${ago(rep.at)}${rep.inTokens ? ` · ${rep.inTokens + rep.outTokens} tokens` : ""}</span>` : ''}</div>`;
    let body = '';
    if (rep && rep.error) body = `<div class="downbar">⚠ ${esc(rep.error)}</div>`;
    else if (rep) {
      // the report itself is written in Persian by the model: it reads right to left whatever the
      // panel's language (data-notr), the panel's own labels follow the panel's language
      const ai = (t) => `<span data-notr dir="auto">${esc(t)}</span>`;
      body = `<div class="aireport">
        <p class="aisum">${ai(rep.summary)}</p>
        ${(rep.actions || []).length ? `<h3 class="aih">Suggested actions</h3>${rep.actions.map((a, i) => `<div class="card pad aicard"><b>${esc(tname(a.tunnel))}</b> — ${a.kind === 'switch_path' ? 'move the users to the path <span class="mono">' + esc(a.path) + '</span>' : 'switcher mode: ' + (a.auto ? 'automatic' : 'manual')}<div class="faint aiwhy">${ai(a.why)}</div><div style="margin-top:6px">${a.applied ? `<span class="chip">✓ ${esc(a.result || 'done')}</span>` : `<button class="btn sm pri" data-aiapply="${i}">Apply</button>`}</div></div>`).join('')}` : ''}
        ${(rep.findings || []).map(f => `<div class="card pad aicard"><div><span class="chip ${sev[f.severity] || ''}">${f.severity === 'high' ? 'High' : f.severity === 'medium' ? 'Medium' : 'Low'}</span> <b>${ai(f.title)}</b></div><div class="aitxt">${ai(f.detail)}</div>${f.fix ? `<div class="aitxt">🔧 ${ai(f.fix)}</div>` : ''}</div>`).join('')}
      </div>`;
    }
    box.innerHTML = head + body;
    const run = $('[data-airun]', box);
    if (run) run.onclick = async () => { try { await api('/ai/run', {}); load(); } catch (e) { alertModal('AI analysis', e.message); } };
    $$('[data-aiapply]', box).forEach(b => b.onclick = async () => {
      b.disabled = true;
      try { const x = await api('/ai/apply', { I: +b.dataset.aiapply }); toast(x.result || 'Applied'); load(); } catch (e) { b.disabled = false; alertModal('Could not apply', e.message); }
    });
    // one poll at a time while it runs (each Apply / Analyse press used to start another chain)
    clearTimeout(next); next = r.running ? setTimeout(load, 4000) : null;
  };
  let next = null;
  const load = () => api('/ai').then(paint).catch(e => { box.innerHTML = `<div class="downbar">⚠ ${esc(e.message)}</div>`; });
  load();
}
async function applyMethod(t, mid, fam) {
  try { const r = await api('/tunnels/apply', { ID: t.id, Method: mid, Family: fam || t.family }); openLog(t, r.job); return true; }
  catch (e) { busyOrError(t, e); return false; }
}
async function tunnelJob(t, path, label) {
  try { const r = await api(path, { ID: t.id }); openLog({ id: t.id, name: label + ' · ' + t.name }, r.job); } catch (e) { busyOrError(t, e); }
}
// the card's status chips: repainted by healthWatch when the users' path or a failover changes
function tcChips(t, mainFail, miss) {
  // each piece of a chip is its own text, so the Persian page translates it whole
  return `${mainFail ? `<span class="chip warn" title="${esc(mainFail.failed)} — tried again every hour">⚠ <b>${esc(methodTitle(t.active))}</b> <span>didn't start here</span></span>` : ''}${miss ? `<span class="chip warn" title="needs ${esc(miss)}">⚠ needs upload</span>` : ''}${t.clash ? `<span class="chip bad" title="${esc(t.clash)}">⚠ port clash</span>` : ''}${t.failover ? `<span class="chip fo" title="original ${esc(methodTitle(t.failover.method))} (${t.failover.family}) failed: ${esc(t.failover.reason || '')} — re-checked every hour">🔁 <span>on a backup path</span> · <span>original:</span> <b>${esc(methodTitle(t.failover.method))} ${famName(t.failover.family)}</b>${t.failover.since ? ` · <span>${ago(t.failover.since)}</span>` : ''}</span>` : ''}${t.hotStandby ? hsChip(t) : ''}`;
}
// hot standby: which path carries the users now, and how many work
function hsChip(t) {
  const v = t.hs;
  if (!v || !v.paths || !v.paths.length) return '<span class="chip hs" title="hot standby — starts on the next Start/Re-apply">⚡ standby</span>';
  const n = v.ok.filter(Boolean).length, cur = v.paths[v.active] || '—';
  return `<span class="chip hs${n ? (n < v.paths.length ? ' part' : '') : ' bad'}" title="${esc(v.paths.map((p, i) => (v.ok[i] ? '✓ ' : '✕ ') + p + (i === v.active ? ' ← users' : '') + (!v.ok[i] && v.why && v.why[i] ? ' — ' + v.why[i] : '')).join('\n'))}">⚡ <b class="ltr">${n}/${v.paths.length}</b> <span>paths working</span> · <span>users on</span> <b>${esc(cur)}</b>${v.since ? ` · <span>${ago(v.since)}</span>` : ''}</span>`;
}
function hsBox(t) {
  const v = t.hs;
  if (!t.hotStandby) return '';
  const auto = !!t.hsAuto;
  const seg = `<div class="seg" data-hsmode><button type="button" data-auto="0" class="${auto ? '' : 'on'}" title="${esc('Manual: ' + 'users stay on the chosen path and move only when it is down (3 failed checks). They come back after 60 s of stability — longer for a path that keeps dropping (doubled per drop in 30 min, up to 30 min). At most 3 planned moves an hour.')}">✋ Manual</button><button type="button" data-auto="1" class="${auto ? 'on' : ''}" title="${esc('Auto: ' + "Latency and loss are watched all the time, the speed of the users' path every 2 hours (2 MB). When it gets slow or lossy the best few paths are measured and users move to a clearly better one. No ping-pong: 10 min wait after a move, at most 3 planned moves an hour. Light on traffic: standby paths are checked every 10 s.")}">🤖 Auto · best path</button></div>
    <div class="faint" style="font-size:12px;margin:-4px 0 6px">${auto ? 'Moves users to a clearly better path when theirs gets slow or lossy.' : 'Users stay on the chosen path; they move only when it is down.'} <span title="${esc(auto ? "Latency and loss are watched all the time, the speed of the users' path every 2 hours (2 MB). When it gets slow or lossy the best few paths are measured and users move to a clearly better one. No ping-pong: 10 min wait after a move, at most 3 planned moves an hour. Light on traffic: standby paths are checked every 10 s." : 'users stay on the chosen path and move only when it is down (3 failed checks). They come back after 60 s of stability — longer for a path that keeps dropping (doubled per drop in 30 min, up to 30 min). At most 3 planned moves an hour.')}" style="cursor:help">ⓘ</span></div>`;
  if (!v || !v.paths) return `<div class="lbl">⚡ Hot standby</div>${seg}<div class="faint" style="font-size:12px">every compatible path starts on the next Start/Re-apply.</div>`;
  return `<div class="lbl">⚡ Hot standby paths <span class="faint">(switcher order; the users' path is checked every 2 s on the Iran server)</span></div>${seg}${hsRows(t)}
    <div class="faint" style="font-size:11.5px;margin-top:4px" title="New connections take the new path; open ones finish on the old one (it keeps running). Only a path that died has its connections reset, so clients reconnect at once.">Switching is seamless — nobody is cut. ⓘ</div>`;
}
// the hot-standby paths, switcher order: works or not, quality, the users' one and a "use" button
function hsRows(t) {
  const v = t.hs;
  if (!v || !v.paths || !v.paths.length) return '';
  const ok = v.ok || []; // a switcher state read only in part has no ok list
  const q = (i) => {
    const out = [];
    if (!ok[i]) {
      // a ✕ says why: down since when, and what its core said (or that it runs but nothing
      // answers through it) — a bare ✕ read as a panel bug
      const since = v.changed && v.changed[i] > 0 ? `<span>down</span> · <span>${ago(v.changed[i])}</span>` : '<span>down</span>';
      const why = v.why && v.why[i] ? v.why[i] : "the switcher's check through this path gets no answer";
      return `<span class="hq">${since}</span><span class="hw" title="${esc(why)}">${esc(why)}</span>`;
    }
    if (v.rtt && v.rtt[i] >= 0) out.push(v.rtt[i] + ' ms');
    if (v.loss && v.loss[i] >= 0) out.push(v.loss[i].toFixed(1) + '% loss');
    if (v.kbps && v.kbps[i] > 0) out.push((v.kbps[i] / 1000).toFixed(1) + ' Mbps');
    return out.length ? `<span class="hq mono">${out.join(' · ')}</span>` : '';
  };
  return `<div class="hsl">${v.paths.map((p, i) =>
    `<div class="${ok[i] ? 'ok' : 'bad'}${i === v.active ? ' cur' : ''}"><span class="hi">${ok[i] ? '✓' : '✕'}</span><span class="hm"><span class="hn">${esc(p)}${i === v.pin ? ' <span class="faint">📌 chosen</span>' : ''}</span>${q(i)}</span>${i === v.active ? '<b class="hu">← users</b>' : (ok[i] && v.keys ? `<button type="button" class="btn sm ghost" data-hspin="${esc(v.keys[i])}" title="move the users here now — open connections finish where they are, nobody is cut">use</button>` : '')}</div>`).join('')}</div>`;
}
function hsWire(t, m) {
  $$('[data-hspin]', m).forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { const r = await api('/tunnels/hspin', { ID: t.id, Path: b.dataset.hspin }); toast(r.ok); await loadAll(); renderView(); }
    catch (e) { alertModal('Switch path', e.message); b.disabled = false; }
  });
  $$('[data-hsmode] button', m).forEach(b => b.onclick = async () => {
    const auto = b.dataset.auto === '1';
    try { const r = await api('/tunnels/hsmode', { ID: t.id, Auto: auto }); t.hsAuto = auto; toast(r.ok || 'saved'); await loadAll(); renderView(); }
    catch (e) { alertModal('Hot standby mode', e.message); }
    $$('[data-hsmode] button', m).forEach(x => x.classList.toggle('on', (x.dataset.auto === '1') === auto));
  });
}
// every method over every address family both servers of the tunnel have
const famName = (f) => f === 'v6' ? 'IPv6' : 'IPv4';
function routeChoices(t) {
  const fams = (t.families && t.families.length) ? t.families : [t.family];
  const out = [];
  fams.forEach(f => STATE.methods.forEach(m => { if (m.families.includes(f)) out.push({ m, fam: f }); }));
  return out;
}
// The full controls for one tunnel: method + address family, options, start/switch/stop and tests.
function manageTunnel(t) {
  const choices = routeChoices(t);
  const fams = ['v4', 'v6'].filter(f => choices.some(c => c.fam === f));
  const selId = t.selected || t.active || choices[0]?.m.id || '';
  const sel = choices.find(c => c.m.id === selId && c.fam === t.family) ? `${selId}|${t.family}` : (choices[0] ? `${choices[0].m.id}|${choices[0].fam}` : '');
  const active = STATE.methods.find(m => m.id === t.active);
  const ir = serverById(t.serverId), fg = t.foreignId ? serverById(t.foreignId) : null;
  const m = modal(`<div class="mg">
    <div class="mg-h"><div><h2 style="margin:0" data-notr>${esc(t.name)}</h2><div class="faint" style="font-size:12.5px">${(ir && ir.country) ? flag(ir.country) : '🇮🇷'} ${srvNm(t.serverId)} → ${fg && fg.country ? flag(fg.country) : (fg ? '🌍' : '🖥')} ${fg ? nm(fg.name) : 'this panel host'} · ports <span class="mono">${esc(t.ports)}</span></div></div>
      ${active ? `<span class="pill on"><span class="led"></span>${esc(active.title)}</span>` : `<span class="pill off"><span class="led"></span>stopped</span>`}</div>
    ${t.clash ? `<div class="mwarn">⚠ ${esc(t.clash)}</div>` : ''}
    <div class="lbl">Connection method · address family</div>
    ${fams.length > 1 ? `<div class="seg" data-fams>${fams.map(f => `<button type="button" data-f="${f}">${famName(f)}${f === t.family && t.active ? ' · now' : ''}</button>`).join('')}</div>` : ''}
    <div class="method-row"><select data-method></select><button class="btn sm" data-opts>⚙ Options</button></div>
    ${fams.length < 2 ? `<div class="faint" style="font-size:12px">Only ${famName(fams[0] || t.family)} is available on this route — ${famName((fams[0] || t.family) === 'v4' ? 'v6' : 'v4')} needs a public address on both servers (add it on the Servers page, or run Test connection to detect it).</div>` : ''}
    ${hsBox(t)}
    <div class="mdesc" data-desc></div>
    <div class="mwarn" data-warn hidden></div>
    <div data-optbox hidden></div>
    <div class="actions"><button class="btn pri" data-apply></button>${t.active ? '<button class="btn" data-stop>■ Stop</button>' : ''}<span class="grow"></span>
      ${t.active ? '<button class="btn ghost" data-speedtest>🚀 Speed test</button><button class="btn ghost" data-diag>🩺 Diagnose</button><button class="btn ghost" data-trace title="Watch 30 s while you connect your client (e.g. Xray) and see where it stops">🔎 Trace</button>' : ''}<button class="btn ghost" data-editt>✎ Edit tunnel</button><button class="btn ghost" data-x>Close</button></div>
  </div>`, true);
  const selEl = $('[data-method]', m), descEl = $('[data-desc]', m), warnEl = $('[data-warn]', m), optBox = $('[data-optbox]', m), applyBtn = $('[data-apply]', m);
  const pick = () => { const [mid, fam] = selEl.value.split('|'); return { mid, fam, x: STATE.methods.find(y => y.id === mid) }; };
  // the family switch fills the list with that family's methods (keeping the method when it exists there too)
  const fill = (fam, want) => {
    selEl.innerHTML = groupedOptions(choices.filter(c => c.fam === fam).map(c => c.m), x => { const v = `${x.id}|${fam}`; return `<option value="${v}"${x.id === want ? ' selected' : ''}>${esc(x.title)} · ${esc(x.encrypt)}${methodMissing(x, t) ? ' ⚠ core missing' : ''}${x.id === t.active && fam === t.family ? ' ✓ running' : ''}</option>`; });
    $$('[data-fams] button', m).forEach(b => b.classList.toggle('on', b.dataset.f === fam));
  };
  fill(sel.split('|')[1] || t.family, sel.split('|')[0]);
  $$('[data-fams] button', m).forEach(b => b.onclick = () => { fill(b.dataset.f, pick().mid); optBox.hidden = true; refresh(); });
  hsWire(t, m);
  const refresh = () => {
    const { mid, fam, x } = pick(); descEl.textContent = x ? x.desc : '';
    const miss = methodMissing(x, t);
    warnEl.hidden = !miss;
    if (miss) {
      warnEl.textContent = '⚠ ' + miss;
    }
    applyBtn.textContent = (t.active === mid && t.family === fam) ? '↻ Re-apply' : (t.active ? `⇄ Switch to this (${famName(fam)})` : `▶ Start (${famName(fam)})`);
  };
  selEl.onchange = () => { optBox.hidden = true; refresh(); saveTunnel(t, { selected: pick().mid }); };
  refresh();
  $('[data-opts]', m).onclick = () => { if (!optBox.hidden) { optBox.hidden = true; return; } renderOpts(optBox, t, pick().mid); optBox.hidden = false; };
  applyBtn.onclick = async () => { applyBtn.disabled = true; const { mid, fam } = pick(); if (await applyMethod(t, mid, fam)) m.remove(); else applyBtn.disabled = false; };
  const on = (sel, fn) => { const el = $(sel, m); if (el) el.onclick = fn; };
  on('[data-stop]', async () => { try { const r = await api('/tunnels/stop', { ID: t.id }); m.remove(); openLog(t, r.job); } catch (e) { alertModal('Error', e.message); } });
  on('[data-speedtest]', () => { m.remove(); tunnelJob(t, '/tunnels/speedtest', 'Speed test'); });
  on('[data-diag]', () => { m.remove(); tunnelJob(t, '/tunnels/diagnose', 'Diagnose'); });
  on('[data-trace]', () => { m.remove(); tunnelJob(t, '/tunnels/trace', 'Trace — connect your client now'); });
  on('[data-editt]', () => { m.remove(); tunnelModal(t); });
  on('[data-x]', () => m.remove());
}
// A tunnel runs one job at a time. When another one is still going, offer to watch or cancel it.
function busyOrError(t, e) {
  const mm = /another job \(([0-9a-f]+)\)/.exec(e.message || '');
  if (!mm) { alertModal('Error', e.message); return; }
  // the sentence apart from the name and the job id, so the Persian page translates it whole
  const m = modal(`<h2>A job is still running</h2><p class="muted"><span>Another job is still running on</span> <b data-notr>${esc(t.name)}</b> <span class="mono">(${esc(mm[1])})</span>.</p><p class="muted">Watch it, or cancel it to free the tunnel. Stop always works — it cancels the running job first.</p>
    <div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn ghost" data-x>Close</button><button class="btn" data-w>Show its log</button><button class="btn danger" data-c>Cancel the job</button></div>`);
  $('[data-x]', m).onclick = () => m.remove();
  $('[data-w]', m).onclick = () => { m.remove(); openLog(t, mm[1]); };
  $('[data-c]', m).onclick = async () => { try { await api('/jobs/cancel', { ID: mm[1] }); m.remove(); toast('Cancelled — you can run it again now'); } catch (er) { alertModal('Cancel', er.message); } };
}
// Live health: both units active and the tunnel link up → green; anything else → red card.
async function refreshStatus(t, card) {
  const paint = (el, v) => { if (!el) return; el.className = 'sd ' + (v === 'active' ? 'ok' : (!v || v === 'stopped' || v === '—') ? '' : 'bad'); el.title = v || 'not running'; };
  if (!t.active) { paint($('[data-ir]', card), ''); paint($('[data-fg]', card), ''); return; }
  if (card._busy) return;
  card._busy = true;
  try {
    const r = await api('/tunnels/status?id=' + t.id);
    paint($('[data-ir]', card), r.iran); paint($('[data-fg]', card), r.foreign);
    const why = r.iran !== 'active' ? `Iran service: ${r.iran}` : r.foreign !== 'active' ? `foreign service: ${r.foreign}` : r.link === 'down' ? 'tunnel link is down — no traffic between the servers' : '';
    paintDown(t, card, why);
  } catch (e) {} finally { card._busy = false; }
}
// a running tunnel's down pill and bar (why = "" → running)
function paintDown(t, card, why) {
    card.classList.toggle('down', !!why);
    const pill = $('.tc-h .pill', card);
    if (pill) pill.outerHTML = why ? `<span class="pill bad" title="${esc(why)}"><span class="led"></span>down</span>` : `<span class="pill on"><span class="led"></span>running</span>`;
    let bar = $('.downbar', card);
    if (why && !bar) { bar = h(`<div class="downbar"></div>`); $('.tc-r', card).after(bar); }
    if (bar) { if (why) bar.innerHTML = `⚠ ${esc(why)} <a href="#" data-dg>Diagnose</a>`; else bar.remove(); }
    const dg = $('[data-dg]', card); if (dg) dg.onclick = (e) => { e.preventDefault(); tunnelJob(t, '/tunnels/diagnose', 'Diagnose'); };
    t._down = !!why;
    const led = $(`[data-tled="${t.id}"]`); if (led) led.className = 'led ' + (why ? 'bad' : 'on');
    const n = STATE.tunnels.filter(x => x._down && shownOwner(x.owner)).length, el = $('[data-sum-down]');
    if (el) { el.textContent = n ? `· ${n} down` : ''; }
}
let healthTimer = null;
function healthWatch() {
  if (healthTimer) clearInterval(healthTimer);
  healthTimer = null;
  if (STATE.view !== 'tunnels') return;
  healthTimer = setInterval(() => {
    if (STATE.view !== 'tunnels') { clearInterval(healthTimer); healthTimer = null; return; }
    if (document.hidden) return;
    $$('.tc.live').forEach(card => { if (card.hidden) return; const t = STATE.tunnels.find(x => x.id === card.dataset.id); if (t) refreshStatus(t, card); });
    // which path the users are on and any failover: one list call repaints every card's chips
    api('/tunnels').then(list => {
      if (STATE.view !== 'tunnels') return;
      let moved = false;
      (Array.isArray(list) ? list : []).forEach(n => {
        const t = STATE.tunnels.find(x => x.id === n.id), card = t && $(`.tc[data-id="${n.id}"]`);
        if (!t || !card) return;
        // started or stopped elsewhere (another browser, the bot, a job whose log was closed): the
        // card is drawn again — running and stopped cards differ in more than the chips
        if ((t.active || '') !== (n.active || '')) {
          Object.assign(t, { active: n.active, paths: n.paths, hs: n.hs, failover: n.failover, health: n.health, clash: n.clash });
          if (!t.active) t._down = false;
          const nc = tunnelCard(t);
          nc.classList.toggle('sel', card.classList.contains('sel'));
          card.replaceWith(nc);
          const led = $(`[data-tled="${n.id}"]`); if (led) { led.className = 'led ' + (t.active ? (t.health ? 'bad' : 'on') : 'off'); led.title = t.active ? 'running' : 'stopped'; }
          moved = true;
          return;
        }
        Object.assign(t, { hs: n.hs, failover: n.failover, health: n.health, clash: n.clash });
        const m = $('.tc-m', card);
        if (m) {
          const mainFail = t.hotStandby && t.active ? (t.paths || []).find(p => p.method === t.active && p.family === t.family && p.failed) : null;
          const html = tcChips(t, mainFail, methodMissing(STATE.methods.find(x => x.id === t.active), t));
          // compared with what was drawn, not with the DOM: the Persian page translated the DOM, so
          // it never matched and every card's chips were rewritten each round
          if (m.dataset.was !== html) { m.dataset.was = html; m.innerHTML = html; }
        }
        const hl = $('[data-hsl]', card), rows = hl && hsRows(t);
        if (rows && hl.dataset.was !== rows) { hl.dataset.was = rows; hl.innerHTML = rows; hsWire(t, hl); }
        const fo = $(`[data-tfo="${n.id}"]`); if (fo) fo.hidden = !t.failover;
      });
      if (moved) { // the counts that follow which tunnels run
        const mine = STATE.tunnels.filter(x => shownOwner(x.owner)), cu = $('[data-cu]');
        if (cu) cu.textContent = mine.filter(x => x.active).length;
        const nd = mine.filter(x => x._down).length, sd = $('[data-sum-down]'); if (sd) sd.textContent = nd ? `· ${nd} down` : '';
        paintSide();
      }
    }).catch(() => {});
  }, 15000);
}
// The save endpoint replaces the editable fields, so every save sends all of them
// (sending a partial tunnel used to wipe its traffic-shaping settings).
const tunnelBody = (t, patch) => ({ ID: t.id, name: t.name, serverId: t.serverId, foreignId: t.foreignId, family: t.family,
  ports: t.ports, note: t.note, shape: t.shape || {}, noFailover: !!t.noFailover, hotStandby: !!t.hotStandby, hsAuto: !!t.hsAuto, selected: t.selected || '', ...patch });
async function saveTunnel(t, patch) {
  let r;
  try { r = await api('/tunnels/save', tunnelBody(t, patch)); Object.assign(t, patch); } catch (e) { toast(e.message); return; }
  // a save the server answers with a rebuild of the running tunnel (or a warning) is never silent
  if (r && r.job) openLog(t, r.job);
  else if (r && r.warn) toast(r.warn);
}
function renderOpts(box, t, mid) {
  const m = STATE.methods.find(x => x.id === mid);
  if (!m || !m.fields?.length) { box.innerHTML = `<div class="opts one"><div class="muted">No options for this method.</div></div>`; return; }
  const saved = (t.options && t.options[mid]) || {};
  const field = (f) => {
    const v = saved[f.key] !== undefined ? saved[f.key] : f.default;
    const help = f.help ? `<small class="fhelp">${esc(f.help)}</small>` : '';
    if (f.type === 'bool') return `<label class="row f" style="grid-column:1/-1"><input type="checkbox" data-k="${f.key}"${String(v) === 'true' ? ' checked' : ''}> ${esc(f.label)}${help}</label>`;
    if (f.type === 'select') return `<label class="f">${esc(f.label)}<select data-k="${f.key}">${f.options.map(o => `<option value="${esc(o)}"${o === v ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>${help}</label>`;
    return `<label class="f">${esc(f.label)}<input data-k="${f.key}" class="mono" value="${esc(v)}"${f.type === 'number' ? ` inputmode="numeric" placeholder="${esc(f.default || 'auto')}"` : ''}>${help}</label>`;
  };
  const basic = m.fields.filter(f => !f.advanced), adv = m.fields.filter(f => f.advanced);
  box.innerHTML = `<div class="opts${basic.length < 2 ? ' one' : ''}">${basic.map(field).join('')}
    ${adv.length ? `<details class="advopts" style="grid-column:1/-1"><summary>🎛 Advanced tuning <span class="faint">(${adv.length}) — the defaults are what this method always used</span></summary><div class="opts inner">${adv.map(field).join('')}</div></details>` : ''}
    <div style="grid-column:1/-1;display:flex;justify-content:flex-end;gap:8px"><button class="btn sm ghost" data-reset title="back to the method's defaults (saved when you press Save)">↺ Defaults</button><button class="btn sm pri" data-save>Save options</button></div></div>`;
  $('[data-reset]', box).onclick = () => m.fields.forEach(f => { const el = $(`[data-k="${f.key}"]`, box); if (!el) return; if (el.type === 'checkbox') el.checked = String(f.default) === 'true'; else el.value = f.default; });
  $('[data-save]', box).onclick = async () => {
    const opts = {}; $$('[data-k]', box).forEach(el => opts[el.dataset.k] = el.type === 'checkbox' ? String(el.checked) : el.value);
    try { await api('/tunnels/save', tunnelBody(t, { options: { [mid]: opts } })); await loadAll(); renderView(); toast('Options saved — Re-apply the tunnel to use them'); } catch (e) { alertModal('Error', e.message); }
  };
}
function tunnelModal(t) {
  t = t || {};
  const sh = t.shape || {};
  const foreignOpts = panelHostOpt() + sharedOpts('foreign', t.foreignId) + foreignServers().map(s => `<option value="${s.id}"${t.foreignId === s.id ? ' selected' : ''} data-notr>${esc(serverLabel(s))}</option>`).join('');
  const m = modal(`<h2>${t.id ? 'Edit tunnel' : 'New tunnel'}</h2>
    <form class="ff tform" id="tf">
      <div class="two">
        <label class="f">Name<input name="name" value="${esc(t.name || '')}" required></label>
        <label class="f">Note<input name="note" value="${esc(t.note || '')}"></label>
      </div>
      ${isAdmin() && !t.id && (STATE.users || []).length > 1 ? `<label class="f">Account <span class="faint">(who sees and runs it — use that account's servers)</span><select name="owner"><option value="">me (admin)</option>${STATE.users.filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}"${STATE.ownerFilter === u.username ? ' selected' : ''} data-notr>${esc(u.username)}</option>`).join('')}</select></label>` : ''}
      <div class="tsec">
        <div class="lbl">Route</div>
        <div class="troute">
          <label class="f">Iran server<select name="serverId" required>${sharedOpts('iran', t.serverId)}${iranServers().map(s => `<option value="${s.id}"${s.id === t.serverId ? ' selected' : ''} data-notr>${esc(serverLabel(s))}</option>`).join('')}</select></label>
          <span class="tarrow" aria-hidden="true">→</span>
          <label class="f">Foreign server<select name="foreignId">${foreignOpts}</select></label>
        </div>
        <div class="two">
          <label class="f">Address family<select name="family"><option value="v4"${t.family === 'v6' ? '' : ' selected'}>IPv4 underlay</option><option value="v6"${t.family === 'v6' ? ' selected' : ''}>IPv6 underlay</option></select></label>
          <label class="f">Ports<input name="ports" class="mono" value="${esc(t.ports || '443')}" placeholder="443,8080=80,2000-2010"><small class="fhelp">e.g. <bdi class="mono">443,8080=80,2000-2010</bdi></small></label>
        </div>
        <div class="faint tnote">Users hit the Iran server on these ports; traffic is forwarded to the foreign server over the tunnel.</div>
      </div>
      <div class="set1"><div><b>⚡ Keep users connected</b><small class="fhelp" id="tModeHelp"></small></div>
        <label class="sw1"><input type="checkbox" id="tAuto"${t.hotStandby ? ' checked' : ''}><i></i></label></div>
      <div id="tPaths" class="tpaths"></div>
      <details class="tshape"${sh.enabled ? ' open' : ''}><summary>Traffic shaping / link tuning</summary>
        <div class="ff">
          <label class="row f"><input type="checkbox" id="shEnabled"${sh.enabled ? ' checked' : ''}> Enable shaping on the Iran egress (CAKE/HTB/… qdisc)</label>
          <div class="two">
            <label class="f">Queue discipline<select id="shQdisc">${['cake', 'htb', 'tbf', 'fq_codel'].map(q => `<option value="${q}"${sh.qdisc === q ? ' selected' : ''}>${q}</option>`).join('')}</select></label>
            <label class="f">MSS clamp <span class="faint">(0 = off)</span><input id="shMss" type="number" class="mono" value="${sh.mss || 0}"></label>
          </div>
          <label class="f">Egress interface <span class="faint">(blank = default route)</span><input id="shIface" class="mono" value="${esc(sh.iface || '')}"></label>
          <label class="row f"><input type="checkbox" id="shJitter"${sh.jitter ? ' checked' : ''}> Add timing jitter (netem)</label>
          <label class="row f"><input type="checkbox" id="shBoth"${sh.onBoth ? ' checked' : ''}> Also shape the foreign egress</label>
          <div class="faint" style="font-size:12px">Applied as a separate systemd unit after the tunnel starts. Change takes effect on the next Start/Switch.</div>
        </div></details>
      <div class="actions tmfoot"><button type="button" class="btn ghost" id="cancel">Cancel</button><button class="btn pri">Save</button></div>
    </form>`, true);
  $('#cancel', m).onclick = () => m.remove();
  // which methods hot standby keeps running on this pair of servers: the Routes page's switches
  // for the pair (off = left out), chosen here before the first Start
  let skipAll = null, pathsKey = '';
  const hasFam = (id, f) => { const s = id ? serverById(id) : null; const st = STATE.settings; return f === 'v4' ? !!(s ? s.ipv4 : st.localIPv4 || true) : !!(s ? s.ipv6 : st.localIPv6); };
  const pair = () => ({ iran: $('[name=serverId]', m).value, foreign: $('[name=foreignId]', m).value || '' });
  const paintPaths = () => {
    const box = $('#tPaths', m);
    // emptied: the next draw starts again from the saved switches (it read the empty box as
    // "everything off is nothing", so Save sent off=[] and turned skipped methods back on)
    if (!$('#tAuto', m).checked || !skipAll) { box.innerHTML = ''; pathsKey = ''; return; }
    const p = pair(), k = p.iran + '|' + p.foreign;
    if (sharedPair(p.iran, p.foreign)) {
      pathsKey = '';
      box.innerHTML = '<div class="faint" style="font-size:12.5px">Which methods this route keeps ready is set by the admin, who owns these servers.</div>';
      return;
    }
    const off = pathsKey === k ? $$('[data-path]', box).filter(c => !c.checked).map(c => c.dataset.path) : (skipAll[k] || []);
    pathsKey = k;
    const fams = ['v4', 'v6'].filter(f => hasFam(p.iran, f) && hasFam(p.foreign, f));
    const ms = STATE.methods.filter(x => x.id !== 'spoof' && fams.some(f => x.families.includes(f)));
    const cells = ms.flatMap(x => fams.filter(f => x.families.includes(f)).map(f => x.id + '|' + f));
    const on = cells.filter(c => !off.includes(c)).length;
    box.innerHTML = `<details open><summary class="muted" style="font-size:13px;cursor:pointer">Tunnels to build: <b data-pn>${on}</b> of ${cells.length} <span class="faint">— only the checked ones are installed and started on the servers, your pick (not the benchmark's); the method you Start with always runs</span></summary>
      <div style="margin-top:8px;padding:10px 12px;background:var(--panel-2);border-radius:10px">
        <div class="actions" style="margin-bottom:6px"><button type="button" class="btn sm ghost" data-pall="1">All</button><button type="button" class="btn sm ghost" data-pall="0">None</button></div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:4px 12px;font-size:13px">${ms.map(x => fams.filter(f => x.families.includes(f)).map(f => `<label class="row"><input type="checkbox" data-path="${esc(x.id)}|${f}"${off.includes(x.id + '|' + f) ? '' : ' checked'}> ${esc(x.title)} <span class="faint">${famName(f)}</span></label>`).join('')).join('')}</div>
        <div class="faint" style="font-size:12px;margin-top:6px">Saved for this pair of servers (the Routes page shows the same switches).</div></div></details>`;
    const count = () => { $('[data-pn]', box).textContent = $$('[data-path]', box).filter(c => c.checked).length; };
    $$('[data-path]', box).forEach(c => c.onchange = count);
    $$('[data-pall]', box).forEach(b => b.onclick = () => { $$('[data-path]', box).forEach(c => c.checked = b.dataset.pall === '1'); count(); });
  };
  api('/routes/skip').then(r => { skipAll = r || {}; paintPaths(); }).catch(() => {});
  // one switch: on = hot standby (every path running, users moved within seconds; new tunnels also
  // move to a clearly faster path), off = the plain failover after 5 min down
  // two texts (the Persian page translates each whole)
  const paintMode = () => { $('#tModeHelp', m).innerHTML = '<span>' + ($('#tAuto', m).checked
    ? 'On: backup paths stay running and users move to a working one within seconds when theirs fails — or to a clearly faster one.'
    : (t.noFailover ? 'Off: nothing switches.' : 'Off: after 5 min down the tunnel switches to a working method, and goes back when the original works.')) + '</span>'
    // a running tunnel is rebuilt on Save when the switch no longer matches what runs on the servers
    + (t.active && $('#tAuto', m).checked !== ((t.paths || []).length > 0) ? ' <span class="twarn">Saving rebuilds the running tunnel now — its users drop for about a minute.</span>' : '');
    paintPaths(); };
  $('#tAuto', m).onchange = paintMode;
  paintMode();
  $('[name=serverId]', m).addEventListener('change', paintPaths);
  $('[name=foreignId]', m).addEventListener('change', paintPaths);
  $('#tf', m).onsubmit = oneAtATime($('#tf', m), async (ev) => {
    const fd = Object.fromEntries(new FormData(ev.target));
    const picks = $$('[data-path]', m);
    if ($('#tAuto', m).checked && picks.length) {
      const p = pair(), offNow = picks.filter(c => !c.checked).map(c => c.dataset.path);
      const before = (skipAll[p.iran + '|' + p.foreign] || []).slice().sort().join(','), after = offNow.slice().sort().join(',');
      if (before !== after) { try { await api('/routes/skip', { iran: p.iran, foreign: p.foreign, off: offNow }); } catch (e) { alertModal('Error', e.message); return; } }
    }
    if (t.id) fd.ID = t.id;
    fd.noFailover = !!t.noFailover;
    fd.hotStandby = $('#tAuto', m).checked;
    fd.hsAuto = fd.hotStandby && (t.hotStandby ? !!t.hsAuto : true); // manual/auto stays switchable in the tunnel's window
    if (t.selected) fd.selected = t.selected;
    fd.shape = {
      enabled: $('#shEnabled', m).checked, qdisc: $('#shQdisc', m).value,
      mss: parseInt($('#shMss', m).value || '0', 10), iface: $('#shIface', m).value.trim(),
      jitter: $('#shJitter', m).checked, onBoth: $('#shBoth', m).checked,
    };
    try {
      const r = await api('/tunnels/save', fd); m.remove(); await loadAll(); renderView();
      // switching "Keep users connected" on a running tunnel rebuilds it on the servers
      if (r.job) openLog(STATE.tunnels.find(x => x.id === r.id) || t, r.job);
      else if (r.warn) alertModal('Saved', r.warn);
      else toast('Tunnel saved');
    } catch (e) { alertModal('Error', e.message); }
  });
}

/* ---------------- benchmark ---------------- */
// The benchmark runs on the server; the page only watches it. benchWatch survives
// navigation, and /bench/active lets a fresh page (or reload) re-attach to a running job.
let benchTimer = null;
function viewBench(w) {
  w.innerHTML = topbar('Route benchmark', 'Measure the tunnels running between two servers (or every method) and compare them.');
  const card = h(`<div class="grid" style="gap:16px">
    <form class="card pad ff" id="bf" style="max-width:640px">
      <div class="two">
        <label class="f">Iran server<select name="iran">${[...iranServers(), ...(STATE.shared || []).filter(s => (s.role || 'iran') === 'iran')].map(s => `<option value="${s.id}"${s.shared ? '' : ' data-notr'}>${esc(serverLabel(s))}${s.shared ? ' · shared' : ''}</option>`).join('')}</select></label>
        <label class="f">Foreign server<select name="foreign">${panelHostOpt()}${[...foreignServers(), ...(STATE.shared || []).filter(s => s.role === 'foreign')].map(s => `<option value="${s.id}"${s.shared ? '' : ' data-notr'}>${esc(serverLabel(s))}${s.shared ? ' · shared' : ''}</option>`).join('')}</select></label>
      </div>
      <div class="two">
        <label class="f">Family<select name="family"><option value="v4">IPv4</option><option value="v6">IPv6</option></select></label>
        <label class="f">Throughput probe (s)<input name="seconds" type="number" class="mono" value="5"></label>
      </div>
      <label class="f">Methods<select name="scope"><option value="running">Only the ones running on this route (every method if none runs)</option><option value="all">All methods</option></select></label>
      <div class="faint" style="font-size:12px">Each method is deployed on a temporary tunnel, measured, then removed. It runs on the server — you can leave this page and come back.</div>
      <div style="display:flex;gap:8px"><button class="btn pri" id="brun">Run benchmark</button><button type="button" class="btn danger" id="bcancel" hidden>■ Cancel</button></div>
    </form>
    <div id="blogcard"></div><div id="bres"></div><div id="bhist"></div></div>`);
  w.appendChild(card);
  const form = $('#bf');
  const cur = () => { const fd = Object.fromEntries(new FormData(form)); return { iran: fd.iran, foreign: fd.foreign || '', family: fd.family }; };
  form.onchange = () => { if (!benchTimer) showBenchResults(cur()); };
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(form));
    try { const r = await api('/bench/start', { iranId: fd.iran, foreignId: fd.foreign, family: fd.family, running: fd.scope !== 'all', seconds: parseInt(fd.seconds || '5', 10) }); benchWatch(r.job, cur()); }
    catch (e) { alertModal('Error', e.message); }
  };
  loadBenchHistory();
  // re-attach to a running benchmark, else show the stored results of the selected route
  api('/bench/active').then(a => {
    const q = (a && a.req) || {};
    // a running benchmark always re-attaches; a finished one only for the route on screen
    const same = q.iranId === cur().iran;
    if (a && a.job && (a.running || same)) {
      if (q.iranId) form.iran.value = q.iranId;
      form.foreign.value = q.foreignId || '';
      if (q.family) form.family.value = q.family;
      benchWatch(a.job, { iran: q.iranId, foreign: q.foreignId || '', family: q.family || 'v4' });
    } else showBenchResults(cur());
  }).catch(() => showBenchResults(cur()));
}
// History: which Iran server was tested against which foreign server, when, and the winner.
async function loadBenchHistory() {
  let hs = [];
  try { hs = await api('/bench/history'); } catch (e) {}
  const box = $('#bhist');
  if (!box) return;
  if (!hs.length) { box.innerHTML = ''; return; }
  const fl = (id, d) => { const s = serverById(id); return s && s.country ? flag(s.country) : d; };
  const rows = hs.map((r, i) => {
    const best = (r.results || []).find(x => x.recommended);
    const ok = (r.results || []).filter(x => x.ok).length;
    const dt = new Date(r.at * 1000);
    return `<tr><td class="mono" style="white-space:nowrap">${dt.toLocaleDateString()} ${dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
      <td>${fl(r.iranId, '🇮🇷')} ${nm(r.iranName)} <span class="faint">→</span> ${fl(r.foreignId, r.foreignId ? '🌍' : '🖥')} ${r.foreignId ? nm(r.foreignName) : esc(r.foreignName)}</td>
      <td>${r.family === 'v6' ? 'IPv6' : 'IPv4'}</td>
      <td>${best ? `<b>${esc(best.title)}</b> <span class="faint">↓${best.downMbps.toFixed(0)} ↑${best.upMbps.toFixed(0)} Mbps · ${best.rttMs.toFixed(0)} ms</span>` : '<span class="faint">no method worked</span>'}</td>
      <td class="faint">${ok}/${(r.results || []).length} ok</td>
      <td><button class="btn sm" data-hv="${i}">View</button></td></tr>`;
  }).join('');
  box.innerHTML = `<div class="card pad"><div style="display:flex;justify-content:space-between;align-items:center"><h3>History</h3>${isAdmin() ? '<button class="btn sm ghost danger" id="bhclear">Clear history</button>' : ''}</div>
    <div style="overflow-x:auto"><table class="tbl"><thead><tr><th>when</th><th>route</th><th>family</th><th>best</th><th>methods</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  $$('[data-hv]', box).forEach(b => b.onclick = () => {
    const r = hs[+b.dataset.hv];
    renderBenchTable(r.results || [], { iran: r.iranId, foreign: r.foreignId, family: r.family },
      `${nm(r.iranName)} → ${r.foreignId ? nm(r.foreignName) : esc(r.foreignName)} · ${r.family} · ${new Date(r.at * 1000).toLocaleString()}`);
    $('#bres').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  // only the admin may clear it (the server refuses others); an error is said, not swallowed
  if ($('#bhclear', box)) $('#bhclear', box).onclick = async (e) => { if (!confirmInline(e.target, 'Click again to clear')) return; try { await api('/bench/history', { Clear: true }); loadBenchHistory(); } catch (er) { alertModal('Error', er.message); } };
}
function benchWatch(job, fd) {
  if (benchTimer) clearInterval(benchTimer);
  const tick = async () => {
    let j;
    try { j = await api('/jobs?id=' + job); } catch (e) { return; }
    if (STATE.view !== 'bench') { if (j.status !== 'running') { clearInterval(benchTimer); benchTimer = null; } return; }
    const lc = $('#blogcard'), btn = $('#brun');
    if (!lc) return;
    if (!$('#blog', lc)) lc.innerHTML = `<div class="card pad"><h3 id="bhead"></h3><div class="logbox" id="blog" style="height:240px"></div></div>`;
    const log = $('#blog', lc);
    const stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
    log.innerHTML = (j.lines || []).map(l => `<div class="ln ${/ERROR|FAILED/.test(l) ? 'err' : /DONE|best| ok:/.test(l) ? 'ok' : ''}">${esc(l)}</div>`).join('');
    if (stick) log.scrollTop = log.scrollHeight;
    $('#bhead', lc).textContent = j.status === 'running' ? 'Running… (continues on the server if you leave)' : (j.status === 'ok' ? 'Finished' : j.status === 'cancelled' ? 'Cancelled' : 'Stopped with an error');
    if (btn) { btn.disabled = j.status === 'running'; btn.textContent = j.status === 'running' ? 'Benchmark running…' : 'Run benchmark'; }
    const cb = $('#bcancel');
    if (cb) { cb.hidden = j.status !== 'running'; cb.onclick = async () => { cb.disabled = true; try { await api('/jobs/cancel', { ID: job }); toast('Benchmark cancelled — cleaning up'); } catch (e) { alertModal('Cancel', e.message); } cb.disabled = false; }; }
    showBenchResults(fd);
    if (j.status !== 'running') { clearInterval(benchTimer); benchTimer = null; loadBenchHistory(); }
  };
  benchTimer = setInterval(tick, 1500); tick();
}
async function showBenchResults(fd) {
  let res = [];
  try { res = await api(`/bench/results?iran=${encodeURIComponent(fd.iran || '')}&foreign=${encodeURIComponent(fd.foreign || '')}&family=${fd.family}`); } catch (e) {}
  renderBenchTable(res || [], fd, '');
}
function renderBenchTable(res, fd, caption) {
  const box = $('#bres');
  if (!box) return; // user left the page
  if (!res || !res.length) { box.innerHTML = ''; return; }
  const n = (v) => v > 0 ? v.toFixed(v < 10 ? 1 : 0) : '—';
  const rows = res.map(r => {
    if (!r.ok) return `<tr class="${r.skipped ? 'skip' : 'fail'}"><td>${esc(r.title)}</td>
      <td colspan="6" class="${r.skipped ? 'faint' : 'errtxt'}" style="white-space:normal;font-size:12.5px">${r.skipped ? 'skipped — ' : '✕ '}${esc(r.error || 'failed')}</td><td></td></tr>`;
    return `<tr class="${r.recommended ? 'best' : ''}">
    <td>${r.recommended ? '★ ' : ''}${esc(r.title)} <span class="faint" style="font-size:11px">${r.kind === 'l3' ? 'L3' : 'port-fwd'}</span></td>
    <td>${n(r.downMbps)}</td><td>${n(r.upMbps)}</td><td>${r.rttMs.toFixed(1)}</td>
    <td>${r.jitterMs.toFixed(1)}</td><td>${r.lossKnown ? r.lossPct.toFixed(0) + '%' : '<span class="faint" title="ICMP loss is only measurable on L3 tunnels">n/a</span>'}</td>
    <td>${r.score.toFixed(0)}</td>
    <td><button class="btn sm pri" data-use="${r.method}">Apply to tunnel</button></td></tr>`;
  }).join('');
  box.innerHTML = `<div class="card pad"><h3>Results${caption ? ` <span class="faint" style="font-weight:500;font-size:13px">· ${caption}</span>` : ''}</h3>
    <div style="overflow-x:auto"><table class="tbl bench"><thead><tr><th>method</th><th>↓ Mbps</th><th>↑ Mbps</th><th>RTT ms</th><th>jitter</th><th>loss</th><th>score</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="faint" style="font-size:12px;margin-top:8px">↓ = foreign → Iran (what users downloading feel), ↑ = Iran → foreign. Measured over TCP through the tunnel itself.</div></div>`;
  $$('[data-use]', box).forEach(b => b.onclick = () => applyBenchToTunnel(fd, b.dataset.use));
}
function applyBenchToTunnel(fd, method) {
  const opts = STATE.tunnels.filter(t => t.serverId === fd.iran && (t.foreignId || '') === (fd.foreign || ''));
  if (!opts.length) { alertModal('No tunnel', 'Create a tunnel for this exact route first, then apply the method from its card.'); return; }
  const m = modal(`<h2>Apply ${esc(methodTitle(method))}</h2><p class="muted">Pick the tunnel to switch to this method:</p>
    <div class="ff">${opts.map(t => `<button class="btn" data-t="${t.id}" data-notr>${esc(t.name)}</button>`).join('')}</div>`, true);
  $$('[data-t]', m).forEach(b => b.onclick = async () => { try { const r = await api('/tunnels/apply', { ID: b.dataset.t, Method: method, Family: fd.family }); m.remove(); STATE.view = 'tunnels'; paintNav(); renderView(); const t = STATE.tunnels.find(x => x.id === b.dataset.t); openLog(t, r.job); } catch (e) { alertModal('Error', e.message); } });
}
const methodTitle = (id) => STATE.methods.find(m => m.id === id)?.title || id;

/* ---------------- log drawer ---------------- */
function openLog(t, jobId) {
  closeLog();
  // a tunnel's own name stays as it is on the Persian page; a label ("Repair", "Benchmark · IPv4") is translated
  const own = STATE.tunnels.some(x => x.id === t.id && x.name === t.name);
  const d = h(`<div class="drawer"><div class="panel">
    <div class="dh"><div><h3${own ? ' data-notr' : ''}>${esc(t.name)}</h3><div class="muted" style="font-size:12px" id="jobstat">${jobId ? 'running…' : 'last job'}</div></div><div style="display:flex;gap:6px"><button class="btn sm danger" id="cancelJob" hidden>■ Cancel job</button><button class="btn ghost sm" id="closeLog">✕ Close</button></div></div>
    <div class="logbox" id="logbox"><span class="muted">${jobId ? 'Starting…' : 'Loading last job…'}</span></div></div></div>`);
  document.body.appendChild(d);
  $('#closeLog', d).onclick = closeLog;
  d.onclick = (e) => { if (e.target === d) closeLog(); };
  pollJob(jobId, t.id);
}
// the drawer goes; its poll notices on the next tick and hands a running job to followJob
function closeLog() { $$('.drawer').forEach(x => x.remove()); }
// a job ended, its drawer open or not: the state is read again and the page on screen shows it
// (closing the drawer early used to leave the card on its old state — red, or still "stopped")
async function jobEnded() {
  if (!STATE.user) return;
  try { await loadAll(); } catch (e) { return; }
  const w = $('#work'); if (!w) return;
  if (STATE.view === 'tunnels') viewTunnels(w);
  else if (STATE.view === 'servers') viewServers(w);
}
// a job whose drawer was closed while it ran: watched quietly until it ends
const followedJobs = new Set();
function followJob(jobId) {
  if (!jobId || followedJobs.has(jobId)) return;
  followedJobs.add(jobId);
  let fails = 0;
  const tick = async () => {
    if (!STATE.user) { followedJobs.delete(jobId); return; }
    let j = null;
    try { j = await api('/jobs?id=' + jobId); fails = 0; } catch (e) { fails++; }
    if ((j && j.status === 'running') || (!j && fails < 5)) { setTimeout(tick, 3000); return; }
    followedJobs.delete(jobId);
    jobEnded();
  };
  setTimeout(tick, 1500);
}
async function pollJob(jobId, tunnelId) {
  const box = $('#logbox'), stat = $('#jobstat'), cb = $('#cancelJob');
  const url = jobId ? '/jobs?id=' + jobId : '/tunnels/lastjob?id=' + tunnelId;
  // each drawer owns its timer, so quickly opening another one can't orphan or kill it
  let me = null, finished = false, jid = jobId, running = !!jobId, sawRun = !!jobId;
  const stop = () => { if (me) clearInterval(me); me = null; };
  const tick = async () => {
    if (finished) return;
    if (!box.isConnected) { stop(); if (running) followJob(jid); return; } // drawer closed or replaced
    try {
      const j = await api(url);
      if (!box.isConnected || finished) return;
      jid = j.id || jid; running = j.status === 'running'; sawRun = sawRun || running;
      const lines = j.lines || [];
      // only the new lines, and the view follows them only when it was at the bottom: you can
      // scroll up to read an error while the job keeps running
      const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
      if (lines.length < box.childElementCount || !box.querySelector(".ln")) box.innerHTML = "";
      box.insertAdjacentHTML('beforeend', lines.slice(box.childElementCount).map(l => { let c = /ERROR|failed| ✕ |WARNING|CANCELLED/.test(l) ? 'err' : /DONE|is active|unit .*active| ✓ /.test(l) ? 'ok' : /\[IR\]/.test(l) ? 'ir' : ''; return `<div class="ln ${c}">${esc(l)}</div>`; }).join(''));
      if (stick) box.scrollTop = box.scrollHeight;
      if (stat) stat.textContent = j.status === 'running' ? 'running…' : (j.status === 'ok' ? 'completed' : j.status === 'cancelled' ? 'cancelled' : 'error');
      if (cb) { cb.hidden = j.status !== 'running'; cb.onclick = async () => { cb.disabled = true; try { await api('/jobs/cancel', { ID: j.id }); toast('Job cancelled'); } catch (e) { alertModal('Cancel', e.message); } cb.disabled = false; }; }
      if (j.status !== 'running') {
        finished = true; stop();
        if (sawRun) jobEnded(); // a last job that had already ended changed nothing
      }
    } catch (e) { if (!jobId) { box.innerHTML = '<span class="muted">No job yet.</span>'; stop(); } }
  };
  me = setInterval(tick, 1200);
  tick();
}


/* ---------------- IG routing ---------------- */
// The igproxy agents on the foreign servers: which way Instagram, Google/Gemini, YouTube Music …
// leave each server (a proxy, Cloudflare WARP, the server's IPv6 or direct). Every action runs
// "igproxy <command>" on the server as one of the panel's jobs (output in a drawer).
const IG = { data: null, cur: null, tab: 'routes', sub: recall('tp-igsub') || 'servers', filter: 'all', q: '' };
const IGSV = { IG: 'Instagram', GOOGLE: 'Google / Gemini', YTM: 'YouTube Music', ADULT: 'Adult', SPOTIFY: 'Spotify', SCLOUD: 'SoundCloud', CUSTOM: 'My sites' };
const IGWIDE = ['ADULT', 'SPOTIFY', 'SCLOUD', 'CUSTOM'];
const IGST = { OK: ['healthy', 'on'], PANEL: ['x-ui panel diverts Google', 'bad'], GEMFAIL: ['Gemini failing', 'bad'], IGFAIL: ['Instagram failing', 'bad'], DOWN: ['router down', 'bad'], GUARD: ['WARP guard not running', 'bad'],
  CHECKING: ['checking…', 'acc'], NOAGENT: ['not installed', 'warn'], SUDO: ['needs sudo without password', 'warn'], PAUSED: ['paused', 'warn'], UPDATE: ['old agent', 'warn'], OFFLINE: ['offline', 'bad'] };
const igBad = (s) => (IGST[s] || ['', 'bad'])[1] === 'bad';
// a proxy that is one of our servers (the agent's relay: own IP = port 12371, WARP n = 12371+n) -> "internal · name"
const igSrvByIP = (ip) => ((IG.data && IG.data.servers) || []).find(s => s.host === ip);
const igInternal = (ip, port) => { const s = igSrvByIP(ip); return 'internal · ' + (s ? s.name : ip) + (+port === 12371 ? '' : ' WARP ' + (port - 12371)); };
const igRelayOf = (i, v) => { const m = /^proxy(\d+)$/.exec(v || ''); if (!m || !i || !i.prelay) return ''; for (const x of i.prelay.split(',')) { const [n, h, p] = x.split(':'); if (n === m[1]) return igInternal(h, p); } return ''; };
const igViaW = (v, i) => { v = v || ''; if (v === 'proxy') return 'Proxy'; if (/^proxy\d+$/.test(v)) { const r = igRelayOf(i, v); return 'Proxy ' + v.slice(5) + (r ? ' · ' + r : ''); } return { warp: 'WARP', warp6: 'WARP IPv6', ipv6: 'IPv6', direct: 'Direct' }[v] || v || '—'; };
// igInternal / igRelayOf / igViaW return plain text (the agent's info and server names inside):
// every place that puts them into HTML escapes them; the class comes from a fixed list only
const igViaC = (v) => { const k = String(v || '').replace(/\d+$/, ''); return ['proxy', 'warp', 'ipv', 'direct'].includes(k) ? 'v-' + k : k ? '' : 'v-direct'; };
const igPill = (st) => { const w = IGST[st] || [st, 'bad']; return `<span class="pill ${w[1]}"><span class="led"></span>${esc(w[0])}</span>`; };
const igChk = (v) => v === 'OK' ? '<i class="igd ok"></i>works' : v === 'FAIL' ? '<i class="igd bad"></i>fail' : '<i class="igd"></i>—';
const igOwner = (s) => isAdmin() && s.owner ? `<span class="chip">👤 ${nm(s.owner)}</span>` : '';
const igList = () => ((IG.data && IG.data.servers) || []).filter(s => shownOwner(s.owner));
const igView = () => isAdmin() ? (STATE.ownerFilter || '') : '';
const igS = (p) => Object.assign({ srv: IG.cur.id }, p);
const igTitles = { route: 'Change route', proxy_add: 'Add proxy', custom_add: 'Add site', set: 'Setting', speedtest: 'Speed test', recent: 'Last 40 connections', watch: 'Live traffic',
  logs: 'Logs', gemusers: 'Gemini users', google_use: 'Google on WARP', warp_del: 'Delete WARP', warp_use: 'Use WARP', warp_add: 'New WARP account', proxy_del: 'Delete proxy', custom_del: 'Delete site',
  ig_session: 'Instagram test account', ig_test: 'Music test', ig_del: 'Remove test account', gemkey_set: 'Gemini key', gemkey_test: 'Gemini test', gemkey_del: 'Remove Gemini key',
  tg_setup: 'Telegram setup — send /start to the bot now', tg_test: 'Telegram test message', tg_del: 'Remove Telegram bot', status: 'Full test', status_short: 'Short test', routes: 'Route details',
  google_rotate: 'Fresh IP for Google', google_countries: 'Country per WARP', panel_check: 'Panel check', panel_fix: 'Fix panel', panel_undo: 'Undo panel fix', diag: 'Diagnose Gemini / Google',
  apply: 'Re-apply', pause: 'Pause igproxy', uninstall: 'Uninstall igproxy', deploy: 'Install / update agent' };
const igJobTitle = (p) => { const t = igTitles[p.action] || p.action || ''; const s = p.srv === 'all' ? 'all servers' : Array.isArray(p.srv) ? p.srv.length + ' servers' : ((IG.data?.servers || []).find(x => x.id === p.srv) || {}).name || ''; return s ? t + ' — ' + s : t; };

async function igLoad(fresh) {
  if (IG.loading) return IG.loading;
  $$('[data-igref]').forEach(b => b.classList.add('busy'));
  IG.loading = (async () => {
    try {
      IG.data = await api('/igproxy/servers' + (fresh ? '?fresh=1' : ''));
      if (IG.cur) IG.cur = IG.data.servers.find(x => x.id === IG.cur.id) || null;
      if (STATE.view === 'igproxy' && !$('.drawer,.modal') && !document.activeElement?.matches('input,select,textarea')) igRender();
      // servers still being read come in a few seconds later
      clearTimeout(IG.again); if (IG.data.pending) IG.again = setTimeout(() => { if (STATE.view === 'igproxy') igLoad(); }, 5000);
    } catch (e) { toast(e.message); }
    finally { IG.loading = null; $$('[data-igref]').forEach(b => b.classList.remove('busy')); }
  })();
  return IG.loading;
}
// a job's output: lines without the panel's time stamp
const igLines = (j) => (j.lines || []).map(l => l.replace(/^\d\d:\d\d:\d\d /, ''));
const igColor = (l) => /^\s*(!!|ERR|.*\b(FAIL|DOWN|failed|rejected|not )\b)/i.test(l) ? 'err' : /^\s*(==|->)/.test(l) ? 'ir' : /\b(OK|added|saved|applied|removed|updated|installed|fixed)\b/.test(l) ? 'ok' : '';
function igRunJob(jobId, title, onDone) {
  return new Promise(res => {
    const d = h(`<div class="drawer"><div class="panel"><div class="dh"><div style="display:flex;gap:10px;align-items:center;min-width:0"><span class="pill acc" id="ijst"><span class="led"></span>running</span><b style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(title)}</b></div>
      <div class="actions"><button class="btn sm" id="ijcopy" title="Copy the output">⧉</button><button class="btn danger sm" id="ijstop">Stop</button><button class="btn sm" id="ijclose">Close ✕</button></div></div><div class="logbox" id="ijout">…</div></div></div>`);
    document.body.appendChild(d);
    let closed = false, done = false, txt = '', status = '', fails = 0;
    const close = () => { if (closed) return; closed = true; d.remove(); document.removeEventListener('keydown', onKey); if (onDone) onDone(); res({ out: txt, done, status }); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', onKey);
    $('#ijclose', d).onclick = close; d.onclick = (e) => { if (e.target === d) close(); };
    $('#ijcopy', d).onclick = (e) => copy(txt, e.target);
    $('#ijstop', d).onclick = () => api('/jobs/cancel', { ID: jobId }).catch(e => toast(e.message));
    const tick = async () => {
      if (closed) return;
      // a failed poll (a panel restart, a network blip) is tried again; only several in a row give up
      let j; try { j = await api('/jobs?id=' + jobId); fails = 0; } catch (e) {
        if (closed) return;
        if (++fails < 6) { setTimeout(tick, 2000); return; }
        toast(e.message); $('#ijstop', d)?.remove();
        $('#ijst', d).className = 'pill bad'; $('#ijst', d).innerHTML = '<span class="led"></span>no answer from the panel';
        return;
      }
      if (closed) return;
      const ls = igLines(j); txt = ls.join('\n');
      const box = $('#ijout', d), stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
      box.innerHTML = ls.map(l => `<div class="ln ${igColor(l)}">${esc(l) || '&nbsp;'}</div>`).join('') || '…';
      if (stick) box.scrollTop = box.scrollHeight;
      if (j.status !== 'running') {
        done = true; status = j.status; $('#ijstop', d)?.remove();
        const ok = j.status === 'ok';
        $('#ijst', d).className = 'pill ' + (ok ? 'on' : 'bad');
        $('#ijst', d).innerHTML = '<span class="led"></span>' + (ok ? 'finished' : j.status === 'cancelled' ? 'stopped' : 'error');
        return;
      }
      setTimeout(tick, 800);
    };
    tick();
  });
}
async function igAct(p, confirmText, opt = {}) {
  if (confirmText && !confirm(confirmText)) return;
  if (p.srv === 'all' && p.view === undefined) p = Object.assign({ view: igView() }, p);
  try {
    const r = await api('/igproxy/action', p);
    await igRunJob(r.job, opt.title || igJobTitle(p), () => { if (opt.refresh !== false) igRefreshAfter(p); });
  } catch (e) { toast(e.message); }
}
// runs an action without the drawer and returns its output (lists: proxies, WARPs, sites)
async function igQuiet(p) {
  const r = await api('/igproxy/action', p);
  for (;;) {
    const j = await api('/jobs?id=' + r.job);
    if (j.status !== 'running') return igLines(j).join('\n');
    await new Promise(s => setTimeout(s, 600));
  }
}
async function igRefreshAfter(p) {
  if (IG.cur && p.srv === IG.cur.id) {
    try { IG.cur.info = await api('/igproxy/info?id=' + encodeURIComponent(IG.cur.id)); if (STATE.view === 'igproxy') igRender(); } catch (e) { toast(e.message); }
  } else igLoad(true);
}

function viewIg(w) {
  if (!IG.data) igLoad();
  igRender(w);
}
function igRender(w) {
  w = w || $('#work'); if (!w || STATE.view !== 'igproxy') return;
  w.innerHTML = '';
  w.classList.add('igp');
  if (IG.cur) return igDetail(w);
  const subs = [['servers', 'Servers'], ['matrix', 'Route table'], ['bulk', 'All servers'], ['backup', 'Backup & copy']];
  w.innerHTML = topbar('IG Routing', 'igproxy on the foreign servers: which way Instagram, Google / Gemini, YouTube Music and the rest leave each server.',
    `${isAdmin() ? '<a class="btn" data-gbtn href="/gbrowser/" target="_blank" rel="noopener" title="Chromium on xe108 with the Google test account: log in here once">🔑 Google test browser</a>' : ''}<button class="btn" data-igref>↻ Refresh</button><button class="btn pri" data-igadd>+ Add server</button>`)
    + `<div class="seg" id="igsub">${subs.map(([k, t]) => `<button data-s="${k}" class="${k === IG.sub ? 'on' : ''}">${t}</button>`).join('')}</div><div id="igbody"></div>`;
  $$('#igsub button', w).forEach(b => b.onclick = () => { IG.sub = b.dataset.s; remember('tp-igsub', IG.sub); igRender(); });
  const body = $('#igbody', w);
  ({ servers: igServers, matrix: igMatrix, bulk: igBulk, backup: igBackup }[IG.sub] || igServers)(body);
  // wired here, not with onclick="…": the panel's CSP (script-src 'self') drops inline handlers, so
  // these buttons did nothing
  $$('[data-igref]', w).forEach(b => b.onclick = () => igLoad(true));
  $$('[data-igadd]', w).forEach(b => b.onclick = () => igAddServer());
  igAcctBadge(w);
}
// the Google test account's state on its button (gemacct.go): red while Google has it signed out
function igAcctBadge(w) {
  const b = $('[data-gbtn]', w); if (!b) return;
  api('/igproxy/gaccount').then(d => {
    if (d.state === 'out') {
      b.textContent = '🔑 Google test account: signed out — log in';
      b.style.color = 'var(--bad, #c0392b)'; b.style.fontWeight = '600';
      b.title = `Google ended the test account's session${d.since ? ' (seen ' + new Date(d.since).toLocaleString() + ')' : ''}. Log in here; it goes out through ${d.exit}.`;
    } else if (d.state === 'in') b.textContent = '🔑 Google test browser ✓';
  }).catch(() => {});
}

// ---- servers
function igServers(box) {
  const d = IG.data;
  if (!d) { box.innerHTML = '<div class="grid cards">' + '<div class="skel" style="height:150px"></div>'.repeat(4) + '</div>'; return; }
  const L = igList(), ok = L.filter(s => s.info.state === 'OK').length, conn = L.reduce((a, s) => a + (+s.info.caught || 0), 0);
  const bad = L.filter(s => s.info.state !== 'OK' && s.info.state !== 'CHECKING').length, old = L.filter(s => ['UPDATE', 'NOAGENT'].includes(s.info.state) || s.info.outdated === '1').length;
  box.insertAdjacentHTML('beforeend', `<div class="summary">
    <div class="stat"><small>Servers</small><b>${L.length}</b></div><div class="stat"><small>Healthy</small><b>${ok}</b></div>
    <div class="stat"><small>Connections routed</small><b>${conn}</b></div><div class="stat"><small>Need attention</small><b>${bad}</b></div></div>`);
  if (old && d.agent) box.insertAdjacentHTML('beforeend', `<div class="mwarn">${old} server(s) don't run the current agent (<span class="mono">${esc(d.agent)}</span>). <button class="btn sm" id="igupd">Update them</button></div>`);
  if (!d.agent) box.insertAdjacentHTML('beforeend', `<div class="mwarn">The agent script isn't on the panel host (<span class="mono">/etc/igpm/igproxy.sh</span>), so install / update is unavailable. Everything else works.</div>`);
  $('#igupd', box) && ($('#igupd', box).onclick = () => igAct({ srv: 'all', action: 'deploy', old: 1 }, 'Update the agent on the servers with an old one? Each server routes everything direct for a few seconds; settings and WARPs are kept.', { title: 'Update agents' }));
  if (!L.length) {
    box.insertAdjacentHTML('beforeend', `<div class="card empty"><div class="big">🌐</div><h3>No servers here yet</h3><p class="muted">Add one of your foreign servers: the igproxy agent is installed on it, then you choose here which way each service leaves.</p><button class="btn pri" data-igadd>+ Add server</button></div>`);
    return;
  }
  const nbad = L.filter(s => s.info.state !== 'OK').length;
  box.insertAdjacentHTML('beforeend', `<div class="filters"><button class="fchip" data-f="all">All <b>${L.length}</b></button><button class="fchip" data-f="bad">Needs attention <b>${nbad}</b></button>
    <input class="inp search" id="igq" placeholder="Search name or IP…" value="${esc(IG.q)}"><span class="faint" style="font-size:12px">updated ${new Date(d.t * 1000).toLocaleTimeString()}</span></div><div class="grid cards" id="igcards"></div>`);
  $$('[data-f]', box).forEach(b => { b.classList.toggle('on', b.dataset.f === IG.filter); b.onclick = () => { IG.filter = b.dataset.f; igRender(); }; });
  $('#igq', box).oninput = (e) => { IG.q = e.target.value; igCards(); };
  igCards();
}
function igCards() {
  const q = IG.q.trim().toLowerCase();
  const L = igList().filter(s => (IG.filter !== 'bad' || s.info.state !== 'OK') && (!q || (s.name + ' ' + s.host).toLowerCase().includes(q)));
  const box = $('#igcards'); if (!box) return;
  box.innerHTML = L.length ? L.map(igCard).join('') : '<div class="empty card"><div class="big">🔍</div>No server matches</div>';
  // the cards open like buttons: a click, or Enter / Space on the keyboard
  $$('.scard', box).forEach(c => {
    c.tabIndex = 0; c.setAttribute('role', 'button');
    c.onclick = () => { IG.cur = IG.data.servers.find(x => x.id === c.dataset.id); IG.tab = 'routes'; igRender(); scrollTo(0, 0); };
    c.onkeydown = (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === c) { e.preventDefault(); c.click(); } };
  });
}
// the country the users' exit gets now, measured by the agent through the users' route:
// Instagram's country_code and Google's OneGoogle domain
// Google should place a server's users in the server's own country (US -> .com)
const igGDom = (cc) => { cc = (cc || '').toLowerCase(); return ({ us: 'com', gb: 'co.uk', uk: 'co.uk', jp: 'co.jp', kr: 'co.kr', in: 'co.in', za: 'co.za', nz: 'co.nz', au: 'com.au', br: 'com.br', tr: 'com.tr', hk: 'com.hk', sg: 'com.sg' })[cc] || cc; };
function igCC(g, i, s) {
  const v = g === 'IG' ? i.igcc : g === 'GOOGLE' ? i.gdom : '';
  if (!v || v === '-') return '';
  const want = igGDom(s && s.country);
  const bad = g === 'IG' ? v === 'IR' : !!want && v !== want;
  return `<span class="note mono" style="color:${bad ? 'var(--crit)' : 'var(--faint)'}" title="${g === 'IG' ? 'the country Instagram places the users of this server in' : 'the Google country of the users of this server' + (want ? ' (should be .' + esc(want) + ', the server\'s own country)' : '')}">${g === 'IG' ? 'Instagram sees ' + esc(v) : 'Google sees .' + esc(v)}</span>`;
}
function igCard(s) {
  const i = s.info;
  const svc = (g) => `<div class="svc"><small>${IGSV[g]}</small><b class="${igViaC(i[g.toLowerCase()])}">${esc(igViaW(i[g.toLowerCase()], i))}</b>${igCC(g, i, s)}${g === 'GOOGLE' && /^warp/.test(i.google || '') && i.gcc && i.gcc !== '-' ? `<span class="note mono" style="color:${i.gcc === 'PROXY' ? 'var(--crit)' : 'var(--faint)'}">${i.gcc === 'PROXY' ? 'on a proxy for now' : 'country ' + esc(i.gcc)}</span>` : ''}</div>`;
  const n = igWarpNeed(i);
  return `<div class="card scard${igBad(i.state) ? ' bad' : ''}" data-id="${esc(s.id)}" style="cursor:pointer"><div class="sh"><div class="sname"><div><h3>${s.country ? flag(s.country) + ' ' : ''}${nm(s.name)} ${igOwner(s)}</h3><small class="mono">${esc(s.host)}</small></div></div>${igPill(i.state)}</div>
    ${i.ig ? `<div class="svcs">${svc('IG')}${svc('GOOGLE')}${svc('YTM')}</div>
    <div class="sfoot"><span>🔗 <b>${+i.caught || 0}</b></span><span>proxies <b>${+i.proxies || 0}</b></span><span>WARP <b>${+i.warps || 0}</b>${n ? `<span class="faint" title="suggested for the 24 h peak"> / ${n.total}</span>` : ''}</span><span class="grow"></span><span>Gemini ${igChk(i.gem)}</span><span>IG ${igChk(i.igp)}</span>${igAccBroken(i) ? '<span class="chip bad" title="Instagram logged the test account out: music is not checked on any exit IP">music check off</span>' : ''}</div>`
    : i.state === 'CHECKING' ? '<div class="skel" style="height:64px;margin-top:10px"></div>' : `<div class="mcrit" style="margin:10px 0 0">${esc(i.err || (IGST[i.state] || [])[0] || '')}</div>`}</div>`;
}
// the shared Instagram test account: igaccst = working | untested | broken:<why> (Instagram logged it out)
const igAccBroken = (i) => /^broken/.test(i.igaccst || '');
const igAccWhy = (i) => (i.igaccst || '').replace(/^broken:?/, '') || 'logged out';
// WARPs needed for the 24 h peak: one WARP keeps its speed up to ~2500 connections / 5 min, +1 spare (3-10), + Google's own
const igWarpNeed = (i) => { if (i.wpeak === undefined || i.wpeak === '-' || i.wpeak === '') return null; const p = +i.wpeak || 0, g = (i.gw || '').split(',').filter(Boolean).length;
  const ig = Math.min(10, Math.max(3, Math.ceil(p / 2500) + 1)); return { p, ig, g, total: ig + g, have: +i.warps || 0 }; };
const igGccChip = (i) => i.gcc === undefined || i.gcc === '-' || i.gcc === '' ? '' : i.gcc === 'PROXY' ? '<span class="chip bad" title="no allowed WARP for Google: Google goes through a proxy for now">no allowed WARP → proxy</span>' : `<span class="chip" title="the country Google sees for its current WARP">${esc(i.gcc)}</span>`;

async function igAddServer() {
  if (!IG.data) await igLoad();
  // the admin can add any account's server, whatever the View shows (on "My own" the list used to
  // be empty though other accounts had servers to add); the viewed account's come first
  const all = IG.data?.candidates || [];
  const c = all.filter(x => shownOwner(x.Owner)).concat(all.filter(x => !shownOwner(x.Owner)));
  const groups = [];
  c.forEach(x => { const g = groups.find(g => g.o === x.Owner); g ? g.l.push(x) : groups.push({ o: x.Owner, l: [x] }); });
  const opt = (x) => `<option value="${esc(x.ID)}" data-notr>${esc(x.Name)} — ${esc(x.Host)}</option>`;
  const opts = isAdmin() ? groups.map(g => `<optgroup label="${g.o ? '👤 ' + esc(g.o) : 'admins'}">${g.l.map(opt).join('')}</optgroup>`).join('') : c.map(opt).join('');
  const m = modal(`<h2>Add a server to IG routing</h2>
    ${c.length ? `<div class="ff" style="grid-template-columns:1fr"><label class="f">Server<select id="igas">${opts}</select></label>
    <label class="f row"><input type="checkbox" id="igad"> Reinstall the agent even if it's already there</label></div>
    <p class="muted" style="font-size:13px">The panel reaches it the way it reaches it for tunnels (its saved SSH login or agent). If igproxy isn't on it yet, it's installed now.</p>
    <div class="actions" style="justify-content:space-between;margin-top:12px"><button class="btn" id="ignew">+ New foreign server</button><button class="btn pri" id="igago">Add</button></div>`
    : `<p class="muted">Every foreign server${isAdmin() ? ' of every account' : ''} is already here. A new machine is added as a foreign server first, then here.</p>
    <div class="actions" style="justify-content:flex-end;margin-top:12px"><button class="btn pri" id="ignew">+ Add foreign server</button></div>`}`);
  const nw = $('#ignew', m);
  // a machine that isn't a server of the panel yet: saved as a foreign server, then put on this page at once
  // (the only way here used to be when every server was already on the page)
  if (nw) nw.onclick = () => { m.remove(); serverModal({ role: 'foreign', onSaved: async (id, name) => {
    if (!id) return;
    try {
      const r = await api('/igproxy/enable', { ID: id, On: true });
      await igRunJob(r.job, 'Add server — ' + name, () => igLoad(true));
    } catch (e) { toast(e.message); }
  } }); };
  const go = $('#igago', m);
  if (go) go.onclick = async () => {
    const x = c.find(x => x.ID === $('#igas', m).value);
    if (!x || go.disabled) return;
    go.disabled = true; // one press, one install (a double press started two)
    let r;
    try { r = await api('/igproxy/enable', { ID: x.ID, On: true, Deploy: $('#igad', m).checked }); }
    catch (e) { go.disabled = false; toast(e.message); return; }
    m.remove();
    await igRunJob(r.job, 'Add server — ' + x.Name, () => igLoad(true));
    if (!shownOwner(x.Owner)) toast(`${x.Name} belongs to ${x.Owner || 'the admins'}: switch View to see it`);
  };
}

// ---- one server
const IGTABS = [['routes', 'Routes'], ['proxies', 'Proxies'], ['warp', 'WARP'], ['sites', 'My sites'], ['settings', 'Settings'], ['checks', 'Test account · Gemini'], ['tools', 'Tests & diagnosis']];
function igDetail(w) {
  const s = IG.cur, i = s.info || {};
  // the agent's own actions (they were the "Server" tab): a ⋯ menu next to Refresh
  const agentMenu = moreMenu([{ label: 'Install / update agent', attr: 'data-ia="deploy"' },
    { label: i.paused === 'YES' ? 'Turn back on' : 'Re-apply / restart', attr: 'data-ia="apply"' },
    i.paused === 'YES' ? null : { label: 'Pause (everything direct)', attr: 'data-ia="pause"' },
    { label: 'Take off this page', attr: 'data-ia="remove"', danger: true }, { label: 'Uninstall igproxy from the server', attr: 'data-ia="uninstall"', danger: true }]);
  if (IG.tab === 'server') IG.tab = 'routes';
  w.innerHTML = topbar(s.name, s.host, `<button class="btn" id="igback">← All servers</button><button class="btn" id="igre">↻</button>${agentMenu}`);
  $$('.topbar h1, .topbar p', w).forEach(x => x.setAttribute('data-notr', '')); // the server's own name and address
  $('#igback', w).onclick = () => { IG.cur = null; igRender(); };
  $('#igre', w).onclick = () => igRefreshAfter({ srv: s.id });
  $$('[data-ia]', w).forEach(b => b.onclick = () => ({
    deploy: () => igAct(igS({ action: 'deploy' }), `Install / update the agent on ${s.name}? A few seconds without routing; settings and WARPs are kept.`),
    apply: () => igAct(igS({ action: 'apply' })),
    pause: () => igAct(igS({ action: 'pause' }), 'Pause igproxy? All traffic goes direct until you turn it back on.'),
    remove: () => igRemove(false), uninstall: () => igRemove(true),
  })[b.dataset.ia]());
  w.insertAdjacentHTML('beforeend', igStatus(s, i) + `
    <div class="seg igtabs">${IGTABS.map(([k, t]) => `<button data-t="${k}" class="${k === IG.tab ? 'on' : ''}">${t}</button>`).join('')}</div><div id="igtab"></div>`);
  $$('.igtabs button', w).forEach(b => b.onclick = () => { IG.tab = b.dataset.t; igRender(); });
  // the status card's fix buttons: a tab to open, or the server's re-apply
  $$('[data-igto]', w).forEach(b => b.onclick = () => { IG.tab = b.dataset.igto; igRender(); });
  // the same actions as the ⋯ menu (its confirmations too)
  $$('[data-igdo]', w).forEach(b => b.onclick = () => b.dataset.igdo === 'deploy' ? igAct(igS({ action: 'deploy' }), `Install / update the agent on ${s.name}? A few seconds without routing; settings and WARPs are kept.`) : igAct(igS({ action: b.dataset.igdo })));
  const det = $('.igst-more', w); if (det) { det.open = recall('tp-igdet') === '1'; det.ontoggle = () => remember('tp-igdet', det.open ? '1' : '0'); }
  if (!i.ig && IG.tab !== 'tools') {
    $('#igtab').innerHTML = `<div class="card empty"><div class="big">${i.state === 'OFFLINE' ? '📡' : '📦'}</div><h3>${esc((IGST[i.state] || [i.state])[0])}</h3>
      <p class="muted">${i.state === 'OFFLINE' ? 'The panel can\'t reach this server right now.' : 'This part works once the agent is installed.'}</p>${i.state === 'OFFLINE' ? '' : `<button class="btn pri" id="igdep">Install / update agent</button>`}</div>`;
    $('#igdep') && ($('#igdep').onclick = () => igAct(igS({ action: 'deploy' })));
    return;
  }
  (IGTAB[IG.tab] || IGTAB.routes)();
}
// ---- the server's status card: is it OK, where Instagram and Google leave and do they work,
// how busy it is. Problems come first with their fix; the router's internals sit under "Details".
const igSet = (v) => v !== undefined && v !== '' && v !== '-';
// the users' exit of one service in plain words: [what, more]
function igExit(i, g) {
  const v = i[g.toLowerCase()] || '';
  if (v === 'direct') return ["Server's own IP", ''];
  if (v === 'ipv6') return ["Server's own IPv6", ''];
  if (/^warp/.test(v)) {
    const w = v === 'warp6' ? 'WARP IPv6' : 'WARP';
    if (g === 'GOOGLE') return i.gcc === 'PROXY' ? ['Proxy', 'no allowed WARP for now'] : [igSet(i.gact) ? w + ' ' + i.gact : w, ''];
    if (i.mode === 'BALANCE') { const [a, b] = String(i.pool || '').split('/'); return [w, igSet(i.pool) && b ? `${a} of ${b} WARPs in use` : 'spread over the WARPs']; }
    return [igSet(i.active) ? w + ' ' + i.active : w, igSet(i.active) ? '' : 'no WARP connected yet'];
  }
  return [igViaW(v, i), ''];
}
// the agent's check on the users' route every minute: [class, text]
function igCheck(i, g) {
  const v = g === 'IG' ? i.igp : i.gem, route = i[g.toLowerCase()] || '';
  if (v === 'OK') return ['ok', 'works'];
  if (v === 'FAIL') return ['bad', "doesn't open"];
  return ['', route === 'direct' ? 'not checked on the own IP' : 'not checked yet'];
}
function igSvcTile(s, i, g) {
  const [via, more] = igExit(i, g), [c, t] = igCheck(i, g), route = i[g.toLowerCase()] || '';
  let cc = '', ccBad = false, ccTip = '';
  if (g === 'IG' && igSet(i.igcc)) { cc = 'seen in ' + i.igcc; ccBad = i.igcc === 'IR'; ccTip = 'the country Instagram places the users of this server in'; }
  if (g === 'GOOGLE' && igSet(i.gdom)) {
    const want = igGDom(s.country); cc = 'google.' + i.gdom; ccBad = !!want && i.gdom !== want;
    ccTip = 'the Google country of the users of this server' + (want ? ' (should be .' + want + ', the server\'s own country)' : '');
  }
  const gcc = g === 'GOOGLE' && /^warp/.test(route) && igSet(i.gcc) && i.gcc !== 'PROXY' ? `<span class="faint" title="the country Google sees for its current WARP" data-notr>${esc(i.gcc)}</span>` : '';
  return `<div class="igst-tile ${c}"><div class="igst-h"><span>${g === 'IG' ? 'Instagram' : 'Gemini · Google'}</span><span class="igst-ck ${c}"><i class="igd ${c}"></i>${esc(t)}</span></div>
    <div class="igst-v"><b class="${igViaC(g === 'GOOGLE' && i.gcc === 'PROXY' ? 'proxy' : route)}"${/^proxy/.test(route) ? ' data-notr' : ''}>${esc(via)}</b>${gcc}</div>
    ${more || cc ? `<div class="igst-n">${more ? `<span>${esc(more)}</span>` : ''}${cc ? `<span class="igst-cc${ccBad ? ' bad' : ''}" title="${esc(ccTip)}">${esc(cc)}</span>` : ''}</div>` : ''}</div>`;
}
// "warp6:14,direct:1" (Gemini connections per exit in 10 min) -> [[exit, n]]
const igGusers = (i) => (i.gusers || '').split(',').filter(Boolean).map(x => { const [k, n] = x.split(':'); return [k, +n || 0]; });
function igProblems(s, i) {
  const P = [], add = (lvl, text, btn, to, act) => P.push({ lvl, text, btn, to, act });
  if (i.paused === 'YES') add('warn', "igproxy is paused: every service leaves through the server's own IP.", 'Turn back on', '', 'apply');
  if (i.ig && i.paused !== 'YES' && (i.router !== 'active' || i.redirect !== 'ON')) add('bad', "The router isn't running: Instagram and Google leave through the server's own IP.", 'Re-apply', '', 'apply');
  if (['BLOCK', 'AWAY', 'MARK', 'V6', 'SOME'].includes(i.panel)) add('bad', 'The x-ui panel on this server blocks or diverts Google before igproxy sees it.', 'Fix panel', 'tools');
  if (i.gem === 'FAIL') add('bad', "Gemini doesn't open on the users' route (checked every minute).", 'Tests & diagnosis', 'tools');
  if (i.igp === 'FAIL') add('bad', "Instagram doesn't open on the users' route (checked every minute).", 'Tests & diagnosis', 'tools');
  if (i.guard === 'DOWN') add('bad', "The WARP guard isn't running: dead WARPs are not replaced.", 'Settings', 'settings');
  if (/^warp/.test(i.google || '') && i.gcc === 'PROXY') add('warn', 'No allowed WARP for Google: Google goes through a proxy for now.', 'WARP', 'warp');
  if (igAccBroken(i)) add('warn', `Instagram logged the test account out (${igAccWhy(i)}): music is not checked on any WARP or proxy.`, 'Test account', 'checks');
  if (i.ig && i.outdated === '1') add('warn', 'The agent here is old.', 'Install / update agent', '', 'deploy');
  return P;
}
function igStatus(s, i) {
  if (!i.ig) { // no agent answer: the state and the reason (the tabs below say what to do)
    const w = IGST[i.state] || [i.state, 'bad'];
    return `<div class="card igst ${w[1]}"><div class="igst-top"><span class="igst-dot"></span><div class="igst-t"><b>${esc(w[0] || '')}</b>${i.err ? `<small class="mono">${esc(i.err)}</small>` : ''}</div>${igOwner(s)}</div></div>`;
  }
  const P = igProblems(s, i), nbad = P.filter(p => p.lvl === 'bad').length;
  const lvl = i.state === 'CHECKING' ? 'acc' : nbad ? 'bad' : P.length ? 'warn' : 'on';
  const head = nbad ? (nbad === 1 ? '1 problem' : nbad + ' problems') : i.paused === 'YES' ? 'Paused' : P.length ? 'Works · needs a look' : 'Everything works';
  const conn = +i.caught || 0, gu = igGusers(i), gsum = gu.reduce((a, x) => a + x[1], 0);
  const probs = P.length ? `<div class="igst-probs">${P.map(p => `<div class="igst-p ${p.lvl}"><span>${esc(p.text)}</span><button class="btn sm" ${p.act ? `data-igdo="${p.act}"` : `data-igto="${p.to}"`}>${esc(p.btn)}</button></div>`).join('')}</div>` : '';
  const yn = (ok, on, off) => ok ? `<b class="ok">${on}</b>` : `<b class="bad">${off}</b>`;
  const row = (k, v, tip) => `<div class="igst-r"${tip ? ` title="${esc(tip)}"` : ''}><span>${k}</span><span class="igst-rv">${v}</span></div>`;
  const n = igWarpNeed(i);
  const det = [
    row('Router', yn(i.router === 'active', 'running', esc(i.router || 'stopped')), 'igproxy-xray: the router that sends each service its way'),
    row('Traffic sent to the router', yn(i.redirect === 'ON', 'on', 'off')),
    row('Wide catch', i.wide === 'ON' ? '<b>on</b><small>all web traffic is routed by domain</small>' : '<b>off</b><small>only the listed services</small>'),
    row('WARP mode', i.mode === 'BALANCE' ? `<b>balance</b>${igSet(i.pool) ? `<small>${esc(String(i.pool).replace('/', ' of '))} in use</small>` : ''}` : `<b>failover</b>${igSet(i.active) ? `<small data-notr>WARP ${esc(i.active)}</small>` : ''}`),
    row('WARP accounts', `<b data-notr>${+i.warps || 0}</b>${n ? `<small>${n.total} suggested for the 24 h peak</small>` : ''}`),
    row('Proxies', `<b data-notr>${+i.proxies || 0}</b>`),
    i.guard !== undefined ? row('WARP guard', i.guard === 'ON' ? '<b class="ok">on</b>' : i.guard === 'DOWN' ? '<b class="bad">not running</b>' : '<b>off</b>', 'replaces a WARP that stops working') : '',
    row('x-ui panel', i.panel === 'OK' ? '<b class="ok">passes Google</b>' : igSet(i.panel) ? `<b class="bad" data-notr>${esc(i.panel)}</b>` : '<b>no x-ui panel</b>', 'does the x-ui panel on this server pass Google to igproxy untouched'),
    row('Gemini connections (10 min)', gu.length ? gu.map(([k, c]) => `<b class="igst-gu"><span${/^proxy/.test(k) ? ' data-notr' : ''}>${esc(k === 'direct' ? "Server's own IP" : k === 'ipv6' ? "Server's own IPv6" : /^warp\d+$/.test(k) ? 'WARP ' + k.slice(4) : igViaW(k, i))}</span> <span data-notr>${c}</span></b>`).join('') : '<b>none</b>'),
    row('Agent', `<b class="mono">${esc(i.sum || '—')}</b>${i.outdated === '1' ? '<small class="bad">old</small>' : '<small>current</small>'}`),
  ].join('');
  return `<div class="card igst ${lvl}"><div class="igst-top"><span class="igst-dot"></span><div class="igst-t"><b>${esc(head)}</b>
      <small><b data-notr>${conn}</b> connections now${gsum ? ` · <b data-notr>${gsum}</b> to Gemini in 10 min` : ''}</small></div>${igOwner(s)}</div>
    ${probs}<div class="igst-tiles">${igSvcTile(s, i, 'IG')}${igSvcTile(s, i, 'GOOGLE')}</div>
    <details class="igst-more"><summary>Details</summary><div class="igst-det">${det}</div></details></div>`;
}
function igViaOpts(svc, cur, nprox, i) {
  const o = ['proxy']; for (let k = 1; k <= nprox; k++) o.push('proxy' + k); o.push('warp'); if (!IGWIDE.includes(svc)) o.push('warp6', 'ipv6'); o.push('direct');
  if (cur && !o.includes(cur)) o.push(cur);
  return o.map(v => `<option value="${esc(v)}"${v === cur ? ' selected' : ''}>${esc(igViaW(v, i))}</option>`).join('');
}
const igSecret = 'type="text" class="inp mono secret" autocomplete="off" data-lpignore="true" data-1p-ignore spellcheck="false"';
const IGTAB = {
  routes() {
    const i = IG.cur.info;
    $('#igtab').innerHTML = `<div class="card pad"><table class="tbl igt"><tr><th>Service</th><th>Goes out through</th><th></th></tr>
      ${Object.keys(IGSV).map(g => `<tr><td><b>${IGSV[g]}</b>${g === 'CUSTOM' ? ` <span class="faint">(${+i.ncustom || 0} sites)</span>` : ''}${g === 'GOOGLE' && /^warp/.test(i.google || '') ? ' ' + igGccChip(i) : ''} ${igCC(g, i, IG.cur)}</td>
      <td><select data-g="${g}" data-cur="${esc(i[g.toLowerCase()])}">${igViaOpts(g, i[g.toLowerCase()], +i.proxies || 0, i)}</select></td>
      <td style="text-align:end"><button class="btn sm pri" data-ap="${g}" hidden>Apply</button></td></tr>`).join('')}</table>
      <div class="mdesc">Proxy = the fastest healthy proxy · "Proxy N" = only that one · WARP = Cloudflare WARP · IPv6 = the server's own IPv6 (Instagram, Google, YouTube Music only) · Direct = the server's own IP.
      The router restarts (a few seconds) only when a setting really changes.</div>
      <div class="actions" style="margin-top:12px"><button class="btn sm" id="igrd">Route details</button></div></div>`;
    $$('#igtab select[data-g]').forEach(sel => sel.onchange = () => { const ch = sel.value !== sel.dataset.cur; sel.classList.toggle('chg', ch); $(`[data-ap="${sel.dataset.g}"]`).hidden = !ch; });
    $$('[data-ap]').forEach(b => b.onclick = () => igAct(igS({ action: 'route', svc: b.dataset.ap, via: $(`select[data-g="${b.dataset.ap}"]`).value })));
    $('#igrd').onclick = () => igAct(igS({ action: 'routes' }), null, { refresh: false });
  },
  proxies() { igpxTab(); },
  warp() {
    const i = IG.cur.info, gA = i.gw !== undefined, id = IG.cur.id;
    $('#igtab').innerHTML = `<div class="card pad sec igw"><h3>WARP accounts <span id="igwsum" class="wchips"></span><span class="grow"></span>
       <span class="wact"><button class="btn sm" id="igwt" title="checks every WARP again now">Test all</button><button class="btn sm pri" id="igwa">+ Add WARP</button>
       ${moreMenu([{ label: 'Google → fresh IP', attr: 'id="igwr"' }, gA && { label: 'Country per WARP (Google)', attr: 'id="igwc"' }])}</span></h3>
     <div class="wsum">${igWarpSvc(i)}</div>
     <div id="igwl" class="wlist"></div>
     <div class="mdesc">Broken WARPs are repaired, WARP+ keys are found and the best WARP (music OK, fastest) is chosen automatically. "Use" moves Instagram — and Google, unless it has its own WARPs — to that WARP now.</div></div>`;
    $('#igwa').onclick = () => igAct(igS({ action: 'warp_add' }), 'Make a new WARP account on ' + IG.cur.name + '? It takes a minute or two.', { title: 'New WARP account' });
    $('#igwr').onclick = () => igAct(igS({ action: 'google_rotate' }));
    $('#igwt').onclick = async () => { const b = $('#igwt'); b.disabled = true; b.textContent = 'Testing…'; try { await igQuiet(igS({ action: 'warp_list' })); } catch (e) { toast(e.message); } igWarpLoad(id, true); };
    if (gA) $('#igwc').onclick = () => igWarpCountries(id);
    igWarpDraw(IG.wcache && IG.wcache[id]);
    igWarpLoad(id);
  },
  sites() {
    const i = IG.cur.info;
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>My sites <span class="faint" style="font-size:12px;font-weight:500">each with all its subdomains</span></h3><div id="igcl" class="lines"><div class="skel" style="height:60px"></div></div></div>
     <div class="card pad sec"><h3>Add a site</h3><div class="ff"><label class="f">Site<input id="igcs" class="inp mono" placeholder="example.com"></label>
     <label class="f">Route<select id="igcr" class="inp"><option value="">the "My sites" route (${esc(igViaW(i.custom, i))})</option><option value="proxy">Proxy</option><option value="warp">WARP</option><option value="direct">Direct</option></select></label>
     <label class="f row"><input type="checkbox" id="igcall"> On every server in view</label></div>
     <div class="actions" style="margin-top:12px"><button class="btn pri" id="igcadd">Add</button></div></div>`;
    $('#igcadd').onclick = () => igAct({ srv: $('#igcall').checked ? 'all' : IG.cur.id, action: 'custom_add', site: $('#igcs').value.trim(), route: $('#igcr').value });
    igListInto('#igcl', 'custom_list', false, 'custom_del');
  },
  settings() { igOptTab(); },
  checks() {
    const i = IG.cur.info, st = (v) => `<span class="pill ${v === 'SET' || v === 'ON' ? 'on' : 'off'}"><span class="led"></span>${v === 'SET' || v === 'ON' ? 'set' : 'not set'}</span>`;
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>Instagram test account (music) ${igAccBroken(i) ? `<span class="pill off"><span class="led"></span>logged out — ${esc(igAccWhy(i))}</span>` : st(i.igacc)}</h3>
      <p class="muted">With a spare account (not a real one) the server tests on every exit IP whether Instagram music plays.</p>
      <div class="ff"><label class="f">sessionid cookie<input id="igsid" ${igSecret}></label></div>
      <div class="actions" style="margin-top:10px"><button class="btn pri" id="igsidgo">Save & test</button><button class="btn" id="igmt">Music test</button><button class="btn danger" id="igsdel">Remove</button></div></div>
     <div class="card pad sec"><h3>Gemini API key ${st(i.gkey)}</h3>
      <p class="muted">With a free aistudio.google.com key each server asks Gemini through its WARP IPs whether the region is blocked.</p>
      <div class="ff"><label class="f">Key (AIza…)<input id="iggk" ${igSecret}></label><label class="f row"><input type="checkbox" id="iggkall"> On every server in view</label></div>
      <div class="actions" style="margin-top:10px"><button class="btn pri" id="iggkgo">Save</button><button class="btn" id="iggkt">Test on every WARP</button><button class="btn danger" id="iggkdel">Remove</button></div></div>`;
    $('#igsidgo').onclick = () => igAct(igS({ action: 'ig_session', sid: $('#igsid').value.trim() }));
    $('#igmt').onclick = () => igAct(igS({ action: 'ig_test' }));
    $('#igsdel').onclick = () => igAct(igS({ action: 'ig_del' }), 'Remove the test account?');
    $('#iggkgo').onclick = () => igAct({ srv: $('#iggkall').checked ? 'all' : IG.cur.id, action: 'gemkey_set', key: $('#iggk').value.trim() });
    $('#iggkt').onclick = () => igAct(igS({ action: 'gemkey_test' }));
    $('#iggkdel').onclick = () => igAct(igS({ action: 'gemkey_del' }), 'Remove the key?');
  },
  tools() { igtTab(); }
};
// ---- Tests & diagnosis: "Run checks" (light: each service through the users' route and every exit,
// a few KB) as a ✓ / ✗ list with what to do; the heavier tests with what they cost and their last
// result; the traffic as a table; the x-ui panel in one line (Fix only when it needs one).
const IGT = { srv: '', h: null, err: '', busy: 0, pwhy: '' };
const igtGet = (k, id) => { try { return JSON.parse(recall('tp-igt-' + k + '-' + id) || 'null'); } catch (e) { return null; } };
const igtPut = (k, id, v) => remember('tp-igt-' + k + '-' + id, JSON.stringify(v));
const igtExitName = (k) => k === 'direct' ? "Server's own IP" : k === 'ipv6' ? "Server's own IPv6" : /^warp\d+$/.test(k) ? 'WARP ' + k.slice(4) : /^proxy\d+$/.test(k) ? 'Proxy ' + k.slice(5) : k;
// the services that leave through an exit now (clear cases only: BALANCE spreads Instagram over the pool)
function igtRoles(i, k) {
  const out = [];
  for (const [g, name] of [['ig', 'Instagram'], ['google', 'Google']]) {
    const v = i[g] || '';
    let on = k === v || (k === 'direct' && v === 'direct');
    if (/^warp\d+$/.test(k) && /^warp/.test(v)) {
      const n = +k.slice(4);
      on = g === 'google' && +i.gact ? +i.gact === n : i.mode !== 'BALANCE' && +i.active === n && (g === 'ig' || !igGw(i).length);
    }
    if (on) out.push(name);
  }
  return out;
}
const IGTWOUT = { ip: 'standby: different exit IP', ipnew: 'standby: getting a new IP', music: 'parked: no Instagram music', down: 'parked: down' };
const igtIcon = (c) => ({ ok: '✓', bad: '✕', warn: '!', idle: '–', wait: '…' })[c];
const igtRow = (c, name, chips, det, why, btn) => `<div class="wrow trow ${c}"><div class="wn">${igtIcon(c)}</div><div class="wb"><div class="w1"><b>${name}</b>${chips || ''}</div>
  ${det ? `<div class="w2">${det}</div>` : ''}${why ? `<div class="w3">${why}</div>` : ''}</div>${btn ? `<div class="wa">${btn}</div>` : ''}</div>`;
const igtTo = (tab, label) => `<button class="btn sm" data-igto="${tab}">${label}</button>`;
const igtMs = (ms) => ms ? `<span><b class="mono">${ms}</b> ms</span>` : '';
const igtLoc = (loc, ip) => loc || ip ? `<span class="mono" title="${esc(ip || '')}">${esc(loc || '')}${loc && ip ? ' · ' : ''}${esc(ip || '')}</span>` : '';
// a service's line: through the users' route, as a phone gets it
function igtSvc(i, s) {
  const via = (g) => `<span class="chip">${esc(igViaW(i[g], i))}</span>`;
  if (s.k === 'RELAY') return igtRow('warn', 'Services through the users\' route', '', '', esc(s.why), `<button class="btn sm" data-igdo="deploy">Update agent</button>`);
  const g = s.k === 'IG' ? 'ig' : 'google', name = { IG: 'Instagram', GOOGLE: 'Google', GEMINI: 'Gemini' }[s.k] || s.k;
  const cc = s.k === 'IG' ? i.igcc : i.gcc;
  const det = [igtMs(s.ms), igSet(cc) && cc !== 'PROXY' ? `<span>${s.k === 'IG' ? 'Instagram' : 'Google'} sees <b class="mono">${esc(cc)}</b></span>` : ''].join('');
  let btn = '';
  if (!s.ok) btn = s.k === 'IG' ? igtTo(/^warp/.test(i.ig || '') ? 'warp' : /^proxy/.test(i.ig || '') ? 'proxies' : 'routes', /^warp/.test(i.ig || '') ? 'WARP tab' : /^proxy/.test(i.ig || '') ? 'Proxies tab' : 'Routes tab') : '<button class="btn sm" data-tt="diag">Diagnose</button>';
  return igtRow(s.ok ? 'ok' : 'bad', name, via(g), det, s.ok ? '' : esc(s.why), btn);
}
function igtExit(i, e, spd, id) {
  const c = e.ok ? (e.warn ? 'warn' : 'ok') : e.idle ? 'idle' : 'bad';
  const roles = igtRoles(i, e.k).map(r => `<span class="chip fo">${r}</span>`).join('');
  const sp = spd && spd.m && spd.m[e.k];
  const det = [igtLoc(e.loc, e.ip), igtMs(e.ms), sp ? `<span title="1 connection · 8 parallel = what is left of the line">⚡ <b class="mono">${esc(sp.one)}</b> · <b class="mono">${esc(sp.par)}</b> <span class="faint">${igAgo(Math.round(Date.now() / 1000 - sp.at))}</span></span>` : ''].join('');
  let why = e.idle ? esc(IGTWOUT[e.why] || 'standby: ' + e.why) : esc(e.why || ''), btn = '';
  if (c === 'bad' || c === 'warn') {
    if (/^warp/.test(e.k)) btn = igtTo('warp', 'WARP tab');
    else if (/^proxy/.test(e.k)) btn = igtTo('proxies', 'Proxies tab');
    else if (e.k === 'direct') why += ' <span>— the server itself has no internet?</span>';
  }
  const tgt = e.k === 'direct' ? 'd' : e.k === 'ipv6' ? '6' : e.k.replace(/^warp/, 'w').replace(/^proxy/, 'p');
  const menu = e.ok ? moreMenu([{ label: 'Speed test of this exit', attr: `data-sp1="${tgt}"` }]) : '';
  return igtRow(c, igtExitName(e.k), roles, det, why, btn + menu);
}
// the summary of a result: [level, headline]
function igtSum(h) {
  const bad = h.svcs.filter(s => !s.ok).length + h.exits.filter(e => !e.ok && !e.idle).length, warn = h.exits.filter(e => e.ok && e.warn).length;
  return bad ? ['bad', bad === 1 ? '1 problem' : bad + ' problems'] : warn ? ['warn', warn === 1 ? '1 thing to look at' : warn + ' things to look at'] : ['on', 'Everything works'];
}
function igtHealthDraw() {
  const box = $('#igth'); if (!box || !IG.cur) return;
  const i = IG.cur.info, id = IG.cur.id, h = IGT.h, spd = igtGet('spd', id);
  const run = $('#igtrun');
  if (IGT.busy) {
    const t = Math.round((Date.now() - IGT.busy) / 1000), est = Math.max(8, Math.round(((h && h.took) || 15000) / 1000));
    run.disabled = true; run.innerHTML = `Checking… <span class="mono">${t} s</span>`;
    $('#igtbar').hidden = false; $('#igtbar i').style.width = Math.min(95, t / est * 90) + '%';
  } else { run.disabled = false; run.textContent = h ? 'Run again' : 'Run checks'; $('#igtbar').hidden = true; }
  $('#igtwhen').innerHTML = h ? `<span>${igAgo(Math.round(Date.now() / 1000 - h.at))}</span> · <span class="mono">${Math.round(h.took / 1000)} s</span>` : 'not run yet';
  if (!h) {
    // before the first run: the agent's own check of the users' route (every minute)
    const ag = (v, name, g) => igtRow(v === 'OK' ? 'ok' : v === 'FAIL' ? 'bad' : 'idle', name, `<span class="chip">${esc(igViaW(i[g], i))}</span>`, '<span class="faint">checked by the server every minute</span>', v === 'FAIL' ? 'doesn\'t open on the users\' route' : '', '');
    box.innerHTML = (IGT.err ? `<div class="mcrit">${esc(IGT.err)}</div>` : '')
      + `<div class="wlist">${ag(i.igp, 'Instagram', 'ig')}${ag(i.gem, 'Google / Gemini', 'google')}</div>
      <div class="mdesc" style="margin-top:10px">"Run checks" opens Instagram, Google and Gemini the way a user's phone does, and checks every exit (server IP, IPv6, each WARP and proxy) — about 15 seconds and a few KB of traffic.</div>`;
    return;
  }
  const [lvl, head] = igtSum(h);
  const idle = h.exits.filter(e => e.idle).length;
  box.innerHTML = (IGT.err ? `<div class="mcrit">Couldn't run the checks: ${esc(IGT.err)} — showing the last result.</div>` : '')
    + `<div class="igt-head ${lvl}"><span class="igst-dot"></span><b>${head}</b><span class="faint"><span>${h.svcs.length} services · ${h.exits.length} exits</span>${idle ? ` <span>(${idle} on standby)</span>` : ''}</span></div>
    <h4 class="igt-h">Services — the way users get them</h4><div class="wlist">${h.svcs.map(s => igtSvc(i, s)).join('')}</div>
    <h4 class="igt-h">Exits</h4><div class="wlist g2">${h.exits.map(e => igtExit(i, e, spd, id)).join('')}</div>
    ${h.err ? `<div class="mwarn" style="margin-top:8px">${esc(h.err)}</div>` : ''}`;
  $$('[data-sp1]', box).forEach(b => b.onclick = () => igtHeavy('speedtest', b.dataset.sp1));
}
async function igtRunChecks() {
  if (IGT.busy || !IG.cur) return;
  const id = IG.cur.id; IGT.busy = Date.now(); IGT.err = '';
  const tick = setInterval(() => { if (IG.cur && IG.cur.id === id && IG.tab === 'tools') igtHealthDraw(); else clearInterval(tick); }, 1000);
  igtHealthDraw();
  try { const h = await api('/igproxy/health/run', { id }); if (IGT.srv === id) IGT.h = h; } catch (e) { if (IGT.srv === id) IGT.err = e.message; }
  clearInterval(tick); IGT.busy = 0;
  if (IG.cur && IG.cur.id === id && IG.tab === 'tools') { igtHealthDraw(); igtTestsDraw(); igtPanelDraw(); }
}
// the heavier tests: what each costs, when it last ran; its output is kept to show again
// exits a speed test goes through: the last check's list, else server IP + proxies + WARPs
const igtExits = (i) => IGT.h && IGT.h.exits.length ? IGT.h.exits.length : 1 + (+i.proxies || 0) + (+i.warps || 0);
function igtTests(i) {
  const n = igtExits(i);
  return [
    ['status', 'Full test', 'routes, settings, every proxy and WARP tested', '≈ 1 min'],
    ['speedtest', 'Speed test', 'download speed of every exit', `${n} exits · ≈ ${Math.max(1, Math.round(n * 20 / 60))} min · up to ~${n * 300 >= 1000 ? (n * 0.3).toFixed(1) + ' GB' : n * 300 + ' MB'}`, 1],
    ['diag', 'Diagnose Gemini / Google', 'every step of Google\'s path, with what to do', '≈ 1 min'],
    ['gemusers', 'Gemini users', 'users\' Gemini connections per exit, last 10 min', 'instant'],
    ['logs', 'Logs', 'the agent\'s last 150 lines', 'instant'],
  ];
}
function igtTestsDraw() {
  const box = $('#igtx'); if (!box || !IG.cur) return;
  const i = IG.cur.info, id = IG.cur.id;
  box.innerHTML = igtTests(i).map(([k, t, d, cost, heavy]) => {
    const last = igtGet('o-' + k, id);
    return `<div class="igt-t"><button class="igt-tb" data-tt="${k}"><b>${t}</b><small>${d}</small><span class="igt-cost${heavy ? ' heavy' : ''}">${heavy ? '⚠ ' : ''}${cost}</span></button>
      ${last ? `<div class="igt-last"><span class="${last.st === 'ok' ? '' : 'bad'}"><span>${last.st === 'ok' ? 'last run' : last.st === 'cancelled' ? 'stopped' : 'failed'}</span> <span>${igAgo(Math.round(Date.now() / 1000 - last.at))}</span></span><button class="lnk" data-tl="${k}">show</button></div>` : ''}</div>`;
  }).join('');
  $$('[data-tl]', box).forEach(b => b.onclick = () => { const l = igtGet('o-' + b.dataset.tl, id); if (l) igtShow(igtTests(i).find(x => x[0] === b.dataset.tl)[1] + ' — ' + IG.cur.name, l); });
}
// a kept output, read-only, in the same drawer as a running job
function igtShow(title, l) {
  const d = h(`<div class="drawer"><div class="panel"><div class="dh"><div style="display:flex;gap:10px;align-items:center;min-width:0"><span class="pill ${l.st === 'ok' ? 'on' : 'bad'}"><span class="led"></span>${igAgo(Math.round(Date.now() / 1000 - l.at))}</span><b style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(title)}</b></div>
    <div class="actions"><button class="btn sm" data-c title="Copy the output">⧉</button><button class="btn sm" data-x>Close ✕</button></div></div><div class="logbox">${l.out.split('\n').map(x => `<div class="ln ${igColor(x)}">${esc(x) || '&nbsp;'}</div>`).join('')}</div></div></div>`);
  document.body.appendChild(d);
  const close = () => { d.remove(); document.removeEventListener('keydown', key); }, key = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', key);
  $('[data-x]', d).onclick = close; d.onclick = (e) => { if (e.target === d) close(); }; $('[data-c]', d).onclick = (e) => copy(l.out, e.target);
}
// speed test lines: "  WARP 3   182ms   95 Mbps   410 Mbps"
function igtSpeedParse(out, id) {
  const old = igtGet('spd', id) || { m: {} }, at = Math.round(Date.now() / 1000);
  let n = 0;
  out.split('\n').forEach(l => {
    const m = l.match(/^\s*(DIRECT|IPv6|PROXY \d+|WARP \d+)\s+(\S+)\s+(fail|\d+ Mbps)\s+(fail|\d+ Mbps)\s*$/);
    if (!m) return;
    const k = m[1] === 'DIRECT' ? 'direct' : m[1] === 'IPv6' ? 'ipv6' : m[1].toLowerCase().replace(' ', '');
    old.m[k] = { ping: m[2], one: m[3], par: m[4], at }; n++;
  });
  if (n) igtPut('spd', id, old);
}
async function igtHeavy(k, target) {
  const i = IG.cur.info, id = IG.cur.id, name = IG.cur.name;
  const P = { status: { action: 'status' }, speedtest: { action: 'speedtest', target: target || 'all' }, diag: { action: 'diag' }, gemusers: { action: 'gemusers', n: 10 }, logs: { action: 'logs', n: 150 } }[k];
  if (k === 'speedtest') {
    const n = target ? 1 : igtExits(i);
    if (!confirm(`Speed test of ${target ? 'this exit' : 'every exit (' + n + ')'} on ${name}? It downloads for about 20 s per exit — up to ~${n * 300} MB of traffic — and users on this server share the line meanwhile.`)) return;
  }
  try {
    const r = await api('/igproxy/action', igS(P));
    const res = await igRunJob(r.job, igJobTitle(igS(P)) || k);
    if (res.done) {
      if (!target) igtPut('o-' + k, id, { at: Math.round(Date.now() / 1000), st: res.status, out: res.out.slice(-60000) });
      if (k === 'speedtest') igtSpeedParse(res.out, id);
    }
  } catch (e) { toast(e.message); }
  if (IG.cur && IG.cur.id === id && IG.tab === 'tools') { igtTestsDraw(); igtHealthDraw(); }
}
// ---- traffic: domain → exit, as a table; filter chips + own words; Live with pause / stop
const IGTF = [['', 'All'], ['google gemini gstatic youtube ytimg googlevideo', 'Google'], ['instagram fbcdn facebook', 'Instagram']];
const igtXName = (x) => /^warp\d+$/.test(x) ? 'WARP ' + x.slice(4) : /^proxy\d+$/.test(x) ? 'Proxy ' + x.slice(5) : /^v6p\d+$/.test(x) ? 'IPv6 ' + x.slice(3) : { direct: 'Direct', ipv6: 'IPv6', block: 'Blocked' }[x] || x;
const igtXCls = (x) => /^warp/.test(x) ? 'v-warp' : /^proxy/.test(x) ? 'v-proxy' : /^(ipv6|v6p)/.test(x) ? 'v-ipv6' : 'v-direct';
function igtParse(lines) {
  const rows = [], notes = [];
  for (const l of lines) {
    const m = l.match(/^\s*\d{4}\/\d\d\/\d\d (\d\d:\d\d:\d\d)\s+(\S+)\s+->\s+(\S+)\s*(.*)$/);
    if (m) rows.push({ t: m[1], d: m[2].replace(/^(tcp|udp):/, '').replace(/:(443|80)$/, ''), x: m[3], who: m[4].trim() });
    else if (/^\s*!!/.test(l)) notes.push(l.replace(/^\s*!!\s*/, ''));
  }
  return { rows, notes };
}
const IGTR = { srv: '', f: '', w: '', rows: [], notes: [], mode: '', job: '', paused: false, buf: 0, end: 0 };
const igtWords = () => [IGTR.f, IGTR.w].join(' ').trim();
function igtTrafficDraw() {
  const box = $('#igtrt'); if (!box) return;
  const live = IGTR.mode === 'live' && IGTR.job;
  $$('#igtrf button').forEach(b => b.classList.toggle('on', b.dataset.f === IGTR.f));
  $('#igrec').disabled = !!live;
  $('#igwatch').outerHTML = live ? `<span class="igt-live" id="igwatch"><span class="pill acc"><span class="led"></span>live <span class="mono">${Math.max(0, Math.round((IGTR.end - Date.now()) / 1000))}</span> s</span>
      <button class="btn sm" id="igtp">${IGTR.paused ? '▶ Resume' : '⏸ Pause'}</button><button class="btn sm danger" id="igts">■ Stop</button></span>`
    : `<button class="btn sm pri" id="igwatch">▶ Live 60 s</button>`;
  if (live) { $('#igtp').onclick = () => { IGTR.paused = !IGTR.paused; IGTR.buf = 0; igtTrafficDraw(); }; $('#igts').onclick = () => api('/jobs/cancel', { ID: IGTR.job }).catch(e => toast(e.message)); }
  else $('#igwatch').onclick = igtLive;
  if (!IGTR.mode) { box.innerHTML = '<div class="faint igt-empty">Which exit each site leaves through. "Last 40" shows what already happened; "Live" shows new connections for 60 s — open the app on a phone meanwhile.</div>'; return; }
  const rows = IGTR.rows.slice(-300).reverse();
  box.innerHTML = (IGTR.notes.length ? `<div class="mwarn">${IGTR.notes.map(esc).join('<br>')}</div>` : '')
    + (IGTR.paused && IGTR.buf ? `<div class="faint igt-empty"><span>paused ·</span> <b class="mono">${IGTR.buf}</b> <span>new connections waiting</span></div>` : '')
    + (rows.length ? `<div class="igt-tr"><table class="tbl"><thead><tr><th>Time</th><th>Site</th><th>Exit</th><th>Who</th></tr></thead><tbody>${rows.map(r => `<tr${r.who === 'user' ? '' : ' class="faint"'}><td class="mono" data-l="Time">${esc(r.t)}</td><td class="mono igt-d" data-l="Site">${esc(r.d)}</td>
        <td data-l="Exit"><b class="${igtXCls(r.x)}">${esc(igtXName(r.x))}</b></td><td data-l="Who">${r.who === 'user' ? 'user' : 'test'}</td></tr>`).join('')}</tbody></table></div>`
      : `<div class="faint igt-empty">${live ? 'Waiting for connections…' : 'No connection' + (igtWords() ? ' with these words' : '') + '.'}</div>`);
}
async function igtRecent() {
  const id = IG.cur.id; IGTR.mode = 'recent'; IGTR.rows = []; IGTR.notes = [];
  const b = $('#igrec'); b.disabled = true; b.textContent = 'Reading…';
  try { const p = igtParse((await igQuiet(igS({ action: 'recent', word: igtWords() }))).split('\n')); if (IGTR.srv === id) Object.assign(IGTR, p); }
  catch (e) { IGTR.notes = [e.message]; }
  if (IG.cur && IG.cur.id === id && IG.tab === 'tools') { const b2 = $('#igrec'); if (b2) b2.textContent = 'Last 40'; igtTrafficDraw(); }
}
async function igtLive() {
  const id = IG.cur.id;
  let r; try { r = await api('/igproxy/action', igS({ action: 'watch', word: igtWords() })); } catch (e) { toast(e.message); return; }
  Object.assign(IGTR, { mode: 'live', job: r.job, rows: [], notes: [], paused: false, buf: 0, end: Date.now() + 62000 });
  igtTrafficDraw();
  let fails = 0;
  for (;;) {
    await new Promise(s => setTimeout(s, 1000));
    const here = IG.cur && IG.cur.id === id && IG.tab === 'tools' && STATE.view === 'igproxy' && IGTR.job === r.job;
    if (!here) { api('/jobs/cancel', { ID: r.job }).catch(() => {}); if (IGTR.job === r.job) IGTR.job = ''; return; }
    let j; try { j = await api('/jobs?id=' + r.job); fails = 0; } catch (e) { if (++fails < 6) continue; IGTR.notes = [e.message]; IGTR.job = ''; igtTrafficDraw(); return; }
    const p = igtParse(igLines(j));
    if (IGTR.paused) IGTR.buf = Math.max(0, p.rows.length - IGTR.rows.length); else { IGTR.rows = p.rows; IGTR.notes = p.notes; }
    if (j.status !== 'running') { IGTR.rows = p.rows; IGTR.notes = p.notes; IGTR.job = ''; IGTR.paused = false; igtTrafficDraw(); return; }
    igtTrafficDraw();
  }
}
// ---- the x-ui / xray panel on this server: one line; Fix only when it gets in Google's way, Undo only after a fix
const IGPANEL = { OK: ['ok', 'passes Google to igproxy'], FIXED: ['ok', 'fixed: its first rule sends Google to igproxy'], SOME: ['bad', 'sends part of Google elsewhere first'],
  V6: ['bad', 'sends Google over IPv6 (blocked) — random failures'], MARK: ['bad', 'marks Google traffic so igproxy never catches it'], AWAY: ['bad', 'sends Google to another exit first'],
  BLOCK: ['bad', 'blocks Google'], NONE: ['idle', 'no x-ui / xray panel on this server'], ERR: ['warn', 'its config couldn\'t be read'] };
function igtPanelDraw() {
  const box = $('#igtp2'); if (!box || !IG.cur) return;
  const i = IG.cur.info, st = IGPANEL[i.panel] || ['idle', 'not checked yet'], bad = st[0] === 'bad';
  const why = IGT.pwhy || (IGT.h && IGT.h.panelWhy) || '';
  box.innerHTML = `<div class="igt-pl ${st[0]}"><span class="igd ${st[0] === 'ok' ? 'ok' : bad ? 'bad' : ''}"></span><div class="igt-pt"><b>x-ui / xray panel</b> <span class="igt-ps">${st[1]}</span>
    <span class="igt-i" tabindex="0" title="If the panel on this server blocks Google or sends it to another exit, igproxy never sees it. Fix adds one rule at the top of the panel's routing: tested first, backed up, and undone automatically if the panel doesn't come back.">ⓘ</span>
    ${why && i.panel !== 'OK' ? `<small class="mono">${esc(why)}</small>` : ''}</div>
    <div class="igt-pa"><button class="btn sm" id="igpc">Check</button>${bad ? '<button class="btn sm pri" id="igpf">Fix</button>' : ''}${i.panel === 'FIXED' ? '<button class="btn sm danger" id="igpu2">Undo</button>' : ''}</div></div>`;
  $('#igpc').onclick = async () => {
    const b = $('#igpc'), id = IG.cur.id; b.disabled = true; b.textContent = 'Checking…';
    try {
      const out = await igQuiet(igS({ action: 'panel_check' })), m = out.match(/panel: ([A-Z]+)(?: - (.*))?/);
      if (m && IG.cur && IG.cur.id === id) { IG.cur.info.panel = m[1]; IGT.pwhy = (m[2] || '').trim(); }
      else if (!m) toast(out.trim().split('\n').pop() || 'no answer');
    } catch (e) { toast(e.message); }
    if (IG.cur && IG.cur.id === id && IG.tab === 'tools') igtPanelDraw();
  };
  if ($('#igpf')) $('#igpf').onclick = () => igAct(igS({ action: 'panel_fix' }), 'Add one rule at the top of the panel\'s routing? Its Xray restarts for 2-3 seconds.');
  if ($('#igpu2')) $('#igpu2').onclick = () => igAct(igS({ action: 'panel_undo' }), 'Remove the igproxy rule from the panel?');
}
function igtTab() {
  const id = IG.cur.id;
  if (IGT.srv !== id) { Object.assign(IGT, { srv: id, h: null, err: '', busy: 0, pwhy: '' }); }
  if (IGTR.srv !== id) { if (IGTR.job) api('/jobs/cancel', { ID: IGTR.job }).catch(() => {}); Object.assign(IGTR, { srv: id, f: '', w: '', rows: [], notes: [], mode: '', job: '', paused: false, buf: 0 }); }
  $('#igtab').innerHTML = `<div class="card pad sec igt">
      <h3>Health check <span class="faint igt-when" id="igtwhen"></span><span class="grow"></span><button class="btn pri" id="igtrun">Run checks</button></h3>
      <div class="igt-bar" id="igtbar" hidden><i></i></div><div id="igth"></div></div>
    <div class="card pad sec igt"><h3>More tests <span class="faint igt-when">open in a side panel; the last result is kept</span></h3><div class="igt-tests" id="igtx"></div></div>
    <div class="card pad sec igt"><h3>Traffic <span class="faint igt-when">site → exit</span></h3>
      <div class="igt-tbar"><div class="seg iso-seg" id="igtrf">${IGTF.map(([w, t]) => `<button data-f="${w}">${t}</button>`).join('')}</div>
        <input id="igtw" class="inp" dir="ltr" placeholder="other words: site.com …" spellcheck="false" autocapitalize="off" value="${esc(IGTR.w)}">
        <button class="btn sm" id="igrec">Last 40</button><button class="btn sm pri" id="igwatch">▶ Live 60 s</button></div>
      <div id="igtrt"></div></div>
    <div class="card pad sec igt" id="igtp2"></div>`;
  $('#igtrun').onclick = igtRunChecks;
  $$('#igtrf button').forEach(b => b.onclick = () => { IGTR.f = b.dataset.f; igtTrafficDraw(); if (IGTR.mode === 'recent') igtRecent(); });
  $('#igtw').oninput = (e) => { IGTR.w = e.target.value.trim(); };
  $('#igtw').onkeydown = (e) => { if (e.key === 'Enter' && !IGTR.job) igtRecent(); };
  $('#igrec').onclick = igtRecent;
  $('#igtab').addEventListener('click', (e) => { const b = e.target.closest('[data-tt]'); if (b) igtHeavy(b.dataset.tt); });
  // the fix buttons inside the list (open a tab / update the agent)
  $('#igtab').addEventListener('click', (e) => {
    const t = e.target.closest('[data-igto]'); if (t) { e.preventDefault(); IG.tab = t.dataset.igto; igRender(); return; }
    const d = e.target.closest('[data-igdo]'); if (d) igAct(igS({ action: d.dataset.igdo }), `Install / update the agent on ${IG.cur.name}? A few seconds without routing; settings and WARPs are kept.`);
  });
  igtHealthDraw(); igtTestsDraw(); igtTrafficDraw(); igtPanelDraw();
  if (!IGT.h && !IGT.busy) api('/igproxy/health?id=' + encodeURIComponent(id)).then(h => { if (h && h.at && IGT.srv === id && !IGT.h) { IGT.h = h; if (IG.tab === 'tools') { igtHealthDraw(); igtPanelDraw(); } } }).catch(() => {});
}
async function igRemove(uninstall) {
  const s = IG.cur;
  if (uninstall) {
    if (!confirm(`Remove igproxy from ${s.name} completely? Its settings and WARPs on that server are deleted.`)) return;
    try { const r = await api('/igproxy/action', igS({ action: 'uninstall' })); const res = await igRunJob(r.job, 'Uninstall igproxy'); if (!res.done) return; } catch (e) { return toast(e.message); }
  } else if (!confirm(`Take ${s.name} off the IG routing page? igproxy keeps running on it.`)) return;
  try { await api('/igproxy/enable', { ID: s.id, On: false }); IG.cur = null; toast('Removed'); igLoad(true); } catch (e) { toast(e.message); }
}
// ---- Settings tab: the agent's settings in four groups, one Save for the tab (this server or
// every server in view), each value against its default. /igproxy/opts reads the setting files
// themselves: the info line has no "WARPs only for Google" nor the countries for Google.
const IGOPT = { srv: null, o: null, err: '', edit: {}, adv: false, to: 'one' };
const igoN = (lo, hi) => (v) => { v = latinDigits(String(v)).trim(); return /^\d{1,5}$/.test(v) && +v >= lo && +v <= hi ? String(+v) : null; };
const IGO = {
  mode: { t: 'seg', label: 'How the WARPs are used', opts: [['failover', 'One at a time'], ['balance', 'Spread the load']] },
  minspeed: { t: 'num', label: 'Minimum speed', unit: 'Mbps', help: 'a slower WARP is not chosen (its music must work too)', ok: igoN(0, 10000), bad: '0 to 10000' },
  minwarps: { t: 'num', label: 'Keep at least', unit: 'WARPs', help: 'missing ones are made automatically · 0 = none made', ok: igoN(0, 20), bad: '0 to 20' },
  warpauto: { t: 'sw', label: 'More WARPs with the load', help: 'on top of the minimum: 3 to 10 by the 24 h peak, added at night (03-06)' },
  gwarps: { t: 'num', label: 'Google\'s own WARPs', unit: 'WARPs', help: 'the last ones serve only Google, Instagram uses the rest · 0 = shared', ok: igoN(0, 9), bad: '0 to 9' },
  gcountries: { t: 'cc', label: 'Allowed countries', help: 'Google only gets a WARP it places in one of these; none fits → a proxy for now',
    ok: (v) => { v = latinDigits(String(v)).toUpperCase().split(/[\s,]+/).filter(Boolean).join(' '); return /^[A-Z]{2}( [A-Z]{2}){0,60}$/.test(v) ? v : null; }, bad: 'two-letter codes, like US GB DE' },
  gspread: { t: 'sw', label: 'Spread Google over its WARPs', help: 'for many Gemini users: every WARP IP instead of one' },
  grotate: { t: 'num', label: 'Fresh IP every', unit: 'min', help: '0 = only when the IP breaks · 20 suggested', ok: (v) => { const n = igoN(0, 1440)(v); return n !== null && (n === '0' || +n >= 10) ? n : null; }, bad: '0, or 10 to 1440' },
  gall: { t: 'sw', label: 'All of Google', help: 'also google.com, gstatic and googleapis, not only Gemini, sign-in and search (YouTube video stays direct)' },
  guard: { t: 'sw', label: 'Fast switch (WARP guard)', help: 'the WARP in use is checked every 5 s; down, slow or no music → the best other one, live' },
  musiccheck: { t: 'num', label: 'Music check every', unit: 'min', help: '0 = off · plays a song with the test account', ok: igoN(0, 60), bad: '0 to 60' },
  autokey: { t: 'sw', label: 'Find WARP+ keys', help: 'tries WARP+ keys posted in a public channel' },
  geosite: { t: 'sw', label: 'Full domain lists (geosite)', help: 'updated daily, loaded at night' },
  kwg: { t: 'sw', label: 'Kernel WARP (all CPU cores)', help: 'for a busy server: the IPv4 WARPs run as kernel WireGuard, not inside the router; same accounts and exit IPs' },
};
const IGO_SEC = [['pool', 'WARP accounts', ['mode', 'minspeed', 'minwarps', 'warpauto']], ['google', 'Google · Gemini', ['gwarps', 'gcountries', 'gspread', 'grotate', 'gall']],
  ['ig', 'Instagram', ['guard', 'musiccheck']], ['adv', 'Advanced', ['autokey', 'geosite', 'kwg']]];
const igoShow = (k, v) => k === 'mode' ? (v === 'balance' ? 'Spread the load' : 'One at a time') : IGO[k].t === 'sw' ? (v === 'on' ? 'on' : 'off') : v;
async function igOptLoad(id) {
  IGOPT.err = '';
  try { const o = await api('/igproxy/opts?id=' + encodeURIComponent(id)); if (IGOPT.srv === id) IGOPT.o = o; }
  catch (e) { if (IGOPT.srv === id) IGOPT.err = e.message; }
  igOptDraw();
}
function igOptTab() {
  if (IGOPT.srv !== IG.cur.id) Object.assign(IGOPT, { srv: IG.cur.id, o: null, err: '', edit: {}, to: 'one' });
  IGOPT.adv = recall('tp-igadv') === '1';
  igOptDraw();
  if (!Object.keys(IGOPT.edit).length) igOptLoad(IG.cur.id); // unsaved edits survive a repaint of the page
}
// the value a field shows: what is typed, else what the server has
const igoCur = (k) => k in IGOPT.edit ? IGOPT.edit[k] : IGOPT.o.val[k];
// a typed value, checked: [normalised value or null, changed from the server's]
function igoChk(k) {
  if (!(k in IGOPT.edit)) return [IGOPT.o.val[k], false];
  const f = IGO[k], v = f.ok ? f.ok(IGOPT.edit[k]) : IGOPT.edit[k];
  return [v, v === null || v !== IGOPT.o.val[k]];
}
// why a setting does nothing now (another one rules it out), or a warning next to it
function igoWhy(k, i) {
  const val = (x) => igoChk(x)[0] ?? IGOPT.o.val[x], n = (x) => +val(x), on = (x) => val(x) === 'on';
  if (k === 'grotate' && n('gwarps') > 0) return ['off', 'Google has its own WARPs, so it keeps one steady IP and moves only when it fails. Set Google\'s own WARPs to 0 to use this.'];
  if (k === 'grotate' && on('gspread')) return ['off', 'Not used while Google is spread over its WARPs.'];
  if (k === 'musiccheck' && !on('guard')) return ['off', 'Runs inside the WARP guard: turn the fast switch on.'];
  if (k === 'musiccheck' && n('musiccheck') > 0 && i.igacc !== 'SET') return ['warn', 'No Instagram test account yet: nothing is checked.', 'checks'];
  if (k === 'musiccheck' && n('musiccheck') > 0 && igAccBroken(i)) return ['warn', 'The test account is logged out: nothing is checked.', 'checks'];
  if (k === 'mode' && val('mode') === 'balance') return ['warn', 'Instagram music may break: the users\' IP changes between WARPs.'];
  if (k === 'warpauto' && on('warpauto') && n('minwarps') === 0) return ['info', 'With 0 above, only the load decides (3 or more).'];
  if (k === 'guard' && i.guard === 'DOWN' && on('guard')) return ['warn', 'On, but its service isn\'t running: Re-apply in the ⋯ menu.'];
  if (k === 'kwg' && on('kwg') && /^\d+$/.test(i.kwg || '')) return ['info', `${+i.kwg} kernel interface(s) up`];
  return null;
}
function igoRow(k, i) {
  const f = IGO[k], o = IGOPT.o, cur = igoCur(k), [nv, dirty] = igoChk(k), bad = nv === null, why = igoWhy(k, i);
  const def = o.def[k], notDef = (bad ? cur : nv) !== def, off = why && why[0] === 'off';
  let ctl;
  if (f.t === 'sw') ctl = `<label class="sw2"><input type="checkbox" data-ok="${k}"${cur === 'on' ? ' checked' : ''}><i></i></label>`;
  else if (f.t === 'seg') ctl = `<div class="seg iso-seg">${f.opts.map(([v, t]) => `<button type="button" data-ok="${k}" data-v="${v}" class="${cur === v ? 'on' : ''}">${t}</button>`).join('')}</div>`;
  else if (f.t === 'cc') ctl = `<input class="inp mono iso-cc${bad ? ' err' : ''}" data-ok="${k}" dir="ltr" spellcheck="false" autocapitalize="characters" value="${esc(cur)}">`;
  else ctl = `<span class="iso-num"><input class="inp mono${bad ? ' err' : ''}" data-ok="${k}" inputmode="numeric" dir="ltr" value="${esc(cur)}"><span class="faint">${f.unit}</span></span>`;
  const reset = `<button type="button" class="iso-rs" data-rs="${k}" title="Back to the default: ${esc(igoShow(k, def))}"${notDef ? '' : ' hidden'}>↺</button>`;
  const cnt = f.t === 'cc' && !bad ? `<small class="faint iso-cnt">${String(nv).split(' ').length} countries${nv === def ? ' · the default list' : ''}</small>` : '';
  return `<div class="iso-row${dirty ? ' dirty' : ''}${off ? ' off' : ''}${f.t === 'cc' ? ' wide' : ''}" data-row="${k}">
    <div class="iso-d"><b>${f.label}${notDef ? `<span class="iso-nd" title="not the default (${esc(igoShow(k, def))})"></span>` : ''}</b>${f.help ? `<small>${f.help}</small>` : ''}${cnt}
      ${bad ? `<small class="iso-err">${f.bad}</small>` : ''}${why ? `<small class="iso-why ${why[0]}">${why[1]}${why[2] ? ` <a href="#" data-igto="${why[2]}">Open</a>` : ''}</small>` : ''}</div>
    <div class="iso-c">${ctl}${reset}</div></div>`;
}
function igOptDraw() {
  const box = $('#igtab'); if (!box || !IG.cur || IG.tab !== 'settings' || IGOPT.srv !== IG.cur.id) return;
  const i = IG.cur.info, o = IGOPT.o;
  if (!o) {
    box.innerHTML = IGOPT.err ? `<div class="card pad"><div class="igx-empty"><div class="big">⚠️</div><b>Couldn't read the settings</b><p class="mono" data-notr>${esc(IGOPT.err)}</p><button class="btn" id="igoretry">Try again</button></div></div>`
      : '<div class="card pad"><div class="skel" style="height:220px"></div></div>';
    $('#igoretry') && ($('#igoretry').onclick = () => { IGOPT.err = ''; igOptDraw(); igOptLoad(IG.cur.id); });
    return;
  }
  if (o.none) { box.innerHTML = '<div class="card pad"><div class="igx-empty"><div class="big">📦</div><b>The agent isn\'t installed on this server</b></div></div>'; return; }
  const has = (k) => (o.keys || []).includes(k);
  const keys = Object.keys(IGO).filter(has), dirty = keys.filter(k => igoChk(k)[1]), bad = dirty.filter(k => igoChk(k)[0] === null);
  const nd = keys.filter(k => o.val[k] !== o.def[k]).length, n = igList().length;
  const routeNote = (g) => { const v = i[g.toLowerCase()] || ''; return /^warp/.test(v) ? '' : `<div class="iso-note"><b>${IGSV[g]}</b> → <b>${esc(igViaW(v, i))}</b> <span>now · these count once it goes out through WARP (Routes tab)</span></div>`; };
  const sec = ([id, title, ks]) => {
    const rows = ks.filter(has); if (!rows.length) return '';
    const chg = rows.filter(k => igoChk(k)[1]).length;
    const body = (id === 'google' ? routeNote('GOOGLE') : id === 'ig' ? routeNote('IG') : '') + rows.map(k => igoRow(k, i)).join('');
    if (id === 'adv') return `<details class="iso-sec iso-adv"${IGOPT.adv || chg ? ' open' : ''}><summary><h4>${title}</h4><span class="faint">${rows.length} more</span></summary>${body}</details>`;
    return `<section class="iso-sec"><h4>${title}</h4>${body}</section>`;
  };
  box.innerHTML = `<div class="card pad sec igw iso"><h3>Settings ${nd ? `<span class="chip" title="settings that are not the default">${nd} changed from default</span>` : '<span class="chip">all default</span>'}<span class="grow"></span>
      <span class="wact"><button class="btn sm" id="igoload" title="read the settings from the server again">↻</button></span></h3>
    ${IGO_SEC.map(sec).join('')}
    <div class="iso-bar${dirty.length ? ' on' : ''}">
      ${dirty.length ? `<span class="iso-n"><b>${dirty.length}</b> unsaved</span><button class="btn sm ghost" id="igoundo">Undo</button><span class="grow"></span>
        <label class="iso-to"><span class="faint">Save on</span><select class="inp" id="igoto"><option value="one"${IGOPT.to === 'one' ? ' selected' : ''}>This server</option>${n > 1 ? `<option value="all"${IGOPT.to === 'all' ? ' selected' : ''}>All ${n} servers in view</option>` : ''}</select></label>
        <button class="btn pri" id="igosave"${bad.length ? ' disabled' : ''}>Save</button>`
      : '<span class="faint">● = not the default · ↺ = back to the default. Saving can also write the changed settings on every server in view.</span>'}</div></div>`;
  const set = (k, v) => { IGOPT.edit[k] = v; if (v === o.val[k]) delete IGOPT.edit[k]; igOptDraw(); };
  $$('[data-ok]', box).forEach(el => {
    const k = el.dataset.ok;
    if (el.type === 'checkbox') el.onchange = () => set(k, el.checked ? 'on' : 'off');
    else if (el.tagName === 'BUTTON') el.onclick = () => set(k, el.dataset.v);
    else {
      // typing marks only this row (a full redraw would drop the caret); leaving the field redraws all
      el.oninput = () => { IGOPT.edit[k] = el.value; const [v, d] = igoChk(k); el.classList.toggle('err', v === null); el.closest('.iso-row').classList.toggle('dirty', d); };
      el.onchange = () => { const [v] = igoChk(k); set(k, v === null ? el.value : v); };
    }
  });
  $$('[data-rs]', box).forEach(b => b.onclick = () => set(b.dataset.rs, o.def[b.dataset.rs]));
  $$('[data-igto]', box).forEach(a => a.onclick = (e) => { e.preventDefault(); IG.tab = a.dataset.igto; igRender(); });
  const adv = $('.iso-adv', box); if (adv) adv.ontoggle = () => { IGOPT.adv = adv.open; remember('tp-igadv', adv.open ? '1' : '0'); };
  $('#igoload').onclick = () => { IGOPT.o = null; IGOPT.edit = {}; igOptDraw(); igOptLoad(IG.cur.id); };
  $('#igoundo') && ($('#igoundo').onclick = () => { IGOPT.edit = {}; igOptDraw(); });
  $('#igoto') && ($('#igoto').onchange = (e) => { IGOPT.to = e.target.value; });
  $('#igosave') && ($('#igosave').onclick = async () => {
    const setv = {}; dirty.forEach(k => { setv[k] = igoChk(k)[0]; });
    const all = IGOPT.to === 'all', id = IG.cur.id;
    if (all && !confirm(`Save ${dirty.length} setting(s) on all ${n} servers in view? Only these change; each server's other settings stay.`)) return;
    try {
      const r = await api('/igproxy/opts/save', { srv: all ? 'all' : id, view: igView(), set: setv });
      await igRunJob(r.job, all ? `Settings — ${n} servers` : 'Settings — ' + IG.cur.name, () => {});
      if (IGOPT.srv === id) { IGOPT.edit = {}; IGOPT.o = null; igOptDraw(); igOptLoad(id); }
      igRefreshAfter(all ? { srv: 'all' } : { srv: id });
    } catch (e) { toast(e.message); }
  });
}
// ---- WARP tab: one row per WARP account (/igproxy/warps: the agent's state + one Cloudflare trace each)
const igAgo = (s) => s < 0 ? '' : s < 90 ? 'just now' : s < 3600 ? Math.round(s / 60) + ' min ago' : s < 86400 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago';
const igGw = (i) => (i.gw || '').split(',').filter(x => /^\d+$/.test(x)).map(Number);
// how Instagram and Google leave now, in words
function igWarpSvc(i, d) {
  const bal = i.mode === 'BALANCE', igw = /^warp/.test(i.ig || ''), gw = /^warp/.test(i.google || ''), n = igWarpNeed(i);
  const pool = d ? d.warps.filter(w => w.state === 'ok' && !igGw(i).includes(w.n)).length : +(i.pool || '').split('/')[0] || 0;
  const kind = i.ig === 'warp6' ? 'WARP IPv6' : 'WARP';
  const ig = !igw ? 'not on WARP' : bal ? `${kind} · ${pool} WARP${pool === 1 ? '' : 's'} share it` : `${kind} ${+i.active ? +i.active : '—'}`;
  const g = !gw ? 'not on WARP' : i.gcc === 'PROXY' ? 'proxy for now' : +i.gact ? `WARP ${+i.gact}` : 'with Instagram';
  const cell = (k, v, sub, cls) => `<div class="svc"><small>${k}</small><b class="${cls || ''}">${esc(v)}</b>${sub ? `<span class="note">${sub}</span>` : ''}</div>`;
  return `<div class="svcs">${cell('Instagram', ig, igw ? (i.igcc && i.igcc !== '-' ? `Instagram sees <b class="mono">${esc(i.igcc)}</b>` : '') : `goes ${esc(igViaW(i.ig, i))} → Routes tab`, igw ? 'v-warp' : 'v-direct')}
    ${cell('Google / Gemini', g, gw ? (i.gcc === 'PROXY' ? 'no WARP in an allowed country' : i.gcc && i.gcc !== '-' ? `Google sees <b class="mono">${esc(i.gcc)}</b>` : '') : `goes ${esc(igViaW(i.google, i))} → Routes tab`, gw && i.gcc !== 'PROXY' ? 'v-warp' : i.gcc === 'PROXY' ? 'v-proxy' : 'v-direct')}
    ${n ? cell('WARP accounts', `${n.have} · ${n.total} needed`, `busiest 5 min in 24 h: <b class="mono">${n.p}</b> connections → ${n.ig} for Instagram${n.g ? ' + ' + n.g + ' for Google' : ''}${i.wauto === 'ON' ? ' · made automatically' : ''}`, n.have < n.total ? 'wbad' : '') : ''}</div>`;
}
const IGWOUT = { ip: 'Standby: different exit IP', ipnew: 'Getting a new IP', music: 'Parked: no Instagram music', down: 'Parked: down' };
function igWarpRow(i, d, w) {
  const gws = igGw(i), own = gws.includes(w.n), bal = i.mode === 'BALANCE';
  const igOn = /^warp/.test(i.ig || '') && !own && w.state === 'ok' && (bal || d.active === w.n);
  const gOn = /^warp/.test(i.google || '') && i.gcc !== 'PROXY' && (d.gact ? d.gact === w.n : !gws.length && igOn);
  const st = w.state === 'ok' ? ['Working', 'ok'] : w.state === 'out' ? [IGWOUT[w.why] || 'Not in use: ' + w.why, w.why === 'ip' ? 'idle' : 'warn']
    : w.state === 'repair' ? ['Being repaired' + (w.fails ? ` (try ${w.fails})` : ''), 'warn'] : ['Down', 'bad'];
  const v6 = w.ip && w.ip.includes(':');
  const exit = w.ip ? `<span class="mono" title="${esc(w.ip)}">${w.loc ? esc(w.loc) + ' · ' : ''}${esc(w.ip)}</span> <span class="tag">${v6 ? 'IPv6' : 'IPv4'}</span>`
    : `<span class="faint">${w.state === 'out' ? 'not tested while on standby' : 'no exit now'}</span>`;
  const music = w.music === 'ok' ? '<span class="good">music OK</span>' : w.music === 'no' ? `<span class="bad" title="${esc(w.musicWhy || '')}">no music</span>` : w.music === 'down' ? '<span class="bad">was down</span>' : '<span class="faint">music not tested</span>';
  const test = w.music ? `<span>${music}${w.mbps ? ` · <b class="mono">${w.mbps}</b> Mbps` : ''}</span><span class="faint">${igAgo(w.testAge)}</span>` : '<span class="faint">no speed test yet</span>';
  const roles = (igOn ? '<span class="chip fo">Instagram</span>' : '') + (gOn ? '<span class="chip fo">Google</span>' : '') + (own && !gOn ? '<span class="chip">Google\'s reserve</span>' : '');
  const useG = own && i.gw !== undefined, inUse = useG ? gOn : (igOn && (bal || d.active === w.n));
  const prim = inUse || w.state !== 'ok' ? '' : `<button class="btn sm" data-${useG ? 'wg' : 'wu'}="${w.n}">${useG ? 'Use for Google' : 'Use'}</button>`;
  const menu = moreMenu([{ label: 'Delete WARP ' + w.n + '…', attr: `data-wd="${w.n}"`, danger: true }]);
  return `<div class="wrow${igOn || gOn ? ' on' : ''}${w.state === 'ok' ? '' : ' dim'}">
    <div class="wn mono">${w.n}</div>
    <div class="wb"><div class="w1"><span class="igd ${st[1] === 'ok' ? 'ok' : st[1] === 'bad' ? 'bad' : ''}"></span><b class="wst ${st[1]}">${st[0]}</b>
      <span class="tag${w.plus ? ' plus' : ''}">${w.plus ? 'WARP+' : 'Free'}</span>${roles}</div>
      <div class="w2"><span>${exit}</span>${w.gcc ? `<span>Google sees <b class="mono">${esc(w.gcc)}</b></span>` : ''}${test}</div>
      ${w.next && w.state === 'ok' ? `<div class="w3">gets a new account soon: ${esc(w.next)}</div>` : ''}${w.old ? '<div class="w3">old account: delete and add again for automatic WARP+ keys</div>' : ''}</div>
    <div class="wa${prim ? ' p' : ''}">${inUse ? '<span class="inuse" title="in use">✓<span class="t"> in use</span></span>' : prim}${menu}</div></div>`;
}
function igWarpDraw(d, err) {
  const box = $('#igwl'); if (!box || !IG.cur) return;
  const i = IG.cur.info;
  if (err && !d) { box.innerHTML = `<div class="mcrit" style="margin:0">Couldn't read the WARPs: ${esc(err)} <button class="btn sm" id="igwrt">Try again</button></div>`; $('#igwrt').onclick = () => { igWarpDraw(); igWarpLoad(IG.cur.id); }; return; }
  if (!d) { box.innerHTML = '<div class="skel" style="height:64px"></div>'.repeat(Math.min(8, Math.max(2, +i.warps || 3))); return; }
  const ws = d.warps, ok = ws.filter(w => w.state === 'ok').length, idle = ws.filter(w => w.state === 'out').length, bad = ws.length - ok - idle;
  $('#igwsum').innerHTML = ws.length ? `<span class="chip">${ws.length} accounts</span><span class="chip">${ok} working</span>${idle ? `<span class="chip">${idle} on standby</span>` : ''}${bad ? `<span class="chip bad">${bad} down</span>` : ''}` : '';
  $('.igw .wsum').innerHTML = igWarpSvc(i, d);
  if (!ws.length) { box.innerHTML = '<div class="empty" style="padding:22px 10px"><div class="big">☁️</div>No WARP account on this server yet.<div class="actions" style="justify-content:center;margin-top:10px"><button class="btn pri" id="igwa2">+ Add WARP</button></div></div>'; $('#igwa2').onclick = () => $('#igwa').click(); return; }
  box.innerHTML = (err ? `<div class="mwarn">Couldn't refresh (${esc(err)}) — showing what was read ${igAgo(Math.round(Date.now() / 1000 - d.at))}.</div>` : '')
    + (d.sel === 'none' ? '<div class="mwarn">No WARP has Instagram music and the minimum speed now, so the current one is kept. Adding a WARP looks for a better IP.</div>' : '')
    + ws.map(w => igWarpRow(i, d, w)).join('')
    + (i.mode === 'BALANCE' && /^warp/.test(i.ig || '') && d.poolIP ? `<div class="mdesc">Instagram's WARPs all leave from one exit IP (<span class="mono">${esc(d.poolIP)}</span>). A WARP that comes out with another IP waits on standby and is checked again later.</div>` : '');
  $$('[data-wu]', box).forEach(b => b.onclick = () => igAct(igS({ action: 'warp_use', n: b.dataset.wu })));
  $$('[data-wg]', box).forEach(b => b.onclick = () => igAct(igS({ action: 'google_use', n: b.dataset.wg })));
  $$('[data-wd]', box).forEach(b => b.onclick = () => igAct(igS({ action: 'warp_del', n: b.dataset.wd }), `Delete WARP ${b.dataset.wd} on ${IG.cur.name}? Its account is removed and the WARPs after it move up one number.`, { title: 'Delete WARP' }));
}
async function igWarpLoad(id, fresh) {
  const here = () => IG.cur && IG.cur.id === id && IG.tab === 'warp';
  try {
    const d = await api('/igproxy/warps?id=' + encodeURIComponent(id));
    IG.wcache = IG.wcache || {}; IG.wcache[id] = d;
    if (here()) igWarpDraw(d);
  } catch (e) { if (here()) igWarpDraw(IG.wcache && IG.wcache[id], e.message); }
  if (fresh && $('#igwt')) { $('#igwt').disabled = false; $('#igwt').textContent = 'Test all'; }
}
// "Country per WARP": Google's country for every WARP, asked fresh, written into the rows
async function igWarpCountries(id) {
  toast('Asking Google for every WARP… (up to a minute)');
  try {
    const out = await igQuiet(igS({ action: 'google_countries' }));
    const d = IG.wcache && IG.wcache[id]; if (!d) return;
    out.split('\n').forEach(l => { const m = l.match(/^\s*WARP (\d+)\s+([A-Z]{2}|\?)/); if (m) { const w = d.warps.find(x => x.n === +m[1]); if (w) w.gcc = m[2] === '?' ? '' : m[2]; } });
    const al = out.match(/allowed for Google:\s*(.*)/);
    if (IG.cur && IG.cur.id === id && IG.tab === 'warp') { igWarpDraw(d); if (al) toast('Allowed countries for Google: ' + al[1].trim()); }
  } catch (e) { toast(e.message); }
}
async function igListInto(sel, action, slow, delA, useA, gA) {
  const box = $(sel); if (!box) return;
  if (slow) box.innerHTML = '<div class="mdesc" style="margin:0">Testing… (a few seconds)</div>';
  try {
    const out = await igQuiet(igS({ action }));
    if (!$(sel)) return;
    const ls = out.split('\n').filter(l => l.trim());
    const gw = (IG.cur.info.gw || '').split(',');
    box.innerHTML = ls.length ? ls.map(l => {
      const m = l.match(/^\s*(\d+)\)/) || l.match(/^\s*WARP (\d+)\b/), hl = l.includes('ACTIVE') || l.includes('GOOGLE');
      const im = l.match(/(\d+\.\d+\.\d+\.\d+):(1237\d)\b/), lt = l.trim() + (im && igSrvByIP(im[1]) ? '  · ' + igInternal(im[1], im[2]) : '');
      return `<div class="ln${hl ? ' hl' : ''}"><span class="t mono" title="${esc(lt)}">${esc(lt)}</span>${m && gA && gw.includes(m[1]) ? `<button class="btn sm" data-gu="${m[1]}" title="only Google moves to this WARP">Google</button>` : ''}${m && useA ? `<button class="btn sm" data-u="${m[1]}">Use</button>` : ''}${m && delA ? `<button class="btn sm danger" data-d="${m[1]}">Delete</button>` : ''}</div>`;
    }).join('') : '<div class="faint">empty</div>';
    $$('[data-d]', box).forEach(b => b.onclick = () => igAct(igS({ action: delA, n: b.dataset.d }), 'Delete number ' + b.dataset.d + '?'));
    $$('[data-u]', box).forEach(b => b.onclick = () => igAct(igS({ action: useA, n: b.dataset.u })));
    $$('[data-gu]', box).forEach(b => b.onclick = () => igAct(igS({ action: gA, n: b.dataset.gu })));
  } catch (e) { toast(e.message); box.innerHTML = ''; }
}

// ---- the Proxies tab: one row per proxy (state, exit IP and country, ping, what uses it now),
// a test per proxy, Delete / "use only this one" by what the proxy is (not its number, which
// shifts when the list changes), and an add form that says what each server answered.
const IGPX = { srv: null, rows: null, err: '', busy: {}, open: false, form: {}, res: null, auto: {} };
const igpxType = (t) => t === 'socks5' ? 'SOCKS5' : 'HTTP';
const igpxDigits = (s) => String(s || '').replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
// what goes out through proxy r now: services pinned to it, the services on "all proxies" (while
// Instagram accepts its IP), and Google's fallback (proxy 1 when no WARP is in an allowed country)
function igpxUses(i, r) {
  const out = [];
  for (const g of Object.keys(IGSV)) {
    const v = i[g.toLowerCase()] || '';
    if (v === 'proxy' + r.n) out.push([g, 'only']);
    else if (v === 'proxy' && !r.bad && !(r.test && !r.test.ok)) out.push([g, 'pool']); // the balancer skips a dead one
    else if (g === 'GOOGLE' && /^warp/.test(v) && i.gcc === 'PROXY' && r.n === 1) out.push([g, 'fallback']);
  }
  return out;
}
// "http://user:pass@host:port", "socks5://host:port", "user:pass@host:port", "host:port:user:pass", "host:port"
function igpxParse(s) {
  s = igpxDigits(s).trim(); if (!s) return null;
  let type = 'http'; const m = /^([a-z0-9]+):\/\//i.exec(s);
  if (m) {
    const k = m[1].toLowerCase();
    if (k === 'http') type = 'http'; else if (['socks5', 'socks5h', 'socks'].includes(k)) type = 'socks5';
    else return { err: k === 'https' ? 'HTTPS proxies are not supported: use HTTP or SOCKS5' : 'Unknown proxy type: ' + k };
    s = s.slice(m[0].length);
  }
  s = s.replace(/\/+$/, '');
  const dec = (x) => { try { return decodeURIComponent(x); } catch (e) { return x; } };
  let user = '', pass = '', hp = s;
  const at = s.lastIndexOf('@');
  if (at >= 0) { const c = s.slice(0, at), k = c.indexOf(':'); user = dec(k < 0 ? c : c.slice(0, k)); pass = k < 0 ? '' : dec(c.slice(k + 1)); hp = s.slice(at + 1); }
  let host, port;
  const v6 = /^\[([^\]]+)\]:(\d+)(?::(.*))?$/.exec(hp);
  if (v6) {
    host = '[' + v6[1] + ']'; port = v6[2];
    if (at < 0 && v6[3]) { const k = v6[3].indexOf(':'); user = k < 0 ? v6[3] : v6[3].slice(0, k); pass = k < 0 ? '' : v6[3].slice(k + 1); }
  } else {
    const f = hp.split(':');
    if (f.length < 2 || !/^\d+$/.test(f[1])) return { err: 'No port found: write it as host:port' };
    host = f[0]; port = f[1];
    if (at < 0 && f.length >= 3) { user = f[2]; pass = f.slice(3).join(':'); } // host:port:user:pass
  }
  return { type, host, port, user, pass };
}
// the same checks as the server (it checks again): a clear word before anything is sent
function igpxCheck(f) {
  const host = igpxDigits(f.host).trim(), port = igpxDigits(f.port).trim();
  if (!host) return 'Host is empty';
  if (/:\/\/|\s|\//.test(host) || /^[^\[:]*:[^:]*$/.test(host)) return 'Host: an IP address or a domain name only (no http://, no :port)';
  if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) return 'Port: a number from 1 to 65535';
  if (f.user && (/\s/.test(f.user) || f.user.includes(':'))) return 'User: no spaces and no ":"';
  if (f.pass && /\s/.test(f.pass)) return 'Password: no spaces';
  if (f.pass && !f.user.trim()) return 'A password needs a user';
  return '';
}
async function igpxLoad(test, n) {
  const id = IG.cur && IG.cur.id; if (!id) return;
  if (test) IGPX.busy[n || 'all'] = true; else if (IGPX.srv !== id) { IGPX.rows = null; IGPX.err = ''; }
  IGPX.srv = id; igpxDraw();
  try {
    const r = await api('/igproxy/proxies', test ? { srv: id, test: 1, n: n || 0 } : { srv: id });
    if (IGPX.srv !== id) return;
    IGPX.rows = r.proxies || []; IGPX.err = '';
  } catch (e) { if (IGPX.srv !== id) return; if (IGPX.rows && test) toast(e.message); else IGPX.err = e.message; }
  finally { if (test) delete IGPX.busy[n || 'all']; }
  igpxDraw();
  // a first look at a server whose proxies were never tested: test them now (a few seconds)
  if (!test && IGPX.rows && IGPX.rows.length && IGPX.rows.every(r => !r.test) && !IGPX.auto[id]) { IGPX.auto[id] = 1; igpxLoad(true); }
}
async function igpxInfo() {
  try { IG.cur.info = await api('/igproxy/info?id=' + encodeURIComponent(IG.cur.id)); } catch (e) { /* the list still shows */ }
}
function igpxTab() {
  if (IGPX.srv !== IG.cur.id) { IGPX.open = false; IGPX.res = null; IGPX.form = {}; IGPX.ferr = ''; igpxLoad(); return; }
  igpxDraw();
}
// a proxy as a row of the WARP tab's kind (.wrow: number, state line, details line, Test + ⋯)
function igpxRow(r, i) {
  const t = r.test, busy = IGPX.busy[r.n] || IGPX.busy.all;
  const st = busy ? ['Testing…', 'idle', ''] : r.bad ? ['Instagram rejects its IP', 'warn', 'bad'] : !t ? ['Not tested yet', 'idle', ''] : t.ok ? ['Working', 'ok', 'ok'] : ['Not working', 'bad', 'bad'];
  const uses = igpxUses(i, r);
  const facts = [`<span class="mono" dir="ltr" data-notr>${esc(r.host)}:${esc(r.port)}</span>`];
  if (r.user) facts.push(`<span class="mono" dir="ltr" data-notr title="user (shortened)">👤 ${esc(r.user)}</span>`);
  if (t && t.ok && !busy) {
    if (t.ip) facts.push(`<span title="exit IP and the country the internet sees"><span class="mono" dir="ltr" data-notr>${t.loc ? esc(t.loc) + ' · ' : ''}${esc(t.ip)}</span></span>`);
    facts.push(t.ms ? `<span title="time to Instagram through this proxy">Instagram <b class="mono" dir="ltr">${+t.ms} ms</b></span>` : '<span class="bad">Instagram doesn\'t answer</span>');
    facts.push(t.google ? '<span class="good">Google ✓</span>' : '<span class="bad">Google ✕</span>');
  }
  if (r.music && !busy) facts.push(r.music === 'ok' ? '<span class="good" title="the agent\'s last Instagram music test through it">music OK</span>' : '<span class="bad" title="the agent\'s last Instagram music test through it">no music</span>');
  if (t && !busy) facts.push(`<span class="faint">tested <span>${esc(ago(t.at))}</span></span>`);
  const roles = uses.map(u => `<span class="chip fo" title="${u[1] === 'only' ? 'only this proxy' : u[1] === 'pool' ? 'with the other working proxies (fastest first)' : 'until a WARP in an allowed country is found'}">${esc(IGSV[u[0]])}${u[1] === 'only' ? ' · only this one' : u[1] === 'fallback' ? ' · fallback' : ''}</span>`).join('');
  const menu = moreMenu([
    ...['IG', 'GOOGLE'].filter(g => i[g.toLowerCase()] !== 'proxy' + r.n).map(g => ({ label: 'Use only this one for ' + esc(IGSV[g]), attr: `data-use="${g}"` })),
    { label: 'Copy address', attr: 'data-copy' },
    { label: 'Delete proxy ' + (+r.n) + '…', attr: 'data-del', danger: true }]);
  return `<div class="wrow${uses.length ? ' on' : ''}${t && !t.ok && !busy ? ' dim' : ''}${busy ? ' busy' : ''}" data-k="${esc(r.key)}">
    <div class="wn mono">${+r.n}</div>
    <div class="wb"><div class="w1"><span class="igd ${st[2]}"></span><b class="wst ${st[1]}">${st[0]}</b><span class="tag">${igpxType(r.type)}</span>${roles}</div>
      <div class="w2">${facts.join('')}</div></div>
    <div class="wa p"><button class="btn sm" data-test ${busy ? 'disabled' : ''}>Test</button>${menu}</div></div>`;
}
function igpxDraw() {
  const box = $('#igtab'); if (!box || !IG.cur || IG.tab !== 'proxies' || IGPX.srv !== IG.cur.id) return;
  const i = IG.cur.info || {}, rows = IGPX.rows, n = rows ? rows.length : 0;
  // the services that use proxies here, in one line
  const on = Object.keys(IGSV).filter(g => /^proxy/.test(i[g.toLowerCase()] || '')).map(g => IGSV[g] + (i[g.toLowerCase()] === 'proxy' ? '' : ' (proxy ' + i[g.toLowerCase()].slice(5) + ')'));
  const gfb = /^warp/.test(i.google || '') && i.gcc === 'PROXY';
  let list;
  if (IGPX.err && !rows) list = `<div class="igx-empty"><div class="big">⚠️</div><b>Couldn't read the proxies</b><p class="muted mono" data-notr>${esc(IGPX.err)}</p><button class="btn" id="igxretry">Try again</button></div>`;
  else if (!rows) list = '<div class="skel" style="height:64px"></div><div class="skel" style="height:64px;margin-top:6px"></div>';
  else if (!n) list = `<div class="igx-empty"><div class="big">🧦</div><b>No proxies on this server yet</b><p class="muted">With a proxy here, Instagram, Google and the others can go out through it (Routes tab). Each proxy is tested before it is added.</p></div>`;
  else list = `<div class="wlist">${rows.map(r => igpxRow(r, i)).join('')}</div>`;
  const others = igList().length;
  const f = IGPX.form;
  box.innerHTML = `<div class="card pad sec igx"><h3>Proxies ${n ? `<span class="chip">${n}</span>` : ''}<span class="grow"></span>
      ${n ? `<button class="btn sm" id="igxtall" ${IGPX.busy.all ? 'disabled' : ''}>${IGPX.busy.all ? 'Testing…' : 'Test all'}</button>` : ''}
      <button class="btn sm pri" id="igxadd" ${IGPX.open ? 'hidden' : ''}>+ Add proxy</button></h3>
    ${n ? `<div class="mdesc igx-desc">${on.length ? 'Through the proxies now: <b>' + esc(on.join(' · ')) + '</b>' : 'No service goes through a proxy now (Routes tab).'}${gfb ? ' · Google is on proxy 1 until a WARP in an allowed country is found.' : ''}</div>` : ''}
    ${IGPX.open ? `<div class="igx-add"><h4>Add a proxy</h4>
      <label class="f"><span>Paste a proxy <span class="faint">(optional — fills the boxes)</span></span><input id="igxurl" class="inp mono" dir="ltr" autocomplete="off" spellcheck="false" placeholder="http://user:pass@host:port   ·   host:port:user:pass"></label>
      <div class="igx-grid"><label class="f">Type<select id="igxt" class="inp"><option value="http">HTTP</option><option value="socks5"${f.type === 'socks5' ? ' selected' : ''}>SOCKS5</option></select></label>
        <label class="f">Host<input id="igxh" class="inp mono" dir="ltr" autocomplete="off" spellcheck="false" placeholder="1.2.3.4 · proxy.example.com" value="${esc(f.host || '')}"></label>
        <label class="f">Port<input id="igxp" class="inp mono" dir="ltr" inputmode="numeric" autocomplete="off" placeholder="8080" value="${esc(f.port || '')}"></label></div>
      <div class="igx-grid2"><label class="f"><span>User <span class="faint">(optional)</span></span><input id="igxu" class="inp mono" dir="ltr" autocomplete="off" spellcheck="false" value="${esc(f.user || '')}"></label>
        <label class="f">Password<input id="igxw" ${igSecret} dir="ltr" value="${esc(f.pass || '')}"></label></div>
      ${others > 1 ? `<label class="f row igx-allr"><input type="checkbox" id="igxall"${f.all ? ' checked' : ''}> Add it to every server in view too (${others})</label>
        <div class="mdesc" style="margin-top:2px">Each server tests the proxy itself first and keeps it only if it works from there; a server that already has it is left as it is. You get each server's answer below.</div>` : ''}
      <div class="mcrit igx-err" id="igxerr" ${IGPX.ferr ? '' : 'hidden'}>${esc(IGPX.ferr || '')}</div>
      <div class="actions"><button class="btn pri" id="igxgo" ${IGPX.adding ? 'disabled' : ''}>${IGPX.adding ? 'Testing the proxy…' : 'Test & add'}</button><button class="btn" id="igxcancel" ${IGPX.adding ? 'disabled' : ''}>Cancel</button></div>
      ${IGPX.res ? igpxResults(IGPX.res) : ''}</div>` : ''}
    ${list}</div>`;
  igpxWire(box);
}
function igpxResults(r) {
  const word = { added: ['✓', 'ok', 'added'], exists: ['=', 'ok', 'already there'], failed: ['✕', 'bad', 'not added'], unreachable: ['✕', 'bad', 'not reached'] };
  const head = r.results.length === 1 ? '' : (r.ok ? '<b>Done on every server</b>' : `<div class="igx-rsum"><span>added</span> <b>${+r.added}</b> · <span>already there</span> <b>${+r.exists}</b> · <span>failed</span> <b>${+r.failed}</b></div>`);
  return `<div class="igx-res ${r.ok ? 'ok' : 'bad'}">${head}${r.results.map(x => {
    const w = word[x.status] || ['?', '', x.status];
    return `<div class="igx-rl ${w[1]}"><span class="igx-ri">${w[0]}</span><b data-notr>${esc(x.name)}</b><span>${w[2]}${x.n ? ` <span class="faint mono">#${+x.n}</span>` : ''}</span>${x.ip ? `<span class="mono" dir="ltr" data-notr>${esc(x.loc)} · ${esc(x.ip)} · ${+x.ms} ms</span>` : ''}${x.msg && x.status !== 'added' ? `<span class="faint igx-msg">${esc(x.msg)}</span>` : ''}</div>`;
  }).join('')}</div>`;
}
const igpxClearPaste = (box) => { const u = $('#igxurl', box); u.value = ''; u.placeholder = '✓ read — the boxes below are filled'; };
function igpxWire(box) {
  const s = IG.cur;
  const keep = () => { const g = (id) => $(id, box); if (!g('#igxh')) return; IGPX.form = { type: g('#igxt').value, host: g('#igxh').value, port: g('#igxp').value, user: g('#igxu').value, pass: g('#igxw').value, all: !!(g('#igxall') && g('#igxall').checked) }; };
  const showErr = (m) => { IGPX.ferr = m; const e = $('#igxerr', box); if (e) { e.textContent = m; e.hidden = !m; } };
  $('#igxretry', box) && ($('#igxretry', box).onclick = () => igpxLoad());
  $('#igxtall', box) && ($('#igxtall', box).onclick = () => igpxLoad(true));
  $('#igxadd', box) && ($('#igxadd', box).onclick = () => { IGPX.open = true; IGPX.res = null; IGPX.ferr = ''; igpxDraw(); $('#igxurl') && $('#igxurl').focus(); });
  $$('.igx-add input, .igx-add select', box).forEach(x => x.addEventListener('input', () => { keep(); if (IGPX.ferr) showErr(''); }));
  $('#igxall', box) && ($('#igxall', box).onchange = keep);
  // fills the boxes as soon as it reads as a proxy; what it can't read is said once typing stops (change)
  $('#igxurl', box) && $('#igxurl', box).addEventListener('input', (e) => {
    const p = igpxParse($('#igxurl', box).value);
    if (!p || p.err) return;
    $('#igxt', box).value = p.type; $('#igxh', box).value = p.host; $('#igxp', box).value = p.port; $('#igxu', box).value = p.user; $('#igxw', box).value = p.pass;
    // the pasted text holds the password in the clear: it leaves the box once read (pasted at once only;
    // typed text stays until it reads as a whole proxy with a password)
    if (p.pass && e.inputType !== 'insertText' && e.inputType !== 'deleteContentBackward') igpxClearPaste(box);
    keep();
  });
  $('#igxurl', box) && $('#igxurl', box).addEventListener('change', () => { const p = igpxParse($('#igxurl', box).value); if (p && p.err) showErr(p.err); else if (p && p.pass) igpxClearPaste(box); });
  $('#igxcancel', box) && ($('#igxcancel', box).onclick = () => { IGPX.open = false; IGPX.form = {}; IGPX.res = null; IGPX.ferr = ''; igpxDraw(); });
  $('#igxgo', box) && ($('#igxgo', box).onclick = async () => {
    keep(); const f = IGPX.form, err = igpxCheck(f);
    if (err) return showErr(err);
    const id = s.id, all = f.all && igList().length > 1;
    IGPX.adding = true; IGPX.res = null; IGPX.ferr = ''; igpxDraw();
    try {
      const r = await api('/igproxy/proxy/add', { srv: all ? 'all' : id, view: igView(), type: f.type, host: igpxDigits(f.host).trim(), port: igpxDigits(f.port).trim(), user: f.user.trim(), pass: f.pass });
      IGPX.adding = false;
      if (IGPX.srv !== id) return;
      const mine = r.results.find(x => x.id === id);
      if (r.results.length === 1 && mine && mine.status === 'added') {
        IGPX.open = false; IGPX.form = {}; IGPX.res = null;
        toast(`Proxy added — working · ${mine.loc || '?'} · ${mine.ms} ms`);
      } else { IGPX.res = r; if (r.ok) IGPX.form = {}; }
      await igpxInfo(); igpxLoad();
      if (all) igLoad(true);
    } catch (e) { IGPX.adding = false; IGPX.ferr = e.message; igpxDraw(); }
  });
  $$('.wrow', box).forEach(row => {
    const r = (IGPX.rows || []).find(x => x.key === row.dataset.k); if (!r) return;
    const name = `${igpxType(r.type)} ${r.host}:${r.port}`;
    $('[data-test]', row).onclick = () => igpxLoad(true, r.n);
    $('[data-copy]', row).onclick = (e) => { copy(r.host + ':' + r.port, e.target); };
    $$('[data-use]', row).forEach(b => b.onclick = async () => {
      const g = b.dataset.use;
      if (!confirm(`${IGSV[g]} goes out only through ${name} from now on (the router reloads for a few seconds). Go on?`)) return;
      row.classList.add('busy');
      try { await api('/igproxy/proxy/cmd', { srv: s.id, key: r.key, do: 'use', svc: g }); toast(`${IGSV[g]} → ${name}`); } catch (e) { toast(e.message); }
      await igpxInfo(); igpxLoad();
    });
    $('[data-del]', row).onclick = async () => {
     
      const u = igpxUses(IG.cur.info || {}, r).filter(x => x[1] === 'only').map(x => IGSV[x[0]]);
      if (!confirm(`Delete ${name} from ${s.name}?` + (u.length ? `\n\n${u.join(', ')} use only this proxy now: they move to all the other proxies.` : '') + (r.n === 1 ? '\n\nProxy 1 is Google\'s fallback: the next proxy takes its place.' : ''))) return;
      row.classList.add('busy');
      try { await api('/igproxy/proxy/cmd', { srv: s.id, key: r.key, do: 'del' }); toast('Proxy deleted · ' + name); } catch (e) { toast(e.message); }
      await igpxInfo(); igpxLoad();
    };
  });
}

// ---- route table: every server × service
function igMatrix(box) {
  if (!IG.data) { box.innerHTML = '<div class="skel" style="height:200px"></div>'; return; }
  const L = igList().filter(s => s.info.ig), maxp = Math.max(0, ...L.map(s => +s.info.proxies || 0));
  if (!L.length) { box.innerHTML = '<div class="card empty"><div class="big">🔀</div>No server with a running agent to route.</div>'; return; }
  box.innerHTML = `<div class="card pad mat"><div class="actions" style="justify-content:flex-end;margin-bottom:6px"><button class="btn pri" id="igmApply" disabled>Apply changes</button></div>
    <table class="tbl igt"><thead><tr><th>Server</th>${Object.keys(IGSV).map(g => `<th>${IGSV[g]}</th>`).join('')}</tr></thead><tbody>
    <tr><td><b>All servers →</b></td>${Object.keys(IGSV).map(g => `<td data-l="${IGSV[g]}"><select data-all="${g}"><option value="">—</option>${igViaOpts(g, '', maxp)}</select></td>`).join('')}</tr>
    ${L.map(s => `<tr><td><b data-notr>${esc(s.name)}</b> ${igOwner(s)} ${s.info.state === 'OK' ? '' : igPill(s.info.state)}</td>${Object.keys(IGSV).map(g => { const v = s.info[g.toLowerCase()]; return `<td data-l="${IGSV[g]}"><select data-s="${esc(s.id)}" data-g="${g}" data-cur="${esc(v)}">${igViaOpts(g, v, +s.info.proxies || 0, s.info)}</select></td>`; }).join('')}</tr>`).join('')}</tbody>
    </table><div class="mdesc">The "All servers" row sets one service on every row (not applied yet). Servers that are offline or without the agent aren't in the table.</div></div>`;
  const mark = () => { let n = 0; $$('select[data-s]', box).forEach(x => { const c = x.value !== x.dataset.cur; x.classList.toggle('chg', c); n += c; }); $('#igmApply').disabled = !n; $('#igmApply').textContent = n ? `Apply ${n} change${n > 1 ? 's' : ''}` : 'Apply changes'; };
  $$('select[data-s]', box).forEach(x => x.onchange = mark);
  // a choice a server doesn't have (Proxy 3 where it has two) leaves that row as it was
  $$('select[data-all]', box).forEach(x => x.onchange = () => { if (!x.value) return; $$(`select[data-g="${x.dataset.all}"][data-s]`, box).forEach(y => { if ([...y.options].some(o => o.value === x.value)) y.value = x.value; }); mark(); });
  $('#igmApply').onclick = async () => {
    const ch = $$('select[data-s]', box).filter(x => x.value !== x.dataset.cur).map(x => ({ srv: x.dataset.s, svc: x.dataset.g, via: x.value }));
    if (!ch.length || !confirm(`Apply ${ch.length} route change${ch.length > 1 ? 's' : ''}?`)) return;
    // one after the other: two changes on one server at once would race
    const label = (c) => ((IG.data.servers.find(s => s.id === c.srv) || {}).name || c.srv) + ' · ' + IGSV[c.svc] + ' → ' + igViaW(c.via);
    const left = []; // what was not applied, and why: said at the end (the rest used to be dropped silently)
    for (let k = 0; k < ch.length; k++) {
      const c = ch[k];
      let r; try { r = await api('/igproxy/action', { srv: c.srv, action: 'route', svc: c.svc, via: c.via }); } catch (e) { left.push(label(c) + ' — ' + e.message); continue; }
      const res = await igRunJob(r.job, 'Route — ' + ((IG.data.servers.find(s => s.id === c.srv) || {}).name || '') + ' · ' + IGSV[c.svc]);
      if (!res.done) {
        left.push(label(c) + ' — not finished when the window closed (it may still be running)');
        ch.slice(k + 1).forEach(x => left.push(label(x) + ' — not started'));
        break;
      }
      if (res.status !== 'ok') left.push(label(c) + ' — ' + (res.status === 'cancelled' ? 'stopped' : 'failed'));
    }
    igLoad(true);
    if (left.length) alertModal('Route changes not applied', left.join('\n'));
  };
}

// ---- every server at once
function igBulk(box) {
  const card = (i, t, d, id) => `<div class="card pad"><h3 style="margin:0 0 6px">${i} ${t}</h3><p class="muted" style="margin:0 0 12px;font-size:13px">${d}</p><button class="btn pri" data-b="${id}">Run</button></div>`;
  box.innerHTML = `<p class="muted" style="margin-top:0">On every server in view, one after the other.</p><div class="grid cards">
    ${card('🧪', 'Test all', 'Tests every proxy and WARP of every server.', 'test')}
    ${card('🔄', 'Fresh Google IP everywhere', 'When users complain about Gemini: on each server where Google goes through WARP, it moves to a fresh WARP IP now. The summary at the end says where it moved and where not.', 'rotate')}
    ${card('⬆️', 'Update old agents', 'Installs the current agent where an old one runs (a few seconds per server).', 'deploy')}
    ${card('🛠', 'Fix panels', 'Where the x-ui panel diverts Google, adds one rule at the top of its routing.', 'fix')}
    ${card('📜', 'Logs of all', 'The last 40 igproxy log lines of each server.', 'logs')}
    ${card('👥', 'Gemini users', 'Gemini connections of the last 10 minutes, per exit.', 'gem')}</div>`;
  const nr = { refresh: false };
  const B = {
    test: () => igAct({ srv: 'all', action: 'status_short' }, null, nr),
    rotate: () => igAct({ srv: 'all', action: 'google_rotate' }, `Move Google to a fresh WARP IP on every server in view (${igList().length}) now? Gemini chats open on the old IPs are cut and reconnect on the new one. Servers where Google is not on WARP are left as they are.`),
    deploy: () => igAct({ srv: 'all', action: 'deploy', old: 1 }, 'Update the agent on the servers with an old one?'),
    fix: () => { const bad = igList().filter(s => s.info.state === 'PANEL'); if (!bad.length) return toast('Every panel lets Google reach igproxy — nothing to fix');
      igAct({ srv: bad.map(s => s.id), action: 'panel_fix' }, bad.map(s => s.name).join(', ') + ' — fix the panel on these? Each panel\'s Xray restarts for 2-3 seconds.'); },
    logs: () => igAct({ srv: 'all', action: 'logs', n: 40 }, null, nr),
    gem: () => igAct({ srv: 'all', action: 'gemusers', n: 10 }, null, nr),
  };
  $$('[data-b]', box).forEach(b => b.onclick = B[b.dataset.b]);
}

// ---- backup / copy settings
async function igBackup(box) {
  const L = igList(), opts = L.map(s => `<option value="${esc(s.id)}" data-notr>${esc(s.name)}${isAdmin() && s.owner ? ' (' + esc(s.owner) + ')' : ''}</option>`).join('');
  box.innerHTML = `<p class="muted" style="margin-top:0">WARP accounts are never copied or backed up: each server keeps its own.</p>
   <div class="card pad sec"><h3>Copy settings from one server to others</h3><div class="ff">
    <label class="f">From<select id="igcf" class="inp">${opts}</select></label>
    <label class="f" style="grid-column:span 2">What<select id="igcp" class="inp"><option value="routes proxies ig tg opts">Everything: routes, sites, proxies, test account + Gemini key, Telegram, settings</option><option value="routes">Routes + sites only</option><option value="proxies">Proxies only</option><option value="routes proxies">Routes + sites + proxies</option><option value="opts">WARP settings only</option></select></label></div>
    <div style="margin:12px 0" id="igct">${L.map(s => `<label class="f row" style="display:inline-flex;margin-inline-end:14px"><input type="checkbox" value="${esc(s.id)}" checked> ${nm(s.name + (isAdmin() && s.owner ? ' (' + s.owner + ')' : ''))}</label>`).join('')}</div>
    <button class="btn pri" id="igcgo">Copy to the ticked servers</button></div>
   <div class="card pad sec"><h3>Backup</h3><p class="muted">Routes, sites, proxies, test account, Telegram and settings of each server (the last 10 per server). Each account's backups are its own.</p>
    <button class="btn pri" id="igbgo">Back up every server now</button>
    <h3 style="margin-top:18px">Restore</h3><div id="igbl" class="faint">…</div></div>`;
  $('#igcgo').onclick = async () => {
    const from = $('#igcf').value, to = $$('#igct input:checked').map(x => x.value).filter(x => x !== from);
    if (!to.length) return toast('No target server ticked');
    if (!confirm(`Write the settings of ${$('#igcf').selectedOptions[0].text} to ${to.length} server(s)?`)) return;
    try { const r = await api('/igproxy/copy', { from, parts: $('#igcp').value, to }); igRunJob(r.job, 'Copy settings', () => igLoad(true)); } catch (e) { toast(e.message); }
  };
  $('#igbgo').onclick = async () => { try { const r = await api('/igproxy/backup', { View: igView() }); await igRunJob(r.job, 'Backup', () => { if (IG.sub === 'backup' && $('#igbl')) igBackup(box); }); } catch (e) { toast(e.message); } };
  try {
    const f = ((await api('/igproxy/backups')).files || []).filter(x => shownOwner(x.owner));
    if (!$('#igbl')) return;
    const nameOf = (x) => { const s = (IG.data?.servers || []).find(y => y.id === x.server); return (s ? s.name : x.file) + ' · ' + new Date(x.t * 1000).toLocaleString() + (isAdmin() && x.owner ? ' (' + x.owner + ')' : ''); };
    $('#igbl').outerHTML = f.length ? `<div class="ff"><label class="f" style="grid-column:span 2">Backup<select id="igbf" class="inp">${f.map((x, k) => `<option value="${k}">${esc(nameOf(x))}</option>`).join('')}</select></label><label class="f">Onto<select id="igbs" class="inp">${opts}</select></label><button class="btn danger" id="igbgo2" style="align-self:end">Restore</button></div>` : '<div class="faint">No backup yet</div>';
    if (!f.length) return;
    const pre = () => { const b = f[+$('#igbf').value]; if (b && b.server && [...$('#igbs').options].some(o => o.value === b.server)) $('#igbs').value = b.server; };
    $('#igbf').onchange = pre; pre();
    $('#igbgo2').onclick = async () => {
      const b = f[+$('#igbf').value];
      if (!confirm(`Replace the settings of ${$('#igbs').selectedOptions[0].text} with this backup?`)) return;
      try { const r = await api('/igproxy/restore', { File: b.file, Owner: b.owner, Srv: $('#igbs').value }); igRunJob(r.job, 'Restore', () => igLoad(true)); } catch (e) { toast(e.message); }
    };
  } catch (e) { toast(e.message); }
}
// the server list keeps itself current while it's on screen (not while a form or a log is open)
setInterval(() => {
  if (document.hidden || STATE.view !== 'igproxy' || IG.cur || IG.sub !== 'servers' || $('.drawer,.modal') || document.activeElement?.matches('input,select,textarea')) return;
  igLoad();
}, 60000);

boot();
