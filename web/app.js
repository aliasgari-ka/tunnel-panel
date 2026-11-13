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
    renderAuth('login', STATE.settings.panelName, 'expired');
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
  STATE.settings = (settings && settings.settings) || {}; STATE.hostHw = (settings && settings.hostHw) || null; STATE.agentPin = settings.agentPin || ''; STATE.agentPort = settings.agentPort || 7020;
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
// a country's flag as a bundled SVG (/flags/xx.svg): Windows shows no flag emoji, only the two
// letters. Unknown or bad codes give ''. ccText = the plain code, for <option> and title text.
const FLAGS = new Set('ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cp cr cu cv cw cx cy cz de dg dj dk dm do dz ec ee eg eh er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu ic id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pc pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um un us uy uz va vc ve vg vi vn vu wf ws xk ye yt za zm zw'.split(' '));
const ccText = (cc) => /^[A-Za-z]{2}$/.test(cc || '') ? cc.toUpperCase() : '';
function flag(cc) {
  const c = ccText(cc).toLowerCase();
  if (!c || !FLAGS.has(c === 'uk' ? 'gb' : c)) return c ? `<span class="flagi flagc" title="${c.toUpperCase()}">${c.toUpperCase()}</span>` : '';
  return `<img class="flagi" src="/flags/${c === 'uk' ? 'gb' : c}.svg" alt="${c.toUpperCase()}" title="${c.toUpperCase()}" width="20" height="15" loading="lazy" draggable="false">`;
}
const serverFlag = (id) => { const s = serverById(id); return s && s.country ? flag(s.country) + ' ' : ''; };
const serverLabel = (s) => (ccText(s.country) ? ccText(s.country) + ' · ' : '') + s.name;

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
// small line icons (currentColor): they follow the theme and the accent
const ICON = {
  mark: '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="5.5" cy="12" r="2.6"/><circle cx="18.5" cy="12" r="2.6"/><path d="M8.3 12h7.4"/><path d="M8 7.5c2.6-2.3 5.4-2.3 8 0M8 16.5c2.6 2.3 5.4 2.3 8 0" opacity=".55"/></svg>',
  eye: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  out: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M10 16l-4-4 4-4M6 12h10"/></svg>',
  gear: '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  warn: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5M12 16.2v.3"/></svg>',
};
// the language picker of the sign-in page and the panel's settings: the choice is per browser
// (tp-lang) and the page reloads in it; what was typed in the username field comes along
const langSeg = () => `<div class="seg langseg" role="group" aria-label="Language" data-notr>${[['fa', 'فارسی'], ['en', 'English']].map(([l, t]) => `<button type="button" data-lang="${l}" class="${(window.tpLang || 'fa') === l ? 'on' : ''}" aria-pressed="${(window.tpLang || 'fa') === l}" lang="${l}">${t}</button>`).join('')}</div>`;
function wireLang(root) {
  $$('[data-lang]', root).forEach(b => b.onclick = () => {
    if (b.dataset.lang === (window.tpLang || 'fa')) return;
    const u = $('#af [name=u]'); if (u && u.value) { try { sessionStorage.setItem('tp-auth-u', u.value); } catch (e) {} }
    window.tpSetLang && window.tpSetLang(b.dataset.lang);
  });
}
// why the sign-in page is showing, when it isn't the first visit
const AUTH_WHY = { expired: 'Your session ended. Sign in again.' };
function renderAuth(mode, name, why) {
  const reg = mode === 'register';
  document.body.innerHTML = '';
  let keepU = ''; try { keepU = sessionStorage.getItem('tp-auth-u') || ''; sessionStorage.removeItem('tp-auth-u'); } catch (e) {}
  const el = h(`<div class="auth"><div class="auth-top">${langSeg()}</div>
    <div class="auth-card card">
      <div class="auth-brand"><span class="auth-mark">${ICON.mark}</span>${name ? `<h1 data-notr>${esc(name)}</h1>` : '<h1>Tunnel Panel</h1>'}<p>server link manager</p></div>
      ${reg ? `<div class="auth-note"><b>Create admin account</b><span>Enter the <b>setup code</b> the installer printed. Lost it? On the server run <span class="mono">tunnel-panel setup-code</span></span></div>`
        : why && AUTH_WHY[why] ? `<div class="auth-note">${AUTH_WHY[why]}</div>` : ''}
      <form id="af" class="auth-form" autocomplete="on">
        <label class="f">Username<input name="u" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" dir="ltr" required value="${esc(keepU)}"></label>
        <label class="f">Password<span class="auth-pw"><input name="p" type="password" dir="ltr" autocomplete="${reg ? 'new-password' : 'current-password'}" required${reg ? ' minlength="8" data-strength' : ''}><button type="button" class="auth-eye" data-eye title="show / hide" aria-label="show / hide">${ICON.eye}</button></span>${reg ? '<small class="fhelp" data-meter></small>' : ''}</label>
        ${reg ? '<label class="f">Setup code<input name="c" class="mono" dir="ltr" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" placeholder="xxxx-xxxx-xxxx" required></label>' : ''}
        <div class="auth-err" id="aerr" role="alert" hidden></div>
        <button class="btn pri auth-go" id="ago">${reg ? 'Create account' : 'Sign in'}</button>
      </form>
    </div></div>`);
  document.body.appendChild(el);
  wirePasswordUX(el); wireLang(el);
  const f = $('#af'), go = $('#ago'), err = $('#aerr');
  const say = (m) => { err.innerHTML = ICON.warn + `<span>${esc(m)}</span>`; err.hidden = false; err.classList.remove('shake'); void err.offsetWidth; err.classList.add('shake'); };
  (keepU ? f.p : f.u).focus();
  f.oninput = () => { err.hidden = true; };
  f.onsubmit = async (ev) => {
    ev.preventDefault();
    if (go.disabled) return; // one try at a time: Enter twice doesn't send two
    const label = go.textContent;
    go.disabled = true; go.classList.add('busy'); go.textContent = reg ? 'Creating…' : 'Signing in…'; err.hidden = true;
    try {
      await api(reg ? '/register' : '/login', { username: f.u.value.trim(), password: f.p.value, code: reg ? f.c.value : '' });
      location.reload();
      return;
    } catch (e) {
      // fetch itself failed: no answer from the panel (offline, the panel restarting)
      say(e instanceof TypeError ? "Can't reach the panel. Check the connection and try again." : e.message);
      if (!reg && /wrong/i.test(e.message)) { f.p.value = ''; f.p.focus(); }
    }
    go.disabled = false; go.classList.remove('busy'); go.textContent = label;
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
        ${meFoot()}
      </div></aside>
    <div class="sidebg" id="sidebg"></div>
    <main class="main" id="work"></main></div>`);
  document.body.appendChild(shell);
  $$('.nav button', shell).forEach(b => b.onclick = () => { navReset(b.dataset.v); setView(b.dataset.v); paintNav(); renderView(); scrollTo(0, 0); $('#side').classList.remove('open'); });
  $('#sidebg').onclick = () => $('#side').classList.remove('open');
  const os = $('#ownerSel', shell);
  if (os) { os.value = STATE.ownerFilter || ''; os.onchange = () => { setOwnerFilter(os.value); renderShell(); }; } // the sidebar's counts follow it too
  wireMe(shell);
  paintNav(); renderView();
}
// a sidebar click always opens the section's main list — also when it is the section already
// shown: an opened record (an IG Routing server, the Outage log's picked server or tunnel, a
// benchmark run picked from history) is closed. Filters and sub-tabs the user chose stay.
function navReset(v) {
  if (v === 'igproxy') { IG.cur = null; IG.tab = 'routes'; }
  if (v === 'servers') OUT.pick = '';
  if (v === 'bench') BN.view = {};
}
function paintNav() { $$('.nav button').forEach(b => b.classList.toggle('on', b.dataset.v === STATE.view)); }
// the sidebar's last row: who is signed in (opens Appearance: theme, language, accent) and sign out
const THEME_NAME = { black: 'Black', graphite: 'Graphite', white: 'White' };
// accent colours (per browser): '' is the theme's own; each is fitted to the theme (boot.js)
const ACCENTS = ['', '#0ea5e9', '#10b981', '#f59e0b', '#ec4899', '#a855f7'];
function meFoot() {
  const ver = STATE.version ? `<div class="lk-ver"><span>version</span> <span class="mono" data-notr>${esc(STATE.version)}</span></div>` : '';
  return `<div class="me" id="me">
    <button type="button" class="me-chip" id="meBtn" aria-haspopup="dialog" aria-expanded="false" aria-controls="mePop" title="Appearance">
      <span class="me-av" data-notr>${esc((STATE.user || '?').slice(0, 1).toUpperCase())}</span>
      <span class="me-txt"><b data-notr>${esc(STATE.user)}</b><small>${isAdmin() ? 'admin' : 'user'}</small></span>
      <span class="me-gear">${ICON.gear}</span>
    </button>
    <button type="button" class="me-out" id="logout" title="Sign out" aria-label="Sign out">${ICON.out}</button>
    <div class="me-pop card" id="mePop" role="dialog" aria-label="Appearance" hidden>
      <div class="lk-h">Theme</div>
      <div class="lk-themes">${tpLook.THEMES.map(t => `<button type="button" class="lk-th" data-th="${t}"><i class="lk-prev lk-${t}"><i></i></i><span>${THEME_NAME[t]}</span></button>`).join('')}</div>
      <button type="button" class="lk-sys" data-th="">Follow the system</button>
      <div class="lk-h">Accent colour</div>
      <div class="swatches">${ACCENTS.map(c => `<button type="button" class="sw" data-acc="${c}" style="--c:${c || 'var(--accent-def)'}" aria-label="${c ? 'accent ' + c : 'theme colour'}" title="${c ? '' : 'theme colour'}"></button>`).join('')}</div>
      <div class="lk-h">Language</div>
      ${langSeg()}
      ${ver}
    </div>
  </div>`;
}
function wireMe(shell) {
  const btn = $('#meBtn', shell), pop = $('#mePop', shell);
  const open = (on) => { pop.hidden = !on; btn.setAttribute('aria-expanded', on); if (on) paintLook(); };
  btn.onclick = (e) => { e.stopPropagation(); open(pop.hidden); };
  pop.onclick = (e) => e.stopPropagation();
  STATE.meClose = (focus) => { if (pop.isConnected && !pop.hidden) { open(false); if (focus) btn.focus(); } };
  if (!wireMe.once) { // once per page: the shell is drawn again, these find the current one
    wireMe.once = true;
    document.addEventListener('click', () => STATE.meClose && STATE.meClose());
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && STATE.meClose) STATE.meClose(true); });
  }
  $$('[data-th]', pop).forEach(b => b.onclick = () => { tpLook.setTheme(b.dataset.th); paintLook(); });
  $$('[data-acc]', pop).forEach(b => b.onclick = () => { tpLook.setAccent(b.dataset.acc); paintLook(); });
  wireLang(pop);
  $('#logout', shell).onclick = async () => { try { await api('/logout', {}); } catch (e) {} location.reload(); };
}
function paintLook() {
  const chosen = tpLook.chosen(), cur = tpLook.theme(), acc = tpLook.accent();
  $$('.lk-th').forEach(b => { const on = b.dataset.th === cur; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on); });
  $$('.lk-sys').forEach(b => { b.classList.toggle('on', !chosen); b.setAttribute('aria-pressed', !chosen); });
  $$('[data-acc]').forEach(b => b.classList.toggle('on', b.dataset.acc === acc));
}

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
// What the tunnels used and what of it costs, over ONE range for the whole page: the totals and
// the change from the period just before, who uses the most (by Iran server, foreign server,
// tunnel or account), the hours / days on a chart, and what looks unusual. Iran's upload is
// free, so a tunnel pays what its Iran server received for it — its users' upload plus what its
// foreign server sent (usage.go usagePaid). usage.go reads the counters every 5 min, always.
const USAGE = { gran: '' }; // the chart's step the user picked (hour / day); '' = by the range
async function viewUsage(w) {
  const TZ = 12600, fa = document.documentElement.dir === 'rtl'; // Tehran is UTC+3:30 all year
  const nowU = Math.floor(Date.now() / 1000), hourS = nowU - (nowU + TZ) % 3600, today = nowU - (nowU + TZ) % 86400;
  const thrIn = (u) => new Date((u + TZ) * 1000).toISOString().slice(0, 14) + '00';
  const thrOut = (v) => Math.floor(Date.parse(v.slice(0, 13) + ':00Z') / 1000) - TZ;
  // a quick range ("today") and a span that ends now are kept as such, so they move with the clock
  const quick = { today: [today, nowU], yesterday: [today - 86400, today], d3: [today - 2 * 86400, nowU], week: [today - 6 * 86400, nowU] };
  let rk = recall('tp-usage-r');
  if (!['24h', '7d', '30d', 'c'].includes(rk)) rk = '24h';
  let rng = {}; try { rng = JSON.parse(recall('tp-usage-rng') || '{}') || {}; } catch (e) {}
  if (quick[rng.q]) rng = { q: rng.q, f: quick[rng.q][0], t: quick[rng.q][1] };
  else if (rng.live && rng.f > 0) rng.t = nowU;
  if (!(rng.f > 0 && rng.t > rng.f)) rng = { q: 'today', f: today, t: nowU };
  // the range, and how far back "the period before" is: the same span, one span earlier
  // "24 hours" is the 24 whole hours before this one and this hour so far: a range of at least
  // a day (23 h and some minutes made the per-day average larger than the total)
  const [f0, t0] = rk === '24h' ? [hourS - 24 * 3600, nowU] : rk === '7d' ? [today - 6 * 86400, nowU] : rk === '30d' ? [today - 29 * 86400, nowU] : [rng.f, rng.t];
  const owners = isAdmin() && new Set(STATE.tunnels.map(t => t.owner || '')).size > 1;
  let by = recall('tp-usage-by');
  if (!['iran', 'foreign', 'tunnel', 'owner'].includes(by) || (by === 'owner' && !owners)) by = 'iran';
  let sel = null; try { sel = JSON.parse(recall('tp-usage-pick') || 'null'); } catch (e) {}

  w.innerHTML = topbar('Usage', 'How much your tunnels used and what you pay for — compared with the period before.',
    `<button class="btn" data-ucsv title="Every hour (or day) of every tunnel in this range, as a spreadsheet">⬇ CSV</button>`);
  const ctl = h(`<div class="uctl"><div class="seg">${[['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['c', '📅 Date & time']].map(x => `<button class="${rk === x[0] ? 'on' : ''}" data-ur="${x[0]}">${x[1]}</button>`).join('')}</div><span class="urng" data-urng></span></div>`);
  w.appendChild(ctl);
  $$('[data-ur]', ctl).forEach(b => b.onclick = () => { remember('tp-usage-r', b.dataset.ur); renderView(); });
  if (rk === 'c') {
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
  const box = h('<div class="ubody"><div class="ukpi4"><div class="skel" style="height:110px"></div><div class="skel" style="height:110px"></div><div class="skel" style="height:110px"></div><div class="skel" style="height:110px"></div></div><div class="skel" style="height:300px"></div></div>');
  w.appendChild(box);
  let r, p = null;
  try { r = await api(`/usage?from=${f0}&to=${t0}`); } catch (e) { box.innerHTML = `<div class="card pad errtxt">${esc(e.message)}</div>`; return; }
  const tEnd = Math.min(t0, nowU, r.to);
  // the period before: the same span shifted back (24 h, 7 or 30 days; a picked range by its length)
  const D = rk === '24h' ? 86400 : rk === '7d' ? 7 * 86400 : rk === '30d' ? 30 * 86400 : r.n * r.step;
  try { p = await api(`/usage?from=${r.from - D}&to=${tEnd - D}`); } catch (e) { p = null; }
  if (!box.isConnected) return;
  // the before period counts only when the counters were running all of it
  const prevOK = !!p && p.from >= (r.started || 0) - 300;
  // its last step can be cut short (the range ends now, mid-hour): only that part of it counts
  const pLast = p ? Math.min(1, Math.max(0, 1 - (p.n * p.step - (tEnd - D - p.from)) / p.step)) : 1;

  // the tunnels: today's, and deleted ones with bytes in either period (their route as it was;
  // one deleted before routes were kept has none: '~', "route unknown", paid at ×1)
  const z = { d: 0, u: 0, p: 0, est: false };
  const goneOf = (g, id) => { const q = (g.pair || '').split('|'); const k = q.length === 2; return { id, name: g.name || 'deleted ' + id.slice(0, 6), owner: g.owner || '', serverId: k ? q[0] : '~', foreignId: k ? q[1] : '~', active: '', deleted: true }; };
  const byId = new Map(STATE.tunnels.map(t => [t.id, t]));
  [r, p].forEach(x => Object.entries((x && x.gone) || {}).forEach(([id, g]) => { if (!byId.has(id)) byId.set(id, goneOf(g, id)); }));
  const C = Object.fromEntries((r.tunnels || []).map(x => [x.id, x]));
  const P = {};
  if (p) (p.tunnels || []).forEach(x => { const s = x.series || [], l = s[p.n - 1] || {}, k = 1 - pLast;
    P[x.id] = { d: x.down - (l.d || 0) * k, u: x.up - (l.u || 0) * k, p: (x.paid || 0) - (l.p || 0) * k }; });
  const items = [...byId.values()].filter(t => shownOwner(t.owner)).map(t => {
    const c = C[t.id];
    return { ...t, cur: c ? { d: c.down, u: c.up, p: c.paid || 0, est: !!c.est } : z, prev: P[t.id] || z, series: c ? c.series : null };
  }).filter(t => !t.deleted || t.cur.d + t.cur.u > 0 || t.prev.d + t.prev.u > 0);

  // names
  const srvOf = (id) => id && id !== '~' ? serverById(id) : null;
  const flagOf = (id) => { if (id === '~') return '❔'; const s = srvOf(id); return s ? (s.country ? flag(s.country) : '🌍') : '🏠'; };
  const nameOf = (id) => { if (id === '~') return '<span>route unknown</span>'; const s = srvOf(id); return s ? nm(s.name) : '<span>panel host</span>'; };
  const ownerName = (o) => o ? nm(o) : '<span>me (admin)</span>';
  const tot = (x) => x.d + x.u;
  const add = (a, x) => ({ d: a.d + x.d, u: a.u + x.u, p: a.p + x.p, est: a.est || !!x.est });
  const sum = (list, k) => list.reduce((a, t) => add(a, t[k]), z);
  const coefN = (x) => tot(x) > 1 << 20 && x.p > 0 ? x.p / tot(x) : 0;
  const coefTxt = (x) => { const c = coefN(x); return c ? '×' + c.toFixed(2) : '—'; };
  const coefCls = (x) => { const c = coefN(x); return c > 1.3 ? 'ucoef bad' : c > 1.1 ? 'ucoef warn' : 'ucoef'; };
  // the change from the period before: ▲ / ▼ percent, or nothing when there is no "before"
  const delta = (cur, prev, big) => {
    if (!prevOK) return '';
    // next to nearly nothing a percent says nothing (▲ 149212%): it is new
    if (prev < 2 ** 30) return cur >= 2 ** 30 ? `<span class="udelta up" title="nothing in the period before">new</span>` : '';
    const v = (cur - prev) / prev * 100, a = Math.abs(v);
    if (a < 0.5) return `<span class="udelta" title="vs the period before">= 0%</span>`;
    return `<span class="udelta ${v > 0 ? 'up' : 'down'}${big ? ' big' : ''}" title="vs the period before"><bdi>${v > 0 ? '▲' : '▼'} ${a >= 1000 ? '>999' : a >= 100 ? Math.round(a) : a.toFixed(a < 10 ? 1 : 0)}%</bdi></span>`;
  };

  // the groups of the breakdown, and the scope: the row picked (the whole page shows only it)
  const KEY = { iran: (t) => t.serverId || '', foreign: (t) => t.foreignId || '', tunnel: (t) => t.id, owner: (t) => t.owner || '' };
  const groupLabel = (k, key, list) => {
    if (k === 'tunnel') { const t = list[0]; return { flag: flagOf(t.foreignId), name: nm(t.name) + (t.deleted ? ' <span class="faint">(deleted)</span>' : t.active ? '' : ' <span class="faint">(stopped)</span>'), sub: `${nameOf(t.serverId)} → ${nameOf(t.foreignId)}` }; }
    const dn = list.filter(t => t.deleted && tot(t.cur) > 0).length, live = list.filter(t => !t.deleted).length;
    const sub = `<span>${live} ${live === 1 ? 'tunnel' : 'tunnels'}</span>${dn ? ` + <span>${dn}</span> <span>deleted</span>` : ''}`;
    if (k === 'owner') return { flag: '👤', name: ownerName(key), sub };
    return { flag: flagOf(key), name: key === '~' ? '<span>Route unknown</span>' : nameOf(key), sub: key === '~' ? '<span>deleted before routes were kept · ×1</span>' : sub };
  };
  const groupsOf = (k) => {
    const m = new Map();
    items.forEach(t => { const key = KEY[k](t); if (!m.has(key)) m.set(key, []); m.get(key).push(t); });
    // a group of deleted tunnels only, with nothing in this range, is not shown (its bytes were before)
    return [...m].filter(([, list]) => list.some(t => !t.deleted || tot(t.cur) > 0)).map(([key, list]) => ({ key, list, cur: sum(list, 'cur'), prev: sum(list, 'prev'), ...groupLabel(k, key, list) }))
      .sort((a, b) => tot(b.cur) - tot(a.cur) || tot(b.prev) - tot(a.prev));
  };
  if (sel && !(KEY[sel.by] && items.some(t => KEY[sel.by](t) === sel.key))) sel = null;
  const scope = sel ? items.filter(t => KEY[sel.by](t) === sel.key) : items;
  const cur = sum(scope, 'cur'), prev = sum(scope, 'prev');

  // the range in words, and when counting started
  const fmtD = (u, o) => new Date(u * 1000).toLocaleString(fa ? 'fa-IR-u-nu-latn' : 'en-GB', { timeZone: 'Asia/Tehran', ...o });
  const dOpt = { day: 'numeric', month: 'short' }, hOpt = { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
  const stamp = (u) => fmtD(u, dOpt) + ' ' + fmtD(u, hOpt);
  const urng = $('[data-urng]', ctl);
  urng.innerHTML = `<bdi data-notr>${stamp(r.from)}</bdi> <span>→</span> ${tEnd >= nowU - 60 ? '<span>now</span>' : `<bdi data-notr>${stamp(tEnd)}</bdi>`} <span class="faint">(Tehran time)</span>`;
  const since = r.started ? Math.floor((nowU - r.started) / 3600) : 0;
  const notes = [];
  if (r.started > r.from) notes.push(`<span>Counting started</span> <b>${since < 48 ? Math.max(1, since) + ' h' : Math.floor(since / 24) + ' d'}</b> <span>ago: the range has no data before that.</span>`);
  else if (p && !prevOK) notes.push('<span>No comparison: counting had not started yet in the period before.</span>');
  if (r.step === 86400 && rk === 'c') notes.push(`<span>${r.from > f0 + 86400 ? 'Only the last 400 days are kept: the range starts at the oldest day kept. ' : ''}Hours are kept 35 days: a range that starts earlier is shown day by day, whole Tehran days.</span>`);

  // the steps of the chart: the hours, or the days (Tehran) they make
  const hourly = r.step === 3600;
  const gran = !hourly ? 'd' : USAGE.gran === 'h' || USAGE.gran === 'd' ? (r.n <= 25 ? 'h' : USAGE.gran) : r.n <= 72 ? 'h' : 'd';
  const bins = [];
  {
    const raw = Array.from({ length: r.n }, (_, i) => ({ t: r.from + i * r.step, d: 0, u: 0, p: 0 }));
    scope.forEach(t => (t.series || []).forEach((s, i) => { const b = raw[i]; if (b && s) { b.d += s.d || 0; b.u += s.u || 0; b.p += s.p || 0; } }));
    // not the empty steps before counting started (a 30-day range on a panel counting for 11 days)
    raw.filter(b => b.t < nowU && b.t + r.step > (r.started || 0)).forEach(b => {
      const k = gran === 'd' && hourly ? b.t - (b.t + TZ) % 86400 : b.t;
      const last = bins[bins.length - 1];
      if (last && last.t === k) { last.d += b.d; last.u += b.u; last.p += b.p; } else bins.push({ t: k, d: b.d, u: b.u, p: b.p, step: gran === 'd' ? 86400 : r.step });
    });
  }
  // the date and the hours each isolated: "20 آبان" beside "23:00–00:00" read in either direction
  const binLbl = (b, long) => b.step === 86400 ? `<bdi>${fmtD(b.t, long ? { weekday: 'short', ...dOpt } : dOpt)}</bdi>` : (long || r.n > 25 ? `<bdi>${fmtD(b.t, dOpt)}</bdi> ` : '') + `<bdi>${fmtD(b.t, hOpt)}${long ? '–' + fmtD(b.t + 3600, hOpt) : ''}</bdi>`;
  // the busiest hour and day
  const busy = (list) => list.reduce((a, b) => (!a || tot(b) > tot(a) ? b : a), null);
  const hoursB = hourly ? Array.from({ length: r.n }, (_, i) => ({ t: r.from + i * 3600, step: 3600, d: 0, u: 0, p: 0 })) : [];
  if (hourly) scope.forEach(t => (t.series || []).forEach((s, i) => { if (s) { hoursB[i].d += s.d || 0; hoursB[i].u += s.u || 0; } }));
  const daysB = gran === 'd' ? bins : [];
  const bh = busy(hoursB), bd = busy(daysB.filter(b => b.t + 86400 <= nowU || daysB.length === 1));
  // the span the numbers cover, exactly: from the range's start (or when counting started) to its end
  const spanS = Math.max(3600, tEnd - Math.max(r.from, r.started || 0)), spanDays = spanS / 86400;
  const [uD, uH, uM] = fa ? [' روز', ' ساعت', ' دقیقه'] : [' d', ' h', ' min'];
  const spanTxt = spanS >= 2 * 86400 ? `${Math.floor(spanS / 86400)}${uD} ${Math.floor(spanS % 86400 / 3600)}${uH}` : `${Math.floor(spanS / 3600)}${uH} ${Math.floor(spanS % 3600 / 60)}${uM}`;
  // tunnels with traffic here whose pay is (partly) estimated: no count of their foreign server
  const estN = scope.filter(t => t.cur.est && tot(t.cur) > 0).length, usedN = scope.filter(t => tot(t.cur) > 0).length;

  // the four numbers
  const kpis = `<div class="ukpi4">
    <div class="card pad"><small>Σ Traffic</small><b>${fmtBytes(tot(cur))}</b><span class="umini"><bdi class="dl">⬇ ${fmtBytes(cur.d)}</bdi> · <bdi class="ul">⬆ ${fmtBytes(cur.u)}</bdi></span>${delta(tot(cur), tot(prev), 1)}</div>
    <div class="card pad paid"><small>💰 You pay for</small><b>${cur.est ? '≈ ' : ''}${fmtBytes(cur.p)}</b><span class="umini"><b class="${coefCls(cur)}">${coefTxt(cur)}</b> <span>of the traffic</span></span>${estN ? `<span class="umini" title="No count of their foreign server for some hours: those hours are priced at the tunnel's own coefficient (or ×1)"><span>≈ estimated for</span> <bdi>${estN}/${usedN}</bdi> <span>tunnels</span></span>` : ''}${delta(cur.p, prev.p, 1)}</div>
    <div class="card pad"><small>📆 Per day</small><b>${fmtBytes(cur.p / spanDays)}</b><span class="umini"><span>${spanDays < 1 ? 'at this pace — the range is shorter than a day:' : 'paid, on average over'}</span> <bdi data-notr>${spanTxt}</bdi></span><span class="umini"><span>≈</span> <bdi>${fmtBytes(cur.p / spanDays * 30)}</bdi> <span>per 30 days</span></span></div>
    <div class="card pad"><small>⏰ Busiest</small>${bh && tot(bh) > 0 ? `<b class="ubusy"><bdi data-notr>${fmtD(bh.t, hOpt)}–${fmtD(bh.t + 3600, hOpt)}</bdi></b><span class="umini"><bdi data-notr>${r.n > 25 ? fmtD(bh.t, dOpt) + ' · ' : ''}</bdi><bdi>${fmtBytes(tot(bh))}</bdi> <span>in that hour</span></span>` : bd && tot(bd) > 0 ? `<b class="ubusy"><bdi data-notr>${fmtD(bd.t, dOpt)}</bdi></b><span class="umini"><bdi>${fmtBytes(tot(bd))}</bdi> <span>that day</span></span>` : '<b>—</b>'}${bh && bd && daysB.length > 1 && tot(bd) > 0 ? `<span class="umini"><span>busiest day:</span> <bdi data-notr>${fmtD(bd.t, dOpt)}</bdi> · <bdi>${fmtBytes(tot(bd))}</bdi></span>` : ''}</div></div>`;

  // the chart: download + upload stacked, what you pay for as a line; hover (or touch) a step for its numbers
  const chart = () => {
    const N = bins.length;
    if (!N) return '<div class="faint sempty">No traffic in this range.</div>';
    let mx = Math.max(1, ...bins.map(b => Math.max(tot(b), b.p)));
    const unit = [2 ** 40, 2 ** 30, 2 ** 20, 1024, 1].find(x => mx / 3 >= x) || 1;
    const st = niceStep(mx / 3 / unit) * unit;
    mx = st * 3;
    const W = N * 10, H = 100, g = N > 120 ? 0 : N > 40 ? 1.5 : 2.5;
    const y = (v) => H - v / mx * H;
    const bars = bins.map((b, i) => `<rect class="cd" x="${i * 10 + g}" y="${y(b.d)}" width="${10 - 2 * g}" height="${H - y(b.d)}"/><rect class="cu" x="${i * 10 + g}" y="${y(b.d + b.u)}" width="${10 - 2 * g}" height="${H - y(b.u)}"/>`).join('');
    const line = bins.map((b, i) => `${i ? 'L' : 'M'}${i * 10 + 5},${y(b.p).toFixed(2)}`).join('');
    const every = Math.max(1, Math.ceil(N / (window.innerWidth < 600 ? 4 : 8)));
    const xl = bins.map((b, i) => i % every ? '' : `<span style="left:${(i + 0.5) / N * 100}%">${binLbl(b)}</span>`).join('');
    return `<div class="uchart" dir="ltr" data-notr>
      <div class="uyax">${[3, 2, 1].map(k => `<span style="top:${(1 - k / 3) * 100}%">${fmtBytes(st * k)}</span>`).join('')}</div>
      <div class="uplot"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${[1, 2].map(k => `<line class="cg" x1="0" x2="${W}" y1="${H * k / 3}" y2="${H * k / 3}"/>`).join('')}<rect class="chov" x="0" y="0" width="0" height="${H}"/>${bars}<path class="cp" d="${line}"/></svg><div class="utip" hidden></div></div>
      <div class="uxax">${xl}</div></div>`;
  };
  const table = () => `<div class="uscroll uhours"><table class="tbl utbl"><thead><tr><th>${gran === 'd' ? 'Day (Tehran)' : 'Hour (Tehran)'}</th><th>⬇ Download</th><th>⬆ Upload</th><th>Σ Total</th><th>💰 Paid</th><th>Coefficient</th></tr></thead><tbody>${bins.slice().reverse().map(b => `<tr><td class="mono">${binLbl(b, true)}</td><td>${fmtBytes(b.d)}</td><td>${fmtBytes(b.u)}</td><td><b>${fmtBytes(tot(b))}</b></td><td>${fmtBytes(b.p)}</td><td><b class="${coefCls(b)}">${coefTxt(b)}</b></td></tr>`).join('')}</tbody>
    <tfoot><tr><td><b>Total</b></td><td>${fmtBytes(cur.d)}</td><td>${fmtBytes(cur.u)}</td><td><b>${fmtBytes(tot(cur))}</b></td><td><b>${fmtBytes(cur.p)}</b></td><td><b class="${coefCls(cur)}">${coefTxt(cur)}</b></td></tr></tfoot></table></div>`;

  // what looks unusual, in the scope: overhead, jumps and drops against the period before,
  // a live tunnel with no traffic, one hour far above the tunnel's usual, an Iran server
  // receiving much more than its tunnels explain
  const odd = [];
  {
    const cs = items.filter(t => tot(t.cur) > 1 << 30).map(t => coefN(t.cur)).filter(Boolean).sort((a, b) => a - b);
    const med = cs.length ? cs[Math.floor(cs.length / 2)] : 1;
    scope.forEach(t => {
      const c = coefN(t.cur), u = tot(t.cur), pu = tot(t.prev), nm2 = nm(t.name) + (t.deleted ? ' <span class="faint">(deleted)</span>' : '');
      if (u > 1 << 30 && c >= Math.max(1.1, med + 0.06)) odd.push({ w: 3 + c, k: 't:' + t.id, ic: '💰', name: nm2, what: 'pays much more than its traffic', val: `<b class="${coefCls(t.cur)}">×${c.toFixed(2)}</b> <span class="faint">(</span><span class="faint">others</span> <span class="faint">×${med.toFixed(2)})</span>`, hint: 'Tunnel overhead, health checks or tests — or traffic of something else on its Iran server.' });
      if (prevOK && !t.deleted && pu > 10 * 2 ** 30 && u < pu * 0.3) odd.push({ w: 2.5, k: 't:' + t.id, ic: '📉', name: nm2, what: 'used much less than the period before', val: `<bdi class="faint">${fmtBytes(pu)}</bdi> <span class="faint">→</span> <bdi>${fmtBytes(u)}</bdi>`, hint: 'Did its users leave, or is it down part of the time?' });
      if (prevOK && u > 10 * 2 ** 30 && pu > 1 << 30 && u > pu * 2) odd.push({ w: 2, k: 't:' + t.id, ic: '📈', name: nm2, what: 'used much more than the period before', val: `<bdi class="faint">${fmtBytes(pu)}</bdi> <span class="faint">→</span> <bdi>${fmtBytes(u)}</bdi>`, hint: '' });
      if (!t.deleted && t.active && u === 0 && tEnd - r.from >= 3 * 3600) odd.push({ w: 4, k: 't:' + t.id, ic: '⛔', name: nm2, what: 'had no traffic at all in this range', val: '', hint: 'It is on, but nobody used it: check it on the Tunnels page.' });
      if (hourly && t.series) {
        const hs = t.series.map(s => (s.d || 0) + (s.u || 0)), nz = hs.filter(v => v > 0).sort((a, b) => a - b);
        if (nz.length >= 12) {
          const md = nz[Math.floor(nz.length / 2)], mi = hs.indexOf(Math.max(...hs));
          if (hs[mi] > 5 * 2 ** 30 && hs[mi] > md * 4) odd.push({ w: 1.5 + hs[mi] / md / 10, k: 't:' + t.id, ic: '⚡', name: nm2, what: 'one hour far above its usual', val: `<bdi data-notr>${fmtD(r.from + mi * 3600, dOpt)} ${fmtD(r.from + mi * 3600, hOpt)}</bdi> · <bdi>${fmtBytes(hs[mi])}</bdi> <span class="faint">(</span><span class="faint">usual</span> <bdi class="faint">${fmtBytes(md)})</bdi>`, hint: '' });
        }
      }
    });
  }
  // one Iran server's whole bill: what its card received, the part its tunnels explain (the ones
  // shown, and others on the same card: another account's, or hidden by the View), the rest
  const S = Object.fromEntries((r.servers || []).map(x => [x.id, x]));
  const all = STATE.servers.concat(STATE.shared || []);
  const nicOf = (id) => {
    if (id === '~') return { key: '~', u: null };
    const s = id ? serverById(id) : null;
    const ip = s ? (s.ipv4 || s.ipv6 || id) : 'panel';
    return { key: ip, u: S[id] || (s ? all.filter(o => (o.ipv4 || o.ipv6) === ip).map(o => S[o.id]).find(Boolean) : null) || null };
  };
  const bills = [];
  {
    const routeOf = new Map([...byId.values()].map(t => [t.id, t.serverId]));
    const seen = new Map();
    scope.forEach(t => { if (t.serverId === '~') return; const n = nicOf(t.serverId); if (!n.u) return;
      if (!seen.has(n.key)) { const b = { id: t.serverId, key: n.key, recv: n.u.down, list: [] }; seen.set(n.key, b); bills.push(b); } seen.get(n.key).list.push(t); });
    bills.forEach(b => {
      b.x = sum(b.list, 'cur');
      b.other = (r.tunnels || []).reduce((a, x) => routeOf.has(x.id) && nicOf(routeOf.get(x.id)).key === b.key && !b.list.some(t => t.id === x.id) ? a + (x.paid || 0) : a, 0);
      b.rest = Math.max(0, b.recv - b.x.p - b.other);
      if (b.rest > 5 * 2 ** 30 && b.rest > b.recv * 0.1) odd.push({ w: 2.2, k: '', ic: '🧾', name: `${flagOf(b.id)} ${nameOf(b.id)}`, what: 'received more than its tunnels explain', val: `<bdi>${fmtBytes(b.rest)}</bdi> <span class="faint">of</span> <bdi class="faint">${fmtBytes(b.recv)}</bdi>`, hint: 'Updates, tests, or traffic that does not go through a tunnel — you pay for it too.' });
    });
  }
  odd.sort((a, b) => b.w - a.w);
  bills.sort((a, b) => b.recv - a.recv);
  const billTbl = () => !bills.length ? '' : `<details class="card pad udet"><summary><b>🧾 Iran servers — the whole bill</b> <span class="faint">what each Iran server's network card received, and how much of it the tunnels explain</span></summary><div class="uscroll"><table class="tbl utbl"><thead><tr><th>Iran server</th><th>Σ Tunnels' traffic</th><th>💰 Tunnels' paid</th>${bills.some(b => b.other > 0) ? "<th>💰 Other tunnels on this server</th>" : ''}<th>Other (updates, tests…)</th><th>💰 Server received (bill)</th></tr></thead><tbody>${bills.map(b => `<tr><td><b>${flagOf(b.id)} ${nameOf(b.id)}</b></td><td>${fmtBytes(tot(b.x))}</td><td>${fmtBytes(b.x.p)}</td>${bills.some(x => x.other > 0) ? `<td>${fmtBytes(b.other)}</td>` : ''}<td>${fmtBytes(b.rest)}</td><td><b>${fmtBytes(b.recv)}</b></td></tr>`).join('')}</tbody></table></div></details>`;

  // the breakdown: one row per group, its share of the traffic, what it pays and its change
  const segBy = [['iran', `${flag('IR')} <span>Iran server</span>`], ['foreign', '🌍 Foreign server'], ['tunnel', '🛰 Tunnel']].concat(owners ? [['owner', '👤 Account']] : []);
  const breakdown = () => {
    const gs = groupsOf(by), live = by === 'tunnel' ? gs.filter(g => !g.list[0].deleted) : gs, dead = by === 'tunnel' ? gs.filter(g => g.list[0].deleted && tot(g.cur) > 0) : [];
    const all2 = Math.max(1, tot(sum(items, 'cur')));
    const row = (g) => { const share = tot(g.cur) / all2 * 100, on = sel && sel.by === by && sel.key === g.key;
      return `<button class="ubrow${on ? ' on' : ''}${tot(g.cur) === 0 ? ' zero' : ''}" data-k="${esc(g.key)}">
        <span class="ubname"><span class="sflag">${g.flag}</span><span class="sinfo"><b>${g.name}</b><small>${g.sub}</small></span></span>
        <span class="ubshare"><span class="ubar"><i style="width:${Math.max(share > 0 ? 1 : 0, share).toFixed(1)}%"></i></span><span class="ubpct">${share < 0.1 && share > 0 ? '<0.1' : share.toFixed(share < 10 ? 1 : 0)}%</span></span>
        <span class="ubnum"><b>${fmtBytes(tot(g.cur))}</b><small>💰 ${g.cur.est ? '≈' : ''}${fmtBytes(g.cur.p)} · <span class="${coefCls(g.cur)}">${coefTxt(g.cur)}</span></small></span>
        <span class="ubdel">${delta(tot(g.cur), tot(g.prev))}</span></button>`; };
    return `<div class="card pad ubreak">
      <div class="uhrow"><h3>Who uses the most</h3><div class="seg sm" data-uby>${segBy.map(x => `<button class="${by === x[0] ? 'on' : ''}" data-b="${x[0]}">${x[1]}</button>`).join('')}</div></div>
      <div class="ubhead"><span>Name</span><span>Share of the traffic</span><span>Traffic · 💰 paid</span><span>${prevOK ? 'Change' : ''}</span></div>
      ${live.map(row).join('') || '<div class="faint sempty">No tunnels yet.</div>'}
      ${dead.length ? `<details class="udead"><summary><span>🗑 Deleted tunnels</span> <b>${dead.length}</b> <span class="faint">· their traffic in this range is in the totals</span></summary>${dead.map(row).join('')}</details>` : ''}
      <small class="faint uclick">Click a row to see only it on the whole page.</small></div>`;
  };

  const legend = `<details class="card pad udet ulegend"><summary><b>ⓘ What do these numbers mean?</b></summary>
    <div><b>💰 You pay for</b> = what the Iran server <b>received</b> for the tunnel: the users' upload + what the foreign server sent it. Sending from Iran is free.</div>
    <div><b>Coefficient</b> = paid ÷ total traffic. ×1.00 means you pay exactly what the users used; ×1.15 means 15 % more (tunnel headers, health checks, tests).</div>
    <div class="faint">Each Iran server's intake is counted separately per foreign server, so an Iran server with two foreign servers is split between them.${cur.est ? ' Hours before this was counted (marked ≈) are estimated from the whole Iran server.' : ''}${scope.some(t => t.serverId === '~') ? ' Tunnels deleted before their route was kept (route unknown) are counted at ×1: the panel cannot tell which Iran server they ran on.' : ''}</div></details>`;

  const pickName = () => { if (!sel) return ''; const g = groupsOf(sel.by).find(x => x.key === sel.key); return g ? `<span class="sflag">${g.flag}</span> <b>${g.name}</b>` : ''; };
  box.innerHTML = `${sel ? `<div class="upick"><span class="faint">Showing only:</span> ${pickName()} <button class="btn sm ghost" data-unpick>✕ Show all</button></div>` : ''}
    ${notes.length ? `<div class="card pad faint unote">${notes.join('<br>')}</div>` : ''}
    ${kpis}
    <div class="card pad uchartc"><div class="uhrow"><h3>${gran === 'd' ? 'Day by day' : 'Hour by hour'}</h3>
      <span class="ulegk"><span><i class="kd"></i>⬇ Download</span><span><i class="ku"></i>⬆ Upload</span><span><i class="kp"></i>💰 You pay for</span></span>
      ${hourly && r.n > 25 ? `<div class="seg sm" data-ugr><button class="${gran === 'h' ? 'on' : ''}" data-g="h">By hour</button><button class="${gran === 'd' ? 'on' : ''}" data-g="d">By day</button></div>` : ''}</div>
      ${chart()}
      <details class="utd"><summary>Show as a table</summary><div data-utbl></div></details></div>
    <div class="ugrid2">${breakdown()}
      <div class="card pad uodd"><h3>⚠ Worth a look</h3>${odd.length ? odd.slice(0, 8).map(o => `<div class="uoddr"${o.k ? ` data-ot="${esc(o.k)}"` : ''}><span class="uoic">${o.ic}</span><div><div><b>${o.name}</b> <span>${o.what}</span></div>${o.val ? `<div class="uoval">${o.val}</div>` : ''}${o.hint ? `<small class="faint">${o.hint}</small>` : ''}</div></div>`).join('') + (odd.length > 8 ? `<small class="faint"><span>and</span> ${odd.length - 8} <span>more</span></small>` : '') : '<div class="faint">Nothing unusual in this range.</div>'}</div></div>
    ${billTbl()}${legend}`;

  // wiring
  const pickSet = (v) => { remember('tp-usage-pick', v ? JSON.stringify(v) : ''); renderView(); };
  $$('[data-uby] [data-b]', box).forEach(b => b.onclick = () => { remember('tp-usage-by', b.dataset.b); renderView(); });
  $$('.ubrow', box).forEach(b => b.onclick = () => pickSet(sel && sel.by === by && sel.key === b.dataset.k ? null : { by, key: b.dataset.k }));
  $$('[data-ot]', box).forEach(b => b.onclick = () => { const id = b.dataset.ot.slice(2); remember('tp-usage-by', 'tunnel'); pickSet({ by: 'tunnel', key: id }); });
  const un = $('[data-unpick]', box); if (un) un.onclick = () => pickSet(null);
  $$('[data-ugr] [data-g]', box).forEach(b => b.onclick = () => { USAGE.gran = b.dataset.g; renderView(); });
  const td = $('.utd', box); td.ontoggle = () => { if (td.open && !td.dataset.done) { td.dataset.done = 1; $('[data-utbl]', td).innerHTML = table(); } };
  const plot = $('.uplot', box);
  if (plot) {
    const tip = $('.utip', plot), hov = $('.chov', plot), N = bins.length;
    const move = (e) => {
      const rc = plot.getBoundingClientRect(), i = Math.min(N - 1, Math.max(0, Math.floor((e.clientX - rc.left) / rc.width * N))), b = bins[i];
      hov.setAttribute('x', i * 10); hov.setAttribute('width', 10);
      tip.hidden = false;
      tip.innerHTML = `<b>${binLbl(b, true)}</b><span><i class="kd"></i>${tpT('⬇ Download')}</span><b>${fmtBytes(b.d)}</b><span><i class="ku"></i>${tpT('⬆ Upload')}</span><b>${fmtBytes(b.u)}</b><span>${tpT('Σ Total')}</span><b>${fmtBytes(tot(b))}</b><span><i class="kp"></i>${tpT('💰 You pay for')}</span><b>${fmtBytes(b.p)} <em class="${coefCls(b)}">${coefTxt(b)}</em></b>`;
      const x = (i + 0.5) / N * rc.width;
      tip.style.left = Math.min(Math.max(0, x - tip.offsetWidth / 2), rc.width - tip.offsetWidth) + 'px';
    };
    plot.onpointermove = move; plot.onpointerdown = move;
    plot.onpointerleave = () => { tip.hidden = true; hov.setAttribute('width', 0); };
  }
  // the CSV: every step of every tunnel in the scope (bytes, and GB to read at a glance)
  $('[data-ucsv]', w).onclick = () => {
    const q = (s) => /[",\n]/.test(s) ? '"' + String(s).replace(/"/g, '""') + '"' : s;
    const sname = (id) => id === '~' ? 'route unknown' : (srvOf(id) || {}).name || 'panel host';
    const iso = (u) => new Date((u + TZ) * 1000).toISOString().slice(0, 16).replace('T', ' ');
    const L = [];
    const G = (v) => (v / 2 ** 30).toFixed(3);
    scope.forEach(t => (t.series || []).forEach((s, i) => {
      const a = r.from + i * r.step; if (!s || a >= nowU || !((s.d || 0) + (s.u || 0) + (s.p || 0))) return;
      L.push([a, iso(a), iso(a + r.step), q(t.name), t.deleted ? 'yes' : '', q(sname(t.serverId)), q(sname(t.foreignId)), q(t.owner || 'admin'), s.d || 0, s.u || 0, s.p || 0, G(s.d || 0), G(s.u || 0), G((s.d || 0) + (s.u || 0)), G(s.p || 0)]);
    }));
    L.sort((x, y) => x[0] - y[0]); // by time, then the tunnels as above (most traffic first)
    const csv = ['start (Tehran),end (Tehran),tunnel,deleted,iran server,foreign server,account,download bytes,upload bytes,paid bytes,download GB,upload GB,total GB,paid GB'].concat(L.map(x => x.slice(1).join(',')));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob(['\ufeff' + csv.join('\n') + '\n'], { type: 'text/csv' })); // (the mark: Excel reads it as UTF-8)
    a.download = `usage-${iso(r.from).slice(0, 13).replace(' ', '_')}-${iso(tEnd).slice(0, 13).replace(' ', '_')}.csv`;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  };
}
// 1, 2, 2.5 or 5 times a power of ten, at least v: the chart's gridlines fall on round numbers
const niceStep = (v) => { const e = 10 ** Math.floor(Math.log10(Math.max(v, 1e-9))), m = v / e; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * e; };

/* ---------------- routes ---------------- */
// One tunnel at a time: where its users are now, the paths it keeps ready (each ✓/✕, quality,
// use / on-off), the methods it doesn't run (folded) and one Measure for IPv4 and IPv6. The
// tunnels are listed on the side (a chip strip on a phone); the pick is remembered.
const ageTxt = (u) => { const s = Math.floor(Date.now() / 1000) - u; return s < 3600 ? `${Math.max(1, Math.floor(s / 60))} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
// the switcher's view older than this is not "now" (the monitor reads it every minute, a pass
// over every tunnel takes up to ~90 s): the Iran server stopped answering
const RX_STALE = 180;
// where a running tunnel's users are: the switcher's path (hot standby), else its own method
function rxUsersOn(t) {
  if (!t.active) return null;
  const v = t.hotStandby ? t.hs : null;
  if (v && v.keys && v.active >= 0 && v.keys[v.active]) { const [mid, fam] = v.keys[v.active].split('|'); return { mid, fam, i: v.active, v }; }
  if (t.hotStandby) return { reading: true };
  return { mid: t.active, fam: t.family };
}
// the tunnel's status, in the Tunnels page's words and colours
function rxState(t) {
  if (!t.active) return { cls: 'off', txt: 'stopped' };
  if (t.health === null || t.health === undefined) return { cls: 'unk', txt: 'not checked yet' };
  if (t.health) return { cls: 'bad', txt: 'down', why: t.health };
  return { cls: 'ok', txt: 'connected' };
}
let routesTok = 0;
async function viewRoutes(w) {
  const tok = ++routesTok; // a newer draw of the page wins (an older one finishing later took its timer)
  w.innerHTML = topbar('Routes', 'Pick a tunnel: where its users are, the paths it keeps ready and the methods it may use.');
  const box = h('<div class="grid" style="gap:18px"><div class="skel" style="height:120px"></div><div class="skel" style="height:220px"></div></div>');
  w.appendChild(box);
  let hist = [], skip = {}, bst = {};
  try { [hist, skip, bst] = await Promise.all([api('/bench/history'), api('/routes/skip'), api('/bench/status').catch(() => ({}))]); } catch (e) {}
  if (tok !== routesTok || !box.isConnected) return;
  const pairs = new Map();
  const key = (i, f) => i + '|' + (f || '');
  STATE.tunnels.filter(t => shownOwner(t.owner)).forEach(t => { const k = key(t.serverId, t.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: t.serverId, foreign: t.foreignId || '', tunnels: [] }); pairs.get(k).tunnels.push(t); });
  hist.filter(r => shownOwner((serverById(r.iranId) || {}).owner)).forEach(r => { const k = key(r.iranId, r.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: r.iranId, foreign: r.foreignId || '', tunnels: [] }); });
  if (!pairs.size) { box.innerHTML = ''; box.appendChild(h('<div class="card empty"><div class="big">🔀</div>No tunnels or benchmarks yet.</div>')); return; }
  const hasFam = (id, f) => { const s = id ? serverById(id) : null; const st = STATE.settings; return f === 'v4' ? !!(s ? s.ipv4 : st.localIPv4 || true) : !!(s ? s.ipv6 : st.localIPv6); };
  const fl = (id, d) => { const s = id ? serverById(id) : null; return s && s.country ? flag(s.country) : d; };
  const mTitle = (mid) => methodTitle(mid) || mid;
  const maxMB = bst.maxMB || 6;

  // one item per tunnel, in the Tunnels page's order; a measured pair with no tunnel is an
  // item of its own at the end ("measured, no tunnel")
  const items = [];
  [...pairs.values()].forEach(p => {
    if (!p.tunnels.length) { items.push({ ...p, id: 'p:' + key(p.iran, p.foreign), pairOnly: true, shared: [] }); return; }
    p.tunnels.forEach(t => items.push({ ...p, tunnel: t, id: t.id, pairTunnels: p.tunnels, shared: p.tunnels.filter(x => x !== t).map(x => x.name) }));
  });
  items.sort((a, b) => (!!a.pairOnly - !!b.pairOnly) || (a.tunnel && b.tunnel ? tunnelOrder(a.tunnel, b.tunnel) : serverName(a.iran).localeCompare(serverName(b.iran))));

  // ---- the list (side on a wide screen) and the chip strip (phone) ----
  const dotCls = (it) => it.pairOnly ? '' : rxState(it.tunnel).cls;
  const label = (it) => it.pairOnly ? `${srvNm(it.iran)} → ${srvNm(it.foreign, 'panel host')}` : nm(it.tunnel.name);
  const subOf = (it) => {
    if (it.pairOnly) return '<span>measured, no tunnel</span>';
    const u = rxUsersOn(it.tunnel);
    return `<span>→</span> ${srvNm(it.foreign, 'panel host')} · ${!it.tunnel.active ? '<span>stopped</span>' : u && u.mid ? `<bdi>${esc(mTitle(u.mid))}</bdi>` : '<span>reading…</span>'}`;
  };
  const row = (it) => `<button type="button" class="srow rx-row" data-rsel="${esc(it.id)}" data-q="${esc((it.tunnel ? it.tunnel.name + ' ' : '') + serverName(it.iran) + ' ' + (it.foreign ? serverName(it.foreign) : '')).toLowerCase()}">
      <span class="rx-cc">${it.pairOnly ? '📊' : esc(((serverById(it.foreign) || {}).country || '').toUpperCase()) || '🛰'}</span>
      <span class="sinfo"><b>${label(it)}</b><small>${subOf(it)}</small></span><span class="rx-dot ${dotCls(it)}"></span></button>`;
  const groups = [];
  items.forEach(it => { const gk = it.pairOnly ? '~' : it.iran; let g = groups.find(x => x.id === gk); if (!g) groups.push(g = { id: gk, items: [] }); g.items.push(it); });
  groups.sort((x, y) => (x.id === '~') - (y.id === '~') || serverName(x.id).localeCompare(serverName(y.id)));
  items.splice(0, items.length, ...groups.flatMap(g => g.items)); // chips, ↑/↓ and the default pick follow the list
  const listHTML = () => groups.map(g => `<div class="sgrp"><div class="sgh"><span>${g.id === '~' ? '<span>Measured, no tunnel</span>' : `${fl(g.id, flag('IR'))} ${srvNm(g.id)}`}</span><span class="count">${g.items.length}</span></div>${g.items.map(row).join('')}</div>`).join('');
  // the pick: remembered; an old "All tunnels" / "Other routes" pick or a deleted tunnel → the first
  let sel = recall('tp-routesel');
  if (!items.some(x => x.id === sel)) sel = items[0].id;
  const cur = () => items.find(x => x.id === sel) || items[0];
  const picker = h(`<aside class="card srvlist rx-list">${items.length > 6 ? '<input class="sq" type="search" data-rq placeholder="Search tunnels…" aria-label="Search tunnels">' : ''}<div data-rl>${listHTML()}</div></aside>`);
  const strip = h(`<div class="rx-strip" role="tablist"><button type="button" class="rx-all" data-rall aria-label="All tunnels">☰</button><div class="rx-chips">${items.map(it => `<button type="button" class="rx-chip" role="tab" data-rsel="${esc(it.id)}"><i class="rx-dot ${dotCls(it)}"></i>${it.pairOnly ? '📊 ' + srvNm(it.iran) : nm(it.tunnel.name)}</button>`).join('')}</div></div>`);
  const split = h('<div class="srvsplit usplit rx"><div class="srvdetail"></div></div>');
  box.replaceWith(split);
  split.prepend(picker);
  const detail = $('.srvdetail', split);
  detail.appendChild(strip);
  const card = h('<div></div>');
  detail.appendChild(card);
  const q = $('[data-rq]', picker);
  if (q) q.oninput = () => { const s = q.value.trim().toLowerCase(); $$('[data-rsel]', picker).forEach(b => { b.hidden = !!s && !b.dataset.q.includes(s); }); $$('.sgrp', picker).forEach(g => { g.hidden = !$$('[data-rsel]', g).some(b => !b.hidden); }); };

  // ---- the picked tunnel ----
  const benchOf = (p, f) => hist.find(x => x.iranId === p.iran && (x.foreignId || '') === p.foreign && x.family === f);
  // a method's last measurement on the route: rank among the ones that worked, numbers or why it failed
  const measured = (p, mid, f) => {
    const r = benchOf(p, f); if (!r) return null;
    let pos = 0;
    for (const x of r.results) { if (x.ok) pos++; if (x.method === mid) return { x, pos: x.ok ? pos : 0, at: r.at }; }
    return null;
  };
  const benchTxt = (m) => {
    if (!m) return '<span class="faint">not measured</span>';
    const x = m.x;
    if (x.skipped) return '<span class="faint">not measurable</span>';
    if (x.ok) return `<span class="rt-rank${x.recommended ? ' top' : ''}" title="its place in the last benchmark">${x.recommended ? '★' : m.pos}</span><span class="rx-num" data-notr>↓${x.downMbps.toFixed(0)} ↑${x.upMbps.toFixed(0)} <small>Mbps</small> · ${x.rttMs.toFixed(0)} <small>ms</small></span>`;
    return `<button type="button" class="rt-err" data-err="${esc(x.error || 'failed')}" title="${esc(x.error || 'failed')}">✕ ${esc(shortErr(x.error))}</button>`;
  };
  const sw = (p, k, admin) => { if (admin) return ''; const isOff = (skip[key(p.iran, p.foreign)] || []).includes(k);
    return `<label class="rt-sw" title="${isOff ? 'off: never used on this route — turn on to keep it ready' : 'on: kept ready (hot standby, failover) — turn off to leave it out on this route'}"><input type="checkbox" data-use="${esc(k)}"${isOff ? '' : ' checked'} aria-label="use on this route"><i></i></label>`; };
  const famChip = (f) => `<span class="rx-fam">${famName(f)}</span>`;

  const build = (it) => {
    const p = it, t = it.tunnel;
    const fams = ['v4', 'v6'].filter(f => hasFam(p.iran, f) && hasFam(p.foreign, f));
    const off = skip[key(p.iran, p.foreign)] || [];
    const admin = sharedPair(p.iran, p.foreign);
    const now = Math.floor(Date.now() / 1000);

    // header: name, the route, the status, Measure
    const st = t ? rxState(t) : null;
    const route = `<span class="rx-end">${fl(p.iran, flag('IR'))} ${srvNm(p.iran)}</span><span class="rx-arr">→</span><span class="rx-end">${fl(p.foreign, '🖥')} ${srvNm(p.foreign, 'panel host')}</span>${t ? `<span class="faint mono">:${esc(t.ports)}</span>` : ''}`;
    const head = `<div class="rx-h"><div class="rx-ht"><h3>${t ? nm(t.name) : '<span>Measured, no tunnel</span>'}</h3><div class="rx-route">${route}</div></div>
      <div class="rx-ha">${st ? `<span class="pill ${st.cls === 'ok' ? 'on' : 'off'} rx-st ${st.cls}"${st.why ? ` title="${esc(st.why)}"` : ''}><span class="led"></span>${esc(st.txt)}</span>` : ''}${fams.length ? '<button type="button" class="btn sm" data-measure>📊 Measure</button>' : ''}</div></div>`;

    // 1. where the users are
    let hero = '';
    if (t) {
      const u = rxUsersOn(t);
      if (!u) hero = `<div class="rx-hero off"><div class="rx-hl">The tunnel is stopped</div><div class="faint">${t.selected ? `<span>Starts on</span> <b>${esc(mTitle(t.selected))}</b> · ` : ''}<span>Start it on the Tunnels page.</span></div></div>`;
      else if (u.reading) hero = `<div class="rx-hero"><div class="rx-hl">⚡ <span>Reading which path the users are on…</span></div></div>`;
      else {
        const v = u.v, i = u.i;
        const q = [];
        if (v) {
          if (v.kbps && v.kbps[i] > 0) q.push(`<bdi><b>${(v.kbps[i] / 1000).toFixed(1)}</b> Mbps</bdi>`);
          if (v.rtt && v.rtt[i] >= 0) q.push(`<bdi><b>${v.rtt[i]}</b> ms</bdi>`);
          if (v.loss && v.loss[i] >= 0) q.push(`<bdi><b>${v.loss[i].toFixed(1)}%</b></bdi> <span>loss</span>`);
        }
        const m = measured(p, u.mid, u.fam);
        if (!q.length && m && m.x.ok) q.push(`<span>measured</span> <bdi><b>↓${m.x.downMbps.toFixed(0)}</b> Mbps</bdi> · <bdi><b>${m.x.rttMs.toFixed(0)}</b> ms</bdi>`);
        const stale = v && v.read && now - v.read > RX_STALE;
        const pathOk = v ? !!(v.ok || [])[i] : st.cls !== 'bad';
        const since = v && v.since ? `<span>since</span> <span>${ago(v.since)}</span>` : t.failover && t.failover.since ? `<span>since</span> <span>${ago(t.failover.since)}</span>` : '';
        const mode = t.hotStandby ? `<span class="chip">${t.hsAuto ? '🤖 <span>auto switching</span>' : '✋ <span>manual switching</span>'}</span>` : t.noFailover ? '<span class="chip">Off: nothing switches.</span>' : '<span class="chip">🔁 <span>Failover after 5 min down</span></span>';
        const own = t.active + '|' + t.family, onOwn = u.mid + '|' + u.fam === own;
        hero = `<div class="rx-hero ${pathOk && !stale ? 'ok' : 'bad'}">
          <div class="rx-hk">👥 <span>Users are on</span></div>
          <div class="rx-hl"><b><bdi>${esc(mTitle(u.mid))}</bdi></b> ${famChip(u.fam)}${since ? `<span class="rx-since">${since}</span>` : ''}</div>
          <div class="rx-hq">${q.length ? `<span class="rx-qv">${q.join(' · ')}</span>` : ''}${mode}${!onOwn ? `<span class="chip" title="the method the tunnel was started with">⚙ <span>own method:</span> <bdi>${esc(mTitle(t.active))}</bdi> ${famName(t.family)}</span>` : ''}${t.failover ? `<span class="chip fo" title="${esc(t.failover.reason || '')}">🔁 <span>on a backup path</span></span>` : ''}</div>
          ${stale ? `<div class="rx-warn">⚠ <span>Last read</span> <span>${ago(v.read)}</span> — <span>the Iran server isn't answering: this may no longer be true.</span></div>` : ''}
          ${!pathOk && v && v.why && v.why[i] ? `<div class="rx-warn">⚠ ${esc(v.why[i])}</div>` : st.why ? `<div class="rx-warn">⚠ ${esc(st.why)}</div>` : ''}</div>`;
      }
    }

    // 2. the paths it keeps ready (hot standby), or the one it runs
    const inPaths = new Set();
    let paths = '';
    if (t && t.active) {
      const v = t.hotStandby ? t.hs : null;
      const rows = [];
      if (v && v.keys && v.paths) {
        const ok = v.ok || [];
        v.keys.forEach((k, i) => {
          inPaths.add(k);
          const [mid, f] = k.split('|');
          const qual = [];
          if (ok[i]) {
            if (v.kbps && v.kbps[i] > 0) qual.push(`<bdi>${(v.kbps[i] / 1000).toFixed(1)} Mbps</bdi>`);
            if (v.rtt && v.rtt[i] >= 0) qual.push(`<bdi>${v.rtt[i]} ms</bdi>`);
            if (v.loss && v.loss[i] >= 0) qual.push(`<bdi>${v.loss[i].toFixed(1)}%</bdi> <span>loss</span>`);
          }
          const why = !ok[i] ? `<span class="rx-why" title="${esc(v.why && v.why[i] ? v.why[i] : "the switcher's check through this path gets no answer")}"><span>down</span>${v.changed && v.changed[i] > 0 ? ` · <span>${ago(v.changed[i])}</span>` : ''} — ${esc(v.why && v.why[i] ? v.why[i] : "the switcher's check through this path gets no answer")}</span>` : '';
          const act = i === v.active ? '<b class="rx-users">👥 <span>users</span></b>' : ok[i] ? `<button type="button" class="btn sm" data-hspin="${esc(k)}" title="move the users here now — open connections finish where they are, nobody is cut">use</button>` : '';
          rows.push({ cls: (ok[i] ? 'ok' : 'bad') + (i === v.active ? ' cur' : ''), icon: ok[i] ? '✓' : '✕', mid, f, k, line: qual.length ? `<span class="rx-qn" title="now, as the switcher measures it">${qual.join(' · ')}</span>` : why, act, bench: measured(p, mid, f), pin: i === v.pin });
        });
        (t.paths || []).filter(x => x.failed && !inPaths.has(x.method + '|' + x.family)).forEach(x => {
          const k = x.method + '|' + x.family; inPaths.add(k);
          rows.push({ cls: 'bad', icon: '✕', mid: x.method, f: x.family, k, line: `<span class="rx-why" title="${esc(x.failed)}"><span>didn't start</span> — ${esc(x.failed)}</span>`, act: '', bench: measured(p, x.method, x.family) });
        });
      } else if (!t.hotStandby) {
        const k = t.active + '|' + t.family; inPaths.add(k);
        const sc = rxState(t);
        rows.push({ cls: (sc.cls === 'bad' ? 'bad' : 'ok') + ' cur', icon: sc.cls === 'bad' ? '✕' : '✓', mid: t.active, f: t.family, k, line: sc.why ? `<span class="rx-why">${esc(sc.why)}</span>` : '', act: '<b class="rx-users">👥 <span>users</span></b>', bench: measured(p, t.active, t.family) });
      }
      const nOk = rows.filter(r => r.icon === '✓').length;
      paths = rows.length ? `<section class="rx-sec"><div class="rx-sh"><b>${t.hotStandby ? '⚡ <span>Paths kept ready</span>' : '<span>Path</span>'}</b>${t.hotStandby ? `<span class="count">${nOk}/${rows.length} <span>working</span></span>` : ''}</div>
        <div class="rx-paths">${rows.map(r => `<div class="rx-p ${r.cls}"><span class="rx-i">${r.icon}</span>
          <span class="rx-pm"><span class="rx-pn"><bdi>${esc(mTitle(r.mid))}</bdi> ${famChip(r.f)}${r.pin ? ' <span class="faint">📌 <span>chosen</span></span>' : ''}</span><span class="rx-pq">${r.line}</span></span>
          <span class="rx-pb" title="the last benchmark">${benchTxt(r.bench)}</span><span class="rx-pa">${r.act}${t.hotStandby ? sw(p, r.k, admin) : ''}</span></div>`).join('')}</div>${t.hotStandby ? hsOffFold(t) : ''}</section>` : '';
    }

    // 3. the methods it doesn't run: folded, the ones on first, then by the last benchmark
    const cells = [];
    STATE.methods.filter(m => m.id !== 'spoof').forEach(m => fams.forEach(f => { if (m.families.includes(f) && !inPaths.has(m.id + '|' + f)) cells.push({ mid: m.id, f, k: m.id + '|' + f, off: off.includes(m.id + '|' + f), b: measured(p, m.id, f) }); }));
    const score = (c) => c.b && c.b.x.ok ? c.b.pos : c.b && !c.b.x.skipped ? 500 : 900;
    cells.sort((a, b) => a.off - b.off || score(a) - score(b) || mTitle(a.mid).localeCompare(mTitle(b.mid)));
    const nOn = cells.filter(c => !c.off).length;
    const famAge = fams.map(f => { const r = benchOf(p, f); return `<span>${famName(f)}</span>: ${r ? `<span>measured</span> <span>${ageTxt(r.at)}</span>` : '<span>not measured yet</span>'}`; }).join(' · ');
    const others = cells.length ? `<details class="rx-sec rx-more"${it.pairOnly ? ' open' : ''}><summary><b>${t && t.active ? '<span>Other methods</span>' : '<span>Methods on this route</span>'}</b> <span class="count">${cells.length}</span> <span class="faint">${nOn} <span>on</span></span><span class="rx-chev">▾</span></summary>
      <div class="rx-paths">${cells.map(c => `<div class="rx-p${c.off ? ' left' : ''}"><span class="rx-i faint">${c.off ? '–' : '○'}</span>
        <span class="rx-pm"><span class="rx-pn"><bdi>${esc(mTitle(c.mid))}</bdi> ${famChip(c.f)}</span>${c.off ? '<span class="rx-pq faint">off on this route</span>' : ''}</span>
        <span class="rx-pb" title="the last benchmark">${benchTxt(c.b)}</span><span class="rx-pa">${sw(p, c.k, admin)}</span></div>`).join('')}</div>
      <div class="faint rt-leg">${famAge}</div></details>` : '';

    const notes = [];
    if (admin) notes.push('These servers belong to the admin, who decides which methods this route uses.');
    else if (it.shared.length) notes.push(`<span>The switches belong to the server pair: they also apply to</span> ${it.shared.map(nm).join(', ')}.`);
    if (!admin) notes.push('Switch on = kept ready on this route (hot standby, failover); off = never used here. ★ best measured · numbers = the order they are tried.');
    const el = h(`<div class="card rt-card rx-card">${head}${hero}${paths}${others}<div class="faint rt-leg rx-legend">${notes.map(x => `<div>${x}</div>`).join('')}</div></div>`);

    // folds opened or closed by hand stay so through the refresh
    const rtOpen = (STATE.rtOpen = STATE.rtOpen || {});
    $$('details', el).forEach((d, i) => { const k2 = p.id + '|' + i; if (k2 in rtOpen) d.open = rtOpen[k2]; d.addEventListener('toggle', () => { rtOpen[k2] = d.open; }); });
    $$('[data-use]', el).forEach(b => b.onchange = () => setSkip(p, b.dataset.use, !b.checked, b));
    $$('[data-err]', el).forEach(b => b.onclick = () => alertModal('Why it failed', b.dataset.err));
    const ms = $('[data-measure]', el); if (ms) ms.onclick = () => rxMeasure(p, fams, maxMB, skip);
    if (t) hsWire(t, el);
    return el;
  };
  // a switch: saved for the server pair; the users' path can't be switched off (they'd be cut)
  const setSkip = async (p, v, on, input) => {
    const [method, family] = v.split('|');
    const t = p.tunnel, u = t ? rxUsersOn(t) : null;
    if (on && u && u.mid === method && u.fam === family && t.hotStandby) {
      input.checked = true;
      const msg = 'The users are on this path — move them to another one with “use” first.';
      return alertModal('Routes', window.tpT ? tpT(msg) : msg);
    }
    input.disabled = true;
    try {
      skip = await api('/routes/skip', { iran: p.iran, foreign: p.foreign, method, family, skip: on });
      toast(on ? `${mTitle(method)} (${famName(family)}) left out on this route — running hot-standby tunnels stop it within seconds` : `${mTitle(method)} (${famName(family)}) is back on this route — running hot-standby tunnels start it within seconds`);
    } catch (er) { alertModal('Routes', er.message); } // the switch goes back to what is saved
    paint();
  };

  const paint = () => {
    $$('[data-rsel]', split).forEach(b => b.classList.toggle('on', b.dataset.rsel === sel));
    $$('[data-rsel]', strip).forEach(b => b.setAttribute('aria-selected', b.dataset.rsel === sel ? 'true' : 'false'));
    items.forEach(it => {
      $$(`[data-rsel="${CSS.escape(it.id)}"] .rx-dot`, split).forEach(d => { d.className = 'rx-dot ' + dotCls(it); });
      const s = $(`.rx-row[data-rsel="${CSS.escape(it.id)}"] small`, picker); if (s) s.innerHTML = subOf(it);
    });
    card.innerHTML = '';
    // one tunnel that can't be drawn must not leave the page empty
    try { card.appendChild(build(cur())); }
    catch (e) { card.appendChild(h(`<div class="card rt-card"><div class="faint">${esc(e.message)}</div></div>`)); console.error(e); }
  };
  const pick = (id) => {
    sel = id; remember('tp-routesel', id); paint();
    const c = $(`.rx-chip[data-rsel="${CSS.escape(id)}"]`, strip); if (c) c.scrollIntoView({ block: 'nearest', inline: 'center' });
    if (window.innerWidth <= 860) strip.scrollIntoView({ block: 'start' });
  };
  $$('[data-rsel]', split).forEach(b => b.onclick = () => pick(b.dataset.rsel));
  // phone: every tunnel in a sheet, with search
  $('[data-rall]', strip).onclick = () => {
    const m = modal(`<h2>Routes</h2><input class="inp" type="search" data-mq placeholder="Search tunnels…" style="margin:8px 0"><div class="rx-sheet">${listHTML()}</div>`);
    $$('[data-rsel]', m).forEach(b => { b.classList.toggle('on', b.dataset.rsel === sel); b.onclick = () => { m.remove(); pick(b.dataset.rsel); }; });
    const mq = $('[data-mq]', m);
    mq.oninput = () => { const s = mq.value.trim().toLowerCase(); $$('[data-rsel]', m).forEach(b => { b.hidden = !!s && !b.dataset.q.includes(s); }); $$('.sgrp', m).forEach(g => { g.hidden = !$$('[data-rsel]', g).some(b => !b.hidden); }); };
  };
  // ↑/↓ on the list steps through the tunnels
  picker.addEventListener('keydown', (e) => {
    if (!['ArrowDown', 'ArrowUp'].includes(e.key) || e.target === q) return;
    const vis = items.filter(it => { const b = $(`[data-rsel="${CSS.escape(it.id)}"]`, picker); return b && !b.hidden; });
    const i = vis.findIndex(x => x.id === sel), n = vis[Math.max(0, Math.min(vis.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))];
    if (n) { e.preventDefault(); pick(n.id); const b = $(`[data-rsel="${CSS.escape(n.id)}"]`, picker); b && b.focus(); }
  });
  paint();
  { const c = $(`.rx-chip[data-rsel="${CSS.escape(sel)}"]`, strip); if (c) c.scrollIntoView({ block: 'nearest', inline: 'center' }); }
  // health, the users' path and new results come in while the page is open; not while a
  // switch or field is being used
  if (routesTimer) clearInterval(routesTimer);
  const timer = setInterval(async () => {
    if (tok !== routesTok || STATE.view !== 'routes' || !split.isConnected) { clearInterval(timer); if (routesTimer === timer) routesTimer = null; return; }
    if (document.hidden || document.querySelector('.modal') || (document.activeElement && split.contains(document.activeElement) && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName) && document.activeElement !== q)) return;
    try {
      const [list, h2, s2] = await Promise.all([api('/tunnels'), api('/bench/history'), api('/routes/skip')]);
      if (tok !== routesTok || !split.isConnected) return;
      // the whole tunnel, not a few fields: a Stop, a failover to the other family or hot
      // standby turned off elsewhere showed the old state until the page was opened again
      (Array.isArray(list) ? list : []).forEach(n => { const t = STATE.tunnels.find(x => x.id === n.id); if (t) { Object.keys(t).forEach(k => { if (!(k in n)) delete t[k]; }); Object.assign(t, n); } });
      items.forEach(it => { if (!it.tunnel) return; const t = STATE.tunnels.find(x => x.id === it.tunnel.id); if (t) it.tunnel = t; });
      hist = h2 || hist; skip = s2 || skip;
      const y = window.scrollY; paint(); window.scrollTo(0, y);
    } catch (e) {}
  }, 15000);
  routesTimer = timer;
}
let routesTimer = null;
// one Measure for the route: the families picked (IPv4 then IPv6, on the server) and what it costs
function rxMeasure(p, fams, maxMB, skip) {
  const k = bnKey(p.iran, p.foreign);
  const use = Object.fromEntries(fams.map(f => { const { users, standby } = bnUse({ tunnels: p.pairTunnels || p.tunnels || [] }, f); return [f, users.size + standby.size]; }));
  const all = Object.fromEntries(fams.map(f => [f, bnAll(f).length]));
  const m = modal(`<h2>📊 Measure this route</h2><p class="muted" style="margin-top:4px">${srvNm(p.iran)} → ${srvNm(p.foreign, 'panel host')}</p>
    <form class="ff" id="rxmf">
      <div class="rx-fams">${fams.map(f => `<label class="ochk"><input type="checkbox" name="f" value="${f}" checked> ${famName(f)}</label>`).join('')}</div>
      <label class="bn-opt"><input type="radio" name="scope" value="running" checked><span><b>The methods in use</b><small data-cost="running"></small></span></label>
      <label class="bn-opt"><input type="radio" name="scope" value="all"><span><b>Every method</b><small data-cost="all"></small></span></label>
      <div class="faint" style="font-size:12px">Each method runs on a temporary tunnel, is measured, then removed — live tunnels are not touched. It runs on the server: you can leave this page.</div>
      <div class="actions" style="justify-content:flex-end"><button type="button" class="btn ghost" data-no>Cancel</button><button class="btn pri">▶ Start</button></div></form>`);
  const f = $('#rxmf', m);
  const picked = () => $$('[name=f]', f).filter(x => x.checked).map(x => x.value);
  const cost = () => {
    const fs = picked();
    const n = (sc) => fs.reduce((a, x) => a + (sc === 'running' ? (use[x] || all[x]) : all[x]), 0);
    $('[data-cost=running]', f).textContent = `${n('running')} methods · ≤ ${n('running') * 2 * maxMB} MB`;
    $('[data-cost=all]', f).textContent = bnCostAll(n('all'), maxMB);
    $('button.pri', f).disabled = !fs.length;
  };
  $$('[name=f]', f).forEach(x => x.onchange = cost); cost();
  // the exact count of every method from the server (a Golden-GRE a live tunnel runs here stays out)
  fams.forEach(fm => api(`/bench/plan?iran=${encodeURIComponent(p.iran)}&foreign=${encodeURIComponent(p.foreign || '')}&family=${fm}`).then(pl => { all[fm] = (pl.methods || []).length; if (m.isConnected) cost(); }).catch(() => {}));
  $('[data-no]', m).onclick = () => m.remove();
  f.onsubmit = oneAtATime(f, async () => {
    const fs = picked(); if (!fs.length) return;
    const req = { iranId: p.iran, foreignId: p.foreign, family: fs[0], running: f.scope.value !== 'all', all: f.scope.value === 'all', seconds: 3 };
    if (fs[1]) req.then = fs[1];
    try { const r = await api('/bench/start', req); m.remove(); toast(fs[1] ? `Benchmark started — ${famName(fs[0])}, then ${famName(fs[1])}` : 'Benchmark started'); openLog({ id: 'bench', name: 'Benchmark · ' + fs.map(famName).join(' + ') }, r.job); }
    catch (er) { alertModal('Benchmark', er.message); }
  });
}
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
// a server's size (bytes), as the once-a-minute resource check last read it
const gbTxt = (b) => { const g = b / 2 ** 30; return g >= 1000 ? (g / 1024).toFixed(1) + ' TB' : (g >= 10 || Math.abs(g - Math.round(g)) < 0.05 ? Math.round(g) : g.toFixed(1)) + ' GB'; };
const hwShort = (hw) => hw && hw.cores ? `<small class="shw mono" title="${esc(L('cores · RAM · disk', 'هسته · رم · دیسک'))}">${hw.cores} core · ${gbTxt(hw.memTotal)} · ${gbTxt(hw.diskTotal)}</small>` : '';
function hwRows(hw) {
  if (!hw || !hw.cores) return `<div class="wide" data-notr><dt>${L('Hardware', 'سخت‌افزار')}</dt><dd><span class="faint">${L('read by the next resource check (once a minute, while the server is reachable)', 'در بررسی بعدی منابع خوانده می‌شود (هر دقیقه، وقتی سرور در دسترس است)')}</span></dd></div>`;
  const pc = (a, b) => b ? Math.round(100 * a / b) : 0;
  const when = `<span class="faint" title="${esc(new Date(hw.at * 1000).toLocaleString())}"> · ${hwAgo(hw.at)}</span>`;
  return `<div data-notr><dt>CPU</dt><dd><b>${hw.cores}</b> ${L(hw.cores === 1 ? 'core' : 'cores', 'هسته')}</dd></div>
    <div data-notr><dt>${L('RAM', 'رم')}</dt><dd><b><bdi>${gbTxt(hw.memTotal)}</bdi></b> <span class="faint">· ${L('used', 'استفاده‌شده')} <bdi>${gbTxt(hw.memUsed)} (${pc(hw.memUsed, hw.memTotal)}%)</bdi></span></dd></div>
    <div class="wide" data-notr><dt>${L('Disk', 'دیسک')}</dt><dd><b><bdi>${gbTxt(hw.diskTotal)}</bdi></b> <span class="faint">· ${L('free', 'آزاد')} <bdi>${gbTxt(hw.diskFree)} (${pc(hw.diskFree, hw.diskTotal)}%)</bdi></span>${when}</dd></div>`;
}
const hwAgo = (ts) => { const m = Math.max(0, Math.round((Date.now() / 1000 - ts) / 60)); return m < 2 ? L('read just now', 'همین الان خوانده شد') : m < 120 ? L(`read ${m} min ago`, `${m} دقیقه پیش خوانده شد`) : m < 2880 ? L(`read ${Math.round(m / 60)} h ago`, `${Math.round(m / 60)} ساعت پیش خوانده شد`) : L(`read ${Math.round(m / 1440)} d ago`, `${Math.round(m / 1440)} روز پیش خوانده شد`); };
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
    const dn = !host && s.up && s.up.down;
    const led = dn ? 'bad' : host || s.agentOnline ? 'on' : s.prepared ? 'ok2' : 'off';
    const tip = dn ? 'down' : host ? 'local' : s.agentOnline ? 'agent online' : s.prepared ? 'reachable' : 'not tested';
    const n = host ? STATE.tunnels.filter(t => !t.foreignId).length : STATE.tunnels.filter(t => t.serverId === s.id || t.foreignId === s.id).length;
    const fl = host ? '🖥' : s.country ? flag(s.country) : ((s.role || 'iran') === 'iran' ? flag('IR') : '🌍');
    const ip = host ? STATE.settings.localIPv4 : (s.ipv4 || s.ipv6);
    return `<button class="srow${id === cur ? ' on' : ''}" data-pick="${id}">
      <span class="sflag">${fl}</span>
      <span class="sinfo"><b>${host ? 'This panel host' : s.name ? nm(s.name) : '(unnamed)'}${host ? '' : ' ' + ownerChip(s.owner)}</b><small class="mono">${esc(ip || '—')}</small>${hwShort(host ? STATE.hostHw : s.hw)}${host ? '' : upLine(s.up, true)}</span>
      <span class="smeta"><span class="led ${led}" title="${tip}"></span><small class="faint" title="tunnels">🛰 ${n}</small><small class="faint mono" data-mini="${host ? '' : s.id}" title="CPU · RAM"></small></span>
    </button>`;
  };
  // Iran and foreign: one switch at the top of the list, one group shown at a time (no scrolling
  // past every Iran server to reach the foreign ones); the choice is remembered
  const fgItems = hostShown ? ['host', ...fg] : fg;
  const grpOf = (id) => id === 'host' || fg.some(x => x.id === id) ? 'foreign' : 'iran';
  let side = recall('tp-srvgrp');
  if (side !== 'iran' && side !== 'foreign') side = cur ? grpOf(cur) : 'iran';
  if (cur && grpOf(cur) !== side) { // the remembered server is on the other side: that side's first
    const first = side === 'iran' ? ir[0] : fgItems[0];
    if (first) cur = first === 'host' ? 'host' : first.id; else side = grpOf(cur);
  }
  const grp = (key, items) => `<div class="sgrp" data-grp="${key}"${key === side ? '' : ' hidden'}>
    ${items.length ? items.map(row).join('') : `<div class="faint sempty">${key === 'iran' ? 'No Iran server yet — add one to start building tunnels.' : 'No foreign server yet.'}</div>`}
    <div class="faint sempty" data-nomatch hidden>${L('No server matches the filter here.', 'سروری در این گروه با فیلتر جور نیست.')}</div></div>`;
  const segBtn = (key, label, n) => `<button type="button" role="tab" data-side="${key}" class="${key === side ? 'on' : ''}" aria-selected="${key === side}">${label} <span class="sgn" data-sgn="${key}">${n}</span></button>`;
  const downNow = all.filter(s => s.up && s.up.down).sort((a, b) => a.up.since - b.up.since);
  if (downNow.length) w.appendChild(h(`<div class="card sdown" data-notr><div class="odh"><b>🔴 ${L('Down now', 'الان قطع')}</b><span class="count">${downNow.length}</span></div>${downNow.map(s => `<button class="sdr" data-pick="${s.id}"><b>${nm(s.name || '(unnamed)')}</b><span class="faint">${L('down since', 'قطع از')} ${upWhen(s.up.since, s.up.now)}</span><b class="mono bad">${upDur(s.up.now - s.up.since)}</b><span class="faint">${s.up.recent && s.up.recent[0] ? upWhy(s.up.recent[0]) : ''}</span></button>`).join('')}</div>`));
  const split = h(`<div class="srvsplit">
    <aside class="card srvlist">
      ${all.length > 6 ? '<input class="sq" type="search" placeholder="Filter by name or IP…" data-sq>' : ''}
      <div class="sside" data-notr><div class="seg sm" role="tablist" aria-label="${L('Server group', 'گروه سرورها')}">${segBtn('iran', `${flag('IR')} ${L('Iran', 'ایران')}`, ir.length)}${segBtn('foreign', `🌍 ${L('Foreign', 'خارج')}`, fgItems.length)}</div><button class="btn sm" data-add title="${L('Add a server to the group shown', 'افزودن سرور به گروه نمایش‌داده‌شده')}">+ ${L('Add', 'افزودن')}</button></div>
      ${grp('iran', ir)}
      ${grp('foreign', fgItems)}
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
  const q = $('[data-sq]', split);
  // the filter looks in both groups; each segment counts its matches
  const refilter = () => {
    const v = q ? q.value.trim().toLowerCase() : '';
    $$('.sgrp', split).forEach(g => {
      const rows = $$('.srow', g);
      rows.forEach(r => r.hidden = !!v && !r.textContent.toLowerCase().includes(v));
      const n = rows.filter(r => !r.hidden).length;
      $(`[data-sgn="${g.dataset.grp}"]`, split).textContent = v ? `${n}/${rows.length}` : rows.length;
      $('[data-nomatch]', g).hidden = !v || !rows.length || n > 0;
    });
  };
  const pickSide = (k) => {
    side = k; remember('tp-srvgrp', k);
    $$('[data-side]', split).forEach(b => { b.classList.toggle('on', b.dataset.side === k); b.setAttribute('aria-selected', b.dataset.side === k); });
    $$('.sgrp', split).forEach(g => g.hidden = g.dataset.grp !== k);
  };
  $$('[data-side]', split).forEach(b => b.onclick = () => {
    if (b.dataset.side === side) return;
    pickSide(b.dataset.side);
    // show that side's chosen (or first visible) server on the right
    if (grpOf(cur) !== side) { const r = $(`.sgrp[data-grp="${side}"] .srow:not([hidden])`, split) || $(`.sgrp[data-grp="${side}"] .srow`, split); if (r) show(r.dataset.pick, false); }
  });
  $$('[data-pick]', split).forEach(b => b.onclick = () => show(b.dataset.pick, true));
  $$('.sdr', w).forEach(b => b.onclick = () => { if (grpOf(b.dataset.pick) !== side) pickSide(grpOf(b.dataset.pick)); show(b.dataset.pick, true); });
  $('[data-add]', split).onclick = () => serverModal({ role: side });
  if (q) q.oninput = refilter;
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
// Outage log: every server (SSH port checked every few seconds) and tunnel outage, in Tehran
// time — ongoing ones on top, the rest by day with short drops folded, and which servers and
// tunnels went down most. It follows the View selector (an account's own servers and tunnels).
const OUT = { range: recall('tp-orange') || '7d', kind: recall('tp-okind') || 'all', fam: false, pick: '', open: {}, data: null };
const durTxt = (s) => s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s` : s < 86400 ? `${Math.floor(s / 3600)}h${String(Math.floor(s / 60) % 60).padStart(2, '0')}m` : `${Math.floor(s / 86400)}d${String(Math.floor(s / 3600) % 24).padStart(2, '0')}h`;
const oClock = (u) => new Date(u * 1000).toLocaleTimeString('en-GB', { timeZone: 'Asia/Tehran', hour: '2-digit', minute: '2-digit' });
const oDayKey = (u) => new Date(u * 1000).toLocaleDateString('en-CA', { timeZone: 'Asia/Tehran' }); // 2026-11-12
const oDayLabel = (u, now) => {
  const k = oDayKey(u);
  if (k === oDayKey(now)) return 'Today';
  if (k === oDayKey(now - 86400)) return 'Yesterday';
  return window.tpLang === 'fa' ? new Date(u * 1000).toLocaleDateString('fa-IR-u-nu-latn', { timeZone: 'Asia/Tehran', weekday: 'long', day: 'numeric', month: 'long' })
    : new Date(u * 1000).toLocaleDateString('en-GB', { timeZone: 'Asia/Tehran', weekday: 'short', day: 'numeric', month: 'short' });
};
const O_SHORT = 60; // drops shorter than this (seconds) are folded into a count
// Uptime (uptime.go, from the outage log): a tunnel's is its users' — a switch between
// hot-standby paths isn't an outage — a server's is its SSH monitor's. Written in both
// languages here (the numbers move every load; the translator's table can't hold them).
const L = (en, fa) => window.tpLang === 'fa' ? fa : en;
const upDur = (s) => {
  s = Math.max(0, Math.floor(s)); const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  const u = window.tpLang === 'fa' ? [' روز', ' ساعت', ' دقیقه', ' ثانیه'] : ['d', 'h', 'm', 's'];
  return d ? `${d}${u[0]} ${hh}${u[1]}` : hh ? `${hh}${u[1]} ${m}${u[2]}` : m ? `${m}${u[2]}` : `${s}${u[3]}`;
};
const upPct = (p) => (p >= 99.995 ? '100' : p >= 99.9 ? p.toFixed(2) : p.toFixed(1)) + '%';
const upCls = (p) => p >= 99.5 ? 'ok' : p >= 97 ? 'warn' : 'bad';
const upWhen = (u, now) => { const d = oDayLabel(u, now); return `${d === 'Today' ? L('today', 'امروز') : d === 'Yesterday' ? L('yesterday', 'دیروز') : d} ${oClock(u)}`; };
// how long it has been up; with no outage since the log began, "at least" that long
const upFor = (u) => { const d = upDur(u.now - (u.since || u.from)); return u.since ? d : L(`${d}+`, `بیش از ${d}`); };
// one small line: "up 3d 4h · 7d 99.2%" (and the 24 h when under 100%), or red "down 12m"
function upLine(u, short) {
  if (!u) return '';
  const now = u.now;
  if (u.down) return `<small class="upl down" data-notr title="${esc(L('Down since ', 'قطع از ') + upWhen(u.since, now) + L(' (Tehran)', ' (تهران)'))}">● ${L('down', 'قطع')} ${upDur(now - u.since)}</small>`;
  const tip = u.since ? L(`Up since ${upWhen(u.since, now)} (Tehran) · ${u.n7} outage(s) in 7 days`, `روشن از ${upWhen(u.since, now)} (تهران) · ${u.n7} قطعی در 7 روز`)
    : L(`No outage since the log began (${upWhen(u.from, now)})`, `از شروع لاگ (${upWhen(u.from, now)}) قطعی نداشته`);
  // the 7 days always, the last 24 h only when they were not all up (the row stays one line)
  const pc = (p, l) => p < 0 ? '' : ` · <span class="${upCls(p)}">${l} <bdi>${upPct(p)}</bdi></span>`;
  const pcts = short ? '' : pc(u.a7, L('7d', '7 روز')) + (u.a24 >= 0 && u.a24 < 99.995 ? pc(u.a24, L('24h', '24 ساعت')) : '');
  return `<small class="upl" data-notr title="${esc(tip + L(` · last 24 h ${upPct(Math.max(0, u.a24))}, 7 days ${upPct(Math.max(0, u.a7))}`, ` · 24 ساعت اخیر ${upPct(Math.max(0, u.a24))}، 7 روز ${upPct(Math.max(0, u.a7))}`))}">${L('up', 'روشن')} ${upFor(u)}${pcts}</small>`;
}
const upWhy = (o) => o.why === 'reboot' ? L('the server rebooted', 'سرور ریبوت شد')
  : o.why === 'network' ? L(`${o.others} other server(s) dropped at the same time — network / provider`, `هم‌زمان ${o.others} سرور دیگر هم قطع شد — شبکه / دیتاسنتر`)
  : (o.end && o.end - o.start < 60) ? L('short network drop', 'قطعی کوتاه شبکه')
  : L("SSH didn't answer — the server or its network", 'SSH جواب نداد — خود سرور یا شبکه‌اش');
// the server card's uptime: one line, the last outage, the last few on expand
function upBox(s) {
  const u = s.up; if (!u) return '';
  const now = u.now, last = (u.recent || []).find(o => o.end), live = u.down;
  const head = live ? `<b class="bad">● ${L('Down', 'قطع')} ${upDur(now - u.since)}</b> <span class="faint">${L('since', 'از')} ${upWhen(u.since, now)}</span>`
    : `<b class="ok">● ${L('Up', 'روشن')} ${upFor(u)}</b>${u.since ? ` <span class="faint">${L('since', 'از')} ${upWhen(u.since, now)}</span>` : ''}`;
  const pc = (p, l) => p < 0 ? '' : `<span class="${upCls(p)}">${l} <bdi>${upPct(p)}</bdi></span>`;
  const meta = [u.boot ? `${L('machine booted', 'آخرین بوت')} ${upDur(now - u.boot)} ${L('ago', 'پیش')}` : '',
    !live && last ? `${L('last down', 'آخرین قطعی')} ${upWhen(last.start, now)}، ${upDur(last.end - last.start)} — ${upWhy(last)}` : (!live && !last ? L('no outage recorded', 'قطعی ثبت نشده') : ''),
    live && u.recent && u.recent[0] ? upWhy(u.recent[0]) : ''].filter(Boolean);
  const rows = (u.recent || []).map(o => `<div class="upr"><span class="mono">${upWhen(o.start, now)}</span><b class="mono">${o.end ? upDur(o.end - o.start) : L('ongoing', 'ادامه دارد')}</b><span class="faint">${upWhy(o)}</span></div>`).join('');
  return `<div class="upbox${live ? ' down' : ''}" data-notr><div class="uph">${head}<span class="upp">${pc(u.a24, L('24h', '24 ساعت'))}${pc(u.a7, L('7d', '7 روز'))}</span></div>
    ${meta.length ? `<div class="upm faint">${meta.map(esc).join(' · ')}</div>` : ''}
    ${rows ? `<details class="upd"><summary class="faint">${L(`Last outages (${u.recent.length})`, `قطعی‌های اخیر (${u.recent.length})`)}</summary>${rows}</details>` : ''}</div>`;
}
// what an outage was, in plain words, and whose it is (the current name: servers get renamed)
function outageInfo(o) {
  let name = o.name || '', owner = '', gone = false, key, icon;
  if (o.kind === 'tunnel') {
    const t = STATE.tunnels.find(x => x.id === o.target); key = 't:' + o.target; icon = '🛰';
    if (t) { name = t.name; owner = t.owner || ''; } else gone = true;
  } else if (o.kind === 'panel') { name = 'This panel host'; key = 'panel'; icon = '🖥'; }
  else {
    const sid = (o.target || '').split('/')[0], s = STATE.servers.find(x => x.id === sid); key = 's:' + sid; icon = '🖧';
    if (s) { name = s.name; owner = s.owner || ''; } else { gone = true; name = name.replace(/ \(IPv[46]\)$/, ''); }
  }
  const c = o.cause || '';
  const [cause, cls] = o.kind === 'server' ? ['Server unreachable', 'bad']
    : o.kind === 'ssh-v4' ? ['Only IPv4 down — IPv6 worked', 'warn']
    : o.kind === 'ssh-v6' ? ['Only IPv6 down — IPv4 worked', 'warn']
    : o.kind === 'panel' ? ['The panel host was offline', 'warn']
    : /both servers answer/.test(c) ? ['Tunnel dropped — its servers answered', 'bad']
    : /panel host/.test(c) ? ['The panel host was offline', 'warn']
    : /Iran server .* and foreign server/.test(c) ? ['Both its servers were unreachable', 'warn']
    : /^Iran server/.test(c) ? ['Its Iran server was unreachable', 'warn']
    : /^foreign server/.test(c) ? ['Its foreign server was unreachable', 'warn']
    : ['Tunnel down', 'bad'];
  // a tunnel's own cause in plain words (outagecause.go), in the page's language
  const why = o.kind === 'tunnel' && o.why ? L(o.why, o.whyFa || o.why) : '';
  return { name, owner, gone, key, icon, cause, why, cls: why && /^(panel|iran_down|foreign_down|servers)/.test(o.code || '') ? 'warn' : cls,
    fam: o.kind === 'ssh-v4' || o.kind === 'ssh-v6', approx: /panel restarted/.test(o.reason || ''), probe: o.old === 'probe' };
}
function outageSection() {
  const sec = h(`<section class="group olog"><div class="ghd"><div><h2>📉 Outage log <span class="qi" title="Every server's SSH port is checked every few seconds (a miss is retried twice), so short drops show up too. A tunnel counts as down only when its users had no working path — every path down, or left on a dead one — not when one path or one probe failed; each outage says why. Repeated drops of one tunnel on a day share one line. Times are Tehran time.">ⓘ</span></h2><p>Servers and tunnels that went down · Tehran time</p></div>
    <div class="ohd"><div class="seg sm" data-orange>${[['24h', '24 h'], ['7d', '7 days'], ['all', 'All']].map(([v, l]) => `<button data-v="${v}"${OUT.range === v ? ' class="on"' : ''}>${l}</button>`).join('')}</div>
    <button class="btn sm" data-oref title="Refresh">⟳</button>${moreMenu([{ label: '🗑 Clear the log…', attr: 'data-oclr', danger: true }])}</div></div>
    <div data-obody><div class="card muted" style="padding:14px">loading…</div></div></section>`);
  const body = $('[data-obody]', sec);
  const paint = () => {
    const r = OUT.data; if (!r) return;
    const now = r.now, since = OUT.range === '24h' ? now - 86400 : OUT.range === '7d' ? now - 7 * 86400 : 0;
    const hostShown = !STATE.ownerFilter || STATE.ownerFilter === '-';
    let all = r.outages.map(o => ({ ...o, i: outageInfo(o), d: (o.end || now) - o.start }))
      .filter(o => (o.end || now) >= since && (o.kind === 'panel' ? hostShown : o.i.gone ? !STATE.ownerFilter : shownOwner(o.i.owner)));
    const famN = all.filter(o => o.i.fam).length;
    if (!OUT.fam) all = all.filter(o => !o.i.fam);
    if (OUT.kind === 'server') all = all.filter(o => o.kind !== 'tunnel'); else if (OUT.kind === 'tunnel') all = all.filter(o => o.kind === 'tunnel');
    // the old rule's hot-standby entries (one failed probe, users not proven cut) stay folded
    // and count nowhere; the rest make the summary and the days
    const real = all.filter(o => !o.i.probe);
    // the summary: who went down most (time down inside the period)
    const by = {};
    for (const o of real) {
      const x = by[o.i.key] || (by[o.i.key] = { key: o.i.key, name: o.i.name, icon: o.i.icon, n: 0, t: 0, open: false });
      x.n++; x.t += Math.max(0, (o.end || now) - Math.max(o.start, since)); x.open = x.open || !o.end;
    }
    const top = Object.values(by).sort((a, b) => b.t - a.t || b.n - a.n).slice(0, 6), max = top.length ? top[0].t || 1 : 1;
    const picked = OUT.pick && by[OUT.pick] ? by[OUT.pick] : null;
    if (OUT.pick && !picked && !all.some(o => o.i.key === OUT.pick)) OUT.pick = '';
    const list = OUT.pick ? all.filter(o => o.i.key === OUT.pick) : all;
    const oCause = (o) => o.i.why ? `<small class="oc ${o.i.cls}" data-notr>${esc(o.i.why)}</small>` : `<small class="oc ${o.i.cls}">${o.i.cause}</small>`;
    const row = (o, sub = false, same = '') => {
      const dayOf = (u) => oDayKey(u) !== oDayKey(o.start) ? ` (<span>${oDayLabel(u, now)}</span>)` : '';
      const tip = [o.reason, o.cause].filter(Boolean).join(' — ');
      return `<div class="orow${o.end ? '' : ' live'}${sub ? ' osub' : ''}" title="${esc(tip)}"><span class="oic">${sub ? '' : o.i.icon}</span>
        <div class="om">${sub ? '' : `<b>${nm(o.i.name)}${o.i.gone ? ' <small class="faint">(deleted)</small>' : ''}</b>`}${sub && (o.i.why || o.i.cause) === same ? '' : oCause(o)}</div>
        <div class="ot">${o.end ? `<span class="faint"><span class="mono">${oClock(o.start)} – ${oClock(o.end)}</span>${dayOf(o.end)}${o.i.approx ? ' <span title="the panel restarted during it: the end time is approximate">≈</span>' : ''}</span>` : `<span class="faint"><span>since</span> <span class="mono">${oClock(o.start)}</span>${oDayKey(o.start) !== oDayKey(now) ? ` (<span>${oDayLabel(o.start, now)}</span>)` : ''}</span>`}<b class="mono">${durTxt(o.d)}</b></div></div>`;
    };
    // one line per tunnel/server and day: "تانل انگلیس · 4 drops · 03:52–05:17 · total 11m",
    // each drop on expand; the cause most of them had
    const group = (rs) => {
      if (rs.length < 2) return rs.map(o => row(o)).join('');
      const o = rs[0], n = rs.length, tot = rs.reduce((s, x) => s + x.d, 0);
      const first = Math.min(...rs.map(x => x.start)), last = Math.max(...rs.map(x => x.end || now));
      const cnt = {}; for (const x of rs) { const c = x.i.why || x.i.cause; cnt[c] = (cnt[c] || 0) + 1; }
      const top1 = Object.keys(cnt).sort((a, b) => cnt[b] - cnt[a])[0], same = rs.find(x => (x.i.why || x.i.cause) === top1);
      const kinds = Object.keys(cnt).length;
      return `<details class="ogrp"><summary class="orow"><span class="oic">${o.i.icon}</span>
        <div class="om"><b>${nm(o.i.name)}${o.i.gone ? ' <small class="faint">(deleted)</small>' : ''} <span class="ocount" data-notr>${L(`${n} drops`, `${n} قطعی`)}</span></b>${oCause(same)}${kinds > 1 ? `<small class="faint" data-notr>${L(`+ ${kinds - 1} other cause(s) — tap to see each`, `+ ${kinds - 1} علت دیگر — برای دیدن هر کدام بزنید`)}</small>` : ''}</div>
        <div class="ot"><span class="faint mono">${oClock(first)} – ${oClock(last)}</span><b class="mono" data-notr>${L('total', 'جمعاً')} <bdi>${durTxt(tot)}</bdi></b></div></summary>${rs.map(x => row(x, true, top1)).join('')}</details>`;
    };
    const groups = (rs) => { const m = new Map(); for (const o of rs) { if (!m.has(o.i.key)) m.set(o.i.key, []); m.get(o.i.key).push(o); } return [...m.values()].map(group).join(''); };
    const live = list.filter(o => !o.end), done = list.filter(o => o.end).sort((a, b) => b.start - a.start); // newest day first, one card per day
    const days = []; let cur = null;
    for (const o of done) { const k = oDayKey(o.start); if (!cur || cur.k !== k) days.push(cur = { k, u: o.start, rows: [] }); cur.rows.push(o); }
    body.innerHTML = `<div class="ofil"><div class="seg sm" data-okind>${[['all', 'All'], ['server', 'Servers'], ['tunnel', 'Tunnels']].map(([v, l]) => `<button data-v="${v}"${OUT.kind === v ? ' class="on"' : ''}>${l}</button>`).join('')}</div>
      ${famN || OUT.fam ? `<label class="ochk" title="One address family's SSH down while the other answered — the server stayed up"><input type="checkbox" data-ofam${OUT.fam ? ' checked' : ''}> IPv4/IPv6-only drops <span class="count">${famN}</span></label>` : ''}
      ${OUT.pick ? `<button class="chip opick" data-opick="">${picked ? picked.icon : ''} ${nm(picked ? picked.name : (list[0] ? list[0].i.name : ''))} ✕</button>` : ''}</div>
      ${!all.length ? `<div class="card oempty">✅ <span>${r.outages.length ? 'No outage in this period.' : 'No outage recorded yet.'}</span></div>` : `
      ${!real.length ? `<div class="card oempty">✅ <span data-notr>${L('No confirmed outage in this period.', 'در این بازه قطعی تأییدشده‌ای نبوده.')}</span></div>` : ''}
      ${top.length > 1 && !OUT.pick ? `<div class="card osum"><div class="osh">Down the most <span class="faint">· tap one to see only its outages</span></div>${top.map(x => `<button class="osr${x.open ? ' live' : ''}" data-opick="${esc(x.key)}"><span class="oic">${x.icon}</span><b>${nm(x.name)}</b><span class="obar"><i style="width:${Math.max(3, Math.round(x.t / max * 100))}%"></i></span><span class="faint mono">${x.n}×</span><b class="mono">${durTxt(x.t)}</b></button>`).join('')}</div>` : ''}
      ${live.length ? `<div class="card oday onow"><div class="odh"><b>🔴 Down now</b><span class="count">${live.length}</span></div>${live.map(o => row(o)).join('')}</div>` : ''}
      ${days.map(d => {
        const ok = d.rows.filter(o => !o.i.probe), probe = d.rows.filter(o => o.i.probe);
        const long = ok.filter(o => o.d >= O_SHORT), short = ok.filter(o => o.d < O_SHORT), tot = ok.reduce((s, o) => s + o.d, 0), op = OUT.open[d.k], opp = OUT.open['p' + d.k];
        return `<div class="card oday"><div class="odh"><b>${oDayLabel(d.u, now)}</b>${ok.length ? `<span class="faint">${ok.length} outage${ok.length > 1 ? 's' : ''} · ${durTxt(tot)} down</span>` : `<span class="faint" data-notr>${L('no confirmed outage', 'قطعی تأییدشده‌ای نبود')}</span>`}</div>
          ${groups(long)}${short.length ? `${op ? groups(short) : ''}<button class="ofold" data-ofold="${d.k}">${op ? '▴ Hide the short drops' : `▾ ${short.length} short drops (under 1 min)`}</button>` : ''}
          ${probe.length ? `${opp ? `<div class="oold faint" data-notr>${L("Logged by the old check: one failed probe of the users' path, read twice a minute apart. The switcher checks every 2 s and kept the users on a working path — not proven outages, not counted in uptime.", 'با بررسی قدیمی ثبت شده‌اند: یک پروب ناموفق روی مسیر کاربران که دو بار با فاصله یک دقیقه خوانده شد. سوییچر هر ۲ ثانیه بررسی می‌کند و کاربران را روی مسیر سالم نگه داشت — قطعی اثبات‌شده نیستند و در آپتایم حساب نمی‌شوند.')}</div>${groups(probe)}` : ''}<button class="ofold" data-ofold="p${d.k}" data-notr>${opp ? L('▴ Hide', '▴ بستن') : L(`▾ ${probe.length} unconfirmed (old check)`, `▾ ${probe.length} مورد تأییدنشده (بررسی قدیمی)`)}</button>` : ''}</div>`;
      }).join('')}`}`;
    $$('[data-okind] button', body).forEach(b => b.onclick = () => { OUT.kind = b.dataset.v; remember('tp-okind', OUT.kind); OUT.pick = ''; paint(); });
    $$('[data-opick]', body).forEach(b => b.onclick = () => { OUT.pick = b.dataset.opick; paint(); });
    $$('[data-ofold]', body).forEach(b => b.onclick = () => { OUT.open[b.dataset.ofold] = !OUT.open[b.dataset.ofold]; paint(); });
    const fam = $('[data-ofam]', body); if (fam) fam.onchange = () => { OUT.fam = fam.checked; paint(); };
  };
  const load = async () => {
    try { OUT.data = await api('/outages'); paint(); }
    catch (e) { body.innerHTML = `<div class="card" style="padding:14px;color:var(--crit)">${esc(e.message)}</div>`; }
  };
  $$('[data-orange] button', sec).forEach(b => b.onclick = () => { OUT.range = b.dataset.v; remember('tp-orange', OUT.range); $$('[data-orange] button', sec).forEach(x => x.classList.toggle('on', x === b)); paint(); });
  $('[data-oref]', sec).onclick = load;
  $('[data-oclr]', sec).onclick = async (e) => {
    const b = e.currentTarget; if (!confirmInline(b, 'Click again: delete every finished outage')) return;
    try { await api('/outages', { Clear: true }); OUT.pick = ''; load(); } catch (er) { alertModal('Error', er.message); }
  };
  load();
  // ongoing outages count on, and new ones show up, while the page is open
  const timer = setInterval(() => { if (!sec.isConnected) { clearInterval(timer); return; } if (!document.hidden && !$('details.more[open]', sec)) load(); }, 60000);
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
      ${hwRows(STATE.hostHw)}
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
  const status = s.up && s.up.down ? `<span class="pill bad"><span class="led"></span>down</span>`
    : s.agentOnline ? `<span class="pill on"><span class="led"></span>agent online</span>`
    : s.prepared ? `<span class="pill ok2"><span class="led"></span>reachable</span>`
    : `<span class="pill off"><span class="led"></span>not tested</span>`;
  const tl = STATE.tunnels.filter(t => t.serverId === s.id || t.foreignId === s.id);
  const sub = [s.city, s.os && s.arch ? `${s.os} ${s.arch}` : ''].filter(Boolean).join(' · ');
  return h(`<div class="card scard ${isIran ? 'ir' : 'fg'}">
    <div class="sh"><div class="sname"><span class="sflag">${s.country ? flag(s.country) : (isIran ? flag('IR') : '🌍')}</span><div><h3>${s.name ? nm(s.name) : '(unnamed)'} ${ownerChip(s.owner)}</h3><small><span class="srole">${isIran ? 'Iran · entry' : 'foreign · exit'}</span>${sub ? ' ' + esc(sub) : ''}</small></div></div>${status}</div>
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
    ${upBox(s)}
    <dl class="kvt">
      <div><dt>IPv4</dt><dd><span class="mono">${esc(s.ipv4 || '—')}</span></dd></div>
      <div class="wide"><dt>IPv6</dt><dd><span class="mono">${esc(s.ipv6 || (s.prepared ? 'none' : 'reading over SSH…'))}</span></dd></div>
      <div><dt>SSH</dt><dd><span class="mono">${esc(s.sshUser || 'root')}@${esc(s.sshHost || s.ipv4 || s.ipv6 || '?')}:${s.sshPort || 22}</span></dd></div>
      <div><dt>Packages</dt><dd>${s.provisioned ? '<span style="color:var(--good)">✓ installed</span>' : '<span class="faint">not installed yet</span>'}</dd></div>
      ${hwRows(s.hw)}
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
  // the terminal in the theme's own colours (black, graphite or white)
  const cs = getComputedStyle(document.documentElement), tv = (k) => cs.getPropertyValue(k).trim();
  const dark = cs.colorScheme.includes('dark');
  const term = new Terminal({ cursorBlink: true, fontSize: 13, fontFamily: 'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace', scrollback: 5000,
    theme: dark ? { background: tv('--bg') || '#000000', foreground: '#d6dbe4', cursor: '#d6dbe4', selectionBackground: '#3a3f4b' } : { background: '#fbfcfe', foreground: '#1b2030', cursor: '#1b2030', selectionBackground: '#c9d4f5' } });
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
      <div class="two"><label class="f">SSH user<input name="sshUser" class="mono" value="${esc(s.sshUser || 'root')}"></label><label class="f">Country <span class="faint">${s.country ? flag(s.country) + ' ' : ''}${s.countryManual ? '(set by hand — empty it to detect from the IP)' : '(found from the IP; type 2 letters to set it by hand)'}</span><input name="country" class="mono" maxlength="2" value="${esc(s.country || '')}" placeholder="auto"></label></div>
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
    // an emptied country = detect it again from the IP (a country typed here stays for good)
    fd.country = (fd.country || '').trim() || (s.id ? 'auto' : '');
    if (s.id) fd.ID = s.id;
    try { const r = await api('/servers', fd); m.remove(); await loadAll(); renderView(); toast('Server saved'); if (s.onSaved) s.onSaved(r.id || s.id, fd.name); } catch (e) { alertModal('Error', e.message); }
  });
}

/* ---------------- tunnels ---------------- */
// Summary strip, then tunnels grouped by their Iran server.
function viewTunnels(w) {
  w.innerHTML = topbar('Tunnels', 'Each tunnel links one Iran server to one foreign server. Pick a connection method and switch any time.',
    `${isAdmin() ? '' : '<!--'}<button class="btn" id="aiTun" title="Claude reviews the tunnels, their paths, outages and the servers' load, and says what to improve">🧠 AI analysis</button>${isAdmin() ? '' : '-->'}<button class="btn" id="repairTun" title="Check what is wrong on the running tunnels and choose what to fix — the check changes nothing">🛠 Repair</button><button class="btn pri" id="addTun"${iranServers().length ? '' : ' disabled title="Add an Iran server first"'}>+ New tunnel</button>`);
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
      <span class="sinfo"><b data-notr>${esc(t.name)}</b><small>→ ${srvNm(t.foreignId, 'panel host')} · ${esc(methodTitle(t.active || t.selected) || '—')}</small>${upLine(t.up)}</span>
      <span class="smeta"><span class="sbadges">${t.hotStandby ? '<span class="sbadge hs" title="hot standby">⚡</span>' : ''}<span class="sbadge fo" data-tfo="${t.id}" title="on a backup path"${t.failover ? '' : ' hidden'}>🔁</span><span class="led ${t.active ? (t._down || t.health ? 'bad' : 'on') : 'off'}" data-tled="${t.id}" title="${t.active ? 'running' : 'stopped'}"></span></span><small class="faint mono" data-lr="${t.id}"></small></span></button>`;
    const split = h(`<div class="srvsplit usplit">
      <aside class="card srvlist">
        <input class="sq" type="search" data-q placeholder="🔍 Search name, server, port, method…" value="${esc(STATE.tunSearch || '')}">
        <button class="fchip${STATE.tunRunning ? ' on' : ''}" data-run title="show only running tunnels">● Running <b>${run}</b></button>
        ${groups.map(g => `<div class="sgrp" data-g="${g.id}"><div class="sgh"><span>${fl(g.id, flag('IR'))} ${srvNm(g.id)} <span class="count">${g.tunnels.length}</span></span></div>${g.tunnels.map(row).join('')}</div>`).join('')}
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
  if ($('#repairTun')) $('#repairTun').onclick = () => repairModal();
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
      <span class="tc-end"><span class="ef">${fl(ir, flag('IR'))}</span><span class="en"><small>Iran server</small><b class="nm">${srvNm(t.serverId)}</b></span><span class="sd" data-ir></span></span>
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
    ${t.hotStandby && t.active ? `<div class="tc-hs"><div class="lbl">⚡ Hot standby paths</div><div data-hsl>${hsRows(t) || '<div class="faint">paths — reading which one the users are on…</div>'}</div>${hsOffFold(t)}</div>` : ''}
    <div class="tc-f">
      <button class="btn sm pri" data-manage>⚙ Manage</button>
      ${t.active ? `<button class="btn sm ghost" data-stop>■ Stop</button>` : `<button class="btn sm" data-start>▶ Start</button>`}
      <button class="btn sm ghost" data-log>Logs</button>
      <span class="grow"></span>
      ${moreMenu([
        t.active ? { label: '🚀 Speed test', attr: 'data-speedtest' } : null,
        t.active ? { label: '🩺 Diagnose', attr: 'data-diag' } : null,
        t.active ? { label: '🔎 Trace connections (30 s)', attr: 'data-trace' } : null,
        t.active ? { label: '🛠 Repair', attr: 'data-repair' } : null,
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
  on('[data-repair]', () => repairModal(t.id));
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
// Repair: a check first (it changes nothing), then only what was chosen (repair.go). Items
// that cut or move users start unchecked and need a second, explicit OK. only = one tunnel.
function repairModal(only) {
  const tn = only ? (STATE.tunnels.find(t => t.id === only) || {}).name : '';
  const m = modal(`<h2>🛠 Repair${tn ? ` · <span data-notr>${esc(tn)}</span>` : ''}</h2><p class="muted rp-sub">First a check — it changes nothing. Fixes that cut nobody the panel also does by itself every 3 hours; only the ones that cut or move users wait for you.</p><div data-rp></div><div data-rpauto></div>`, true);
  const box = $('[data-rp]', m), autoBox = $('[data-rpauto]', m);
  let poll = null;
  const alive = () => box.isConnected;
  const IMP = { none: ['no impact', 'ok'], blip: ['brief blip', 'warn'], users: ['users moved', 'bad'] };
  const SIDE = { iran: 'Iran', foreign: 'foreign', both: 'both sides' };
  const chips = (it) => `<span class="chip rp-imp ${(IMP[it.impact] || IMP.users)[1]}">${(IMP[it.impact] || IMP.users)[0]}</span><span class="chip rp-side">${SIDE[it.side] || esc(it.side)}</span>`;
  const notMine = (t) => isAdmin() && t.owner && t.owner !== STATE.user;
  // the paths a path update adds (+) and removes (−): method names, kept as they are
  const det = (it) => it.detail ? `<span class="rp-det" data-notr dir="ltr" title="${esc(it.detail)}">${esc(it.detail)}</span>` : '';
  // why one waits for you (repair.go RepairItem.Ask); the others the panel does by itself
  const ask = (it) => it.impact === 'users' ? (it.ask ? `<span class="rp-why">✋ ${esc(it.ask)}</span>` : '') : `<span class="rp-why">🤖 the panel does this by itself</span>`;

  // ---- the check ----
  const check = async () => {
    clearTimeout(poll);
    box.innerHTML = `<div class="rp-wait"><span class="spin"></span><span>Checking the tunnels… (up to a minute)</span></div>`;
    let r;
    try { r = await api('/repair/check', only ? { IDs: [only] } : {}); } catch (e) { if (alive()) box.innerHTML = `<div class="downbar">⚠ ${esc(e.message)}</div>`; return; }
    if (alive()) paintCheck(r.tunnels || []);
  };
  const paintCheck = (ts) => {
    const fix = ts.filter(t => t.state === 'fix'), ok = ts.filter(t => t.state === 'ok'), skip = ts.filter(t => t.state === 'skip');
    const row = (t) => `<div class="rp-t" data-t="${esc(t.id)}">
        <label class="rp-h"><input type="checkbox" data-tall><b data-notr>${esc(t.name)}</b>${t.owner ? `<span class="chip">👤 <span data-notr>${esc(t.owner)}</span></span>` : ''}<span class="grow"></span><span class="chip warn">${t.items.length === 1 ? '1 to fix' : t.items.length + ' to fix'}</span></label>
        ${notMine(t) ? `<div class="rp-note">left unchecked: it belongs to another account — their choice</div>` : ''}
        ${t.items.map(it => `<label class="rp-i"><input type="checkbox" data-k="${esc(it.kind)}" data-imp="${esc(it.impact)}"${it.impact !== 'users' && !notMine(t) ? ' checked' : ''}><span class="rp-x"><span>${esc(it.text)}</span>${det(it)}${ask(it)}</span><span class="rp-c">${chips(it)}</span></label>`).join('')}
        ${t.note ? `<div class="rp-note">${esc(t.note)}</div>` : ''}</div>`;
    box.innerHTML = `
      <div class="rp-sum"><span class="chip ${fix.length ? 'warn' : 'ok'}">${fix.length} to fix</span><span class="chip ok">${ok.length} fine</span>${skip.length ? `<span class="chip">${skip.length} left alone</span>` : ''}
        <span class="grow"></span>${fix.length > 1 ? `<button class="btn sm ghost" data-all>Select all</button><button class="btn sm ghost" data-none>None</button>` : ''}</div>
      ${fix.length ? fix.map(row).join('') : `<div class="rp-allok">✅ Nothing to fix</div>`}
      ${ok.length ? `<div class="rp-ok"><div class="rp-lbl">Nothing to fix</div>${ok.map(t => `<div class="rp-okr"><span class="rp-dot ok"></span><span data-notr>${esc(t.name)}</span>${t.note ? `<span class="rp-note">${esc(t.note)}</span>` : ''}</div>`).join('')}</div>` : ''}
      ${skip.length ? `<div class="rp-ok"><div class="rp-lbl">Left alone</div>${skip.map(t => `<div class="rp-okr"><span class="rp-dot"></span><span data-notr>${esc(t.name)}</span><span class="rp-note">${esc(t.note || '')}</span></div>`).join('')}</div>` : ''}
      <div class="rp-foot"><div data-rpwarn></div><div class="actions"><button class="btn ghost" data-again>↻ Check again</button><span class="grow"></span>${fix.length ? `<button class="btn pri" data-fix>Fix selected</button>` : ''}</div></div>`;
    const sync = () => {
      $$('.rp-t', box).forEach(c => {
        const items = $$('[data-k]', c), on = items.filter(x => x.checked).length, all = $('[data-tall]', c);
        all.checked = on === items.length; all.indeterminate = on > 0 && on < items.length;
      });
      const n = $$('[data-k]:checked', box).length, b = $('[data-fix]', box);
      if (b) { b.disabled = !n; b.textContent = n ? `Fix selected (${n})` : 'Fix selected'; }
      $('[data-rpwarn]', box).innerHTML = '';
    };
    $$('[data-tall]', box).forEach(a => a.onchange = () => { $$('[data-k]', a.closest('.rp-t')).forEach(x => x.checked = a.checked); sync(); });
    $$('[data-k]', box).forEach(x => x.onchange = sync);
    const setAll = (v) => { $$('[data-k]', box).forEach(x => x.checked = v); sync(); };
    if ($('[data-all]', box)) { $('[data-all]', box).onclick = () => setAll(true); $('[data-none]', box).onclick = () => setAll(false); }
    $('[data-again]', box).onclick = check;
    if ($('[data-fix]', box)) $('[data-fix]', box).onclick = () => {
      const picks = {}, users = [];
      $$('.rp-t', box).forEach(c => {
        const ks = $$('[data-k]:checked', c);
        if (!ks.length) return;
        picks[c.dataset.t] = ks.map(x => x.dataset.k);
        if (ks.some(x => x.dataset.imp === 'users')) users.push($('.rp-h b', c).textContent);
      });
      if (!Object.keys(picks).length) return;
      if (!users.length) { start(picks, false); return; }
      // the explicit OK for the items that cut or move users
      const w = $('[data-rpwarn]', box);
      w.innerHTML = `<div class="rp-warn"><b>⚠ Users will be cut or moved</b><div>These tunnels are applied again: their users drop for a moment while it runs.</div><div class="rp-names" data-notr>${users.map(esc).join(' · ')}</div>
        <div class="actions"><button class="btn sm ghost" data-wno>Cancel</button><button class="btn sm danger" data-wyes>Yes, fix and move the users</button></div></div>`;
      $('[data-wno]', w).onclick = () => { w.innerHTML = ''; };
      $('[data-wyes]', w).onclick = () => start(picks, true);

    };
    sync();
  };

  // ---- the run ----
  const start = async (picks, allowUsers) => {
    try { await api('/repair/apply', { Picks: picks, AllowUsers: allowUsers }); follow(); }
    catch (e) { alertModal('Repair', e.message); }
  };
  const RES = { waiting: ['…', 'waiting'], running: ['⟳', 'working…'], fixed: ['✅', 'fixed'], failed: ['❌', 'failed'], skipped: ['⏭', 'left alone'], fine: ['✓', 'nothing to fix'] };
  const ST = { done: '✓', failed: '✕', left: '–' };
  const paintRun = (run, live) => {
    const n = (k) => run.tunnels.filter(t => t.result === k).length;
    const doneN = run.tunnels.filter(t => !['waiting', 'running'].includes(t.result)).length;
    return `<div class="rp-sum">${live ? `<span class="spin"></span><span>Fixing…</span><span>${doneN} / ${run.tunnels.length}</span>` : `<span class="chip ok">${n('fixed')} fixed</span>${n('failed') ? `<span class="chip bad">${n('failed')} failed</span>` : ''}${n('skipped') ? `<span class="chip">${n('skipped')} left alone</span>` : ''}${n('fine') ? `<span class="chip">${n('fine')} fine</span>` : ''}`}
        <span class="grow"></span><span class="faint rp-when">${run.auto ? '🤖 ' : ''}<span>${esc(run.why)}</span> · <span>${ago(run.started)}</span></span></div>
      ${run.tunnels.map(t => { const r = RES[t.result] || RES.waiting; return `<div class="rp-t rp-r ${esc(t.result)}"><div class="rp-h"><span class="rp-ic">${r[0]}</span><b data-notr>${esc(t.name)}</b><span class="grow"></span><span class="chip ${t.result === 'failed' ? 'bad' : t.result === 'fixed' ? 'ok' : ''}">${r[1]}</span></div>
        ${(t.results || []).map(it => `<div class="rp-i rp-ri ${esc(it.status)}"><span class="rp-st">${ST[it.status] || ''}</span><span class="rp-x"><span>${esc(it.text)}</span>${det(it)}${it.why && it.why !== 'not chosen' ? `<span class="rp-why">${esc(it.why)}</span>` : ''}</span><span class="rp-c">${chips(it)}</span></div>`).join('')}
        ${!(t.results || []).length && t.done && t.result !== 'running' ? `<div class="rp-note">${esc(t.done)}</div>` : ''}</div>`; }).join('')}`;
  };
  const follow = async () => {
    clearTimeout(poll);
    if (!alive()) return;
    let s;
    try { s = await api('/repair/status'); } catch (e) { box.innerHTML = `<div class="downbar">⚠ ${esc(e.message)}</div>`; return; }
    if (!alive()) return;
    const run = s.run, live = run && !run.ended;
    if (!run) { check(); return; }
    let log = '';
    try { const j = await api('/jobs?id=' + encodeURIComponent(run.job)); log = (j.lines || []).slice(-60).join('\n'); } catch (e) {}
    const open = !!($('details.rp-log', box) || {}).open;
    box.innerHTML = paintRun(run, live) + `<details class="rp-log"${open ? ' open' : ''}><summary>Job log</summary><pre class="pre mono">${esc(log)}</pre></details>
      <div class="actions rp-foot"><span class="grow"></span>${live ? '' : `<button class="btn pri" data-again>↻ Check again</button>`}</div>`;
    if ($('[data-again]', box)) $('[data-again]', box).onclick = check;
    paintAuto(s);
    if (live) poll = setTimeout(follow, 2000);
  };

  // ---- the automatic Repair after an update (admin) ----
  const paintAuto = (s) => {
    if (!isAdmin() || !('auto' in s)) { autoBox.innerHTML = ''; return; }
    const l = s.last;
    const cnt = (k) => l ? l.tunnels.filter(t => t.result === k).length : 0;
    const wait = l ? l.tunnels.filter(t => (t.results || []).some(i => i.status === 'left' && /needs your OK/.test(i.why || ''))).length : 0;
    autoBox.innerHTML = `<div class="rp-auto"><label class="f">Automatic Repair (after an update and every 3 hours)<select data-amode>
        <option value="">Every fix that cuts nobody; what cuts or moves users waits for your OK</option>
        <option value="all">Everything (users may be moved)</option>
        <option value="off">Off</option></select></label>
      ${l ? `<div class="rp-last"><span class="faint">Last run:</span> ${l.auto ? '🤖 ' : ''}<span>${esc(l.why)}</span> · <span>${ago(l.started)}</span> <span class="chip ok">${cnt('fixed')} fixed</span>${cnt('failed') ? `<span class="chip bad">${cnt('failed')} failed</span>` : ''}${wait ? `<span class="chip warn">${wait} need your OK</span>` : ''} <button class="btn sm ghost" data-lastv>Details</button></div>` : ''}</div>`;
    const sel = $('[data-amode]', autoBox); sel.value = s.auto || '';
    sel.onchange = async () => { try { await api('/repair/auto', { Mode: sel.value }); toast('Saved'); } catch (e) { alertModal('Repair', e.message); } };
    const lv = $('[data-lastv]', autoBox);
    if (lv) lv.onclick = () => { clearTimeout(poll); box.innerHTML = paintRun(l, false) + `<div class="actions rp-foot"><span class="grow"></span><button class="btn pri" data-again>↻ Check now</button></div>`; $('[data-again]', box).onclick = check; };
  };

  // a run in progress is followed; otherwise the check starts at once
  api('/repair/status').then(s => {
    if (!alive()) return;
    paintAuto(s);
    if (s.run && !s.run.ended) follow(); else check();
  }).catch(() => check());
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
  return `<div class="lbl">⚡ Hot standby paths <span class="faint">(switcher order; the users' path is checked every 2 s on the Iran server)</span></div>${seg}${hsRows(t)}${hsOffFold(t)}
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
      // the cause the panel proved (downcause.go), with its evidence and what to do; until
      // it is known, the switcher's own line and a note that the panel is looking
      const c = v.cause && v.cause[i];
      // a route that passes only GRE/ESP: the method can't work here at all — not a fault
      if (c && c.code === 'proto_filter') return `<span class="hq">${L('not possible on this route', 'روی این مسیر شدنی نیست')}</span>${hsCauseHtml(c, v.keys && v.keys[i], i !== v.active, v.paths[i])}`;
      if (c) return `<span class="hq">${since}</span>${hsCauseHtml(c, v.keys && v.keys[i], i !== v.active)}`;
      const why = v.why && v.why[i] ? v.why[i] : "the switcher's check through this path gets no answer";
      return `<span class="hq">${since}</span><span class="hw" title="${esc(why)}">${esc(why)}</span><span class="hw faint" data-notr>${L('finding the exact cause…', 'در حال پیدا کردن علت دقیق…')}</span>`;
    }
    if (v.rtt && v.rtt[i] >= 0) out.push(v.rtt[i] + ' ms');
    if (v.loss && v.loss[i] >= 0) out.push(v.loss[i].toFixed(1) + '% loss');
    if (v.kbps && v.kbps[i] > 0) out.push((v.kbps[i] / 1000).toFixed(1) + ' Mbps');
    return (out.length ? `<span class="hq mono">${out.join(' · ')}</span>` : '') + hsIdleHtml(v, i);
  };
  const na = (i) => !ok[i] && v.cause && v.cause[i] && v.cause[i].code === 'proto_filter';
  return `<div class="hsl">${v.paths.map((p, i) =>
    `<div class="${ok[i] ? 'ok' : na(i) ? 'na' : 'bad'}${i === v.active ? ' cur' : ''}"><span class="hi">${ok[i] ? '✓' : na(i) ? '⛔' : '✕'}</span><span class="hm"><span class="hn">${esc(p)}${i === v.pin ? ' <span class="faint">📌 chosen</span>' : ''}</span>${q(i)}</span>${i === v.active ? '<b class="hu">← users</b>' : (ok[i] && v.keys ? `<button type="button" class="btn sm ghost" data-hspin="${esc(v.keys[i])}" title="move the users here now — open connections finish where they are, nobody is cut">use</button>` : '')}${hsRowMenu(v, ok, i)}</div>`).join('')}</div>`;
}
// what a standby path's cores burn while the users are elsewhere (the hourly standby check):
// shown from 10 % of a core, so an expensive standby is seen before it slows the server down
function hsIdleHtml(v, i) {
  const ir = v.idleIr ? v.idleIr[i] : -1, kh = v.idleKh ? v.idleKh[i] : -1;
  const top = Math.max(ir == null ? -1 : ir, kh == null ? -1 : kh);
  if (i === v.active || top < 10) return '';
  const side = (n, en, fa) => n >= 0 ? `${L(en, fa)} ${n}%` : null;
  const parts = [side(ir, 'Iran', 'ایران'), side(kh, 'foreign', 'خارج')].filter(Boolean).join(' · ');
  const title = L('CPU (% of one core) this path\'s cores used with no users on it, measured by the hourly standby check — ', 'پردازنده (درصد یک هسته) که هسته‌های این مسیر بدون کاربر مصرف کردند، در بررسی ساعتی مسیرهای آماده — ') + parts;
  return `<span class="hq${top >= 25 ? ' hidle-hi' : ''}" title="${esc(title)}" data-notr>⏻ ${L('idle core', 'هسته‌ی بیکار')}: ${top}% CPU <span class="faint">(${esc(parts)})</span></span>`;
}
// a down path's proven cause: one sentence naming the side; the evidence and what to do on expand
function hsCauseHtml(c, key, canRestart, name) {
  const fa = window.tpLang === 'fa';
  const side = { iran: L('Iran', 'ایران'), foreign: L('foreign', 'خارج'), route: L('route', 'مسیر'), panel: L('panel', 'پنل') }[c.side];
  const ev = (c.evidence || []).map(e => `<li>${esc(e)}</li>`).join('');
  const btn = c.restart && canRestart && key ? ` <button type="button" class="btn sm ghost" data-hsrestart="${esc(key)}">↻ ${L('Restart path', 'ری‌استارت مسیر')}</button>`
    : c.code === 'proto_filter' && canRestart && key ? ` <button type="button" class="btn sm ghost" data-hsrm="${esc(key)}" data-hsname="${esc(name || key)}">🗑 ${L('Remove path', 'حذف مسیر')}</button>` : '';
  const act = c.action ? `<div class="hca" data-notr>→ ${esc(fa ? c.actionFa : c.action)}${btn}</div>` : '';
  return `<details class="hcz"><summary><span class="hct" data-notr>${side ? `<b class="hcs">${esc(side)}</b> ` : ''}${esc(fa ? c.textFa : c.text)}</span> <span class="faint" data-notr>${L('evidence', 'شواهد')} ▸</span></summary>${ev ? `<ul data-notr dir="ltr">${ev}</ul>` : ''}${act}<div class="faint" data-notr>${L('checked', 'بررسی شد')} · ${ago(c.at)}</div></details>`;
}
// a path's ⋯ menu: its settings; Restart (a down standby path); Remove — not the users' path (move them first) nor the last working one
function hsRowMenu(v, ok, i) {
  if (!v.keys || !v.keys[i]) return '';
  const working = ok.filter(Boolean).length;
  const why = i === v.active ? 'The users are on this path — move them to another one with “use” first.'
    : (ok[i] && working <= 1) ? 'The last working path can\'t be removed.' : '';
  const rs = !ok[i] && i !== v.active ? { label: '↻ ' + L('Restart path', 'ری‌استارت مسیر'), attr: `data-hsrestart="${esc(v.keys[i])}" title="${esc(L("restart only this path's cores on both servers — the users and the other paths are left alone", 'فقط هسته‌های این مسیر روی هر دو سرور ری‌استارت می‌شود — کاربران و مسیرهای دیگر دست نمی‌خورند'))}"` } : null;
  return moreMenu([{ label: '⚙ Settings', attr: `data-hsset="${esc(v.keys[i])}" data-hsname="${esc(v.paths[i])}"` }, rs, why
    ? { label: '🗑 Remove path', attr: `disabled title="${esc(why)}"`, danger: true }
    : { label: '🗑 Remove path', attr: `data-hsrm="${esc(v.keys[i])}" data-hsname="${esc(v.paths[i])}"`, danger: true },
    why ? { label: `<span class="hwhy">${esc(why)}</span>`, attr: 'disabled' } : null]);
}
// paths removed by hand from this tunnel: auto mode and Repair leave them out until put back
function hsOffFold(t) {
  const off = t.hsOff || [];
  if (!off.length) return '';
  const name = (k) => { const [mid, fam] = k.split('|'); const m = STATE.methods.find(x => x.id === mid); return `${m ? m.title : mid} (${fam})`; };
  return `<details class="hsoff"><summary class="faint">🗑 <span>Removed paths</span> (${off.length}) ▸</summary><div class="hsl">${off.map(k =>
    `<div><span class="hi faint">–</span><span class="hm"><span class="hn">${esc(name(k))}</span><span class="hq">removed by hand — auto mode and Repair leave it out</span></span><button type="button" class="btn sm ghost" data-hsrestore="${esc(k)}" title="allow it again: it starts as a new standby path, the users stay where they are">put back</button></div>`).join('')}</div></details>`;
}
function hsWire(t, m) {
  $$('[data-hsset]', m).forEach(b => b.onclick = () => hsSettings(t, b.dataset.hsset, b.dataset.hsname, b.closest('.hsl > div')));
  $$('[data-hsrm]', m).forEach(b => b.onclick = () => hsRemoveConfirm(t, b.dataset.hsrm, b.dataset.hsname));
  $$('[data-hsrestart]', m).forEach(b => b.onclick = async (e) => {
    e.preventDefault(); b.disabled = true;
    try { const r = await api('/tunnels/hsrestart', { ID: t.id, Path: b.dataset.hsrestart }); openLog(t, r.job); }
    catch (er) { alertModal('Restart path', er.message); b.disabled = false; }
  });
  $$('[data-hsrestore]', m).forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { const r = await api('/tunnels/hsrestore', { ID: t.id, Path: b.dataset.hsrestore }); await loadAll(); renderView(); if (r.job) openLog(t, r.job); else toast('put back — it starts on the next Start/Re-apply'); }
    catch (e) { alertModal('Put back path', e.message); b.disabled = false; }
  });
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
// the confirmation for removing a path, naming it and the tunnel
function hsRemoveConfirm(t, key, name) {
  const m = modal(`<h2>🗑 Remove this hot-standby path?</h2>
    <div class="hsl" style="margin:10px 0 6px"><div class="bad"><span class="hi">🗑</span><span class="hm"><span class="hn">${esc(name)}</span><span class="hq"><span>tunnel</span> · ${esc(t.name)}</span></span></div></div>
    <ul class="muted" style="font-size:13px;line-height:1.7;padding-inline-start:18px;margin:8px 0">
      <li>It stops on both servers (its services, files and firewall rules) and leaves the switcher.</li>
      <li>The users stay where they are — nobody is cut.</li>
      <li>Auto mode and Repair won't add it back. You can put it back under “Removed paths” on this card.</li>
    </ul>
    <div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn" data-no>Cancel</button><button class="btn danger" data-yes>🗑 Remove</button></div>`);
  const close = () => m.remove();
  $('[data-no]', m).onclick = close;
  $('[data-yes]', m).onclick = async (e) => {
    e.target.disabled = true;
    try { const r = await api('/tunnels/hsremove', { ID: t.id, Path: key }); close(); await loadAll(); renderView(); openLog(t, r.job); }
    catch (er) { close(); alertModal('Remove path', er.message); }
  };
}
// A path's settings, open under its row (⋯ → ⚙ Settings): the method's options (applied at once,
// only this method's paths rebuilt — see renderOpts) and the kernel settings of the path's own
// interface (changed live on both servers, nothing restarts). The users are moved to the best
// other working path meanwhile and back; with none, a method change asks first. What the
// servers run with now is read when the panel opens; the server-wide settings are shown
// read-only (Servers → ⚡ Optimize changes them).
function hsSettings(t, key, name, row) {
  if (!row) return;
  const next = row.nextElementSibling;
  if (next && next.classList.contains('hsset')) { next.remove(); return; }
  $$('.hsset', row.parentNode).forEach(x => x.remove());
  const [mid, fam] = key.split('|');
  const m = STATE.methods.find(x => x.id === mid);
  const v = t.hs || {}, i = (v.keys || []).indexOf(key), users = i >= 0 && i === v.active;
  const others = (v.ok || []).some((ok, k) => ok && k !== i);
  const fams = [...new Set((t.paths || []).filter(p => p.method === mid).map(p => p.family))];
  const box = h(`<div class="hsset" data-hsset-for="${esc(key)}">
    <div class="hss-h"><b>⚙ <span>Settings</span></b><span class="hn" data-notr>${esc(name)}</span>${users ? '<span class="chip hs">users on it</span>' : ''}<span class="grow"></span><button type="button" class="btn sm ghost" data-hssx title="Close">✕</button></div>
    <div class="hss-note faint">${users ? (others ? 'The users are on this path: while it changes they move to the best other working path, then come back. Nobody is cut.' : 'The users are on this path and no other path works now: kernel settings change in place (no restart); a method change asks first.') : 'No users on this path: it changes without touching anyone. The other paths keep running.'}</div>
    <div class="hss-sec"><div class="lbl">🔧 <span>Method</span> · <span data-notr>${esc(m ? m.title : mid)}</span></div>${fams.length > 1 ? `<div class="faint hss-small">These options are the method's: its IPv4 and IPv6 paths are both rebuilt.</div>` : ''}<div data-mopts></div></div>
    <div class="hss-sec"><div class="lbl">🐧 <span>Kernel · this path's interface</span> <span class="mono" data-ifc></span></div><div data-knet><div class="faint hss-small">Reading what the servers run…</div></div></div>
    <div class="hss-sec"><div class="lbl">🖥 <span>Server-wide</span> <span class="faint">(read only)</span></div><div data-ksrv></div></div>
  </div>`);
  row.after(box);
  $('[data-hssx]', box).onclick = () => box.remove();
  renderOpts($('[data-mopts]', box), t, mid);
  api('/tunnels/pathnet/info', { ID: t.id, Path: key }).then(info => { if (box.isConnected) pnRender(box, t, key, m, fam, info); })
    .catch(e => { if (box.isConnected) $('[data-knet]', box).innerHTML = `<div class="hss-small" style="color:var(--crit)">✕ ${esc(e.message)}</div>`; });
}
// the kernel part of a path's settings, with what both servers run now
function pnRender(box, t, key, m, fam, info, status) {
  const kn = $('[data-knet]', box), ks = $('[data-ksrv]', box);
  const sides = info.sides || [], ir = sides.find(s => s.side === 'ir') || {}, kh = sides.find(s => s.side === 'kh') || {};
  const mb = (b) => b && +b > 0 ? (+b / 1048576).toFixed(+b >= 10485760 ? 0 : 1) + ' MB' : '—';
  const sideName = (s) => s.side === 'ir' ? 'Iran' : 'Foreign';
  ks.innerHTML = `<div class="hss-tbl"><table><thead><tr><th></th><th>Congestion control</th><th>Default qdisc</th><th>Socket buffers (max)</th><th>Conntrack</th></tr></thead><tbody>${sides.map(s => s.err
    ? `<tr><th>${sideName(s)}</th><td colspan="4" style="color:var(--crit)">✕ ${esc(s.err)}</td></tr>`
    : `<tr><th>${sideName(s)}</th><td class="mono">${esc(s.cc || '—')}</td><td class="mono">${esc(s.defQdisc || '—')}</td><td class="mono">${mb(s.rmem)} / ${mb(s.wmem)}</td><td class="mono">${esc(s.ctCount || '—')} / ${esc(s.ctMax || '—')}</td></tr>`).join('')}</tbody></table></div>
    <div class="faint hss-small">${isAdmin() ? '<span>These are the whole server\'s, shared by every tunnel on it — change them under</span> <a href="#" data-hsopt>Servers → ⚡ Optimize</a>' : '<span>These are the whole server\'s, shared by every tunnel on it.</span>'}</div>`;
  const ol = $('[data-hsopt]', ks); if (ol) ol.onclick = (e) => { e.preventDefault(); optimizeModal(t.serverId); };
  $('[data-ifc]', box).textContent = info.iface || '';
  if (!info.iface) {
    kn.innerHTML = `<div class="faint hss-small">This path forwards the ports in user space — it has no network interface of its own. The kernel settings that affect it are the servers' (below).</div>`;
    return;
  }
  const pn = (t.pathNet || {})[key] || {};
  const ownMtu = !!(m && m.fields.some(f => f.key === 'mtu'));
  const hand = (k) => pn[k] ? ' <span class="faint" title="set by you — kept as it is; ↺ Defaults puts the method\'s back">✋</span>' : '';
  const now = (s) => s.err ? '<span>—</span>' : s.ifUp ? `<span class="mono" data-notr>mtu ${esc(s.mtu)} · txqueuelen ${esc(s.txqlen)} · qdisc ${esc(s.qdisc || '—')}${s.side === 'ir' && s.mss ? ' · ' + esc(s.mss) : ''}</span>` : '<span>interface not up</span>';
  const qd = ['', 'fq', 'fq_codel', 'cake', 'pfifo_fast'];
  const lo = fam === 'v6' ? 1280 : 576;
  kn.innerHTML = `<div class="opts">
    ${ownMtu ? `<div class="faint hss-small" style="grid-column:1/-1">MTU: this method sets it itself — it is in the method's options above.</div>` : `<label class="f"><span>MTU</span>${hand('mtu')}<input data-n="mtu" dir="ltr" inputmode="numeric" value="${pn.mtu || ''}" placeholder="${esc(ir.mtu ? 'default · now ' + ir.mtu : 'default')}"><small class="fhelp">${lo}–9000. Smaller packets for a route that drops big ones.</small></label>`}
    <label class="f"><span>TCP MSS</span>${hand('mss')}<input data-n="mss" dir="ltr" inputmode="numeric" value="${pn.mss || ''}" placeholder="auto · from the MTU"><small class="fhelp">536–1460: a cap on the users' TCP segments on this path (Iran side). Blank = from the path MTU.</small></label>
    <label class="f"><span>Queue length</span>${hand('txqlen')}<input data-n="txqlen" dir="ltr" inputmode="numeric" value="${pn.txqlen || ''}" placeholder="${esc(ir.txqlen ? 'default · now ' + ir.txqlen : 'default')}"><small class="fhelp">txqueuelen, 10–100000. Longer absorbs bursts, shorter keeps latency low.</small></label>
    <label class="f"><span>Queueing discipline</span>${hand('qdisc')}<select data-n="qdisc">${qd.map(q => `<option value="${q}"${(pn.qdisc || '') === q ? ' selected' : ''}>${q || 'kernel default'}</option>`).join('')}</select><small class="fhelp">fq paces (good with bbr); fq_codel and cake keep queues short under load.</small></label>
    <div class="hss-now faint" style="grid-column:1/-1"><div><span>Now on Iran:</span> ${now(ir)}</div><div><span>Now on foreign:</span> ${now(kh)}</div></div>
    <div class="faint hss-small" style="grid-column:1/-1">Changed live on both servers — nothing restarts, open connections stay. Kept after a restart or reboot. What you set (✋) stays as you set it.</div>
    <div class="ostat" data-nst style="grid-column:1/-1;font-size:12.5px"${status ? '' : ' hidden'}>${status || ''}</div>
    <div style="grid-column:1/-1;display:flex;justify-content:flex-end;gap:8px"><button class="btn sm ghost" data-nreset title="the interface as the method makes it, applied now">↺ Defaults</button><button class="btn sm pri" data-nsave>Save &amp; apply</button></div></div>`;
  const st = $('[data-nst]', kn);
  const show = (html) => { st.hidden = !html; st.innerHTML = html || ''; };
  const busy = (on) => $$('[data-n],[data-nsave],[data-nreset]', kn).forEach(el => el.disabled = on);
  // checked here first (the server checks again); a Persian keypad's ۱۴۰۰ is 1400
  const read = () => { const o = {}; $$('[data-n]', kn).forEach(el => o[el.dataset.n] = latinDigits(el.value).trim()); return o; };
  const check = (o) => {
    const n = (k) => o[k] ? +o[k] : 0;
    for (const [k, l] of [['mtu', 'MTU'], ['mss', 'TCP MSS'], ['txqlen', 'Queue length']]) if (o[k] && !/^\d+$/.test(o[k])) return l + ': a number, please';
    if (n('mtu') && (n('mtu') < lo || n('mtu') > 9000)) return `MTU must be between ${lo} and 9000`;
    if (n('mss') && (n('mss') < 536 || n('mss') > 8960)) return 'TCP MSS must be between 536 and 1460';
    if (n('mss') && n('mtu') && n('mss') > n('mtu') - 40) return `TCP MSS doesn't fit in MTU ${n('mtu')} — at most ${n('mtu') - 40}`;
    if (n('txqlen') && (n('txqlen') < 10 || n('txqlen') > 100000)) return 'Queue length must be between 10 and 100000';
    return '';
  };
  const same = (o) => ['mtu', 'mss', 'txqlen', 'qdisc'].every(k => String(o[k] || '') === String(pn[k] || ''));
  const send = async (reset) => {
    const o = reset ? {} : read();
    const err = reset ? '' : check(o);
    if (err) { show(`<span style="color:var(--crit)">✕ ${esc(err)}</span>`); return; }
    if (!reset && same(o)) { show('<span class="muted">Nothing changed.</span>'); return; }
    busy(true); show('<span class="muted">Saving…</span>');
    let r;
    try { r = await api('/tunnels/pathnet', { ID: t.id, Path: key, Net: o, Reset: !!reset }); }
    catch (e) { busy(false); show(`<span style="color:var(--crit)">✕ ${esc(e.message)}</span>`); return; }
    const done = async (html) => {
      try { await loadAll(); } catch (e) {}
      const nt = STATE.tunnels.find(x => x.id === t.id); if (nt) Object.assign(t, { pathNet: nt.pathNet, hs: nt.hs, paths: nt.paths });
      if (!box.isConnected) return;
      let ni = info; try { ni = await api('/tunnels/pathnet/info', { ID: t.id, Path: key }); } catch (e) {}
      if (box.isConnected) pnRender(box, t, key, m, fam, ni, html);
    };
    if (!r.job) { done(`<span style="color:var(--good)">✓ ${esc(r.note || 'Saved')}</span>`); return; }
    jobInline(st, t, r.job, (ok, res, failing) => done(`<div style="color:var(${ok ? '--good' : '--crit'})">${ok ? '✓ Applied' : failing ? "✕ The path doesn't answer with these settings — kept as you set them; users stay on a working path" : '✕ Not applied'}</div>${res.map(l => `<div class="faint mono" style="font-size:11.5px" data-notr>${esc(l)}</div>`).join('')}${ok ? '' : ' <button class="btn sm ghost" data-nodef>↺ Back to defaults</button>'}`));
  };
  $('[data-nsave]', kn).onclick = () => send(false);
  $('[data-nreset]', kn).onclick = () => send(true);
  const nd = $('[data-nodef]', kn); if (nd) nd.onclick = () => send(true);
  $$('select[data-n]', kn).forEach(el => el.onchange = () => send(false));
  $$('input[data-n]', kn).forEach(el => el.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); send(false); } });
}
// a job's progress in el: its last line while it runs, then end(ok, result lines, failing)
function jobInline(el, t, jid, end) {
  let fails = 0;
  const clean = (l) => l.replace(/^\d\d:\d\d:\d\d /, '');
  const tick = async () => {
    if (!el.isConnected) { followJob(jid); return; }
    let j = null;
    try { j = await api('/jobs?id=' + jid); fails = 0; } catch (e) { if (++fails < 5) { setTimeout(tick, 2000); return; } }
    const lines = (j && j.lines) || [];
    if (j && j.status === 'running') {
      el.hidden = false;
      el.innerHTML = `<span class="muted">⏳ <span>Applying…</span> <span class="mono" data-notr>${esc(clean(lines[lines.length - 1] || ''))}</span></span> <a href="#" data-jlog>log</a>`;
      const a = $('[data-jlog]', el); if (a) a.onclick = (e) => { e.preventDefault(); openLog(t, jid); };
      setTimeout(tick, 2000); return;
    }
    // no jobEnded(): redrawing the view would close the panel and its result — end() reloads the data
    end(!!(j && j.status === 'ok'), lines.filter(l => / ✓ | ✕ |DONE|FAILING|ERROR/.test(l)).slice(-4).map(clean), lines.some(l => /FAILING/.test(l)));
  };
  tick();
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
    <div class="mg-h"><div><h2 style="margin:0" data-notr>${esc(t.name)}</h2><div class="faint" style="font-size:12.5px">${(ir && ir.country) ? flag(ir.country) : flag('IR')} ${srvNm(t.serverId)} → ${fg && fg.country ? flag(fg.country) : (fg ? '🌍' : '🖥')} ${fg ? nm(fg.name) : 'this panel host'} · ports <span class="mono">${esc(t.ports)}</span></div></div>
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
    <div class="actions mg-bar"><button class="btn pri" data-apply></button><span class="faint mg-now" data-now hidden>✓ <span>Running now</span></span><span class="grow"></span>
      ${moreMenu([
        t.active ? { label: '↻ Re-apply', attr: 'data-reapply' } : null,
        t.active ? { label: '🚀 Speed test', attr: 'data-speedtest' } : null,
        t.active ? { label: '🩺 Diagnose', attr: 'data-diag' } : null,
        t.active ? { label: '🔎 Trace connections (30 s)', attr: 'data-trace title="Watch 30 s while you connect your client (e.g. Xray) and see where it stops"' } : null,
        { label: '✎ Edit tunnel', attr: 'data-editt' },
        t.active ? { label: '■ Stop tunnel', attr: 'data-stop', danger: true } : null])}</div>
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
    const runs = t.active === mid && t.family === fam;
    applyBtn.hidden = runs; $('[data-now]', m).hidden = !runs;
    applyBtn.textContent = t.active ? `⇄ Switch to this (${famName(fam)})` : `▶ Start (${famName(fam)})`;
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
  on('[data-reapply]', async () => { if (await applyMethod(t, t.active, t.family)) m.remove(); });
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
        if (rows && hl.dataset.was !== rows && !$('details.more[open]', hl) && !$('.hsset', hl)) { hl.dataset.was = rows; hl.innerHTML = rows; hsWire(t, hl); }
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
// Options apply at once: a select or switch saves and rebuilds as soon as it changes (one
// click, nothing half-typed); text and number fields on "Save & apply" (or Enter), so a
// rebuild never starts in the middle of typing a port. The server validates first, rebuilds
// only this method's paths, moves users off a path while it is rebuilt and puts the previous
// A value set by hand (✋) stays as set: no rollback, nothing automatic replaces it; a path
// that doesn't answer with it is shown failing with the reason, and ↺ Defaults gives the
// choice back to the panel. Progress and the result show here.
function renderOpts(box, t, mid, status) {
  const m = STATE.methods.find(x => x.id === mid);
  if (!m || !m.fields?.length) { box.innerHTML = `<div class="opts one"><div class="muted">No options for this method.</div></div>`; return; }
  const saved = (t.options && t.options[mid]) || {};
  const manual = new Set((t.optsManual && t.optsManual[mid]) || []);
  const hand = (f) => manual.has(f.key) ? ' <span class="faint" title="set by you — kept as it is; nothing automatic changes it">✋</span>' : '';
  const field = (f) => {
    const v = saved[f.key] !== undefined ? saved[f.key] : f.default;
    const help = f.help ? `<small class="fhelp">${esc(f.help)}</small>` : '';
    if (f.type === 'bool') return `<label class="row f" style="grid-column:1/-1"><input type="checkbox" data-k="${f.key}"${String(v) === 'true' ? ' checked' : ''}> ${esc(f.label)}${hand(f)}${help}</label>`;
    if (f.type === 'select') return `<label class="f">${esc(f.label)}${hand(f)}<select data-k="${f.key}">${f.options.map(o => `<option value="${esc(o)}"${o === v ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>${help}</label>`;
    return `<label class="f">${esc(f.label)}${hand(f)}<input data-k="${f.key}" class="mono" value="${esc(v)}"${f.type === 'number' ? ` inputmode="numeric" placeholder="${esc(f.default || 'auto')}"` : ''}>${help}</label>`;
  };
  const basic = m.fields.filter(f => !f.advanced), adv = m.fields.filter(f => f.advanced);
  const advOpen = !!$('details.advopts[open]', box);
  box.innerHTML = `<div class="opts${basic.length < 2 ? ' one' : ''}">${basic.map(field).join('')}
    ${adv.length ? `<details class="advopts" style="grid-column:1/-1"${advOpen ? ' open' : ''}><summary>🎛 Advanced tuning <span class="faint">(${adv.length}) — the defaults are what this method always used</span></summary><div class="opts inner">${adv.map(field).join('')}</div></details>` : ''}
    <div class="faint" style="grid-column:1/-1;font-size:12px">${t.active ? 'Changes apply at once: a list or switch as soon as you pick it, text fields with Save &amp; apply. Only this method is rebuilt; users on it move to another path meanwhile. What you set (✋) stays as you set it.' : 'The tunnel is stopped: options are saved and used when it starts.'}</div>
    <div class="ostat" data-ost style="grid-column:1/-1;font-size:12.5px"${status ? '' : ' hidden'}>${status || ''}</div>
    <div style="grid-column:1/-1;display:flex;justify-content:flex-end;gap:8px"><button class="btn sm ghost" data-reset title="back to the method's defaults, applied now — the panel chooses again (the benchmark's carrier for this route)">↺ Defaults</button><button class="btn sm pri" data-save>Save &amp; apply</button></div></div>`;
  const ost = $('[data-ost]', box);
  const show = (html) => { ost.hidden = !html; ost.innerHTML = html || ''; };
  const busy = (on) => $$('[data-k],[data-save],[data-reset]', box).forEach(el => el.disabled = on);
  const read = () => { const o = {}; $$('[data-k]', box).forEach(el => o[el.dataset.k] = el.type === 'checkbox' ? String(el.checked) : el.value); return o; };
  const val = (o, f) => { const v = o[f.key]; return String(v === undefined || v === '' ? (f.default ?? '') : v); };
  const same = (a, b) => m.fields.every(f => val(a, f) === val(b, f));
  const wireLog = (el, jid) => { const lb = $('[data-olog]', el); if (lb) lb.onclick = (e) => { e.preventDefault(); openLog(t, jid); }; };
  let sending = false;
  const apply = async (reset, confirm) => {
    if (sending) return;
    reset = reset === true;
    const opts = reset ? {} : read();
    if (!reset && same(opts, saved)) { show('<span class="muted">Nothing changed.</span>'); return; }
    sending = true; busy(true); show('<span class="muted">Saving…</span>');
    let r;
    try { r = await api('/tunnels/options', { ID: t.id, Method: mid, Options: opts, Reset: reset, Confirm: !!confirm }); }
    catch (e) { sending = false; busy(false); show(`<span style="color:var(--crit)">✕ ${esc(e.message)}</span>`); return; }
    // the users' path would restart with them on it (no other path answers): nothing is saved
    // until the user says so
    if (r.confirm) {
      sending = false; busy(false);
      show(`<div class="oconf">⚠ <span>${esc(r.confirm)}</span><div class="actions" style="margin-top:6px"><button class="btn sm danger" data-oconf>Restart it with the users on it</button><button class="btn sm ghost" data-ocancel>Cancel</button></div></div>`);
      $('[data-oconf]', box).onclick = () => apply(reset, true);
      $('[data-ocancel]', box).onclick = () => show('<span class="muted">Not changed.</span>');
      return;
    }
    t.options = { ...(t.options || {}), [mid]: opts };
    if (reset) t.optsManual = { ...(t.optsManual || {}), [mid]: [] };
    if (!r.job) { sending = false; renderOpts(box, t, mid, `<span style="color:var(--good)">✓ ${esc(r.note || 'Saved')}</span>`); return; }
    follow(r.job);
  };
  // the job's progress, inline: its last line and how long it has run while it runs, the
  // result at the end. The panel stays open with that result: no jobEnded() here — it redrew
  // the whole tunnels view, which closed a path's ⚙ Settings panel and lost the result (the
  // user saw "Applying…" and then nothing, and took it for a save that didn't happen).
  const follow = (jid) => {
    sending = true; busy(true);
    let fails = 0;
    const tick = async () => {
      if (!ost.isConnected) { followJob(jid); return; }
      let j = null;
      try { j = await api('/jobs?id=' + jid); fails = 0; } catch (e) { if (++fails < 5) { setTimeout(tick, 2000); return; } }
      const lines = (j && j.lines) || [], clean = (l) => l.replace(/^\d\d:\d\d:\d\d /, '');
      if (j && j.status === 'running') {
        const s = Math.max(0, Math.floor(Date.now() / 1000) - (j.started || 0)), took = j.started ? ` ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}` : '';
        show(`<span class="muted">⏳ Applying…<span class="mono" data-notr>${took}</span> <span class="mono" data-notr>${esc(clean(lines[lines.length - 1] || ''))}</span></span> <a href="#" data-olog>log</a>`);
        wireLog(ost, jid);
        setTimeout(tick, 2000); return;
      }
      // the result, with the options as stored now and the hand-set marks
      try { await loadAll(); } catch (e) {}
      const nt = STATE.tunnels.find(x => x.id === t.id); if (nt) Object.assign(t, { options: nt.options, optsManual: nt.optsManual, paths: nt.paths, hs: nt.hs });
      if (!box.isConnected) return;
      const res = lines.filter(l => / ✓ | ✕ |DONE|FAILING|ERROR|CANCELLED/.test(l)).slice(-4).map(clean);
      const ok = j && j.status === 'ok', failing = lines.some(l => /FAILING/.test(l));
      const head = ok ? '✓ Applied — saved and running' : failing ? "✕ Saved, but the path doesn't answer with these options — kept as you set them; users stay on a working path"
        : j && j.status === 'cancelled' ? '✕ Cancelled — saved, not applied' : j ? '✕ Saved, but not applied' : "✕ Saved — the job's result couldn't be read";
      sending = false;
      renderOpts(box, t, mid, `<div style="color:var(${ok ? '--good' : '--crit'})">${head}</div>${res.map(l => `<div class="faint mono" style="font-size:11.5px" data-notr>${esc(l)}</div>`).join('')}<a href="#" data-olog>log</a>${ok ? '' : ' <button class="btn sm ghost" data-odef>↺ Back to defaults</button>'}`);
      wireLog(box, jid);
      // the tunnel window (not a path's panel) redraws the cards behind it as before
      if (!box.closest('.hsset')) jobEnded();
    };
    tick();
  };
  // opened (or redrawn) while this method's options job runs: its progress shows here again
  // and the form waits for it, instead of a form that looks idle and answers 409
  if (!status && t.active) api('/tunnels/lastjob?id=' + encodeURIComponent(t.id)).then(j => {
    if (j && j.status === 'running' && j.kind === 'options:' + mid && box.isConnected && !sending) follow(j.id);
  }).catch(() => {});
  $('[data-reset]', box).onclick = () => apply(true);
  $('[data-save]', box).onclick = () => apply(false);
  const od = $('[data-odef]', box); if (od) od.onclick = () => apply(true);
  $$('select[data-k],input[type=checkbox][data-k]', box).forEach(el => el.onchange = () => apply(false));
  $$('input[data-k]:not([type=checkbox])', box).forEach(el => el.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); apply(false); } });
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
// One card per route (Iran server → foreign server), one section per address family: which
// methods work there now, best first, the users' method marked, failures folded under one line
// each, each method's trend as a sparkline. The benchmark runs on the server; the page only
// watches it (BN.job survives navigation, /bench/active re-attaches after a reload).
let benchTimer = null, benchPoll = null;
const BN = { job: null, req: null, view: {}, fam: '', route: '' };
const bnKey = (i, f) => i + '|' + (f || '');
const bnAge = (u) => { const s = Math.max(0, Math.floor(Date.now() / 1000) - u); return s < 90 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
const bnIn = (u) => { const s = u - Math.floor(Date.now() / 1000); return s <= 600 ? 'within 10 min' : s < 3600 ? `in ${Math.round(s / 60)} min` : s < 86400 ? `in ${Math.round(s / 3600)} h` : `in ${Math.round(s / 86400)} d`; };
const bnMb = (v) => v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(0) : v > 0 ? v.toFixed(1) : '0';
// the methods "Every method" measures on a route+family: all that fit it, also the ones left out on the route (only
// measured there, nothing is deployed), less spoof (never measured); the dialogs ask the server (/bench/plan) for the exact list
const bnAll = (fam) => STATE.methods.filter(m => m.id !== 'spoof' && m.families.includes(fam));
const bnCostAll = (n, maxMB) => `${n} methods · ≤ ${n * 2 * maxMB} MB · about ${Math.max(1, Math.round(n * 1.5))} min`;
function bnSpark(pts) {
  if (pts.length < 2) return '';
  const vs = pts.map(p => p.v), mx = Math.max(...vs, 1), w = 64, hh = 18;
  const xy = pts.map((p, i) => [(i / (pts.length - 1)) * w, hh - 2 - (p.v / mx) * (hh - 4)]);
  const d = xy.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join('');
  const last = xy[xy.length - 1];
  const tip = pts.map(p => `${new Date(p.at * 1000).toLocaleDateString()} ↓${bnMb(p.v)}`).join(' · ');
  return `<svg class="bn-spark" viewBox="0 0 ${w} ${hh}" preserveAspectRatio="none" aria-hidden="true"><title>${esc(tip)}</title><path d="${d}"/><circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="1.8"/></svg>`;
}
function viewBench(w) {
  w.innerHTML = topbar('Benchmark', 'Which methods work on each route right now, and which is best — measured on a temporary tunnel, live tunnels are not touched.',
    '<button class="btn sm" id="bnpair">＋ Another pair</button>');
  w.appendChild(h(`<div class="bn"><div id="bnauto"></div><div id="bnrun"></div>
    <div class="bn-filters"><label class="bn-sel"><span>Route</span><select id="bnroute"><option value="">All routes</option></select></label>
      <div class="seg" id="bnfam"><button data-f="" class="on">All</button><button data-f="v4">IPv4</button><button data-f="v6">IPv6</button></div></div>
    <div id="bnlist"><div class="skel" style="height:160px"></div></div><div id="bnfoot"></div></div>`));
  $$('#bnfam button', w).forEach(b => { b.classList.toggle('on', b.dataset.f === BN.fam); b.onclick = () => { BN.fam = b.dataset.f; $$('#bnfam button').forEach(x => x.classList.toggle('on', x === b)); bnPaint(); }; });
  $('#bnroute', w).onchange = (e) => { BN.route = e.target.value; bnPaint(); };
  $('#bnpair', w).onclick = () => bnPairModal();
  bnLoad();
  // re-attach to a running (or just finished) benchmark
  api('/bench/active').then(a => { if (a && a.job && (a.running || BN.job === a.job)) bnWatch(a.job, a.req || {}); }).catch(() => {});
  if (benchPoll) clearInterval(benchPoll);
  benchPoll = setInterval(() => { if (STATE.view !== 'bench' || !$('#bnlist')) { clearInterval(benchPoll); benchPoll = null; return; } if (!document.hidden && !benchTimer) bnLoad(); }, 30000);
}
let BND = null; // the page's data: history, schedule, switches, live results of the running route
async function bnLoad() {
  let hist = [], st = {}, skip = {};
  try { [hist, st, skip] = await Promise.all([api('/bench/history'), api('/bench/status').catch(() => ({})), api('/routes/skip').catch(() => ({}))]); } catch (e) {}
  let live = null;
  if (BN.job && BN.req && BN.req.iranId) {
    try { live = await api(`/bench/results?iran=${encodeURIComponent(BN.req.iranId)}&foreign=${encodeURIComponent(BN.req.foreignId || '')}&family=${BN.req.family || 'v4'}`); } catch (e) {}
  }
  BND = { hist: hist || [], st: st || {}, skip: skip || {}, live };
  bnPaint();
}
// the routes the page shows: the visible tunnels' pairs, the measured pairs and the scheduled ones
function bnRoutes() {
  const { hist, st } = BND, pairs = new Map();
  const add = (iran, foreign) => { const k = bnKey(iran, foreign); if (!pairs.has(k)) pairs.set(k, { k, iran, foreign: foreign || '', tunnels: [] }); return pairs.get(k); };
  STATE.tunnels.filter(t => shownOwner(t.owner)).forEach(t => add(t.serverId, t.foreignId).tunnels.push(t));
  const ownOk = (id) => shownOwner((serverById(id) || {}).owner);
  hist.filter(r => ownOk(r.iranId)).forEach(r => add(r.iranId, r.foreignId));
  (st.routes || []).filter(r => ownOk(r.iranId)).forEach(r => add(r.iranId, r.foreignId));
  if (BN.req && BN.req.iranId && ownOk(BN.req.iranId)) add(BN.req.iranId, BN.req.foreignId);
  const hasFam = (id, f) => { const s = id ? serverById(id) : null, g = STATE.settings || {}; return f === 'v4' ? !!(s ? s.ipv4 : true) : !!(s ? s.ipv6 : g.localIPv6); };
  const out = [...pairs.values()].map(p => {
    p.fams = ['v4', 'v6'].filter(f => (hasFam(p.iran, f) && hasFam(p.foreign, f)) || hist.some(r => r.iranId === p.iran && (r.foreignId || '') === p.foreign && r.family === f));
    p.users = p.tunnels.filter(t => t.active).length;
    p.label = `${serverName(p.iran)} → ${p.foreign ? serverName(p.foreign) : 'this panel host'}`;
    return p;
  });
  return out.sort((a, b) => (b.users > 0) - (a.users > 0) || a.label.localeCompare(b.label));
}
// what the route's tunnels run over fam: the users' method(s) and the hot-standby paths kept ready
function bnUse(p, fam) {
  const users = new Set(), standby = new Set();
  p.tunnels.filter(t => t.active).forEach(t => {
    const hs = t.hs;
    if (t.hotStandby && hs && hs.keys && hs.keys.length) {
      hs.keys.forEach((k, i) => { const [m, f] = k.split('|'); if (f !== fam) return; if (i === hs.active) users.add(m); else if ((hs.ok || [])[i]) standby.add(m); });
    } else if (t.family === fam) users.add(t.active);
  });
  users.forEach(m => standby.delete(m));
  return { users, standby };
}
function bnPaint() {
  const list = $('#bnlist');
  if (!list || !BND) return;
  const { hist, st, skip } = BND;
  const routes = bnRoutes();
  // the route picker
  const sel = $('#bnroute');
  if (BN.route && !routes.some(p => p.k === BN.route)) BN.route = '';
  sel.innerHTML = `<option value="">All routes (${routes.length})</option>` + routes.map(p => `<option value="${esc(p.k)}" data-notr>${esc(p.label)}</option>`).join('');
  sel.value = BN.route;
  bnAutoCard();
  const shown = routes.filter(p => !BN.route || p.k === BN.route);
  if (!shown.length) { list.innerHTML = `<div class="card empty"><div class="big">📊</div><h3>No routes yet</h3><p class="muted">Add a tunnel, or measure a pair of servers with “＋ Another pair”.</p></div>`; bnFoot(); return; }
  list.innerHTML = '';
  shown.forEach(p => { try { list.appendChild(bnCard(p)); } catch (e) { console.error(e); list.appendChild(h(`<div class="card pad bn-card"><b data-notr>${esc(p.label)}</b><div class="faint">couldn't be drawn: ${esc(e.message)}</div></div>`)); } });
  bnFoot();
}
function bnCard(p) {
  const { hist, st, skip } = BND;
  const fams = p.fams.filter(f => !BN.fam || f === BN.fam);
  const fl = (id, d) => { const s = id ? serverById(id) : null; return s && s.country ? flag(s.country) : d; };
  const tnames = p.tunnels.map(t => `<span class="chip" data-notr>${esc(t.name)}</span>`).join('');
  const card = h(`<div class="card bn-card"><div class="bn-head">
      <div class="bn-route">${fl(p.iran, flag('IR'))} ${srvNm(p.iran)} <span class="faint">→</span> ${fl(p.foreign, p.foreign ? '🌍' : '🖥')} ${srvNm(p.foreign, 'this panel host')}</div>
      <div class="bn-tn">${p.users ? `<span class="pill on"><span class="led"></span>${p.users === 1 ? 'tunnel running' : `${p.users} tunnels running`}</span>` : p.tunnels.length ? '<span class="pill off">tunnel stopped</span>' : '<span class="pill off">no tunnel</span>'}${tnames}</div></div></div>`);
  if (!fams.length) card.appendChild(h(`<div class="bn-fam"><div class="faint">${BN.fam ? `No ${famName(BN.fam)} on this route.` : 'These two servers have no address family in common.'}</div></div>`));
  fams.forEach(f => card.appendChild(bnFamSection(p, f)));
  $$('[data-err]', card).forEach(b => b.onclick = () => alertModal('Why it failed', b.dataset.err));
  $$('[data-apply]', card).forEach(b => b.onclick = () => applyBenchToTunnel({ iran: p.iran, foreign: p.foreign, family: b.dataset.fam }, b.dataset.apply));
  $$('[data-run]', card).forEach(b => b.onclick = () => bnRunModal(p, b.dataset.run));
  $$('[data-hv]', card).forEach(b => b.onclick = () => { BN.view[p.k + '|' + b.dataset.fam] = b.dataset.hv || undefined; bnPaint(); });
  return card;
}
function bnFamSection(p, f) {
  const { hist, st, skip } = BND;
  const runs = hist.filter(r => r.iranId === p.iran && (r.foreignId || '') === p.foreign && r.family === f); // newest first
  const running = BN.req && BN.req.iranId === p.iran && (BN.req.foreignId || '') === p.foreign && (BN.req.family || 'v4') === f;
  const busy = !!BN.job && BN.running;
  const vk = p.k + '|' + f, pick = BN.view[vk] && runs.find(r => r.id === BN.view[vk]);
  // the run shown: a past one picked from the history, the live one while it runs, else the newest
  let run = pick || runs[0] || null, results = run ? run.results || [] : [];
  if (!pick && running && BND.live && BND.live.length) { results = BND.live; run = { at: Math.max(...BND.live.map(r => r.at || 0)) || Math.floor(Date.now() / 1000), live: true }; }
  const sched = (st.routes || []).find(r => r.iranId === p.iran && (r.foreignId || '') === p.foreign && r.family === f);
  const fail = (st.fails || []).find(r => r.iranId === p.iran && (r.foreignId || '') === p.foreign && r.family === f);
  const { users, standby } = bnUse(p, f);
  const every = (st.hours || 24) * 3600, now = Math.floor(Date.now() / 1000);
  // freshness of the newest run
  let fresh;
  if (!run) fresh = '<span class="pill off">never measured</span>';
  else if (run.live) fresh = '<span class="pill acc">measuring now…</span>';
  else { const age = now - run.at, c = pick ? 'acc' : age > 7 * 86400 ? 'bad' : age > 2 * every ? 'warn' : 'on'; fresh = `<span class="pill ${c}" title="${esc(new Date(run.at * 1000).toLocaleString())}">${pick ? 'past run · ' : ''}measured ${bnAge(run.at)}</span>`; }
  const ok = results.filter(r => r.ok), bad = results.filter(r => !r.ok && !r.skipped), skipped = results.filter(r => r.skipped);
  const top = Math.max(1, ...ok.map(r => r.downMbps || 0));
  // each method's ↓ over the saved runs (oldest first; a result carried into a later run counts once)
  const trend = (mid) => {
    const pts = [], seen = new Set();
    runs.slice().reverse().forEach(r => { const x = (r.results || []).find(y => y.method === mid && y.ok); if (!x) return; const at = x.at || r.at; if (seen.has(at)) return; seen.add(at); pts.push({ at, v: x.downMbps || 0 }); });
    return pts.slice(-12);
  };
  const carrier = (x) => x.opts ? Object.entries(x.opts).map(([k, v]) => `${k} ${v}`).join(', ') : '';
  const rows = ok.map((x, i) => {
    const old = x.at && run.at && run.at - x.at > 300; // carried over from an earlier run
    const tags = ((BND.skip[bnKey(p.iran, p.foreign)] || []).includes(x.method + '|' + f) ? '<span class="chip" title="left out on this route (Routes page): measured only, not deployed">off on this route</span>' : '') + (users.has(x.method) ? '<span class="chip bn-u">👥 users on it</span>' : '') + (standby.has(x.method) ? '<span class="chip bn-s">⚡ standby</span>' : '') + (carrier(x) ? `<span class="chip" title="the default carrier passes nothing here; this one does" data-notr>${esc(carrier(x))}</span>` : '');
    return `<div class="bn-row${i === 0 ? ' best' : ''}${users.has(x.method) ? ' users' : ''}">
      <span class="bn-rk">${i === 0 ? '★' : i + 1}</span>
      <div class="bn-m"><b>${esc(methodTitle(x.method))}</b>${tags ? `<span class="bn-tags">${tags}</span>` : ''}${old ? `<small class="bn-old" title="this run didn't measure it: its result is from an earlier run">⏱ <span>measured ${bnAge(x.at)}</span></small>` : ''}</div>
      <div class="bn-sp"><div class="bn-bar"><i style="width:${Math.max(3, Math.round((x.downMbps || 0) / top * 100))}%"></i></div>
        <span class="bn-n"><b>↓ ${bnMb(x.downMbps || 0)}</b> <span class="faint">↑ ${bnMb(x.upMbps || 0)}</span> <small>Mbps</small></span></div>
      <span class="bn-lat"><b>${(x.rttMs || 0).toFixed(0)}</b> <small>ms</small>${x.lossKnown ? ` <span class="${x.lossPct >= 5 ? 'bn-bad' : 'faint'}">· ${x.lossPct.toFixed(0)}% <small>loss</small></span>` : ''}</span>
      <span class="bn-tr">${bnSpark(trend(x.method))}</span>
      <button class="btn sm ghost" data-apply="${esc(x.method)}" data-fam="${f}" title="Switch one of this route's tunnels to this method">Apply</button></div>`;
  }).join('');
  // the users' method failed (or wasn't measured) in this run: said first, it is what matters
  const usersWarn = [...users].filter(m => !ok.some(x => x.method === m) && run && !run.live).map(m => {
    const x = results.find(y => y.method === m);
    return `<div class="bn-warn">⚠ <span>Users are on ${esc(methodTitle(m))}, but in this run it</span> ${x ? (x.skipped ? '<span>was not measured</span>' : `<button class="bn-why" data-err="${esc(x.error || 'failed')}">✕ ${esc(shortErr(x.error))}</button>`) : '<span>was not measured</span>'}</div>`;
  }).join('');
  const failBox = fail && (!run || run.live || fail.at > run.at) ? `<div class="bn-warn bad">✕ <span>${fail.auto ? 'Automatic run' : 'Last run'} ${bnAge(fail.at)} measured nothing:</span> <button class="bn-why" data-err="${esc(fail.error)}">${esc(shortErr(fail.error))}</button></div>` : '';
  const fails = bad.length || skipped.length ? `<details class="bn-fails"><summary>${bad.length ? `<span class="bn-bad">✕ ${bad.length} failed</span>` : ''}${bad.length && skipped.length ? ' · ' : ''}${skipped.length ? `<span class="faint">${skipped.length} not measured</span>` : ''}</summary>
      ${bad.map(x => `<div class="bn-f"><b>${esc(methodTitle(x.method))}</b>${users.has(x.method) ? '<span class="chip bn-u">👥 users on it</span>' : ''}<button class="bn-why" data-err="${esc(x.error || 'failed')}" title="show the whole error">${esc(shortErr(x.error))}</button></div>`).join('')}
      ${skipped.length ? `<div class="bn-f sk"><span class="faint">Not measured:</span> ${skipped.map(x => `<span class="chip" title="${esc(x.error || '')}">${esc(methodTitle(x.method))}</span>`).join('')}</div>` : ''}</details>` : '';
  // cost of a run: each method moves at most maxMB each way
  const k = bnKey(p.iran, p.foreign), maxMB = st.maxMB || 6;
  const nRun = (sched && sched.running && sched.running.length) || [...users, ...standby].length;
  const nAll = bnAll(f).length;
  const runBtn = `<button class="btn sm ${run ? '' : 'pri'}" data-run="${f}"${busy ? ' disabled title="one benchmark at a time — wait for the running one"' : ''}>▶ Run benchmark</button>`;
  const cost = `<small class="faint bn-cost">≤ ${(nRun || nAll) * 2 * maxMB} MB</small>`;
  let next = '';
  if (sched && st.hours) next = `<span>${sched.next <= now ? '🤖 due for the automatic run now' : '🤖 next automatic run ' + bnIn(sched.next)}${sched.nextFull ? ' · every method' : ''}</span>`;
  else if (st.hours === 0) next = '<span>🤖 automatic benchmark is off</span>';
  else if (!sched) next = '<span>🤖 not measured automatically: no tunnel runs here</span>';
  const hl = runs.slice(0, 8).map(r => {
    const b = (r.results || []).find(x => x.recommended), n = (r.results || []).filter(x => x.ok).length;
    const on = (pick ? pick.id : (runs[0] || {}).id) === r.id && !(running && BND.live);
    return `<button class="bn-h${on ? ' on' : ''}" data-hv="${r.id === (runs[0] || {}).id ? '' : esc(r.id)}" data-fam="${f}"><span class="mono">${new Date(r.at * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' })} ${new Date(r.at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span><b>${b ? esc(methodTitle(b.method)) : '—'}</b><small class="faint">${n}/${(r.results || []).length} ok${r.full ? ' · all' : ''}${r.auto ? ' · 🤖' : ''}</small></button>`;
  }).join('');
  return h(`<div class="bn-fam${running && busy ? ' live' : ''}">
    <div class="bn-fh"><b class="bn-fn">${famName(f)}</b>${fresh}<span class="bn-sp1"></span>${cost}${runBtn}</div>
    ${failBox}${usersWarn}
    ${ok.length ? `<div class="bn-rows">${rows}</div>` : run ? '<div class="bn-none">No method worked in this run.</div>' : '<div class="bn-none faint">Not measured yet — run the benchmark to see which methods work here.</div>'}
    ${fails}
    <div class="bn-meta">${next}${runs.length > 1 ? `<details class="bn-hist"${pick ? ' open' : ''}><summary>History · ${runs.length} runs</summary><div class="bn-hl">${hl}</div></details>` : ''}</div></div>`);
}
// the automatic benchmark: how often, what it costs, editable here (admin)
function bnAutoCard() {
  const box = $('#bnauto'); if (!box || !BND) return;
  const st = BND.st, hrs = st.hours, now = Math.floor(Date.now() / 1000);
  const due = (st.routes || []).filter(r => r.next).sort((a, b) => a.next - b.next)[0];
  const fails = (st.fails || []).length;
  box.innerHTML = `<div class="card bn-auto"><div class="bn-ai">🤖</div><div class="bn-at">
      <b>${hrs ? `Automatic benchmark every ${hrs} h` : 'Automatic benchmark is off'}</b>
      <small>${hrs ? `only the methods running on each route, at most ${st.autoMB || 3} MB each way per method; every method once in ${(st.fullEvery || 7) * hrs} h` : 'routes are measured only when you run the benchmark'}</small>${due ? `<small class="bn-nx">${due.next <= now ? 'a route is due now' : 'next ' + bnIn(due.next)}</small>` : ''}</div>
      ${fails ? `<span class="pill bad" title="routes whose last run measured nothing — see the route">${fails === 1 ? '1 route failed' : `${fails} routes failed`}</span>` : ''}
      ${isAdmin() ? `<form class="bn-edit" id="bnaf"><label><span>every</span><input name="hours" class="mono" inputmode="numeric" value="${esc(st.set || '')}" placeholder="24" aria-label="hours"><span>h</span></label><button class="btn sm">Save</button></form>` : ''}</div>`;
  const f = $('#bnaf', box);
  if (f) f.onsubmit = oneAtATime(f, async () => { try { await api('/bench/auto', { hours: f.hours.value.trim() }); toast('Saved'); if (STATE.settings) STATE.settings.autoBench = f.hours.value.trim(); bnLoad(); } catch (e) { alertModal('Automatic benchmark', e.message); } });
}
function bnFoot() {
  const box = $('#bnfoot'); if (!box) return;
  box.innerHTML = `<div class="bn-legend faint">↓ = foreign → Iran (what users downloading feel), ↑ = Iran → foreign · ★ best · 👥 the method users are on now · ⚡ kept ready by hot standby · the line = ↓ in the last runs</div>
    ${isAdmin() && BND.hist.length ? '<button class="btn sm ghost danger" id="bhclear">Clear history</button>' : ''}`;
  const c = $('#bhclear', box);
  if (c) c.onclick = async (e) => { if (!confirmInline(e.target, 'Click again to clear')) return; try { await api('/bench/history', { Clear: true }); bnLoad(); } catch (er) { alertModal('Error', er.message); } };
}
// one dialog to start a run: which methods, what it costs at most, how long each probe
function bnRunModal(p, fam) {
  const st = BND.st, maxMB = st.maxMB || 6, k = bnKey(p.iran, p.foreign);
  const sched = (st.routes || []).find(r => r.iranId === p.iran && (r.foreignId || '') === p.foreign && r.family === fam);
  const { users, standby } = bnUse(p, fam);
  const runN = (sched && sched.running && sched.running.length) || [...users, ...standby].length, allN = bnAll(fam).length;
  const m = modal(`<h2>Run benchmark</h2><p class="muted" style="margin-top:4px"><span data-notr>${esc(p.label)}</span> · ${famName(fam)}</p>
    <form class="ff" id="bnrf">
      <label class="bn-opt"><input type="radio" name="scope" value="running" ${runN ? 'checked' : 'disabled'}><span><b>The methods in use</b><small>${runN ? `${runN} methods · ≤ ${runN * 2 * maxMB} MB` : 'no tunnel runs here — nothing in use'}</small></span></label>
      <label class="bn-opt"><input type="radio" name="scope" value="all" ${runN ? '' : 'checked'}><span><b>Every method</b><small data-cost="all">${bnCostAll(allN, maxMB)}</small></span></label>
      <div class="bn-plan" id="bnplan"></div>
      <details class="bn-adv"><summary>Advanced</summary><label class="f">Throughput probe per method (seconds)<input name="seconds" type="number" min="1" max="20" class="mono" value="5"></label></details>
      <div class="faint" style="font-size:12px">Each method runs on a temporary tunnel, is measured, then removed — live tunnels are not touched. At most ${maxMB} MB each way per method. It runs on the server: you can leave this page.</div>
      <div class="actions" style="justify-content:flex-end"><button type="button" class="btn ghost" id="bncx">Cancel</button><button class="btn pri">▶ Start</button></div></form>`);
  $('#bncx', m).onclick = () => m.remove();
  // what "Every method" measures, from the server: the count, and each method left out with why
  api(`/bench/plan?iran=${encodeURIComponent(p.iran)}&foreign=${encodeURIComponent(p.foreign || '')}&family=${fam}`).then(pl => {
    if (!m.isConnected) return;
    const n = (pl.methods || []).length, left = pl.left || [], off = pl.off || [];
    $('[data-cost=all]', m).textContent = bnCostAll(n, pl.maxMB || maxMB);
    $('#bnplan', m).innerHTML = (off.length ? `<small class="faint">${off.length === 1 ? 'Includes 1 method left out on this route' : `Includes ${off.length} methods left out on this route`} — only measured, nothing is deployed</small>` : '')
      + (left.length ? `<details class="bn-adv"><summary>Not measured (${left.length})</summary><div class="bn-left">${left.map(x => `<div><b>${esc(methodTitle(x.method))}</b> <span class="faint">${esc(x.why)}</span></div>`).join('')}</div></details>` : '');
  }).catch(() => {});
  const f = $('#bnrf', m);
  f.onsubmit = oneAtATime(f, async () => {
    const req = { iranId: p.iran, foreignId: p.foreign, family: fam, running: f.scope.value !== 'all', all: f.scope.value === 'all', seconds: parseInt(f.seconds.value || '5', 10) };
    try { const r = await api('/bench/start', req); m.remove(); bnWatch(r.job, req); } catch (e) { alertModal('Benchmark', e.message); }
  });
}
// any pair of servers (also one with no tunnel, or the panel host): what the old form did
function bnPairModal() {
  const opt = (s) => `<option value="${s.id}"${s.shared ? '' : ' data-notr'}>${esc(serverLabel(s))}${s.shared ? ' · shared' : ''}</option>`;
  const m = modal(`<h2>Benchmark a pair of servers</h2><form class="ff" id="bnpf">
    <label class="f">Iran server<select name="iran">${[...iranServers(), ...(STATE.shared || []).filter(s => (s.role || 'iran') === 'iran')].map(opt).join('')}</select></label>
    <label class="f">Foreign server<select name="foreign">${[...foreignServers(), ...(STATE.shared || []).filter(s => s.role === 'foreign')].map(opt).join('')}${panelHostOpt()}</select></label>
    <label class="f">Family<select name="family"><option value="v4">IPv4</option><option value="v6">IPv6</option></select></label>
    <div class="actions" style="justify-content:flex-end"><button class="btn pri">Next</button></div></form>`);
  const f = $('#bnpf', m);
  f.onsubmit = (ev) => { ev.preventDefault(); const iran = f.iran.value, foreign = f.foreign.value || '', fam = f.family.value; m.remove();
    bnRunModal({ k: bnKey(iran, foreign), iran, foreign, tunnels: STATE.tunnels.filter(t => t.serverId === iran && (t.foreignId || '') === foreign), label: `${serverName(iran)} → ${foreign ? serverName(foreign) : 'this panel host'}` }, fam); };
}
function bnWatch(job, req) {
  BN.job = job; BN.req = req; BN.running = true;
  if (benchTimer) clearInterval(benchTimer);
  const tick = async () => {
    let j;
    try { j = await api('/jobs?id=' + job); } catch (e) { return; }
    const done = j.status !== 'running';
    BN.running = !done;
    if (done) { clearInterval(benchTimer); benchTimer = null; }
    if (STATE.view !== 'bench' || !$('#bnrun')) return;
    bnRunCard(j, req, job);
    if (done) { await bnLoad(); return; }
    // while it runs only the route's results change
    try { if (BND) { BND.live = await api(`/bench/results?iran=${encodeURIComponent(req.iranId)}&foreign=${encodeURIComponent(req.foreignId || '')}&family=${req.family || 'v4'}`); bnPaint(); } else await bnLoad(); } catch (e) {}
  };
  benchTimer = setInterval(tick, 2000); tick();
}
// the running benchmark: route, progress, the method being measured, cancel, the log folded
function bnRunCard(j, req, job) {
  const box = $('#bnrun'); if (!box) return;
  const lines = j.lines || [];
  let i = 0, n = 0, cur = '';
  lines.forEach(l => { const mm = /── \[(\d+)\/(\d+)\] (.+) ──/.exec(l); if (mm) { i = +mm[1]; n = +mm[2]; cur = mm[3]; } });
  const running = j.status === 'running';
  const label = `${serverName(req.iranId)} → ${req.foreignId ? serverName(req.foreignId) : 'this panel host'}`;
  const last = [...lines].reverse().find(l => /^DONE/.test(l)) || '';
  const state = running ? '' : j.status === 'ok' ? 'Finished' : j.status === 'cancelled' ? 'Cancelled' : 'Stopped with an error';
  const err = !running && j.status !== 'ok' && j.status !== 'cancelled' ? [...lines].reverse().find(l => /ERROR/.test(l)) : '';
  const old = $('details', box), open = old ? old.open : false, log = $('.logbox', box), stick = !log || log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
  box.innerHTML = `<div class="card bn-runc ${running ? 'on' : j.status === 'ok' ? 'ok' : 'bad'}">
    <div class="bn-rh"><b>${running ? 'Benchmark running' : esc(state)}</b><span data-notr>${esc(label)}</span><span>· ${famName(req.family)}</span>
      <span class="bn-sp1"></span>${running ? '<button class="btn sm danger" id="bncancel">■ Cancel</button>' : '<button class="btn sm ghost" id="bnclose">✕</button>'}</div>
    ${running ? `<div class="bn-prog"><i style="width:${n ? Math.round((i - 0.5) / n * 100) : 3}%"></i></div><div class="bn-now"><span>${n ? `Method ${i} of ${n}` : 'Preparing…'}</span>${cur ? ` · <b data-notr>${esc(cur)}</b>` : ''} <span class="faint">· continues on the server if you leave</span></div>` : `<div class="bn-now">${err ? `<span class="bn-bad" data-notr>${esc(err)}</span>` : last ? `<span data-notr>${esc(last)}</span>` : ''}</div>`}
    <details${open ? ' open' : ''}><summary class="faint">Log</summary><div class="logbox" style="height:200px">${lines.map(l => `<div class="ln ${/ERROR|FAILED/.test(l) ? 'err' : /DONE|best| ok:/.test(l) ? 'ok' : ''}">${esc(l)}</div>`).join('')}</div></details></div>`;
  const lb = $('.logbox', box); if (lb && stick) lb.scrollTop = lb.scrollHeight;
  const cb = $('#bncancel', box);
  if (cb) cb.onclick = async () => { cb.disabled = true; try { await api('/jobs/cancel', { ID: job }); toast('Benchmark cancelled — cleaning up'); } catch (e) { alertModal('Cancel', e.message); cb.disabled = false; } };
  const cl = $('#bnclose', box);
  if (cl) cl.onclick = () => { box.innerHTML = ''; BN.job = null; BN.req = null; bnLoad(); };
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
  // a path's ⚙ Settings panel is open: redrawing the view would close it and its result;
  // the data is fresh, and healthWatch repaints the rows once the panel is closed
  if (STATE.view === 'tunnels' && $('.hsset', w)) return;
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
const IGSV = { IG: 'Instagram', GOOGLE: 'Google / Gemini', YTM: 'YouTube Music', ADULT: 'Adult', SPOTIFY: 'Spotify', SCLOUD: 'SoundCloud', SNAP: 'Snapchat',
  OPENAI: 'ChatGPT', CLAUDE: 'Claude', COPILOT: 'Copilot', PERPLEX: 'Perplexity', GROK: 'Grok', AICODE: 'AI tools', X: 'X', TIKTOK: 'TikTok', REDDIT: 'Reddit', LINKEDIN: 'LinkedIn',
  PINTEREST: 'Pinterest', TELEGRAM: 'Telegram', WHATSAPP: 'WhatsApp', DISCORD: 'Discord', NETFLIX: 'Netflix', DISNEY: 'Disney+', PRIME: 'Prime Video', TWITCH: 'Twitch',
  APPLE: 'Apple Music', GAMES: 'Steam · games', DEV: 'GitHub · Docker', CUSTOM: 'My sites' };
const IGWIDE = Object.keys(IGSV).filter(g => !['IG', 'GOOGLE', 'YTM'].includes(g)); // domain-only: no IPv6 / WARP-IPv6
const IGST = { OK: ['healthy', 'on'], PANEL: ['x-ui panel diverts Google', 'bad'], GEMFAIL: ['Gemini failing', 'bad'], IGFAIL: ['Instagram failing', 'bad'], DOWN: ['router down', 'bad'], GUARD: ['WARP guard not running', 'bad'],
  IGIR: ['Instagram in a no-music country', 'bad'], NOEXIT: ['no exit for Instagram', 'bad'], NOWARP: ['WARP missing', 'warn'],
  FIXED: ['fixed automatically', 'warn'], CHECKING: ['checking…', 'acc'], NOAGENT: ['not installed', 'warn'], SUDO: ['needs sudo without password', 'warn'], PAUSED: ['paused', 'warn'], UPDATE: ['old agent', 'warn'], OFFLINE: ['offline', 'bad'] };
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
const igColor = (l) => /^<< ✓/.test(l) ? 'ok' : /^<< [!✕]/.test(l) ? 'err' : /^<< /.test(l) ? '' : /^\s*(!!|ERR|.*\b(FAIL|DOWN|failed|rejected|not )\b)/i.test(l) ? 'err' : /^\s*(==|->)/.test(l) ? 'ir' : /\b(OK|added|saved|applied|removed|updated|installed|fixed)\b/.test(l) ? 'ok' : '';
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
    `${isAdmin() ? '<a class="btn" data-gbtn href="/gbrowser/" title="Chromium on xe108 with the Google test account: log in here once">🔑 Google test browser</a>' : ''}<button class="btn" data-igref>↻ Refresh</button><button class="btn pri" data-igadd>+ Add server</button>`)
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
// the Google test account's state on its button (gemacct.go): red while Google has it signed out.
// The button opens the test browser in a window on this page (igGSignin), not in a new tab.
function igAcctBadge(w) {
  const b = $('[data-gbtn]', w); if (!b) return;
  b.onclick = (e) => { if (e.ctrlKey || e.metaKey || e.shiftKey || e.button === 1) return; e.preventDefault(); igGSignin(); };
  api('/igproxy/gaccount').then(d => {
    if (d.state === 'out') {
      b.textContent = '🔑 Google test account: signed out — log in';
      b.style.color = 'var(--crit)'; b.style.fontWeight = '600';
      b.title = `Google ended the test account's session${d.since ? ' (seen ' + new Date(d.since).toLocaleString() + ')' : ''}${d.cause ? '. Why: ' + d.cause : ''}. Log in here; it goes out through ${d.exit}.`;
    } else if (d.state === 'in') { b.textContent = '🔑 Google test browser ✓'; b.style.color = ''; b.style.fontWeight = ''; }
  }).catch(() => {});
}
// the test browser (noVNC, /gbrowser/ — admin only, same auth as the page) in a window on this
// page; its status follows the account (polled while the window is open) and it closes by
// itself a few seconds after the account is signed in
const GB_SRC = '/gbrowser/vnc.html?path=gbrowser/websockify&autoconnect=1&resize=scale&reconnect=1';
function igGSignin() {
  const m = modal(`<div class="gbhead"><h2 data-notr>🔑 ${L('Google test account', 'حساب تست Google')}</h2><span class="gbst wait" data-gbst data-notr>${L('Connecting…', 'در حال اتصال…')}</span></div>
    <p class="gbhint" data-gbhint data-notr></p>
    <div class="gbwrap"><iframe class="gbframe" src="${GB_SRC}" title="Google test browser" referrerpolicy="no-referrer"></iframe></div>
    <div class="gbfoot"><a class="btn sm ghost" href="${GB_SRC}" target="_blank" rel="noopener" data-notr>${L('Open in a new tab', 'باز کردن در زبانه‌ی جدید')} ↗</a><button class="btn sm" data-gbclose data-notr>${L('Close', 'بستن')}</button></div>`);
  m.classList.add('conm', 'gbm');
  const st = $('[data-gbst]', m), hint = $('[data-gbhint]', m), fr = $('.gbframe', m);
  let loaded = false, wasOut = false, done = false, timer = 0;
  const close = () => { clearTimeout(timer); m.remove(); igRender(); };
  $('[data-gbclose]', m).onclick = close;
  $('.mclose', m).onclick = close;
  const set = (cls, txt) => { st.className = 'gbst ' + cls; st.textContent = txt; };
  fr.onload = () => { loaded = true; poll(); };
  const exitTxt = (d) => L(`It goes out through ${d.exit ? d.exit.split(':')[0] : 'the panel host'} (Germany, the panel host's own IP) — the only exit this account ever uses.`,
    `از ${d.exit ? d.exit.split(':')[0] : 'سرور پنل'} (آلمان، IP خود سرور پنل) بیرون می‌رود — تنها خروجی این حساب.`);
  async function poll() {
    if (!m.isConnected || done) return;
    let d;
    try { d = await api('/igproxy/gaccount?fresh=1'); } catch (e) { d = { err: String(e.message || e) }; }
    if (!m.isConnected) return;
    if (d.err && !d.state) {
      set('bad', L('Test browser not answering', 'مرورگر تست جواب نمی‌دهد'));
      hint.textContent = d.err;
    } else if (!loaded) {
      set('wait', L('Connecting…', 'در حال اتصال…'));
    } else if (d.state === 'out') {
      wasOut = true;
      set('bad', L('Signed out — sign in below', 'خارج شده — پایین وارد شوید'));
      hint.textContent = L('Reload Gemini in the browser below (an old tab can still show the name) and sign in to the Google account yourself — password and 2-step code are typed by you only. ', 'در مرورگر پایین Gemini را دوباره بارگذاری کنید (زبانه‌ی قدیمی ممکن است هنوز نام حساب را نشان دهد) و خودتان وارد حساب Google شوید — رمز و کد دومرحله‌ای را فقط خودتان وارد کنید. ')
        + exitTxt(d) + (d.cause ? ' ' + L('Why it signed out: ', 'علت خروج: ') + d.cause : '');
    } else if (d.state === 'in') {
      set('ok', L('Signed in ✓', 'وارد شده ✓'));
      hint.textContent = exitTxt(d);
      if (wasOut) {
        done = true;
        set('ok', L('Signed in ✓ — done', 'وارد شد ✓ — تمام'));
        hint.textContent = L('The account is signed in. This window closes in 5 seconds.', 'حساب وارد شد. این پنجره تا ۵ ثانیه دیگر بسته می‌شود.');
        timer = setTimeout(close, 5000);
        return;
      }
    } else set('wait', L('Checking…', 'در حال بررسی…'));
    timer = setTimeout(poll, 4000);
  }
  poll();
}

// ---- servers
function igServers(box) {
  const d = IG.data;
  if (!d) { box.innerHTML = '<div class="grid cards">' + '<div class="skel" style="height:150px"></div>'.repeat(4) + '</div>'; return; }
  const L = igList(), ok = L.filter(s => igCardState(s) === 'OK').length, conn = L.reduce((a, s) => a + (+s.info.caught || 0), 0);
  const bad = L.filter(s => !['OK', 'CHECKING'].includes(igCardState(s))).length, old = L.filter(s => ['UPDATE', 'NOAGENT'].includes(s.info.state) || s.info.outdated === '1').length;
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
  const nbad = L.filter(s => igCardState(s) !== 'OK').length;
  box.insertAdjacentHTML('beforeend', `<div class="filters"><button class="fchip" data-f="all">All <b>${L.length}</b></button><button class="fchip" data-f="bad">Needs attention <b>${nbad}</b></button>
    <input class="inp search" id="igq" placeholder="Search name or IP…" value="${esc(IG.q)}"><span class="faint" style="font-size:12px">updated ${new Date(d.t * 1000).toLocaleTimeString()}</span></div><div class="grid cards" id="igcards"></div>`);
  $$('[data-f]', box).forEach(b => { b.classList.toggle('on', b.dataset.f === IG.filter); b.onclick = () => { IG.filter = b.dataset.f; igRender(); }; });
  $('#igq', box).oninput = (e) => { IG.q = e.target.value; igCards(); };
  igCards();
}
function igCards() {
  const q = IG.q.trim().toLowerCase();
  const L = igList().filter(s => (IG.filter !== 'bad' || igCardState(s) !== 'OK') && (!q || (s.name + ' ' + s.host).toLowerCase().includes(q)));
  const box = $('#igcards'); if (!box) return;
  box.innerHTML = L.length ? L.map(igCard).join('') : '<div class="empty card"><div class="big">🔍</div>No server matches</div>';
  // the cards open like buttons: a click, or Enter / Space on the keyboard
  $$('.scard', box).forEach(c => {
    c.tabIndex = 0; c.setAttribute('role', 'button');
    c.onclick = (e) => { if (e.target.closest('details')) return; IG.cur = IG.data.servers.find(x => x.id === c.dataset.id); IG.tab = 'routes'; igRender(); scrollTo(0, 0); };
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
// ---- one plain line per service: "Instagram ✓ Germany via WARP" / "⚠ fixed automatically: …".
// Built from the agent's info and the panel's automatic repair (igauto.go); the words are
// English / Persian here (L) because they are put together from pieces.
const IG_NOMUSIC = ['IR', 'CN', 'KP', 'SY', 'CU'];
const IG_GBAD = ['ir', 'ru', 'cn', 'by', 'cu', 'sy', 'kp'];
function igCCName(cc) {
  cc = String(cc || '').toUpperCase(); if (!/^[A-Z]{2}$/.test(cc)) return cc;
  try { return new Intl.DisplayNames([window.tpLang === 'fa' ? 'fa' : 'en'], { type: 'region' }).of(cc) || cc; } catch (e) { return cc; }
}
// Google's country domain -> a country code where it is one (co.uk -> GB, com.tr -> TR, de -> DE)
const igDomCC = (d) => { d = String(d || '').toLowerCase(); const m = /^(?:co|com)\.([a-z]{2})$/.exec(d); return m ? (m[1] === 'uk' ? 'GB' : m[1].toUpperCase()) : /^[a-z]{2}$/.test(d) ? d.toUpperCase() : ''; };
// the exit in plain words, both languages
function igExitWord(v, i) {
  v = v || '';
  if (v === 'direct') return L("the server's own IP", 'IP خود سرور');
  if (v === 'ipv6') return L("the server's own IPv6", 'IPv6 خود سرور');
  if (v === 'warp6') return 'WARP IPv6';
  if (v === 'warp') return 'WARP';
  if (v === 'proxy') return L('proxies', 'پراکسی‌ها');
  if (/^proxy\d+$/.test(v)) { const r = igRelayOf(i, v); return L('proxy ', 'پراکسی ') + v.slice(5) + (r ? ' · ' + r : ''); }
  return v || '—';
}
// the repair's reason (igauto.go, English) in the page's language
function igWhyWord(w) {
  w = String(w || '');
  if (w === 'no WARP on the server') return L('no WARP on the server', 'سرور WARP ندارد');
  if (w === 'no answer') return L('no answer', 'بی‌پاسخ');
  const m = /^Instagram sees ([A-Z]{2})$/.exec(w); if (m) return L('Instagram saw ', 'Instagram دید: ') + igCCName(m[1]);
  return w;
}
// [level, html] for one service: level ok | warn | bad
function igLine(s, g) {
  const i = s.info || {}, au = s.auto || {}, route = i[g.toLowerCase()] || '';
  const missing = /^warp/.test(route) && i.warps === '0';
  const eff = missing ? (+i.proxies ? 'proxy' : g === 'YTM' ? 'ipv6' : 'direct') : route;
  const name = g === 'IG' ? 'Instagram' : g === 'GOOGLE' ? 'Google · Gemini' : 'YouTube Music';
  const pin = g === 'IG' ? au.ig && au.ig.pin : au.pins && au.pins[g];
  const off = g === 'IG' && au.ig && au.ig.off;
  const via = (v) => `<span class="igl-via">${L('via', 'از')} <b>${esc(igExitWord(v, i))}</b></span>`;
  const where = (cc) => cc ? `<b class="igl-cc">${esc(igCCName(cc))}</b> ` : '';
  const tags = (pin ? `<span class="chip" title="${esc(L('pinned by hand: while it is broken the panel uses another exit, then comes back', 'به‌دست سنجاق شده: اگر خراب شود پنل موقتاً خروجی دیگری می‌گذارد و بعد برمی‌گردد'))}">📌 ${esc(igExitWord(pin, i))}</span>` : '')
    + (off ? `<span class="chip">${L('auto off', 'خودکار خاموش')}</span>` : '');
  let lvl = 'ok', mark = '✓', body = '';
  if (g === 'IG') {
    const cc = i.igcc && i.igcc !== '-' ? i.igcc : '', cur = au.ig && au.ig.cur;
    if (i.igp === 'FAIL') { lvl = 'bad'; mark = '✗'; body = `${L("doesn't open", 'باز نمی‌شود')} ${via(eff)}`; }
    else if (IG_NOMUSIC.includes(cc)) { lvl = 'bad'; mark = '✗'; body = `${where(cc)}${L('— no music', '— بدون موسیقی')} ${via(eff)}${missing ? ` <span class="igl-why">${L('(WARP missing)', '(WARP نیست)')}</span>` : ''}`; }
    else if (cur) { lvl = 'warn'; mark = '⚠'; body = `${L('fixed automatically:', 'خودکار درست شد:')} <span class="igl-why">${esc(igWhyWord(au.ig.why))} ${L('→', '←')} </span><b>${esc(igExitWord(cur, i))}</b>${cc ? ` · ${where(cc)}` : ''}`; }
    else if (missing) { lvl = 'warn'; mark = '⚠'; body = `${where(cc)}${L('WARP missing →', 'WARP نیست ←')} <b>${esc(igExitWord(eff, i))}</b>`; }
    else body = `${where(cc)}${via(route)}`;
  } else if (g === 'GOOGLE') {
    const d = i.gdom && i.gdom !== '-' ? i.gdom : '', cc = igDomCC(d);
    const shown = cc ? where(cc) : d ? `<b class="igl-cc">google.${esc(d)}</b> ` : '';
    if (i.gem === 'FAIL') { lvl = 'bad'; mark = '✗'; body = `${L("Gemini doesn't open", 'Gemini باز نمی‌شود')} ${via(eff)}`; }
    else if (IG_GBAD.includes(d)) { lvl = 'bad'; mark = '✗'; body = `${shown}${L('— Gemini is not offered there', '— Gemini آنجا ارائه نمی‌شود')} ${via(eff)}`; }
    else if (missing || (/^warp/.test(route) && i.gcc === 'PROXY')) { lvl = 'warn'; mark = '⚠'; body = `${shown}${L('WARP missing →', 'WARP نیست ←')} <b>${esc(igExitWord(+i.proxies ? 'proxy' : 'direct', i))}</b>`; }
    else body = `${shown}${via(route)}`;
  } else {
    if (missing) { lvl = 'warn'; mark = '⚠'; body = `${L('WARP missing →', 'WARP نیست ←')} <b>${esc(igExitWord(eff, i))}</b>`; }
    else body = via(route);
  }
  return [lvl, `<div class="igl ${lvl}"><span class="igl-m">${mark}</span><span class="igl-n">${name}</span><span class="igl-b">${body}</span>${tags}</div>`];
}
const igSvcLines = (s) => ['IG', 'GOOGLE', 'YTM'].map(g => igLine(s, g));
// the card's pill: a bad or patched service line wins over a state that only says the router runs
function igCardState(s) {
  const i = s.info || {};
  if (!i.ig || igBad(i.state) || i.state === 'CHECKING') return i.state;
  const ls = igSvcLines(s);
  if (ls.some(([l]) => l === 'bad')) return ['OK', 'NOWARP', 'UPDATE'].includes(i.state) ? 'IGIR' : i.state;
  if (ls.some(([l]) => l === 'warn')) return s.auto && s.auto.ig && s.auto.ig.cur ? 'FIXED' : ['OK', 'UPDATE'].includes(i.state) ? 'NOWARP' : i.state;
  return i.state;
}
function igCard(s) {
  const i = s.info, st = igCardState(s);
  const n = igWarpNeed(i, s);
  const det = i.ig ? `<details class="igc-more"><summary>${L('Details', 'جزئیات')}</summary><div class="sfoot" data-notr><span>🔗 <b>${+i.caught || 0}</b> ${L('connections', 'اتصال')}</span><span>${L('proxies', 'پراکسی')} <b>${+i.proxies || 0}</b></span><span>WARP <b>${+i.warps || 0}</b>${n ? `<span class="faint"> / ${n.total}</span>` : ''}</span><span class="grow"></span><span>Gemini ${igChk(i.gem)}</span><span>IG ${igChk(i.igp)}</span>${igAccBroken(i) ? `<span class="chip bad">${L('music check off', 'تست موسیقی خاموش')}</span>` : ''}${i.outdated === '1' ? `<span class="chip">${L('old agent', 'agent قدیمی')}</span>` : ''}</div></details>` : '';
  return `<div class="card scard${igBad(st) ? ' bad' : ''}" data-id="${esc(s.id)}" style="cursor:pointer"><div class="sh"><div class="sname"><div><h3>${s.country ? flag(s.country) + ' ' : ''}${nm(s.name)} ${igOwner(s)}</h3><small class="mono">${esc(s.host)}</small></div></div>${igPill(st)}</div>
    ${i.ig ? `<div class="igls" data-notr>${igSvcLines(s).map(x => x[1]).join('')}</div>${det}`
    : i.state === 'CHECKING' ? '<div class="skel" style="height:64px;margin-top:10px"></div>' : `<div class="mcrit" style="margin:10px 0 0">${esc(i.err || (IGST[i.state] || [])[0] || '')}</div>`}</div>`;
}
// the shared Instagram test account: igaccst = working | untested | broken:<why> (Instagram logged it out)
const igAccBroken = (i) => /^broken/.test(i.igaccst || '');
const igAccWhy = (i) => (i.igaccst || '').replace(/^broken:?/, '') || 'logged out';
// WARPs needed for the 24 h peak: one WARP keeps its speed up to ~2500 connections / 5 min, +1 spare (3-10), + Google's own
const igWarpNeed = (i, s) => { const w = s && s.auto && s.auto.warp;
  if (w && w.at) return { p: +i.wpeak || 0, ig: w.carry + w.spare, g: w.g, total: w.need, have: w.have, used: w.used, off: w.off };
  if (i.wpeak === undefined || i.wpeak === '-' || i.wpeak === '') return null; const p = +i.wpeak || 0, g = (i.gw || '').split(',').filter(Boolean).length;
  const ig = Math.min(10, Math.max(3, Math.ceil(p / 2500) + 1)); return { p, ig, g, total: ig + g, have: +i.warps || 0, used: true }; };
const faNum = (n) => String(n).replace(/\d/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]);
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
  $$('[data-auto]', w).forEach(b => b.onclick = () => igAutoSet(s, ...b.dataset.auto.split('|')));
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
  if (IG_NOMUSIC.includes(i.igcc)) add('bad', L(`Instagram places this server's users in ${igCCName(i.igcc)} (no music). The panel moves Instagram to a working exit by itself within minutes; if none works it tells the admin chat — then add a working proxy.`, `Instagram کاربران این سرور را در ${igCCName(i.igcc)} می‌بیند (بدون موسیقی). پنل خودش ظرف چند دقیقه Instagram را به خروجی سالم می‌برد؛ اگر هیچ‌کدام کار نکند در چت ادمین خبر می‌دهد — آن‌وقت یک پراکسی سالم اضافه کنید.`), L('Proxies', 'پراکسی‌ها'), 'proxies');
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
  const cs = igCardState(s), lbad = IGST[cs] && IGST[cs][1] === 'bad' && !nbad ? 1 : 0;
  const lvl = i.state === 'CHECKING' ? 'acc' : nbad || lbad ? 'bad' : P.length || cs === 'FIXED' || cs === 'NOWARP' ? 'warn' : 'on';
  const head = nbad ? (nbad === 1 ? '1 problem' : nbad + ' problems') : lbad ? (IGST[cs] || [''])[0] : i.paused === 'YES' ? 'Paused' : cs === 'FIXED' ? 'Works · fixed automatically' : P.length || cs === 'NOWARP' ? 'Works · needs a look' : 'Everything works';
  const conn = +i.caught || 0, gu = igGusers(i), gsum = gu.reduce((a, x) => a + x[1], 0);
  const probs = P.length ? `<div class="igst-probs">${P.map(p => `<div class="igst-p ${p.lvl}"><span>${esc(p.text)}</span><button class="btn sm" ${p.act ? `data-igdo="${p.act}"` : `data-igto="${p.to}"`}>${esc(p.btn)}</button></div>`).join('')}</div>` : '';
  const yn = (ok, on, off) => ok ? `<b class="ok">${on}</b>` : `<b class="bad">${off}</b>`;
  const row = (k, v, tip) => `<div class="igst-r"${tip ? ` title="${esc(tip)}"` : ''}><span>${k}</span><span class="igst-rv">${v}</span></div>`;
  const n = igWarpNeed(i, s);
  const det = [
    row('Router', yn(i.router === 'active', 'running', esc(i.router || 'stopped')), 'igproxy-xray: the router that sends each service its way'),
    row('Traffic sent to the router', yn(i.redirect === 'ON', 'on', 'off')),
    row('Wide catch', i.wide === 'ON' ? '<b>on</b><small>all web traffic is routed by domain</small>' : '<b>off</b><small>only the listed services</small>'),
    row('WARP mode', i.mode === 'BALANCE' ? `<b>balance</b>${igSet(i.pool) ? `<small>${esc(String(i.pool).replace('/', ' of '))} in use</small>` : ''}` : `<b>failover</b>${igSet(i.active) ? `<small data-notr>WARP ${esc(i.active)}</small>` : ''}`),
    row('WARP accounts', `<b data-notr>${+i.warps || 0}</b>${n ? `<small data-notr>${n.off ? L('by hand', 'دستی') : n.used ? L(`automatic · ${n.total} needed`, `خودکار · ${faNum(n.total)} لازم`) : L('automatic · none needed', 'خودکار · لازم نیست')}</small>` : ''}`),
    row('Proxies', `<b data-notr>${+i.proxies || 0}</b>`),
    i.guard !== undefined ? row('WARP guard', i.guard === 'ON' ? '<b class="ok">on</b>' : i.guard === 'DOWN' ? '<b class="bad">not running</b>' : '<b>off</b>', 'replaces a WARP that stops working') : '',
    row('x-ui panel', i.panel === 'OK' ? '<b class="ok">passes Google</b>' : igSet(i.panel) ? `<b class="bad" data-notr>${esc(i.panel)}</b>` : '<b>no x-ui panel</b>', 'does the x-ui panel on this server pass Google to igproxy untouched'),
    row('Gemini connections (10 min)', gu.length ? gu.map(([k, c]) => `<b class="igst-gu"><span${/^proxy/.test(k) ? ' data-notr' : ''}>${esc(k === 'direct' ? "Server's own IP" : k === 'ipv6' ? "Server's own IPv6" : /^warp\d+$/.test(k) ? 'WARP ' + k.slice(4) : igViaW(k, i))}</span> <span data-notr>${c}</span></b>`).join('') : '<b>none</b>'),
    row('Agent', `<b class="mono">${esc(i.sum || '—')}</b>${i.outdated === '1' ? '<small class="bad">old</small>' : '<small>current</small>'}`),
  ].join('');
  return `<div class="card igst ${lvl}"><div class="igst-top"><span class="igst-dot"></span><div class="igst-t"><b>${esc(head)}</b>
      <small><b data-notr>${conn}</b> connections now${gsum ? ` · <b data-notr>${gsum}</b> to Gemini in 10 min` : ''}</small></div>${igOwner(s)}</div>
    ${probs}<div class="igls igls-d" data-notr>${['IG', 'GOOGLE', 'YTM'].map(g => igLine(s, g)[1].replace(/<\/div>$/, igAutoMenu(s, g) + '</div>')).join('')}</div>${igAutoHist(s)}
    <details class="igst-more"><summary>Details</summary><div class="igst-det">${det}</div></details></div>`;
}
// the small menu of one service: Auto (default) or one exit pinned; Instagram's repair can be turned off
function igAutoMenu(s, g) {
  const i = s.info || {}, au = s.auto || {}, a = g === 'IG' ? au.ig || {} : { pin: au.pins && au.pins[g] };
  const auto = !a.pin && !a.off, cur = i[g.toLowerCase()] || '';
  const o = ['proxy']; for (let k = 1; k <= (+i.proxies || 0); k++) o.push('proxy' + k); o.push('warp', 'warp6', 'ipv6', 'direct');
  const items = [{ label: (auto ? '✓ ' : '') + L('Auto (recommended)', 'خودکار (پیشنهادی)'), attr: `data-auto="${g}|auto"` }]
    .concat(o.map(v => ({ label: (a.pin === v ? '📌 ' : '') + L('Only ', 'فقط ') + esc(igExitWord(v, i)) + (v === cur && !a.pin ? L(' · now', ' · الان') : ''), attr: `data-auto="${g}|pin|${v}"` })));
  if (g === 'IG') items.push({ label: (a.off ? '✓ ' : '') + L("Don't fix automatically", 'خودکار درست نکن'), attr: 'data-auto="IG|off"' });
  return `<span class="igl-menu">${moreMenu(items)}</span>`;
}
async function igAutoSet(s, svc, mode, via) {
  const word = mode === 'pin' ? L(`Send ${svc === 'IG' ? 'Instagram' : svc === 'GOOGLE' ? 'Google' : 'YouTube Music'} only through ${igExitWord(via, s.info)}? If it breaks, the panel uses another exit until it works again.`,
    `${svc === 'IG' ? 'Instagram' : svc === 'GOOGLE' ? 'Google' : 'YouTube Music'} فقط از ${igExitWord(via, s.info)} برود؟ اگر خراب شود پنل تا درست شدنش از خروجی دیگری استفاده می‌کند.`) : '';
  if (word && !confirm(word)) return;
  try {
    s.auto = Object.assign(s.auto || {}, await api('/igproxy/auto', { ID: s.id, Svc: svc, Mode: mode, Via: via || '' }));
    toast(mode === 'auto' ? L('Auto: the panel keeps it working', 'خودکار: پنل خودش درستش نگه می‌دارد') : mode === 'off' ? L('Automatic repair off', 'تعمیر خودکار خاموش شد') : L('Pinned', 'سنجاق شد'));
    igRefreshAfter({ srv: s.id });
  } catch (e) { toast(e.message); }
}
// the last automatic fixes of this server
function igAutoHist(s) {
  const ev = (s.auto && s.auto.last) || [];
  if (!ev.length) return '';
  const ic = { fix: '🔧', back: '↩', fail: '⚠', info: '·' };
  return `<details class="igst-more igah"><summary>${L('Automatic fixes', 'تعمیرهای خودکار')} <span class="faint">${ev.length}</span></summary><div class="igah-l" data-notr>${ev.map(e => `<div class="igah-r ${e.kind}"><span class="faint mono">${new Date(e.t * 1000).toLocaleString(window.tpLang === 'fa' ? 'fa-IR' : undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span><span>${ic[e.kind] || '·'} ${esc(e.svc === 'IG' ? 'Instagram' : e.svc)}: ${esc(e.msg)}</span></div>`).join('')}</div></details>`;
}
// ---- Routes tab: every service as a small chip in its group (AI, social, messaging, video & music,
// developer, adult, my sites). The chip says its exit (Auto · WARP …) and its last check (✓ + the
// country the service sees, or ⚠); a tap opens its exit menu. Changes go at once (the agent swaps
// its routing rules live: no router restart). The words are in both languages here (L).
const IGSVC = { // key: [name, monogram, colour]
  OPENAI: ['ChatGPT', 'AI', '#10a37f'], GOOGLE: ['Gemini · Google', 'G', '#4285f4'], CLAUDE: ['Claude', 'C', '#d97757'], COPILOT: ['Copilot · Bing', 'Co', '#0f6cbd'],
  PERPLEX: ['Perplexity', 'P', '#1f8a8a'], GROK: ['Grok', 'Gk', '#3a3a3f'], AICODE: ['Cursor · AI tools', '&lt;/&gt;', '#6d5bd0'],
  IG: ['Instagram', 'IG', '#d62976'], X: ['X · Twitter', 'X', '#2b2b30'], TIKTOK: ['TikTok', 'Tk', '#ee1d52'], SNAP: ['Snapchat', 'S', '#c9a800'],
  REDDIT: ['Reddit', 'R', '#ff4500'], LINKEDIN: ['LinkedIn', 'in', '#0a66c2'], PINTEREST: ['Pinterest', 'P', '#e60023'],
  TELEGRAM: ['Telegram', 'T', '#229ed9'], WHATSAPP: ['WhatsApp', 'W', '#1fa855'], DISCORD: ['Discord', 'D', '#5865f2'],
  YTM: ['YouTube Music', '♪', '#ff0033'], SPOTIFY: ['Spotify', 'S', '#1db954'], SCLOUD: ['SoundCloud', 'SC', '#ff5500'], NETFLIX: ['Netflix', 'N', '#e50914'],
  DISNEY: ['Disney+', 'D+', '#113ccf'], PRIME: ['Prime Video', 'PV', '#00a8e1'], TWITCH: ['Twitch', 'Tw', '#9146ff'], APPLE: ['Apple Music', '♫', '#fa2d48'], GAMES: ['Steam · games', 'St', '#1b2838'],
  DEV: ['GitHub · Docker · npm', '{ }', '#24292f'], ADULT: [null, '18', '#8a3b5c'], CUSTOM: [null, '★', '#5357f0'] };
const IGCATS = [['ai', 'AI', 'هوش مصنوعی', ['OPENAI', 'GOOGLE', 'CLAUDE', 'COPILOT', 'PERPLEX', 'GROK', 'AICODE']],
  ['social', 'Social', 'شبکه‌های اجتماعی', ['IG', 'X', 'TIKTOK', 'SNAP', 'REDDIT', 'LINKEDIN', 'PINTEREST']],
  ['msg', 'Messaging', 'پیام‌رسان‌ها', ['TELEGRAM', 'WHATSAPP', 'DISCORD']],
  ['media', 'Video, music & games', 'ویدیو، موسیقی و بازی', ['YTM', 'SPOTIFY', 'SCLOUD', 'NETFLIX', 'DISNEY', 'PRIME', 'TWITCH', 'APPLE', 'GAMES']],
  ['dev', 'Developers', 'برنامه‌نویسی', ['DEV']], ['adult', 'Adult', 'بزرگسالان', ['ADULT']], ['mine', 'My sites', 'سایت‌های من', ['CUSTOM']]];
const IGSV_GUARD = ['IG', 'GOOGLE', 'YTM']; // their own guards (igauto.go, the agent's Google / Gemini watch)
const igsvName = (g, i) => g === 'ADULT' ? L('Adult', 'بزرگسالان') : g === 'CUSTOM' ? L('My sites', 'سایت‌های من') + ` (${+((i || {}).ncustom) || 0})` : IGSVC[g][0];
const igsvHasAuto = (g) => g !== 'CUSTOM' && !!IGSVC[g];
// the exit word on the chip (short)
const igsvVia = (v) => { v = v || ''; if (v === 'proxy') return L('Proxy', 'پراکسی'); if (/^proxy\d+$/.test(v)) return L('Proxy ', 'پراکسی ') + v.slice(5); return { warp: 'WARP', warp6: 'WARP v6', ipv6: 'IPv6', direct: L('Direct', 'مستقیم') }[v] || v || '—'; };
// [mode, pin] of one service: auto | pin | manual | off
function igsvMode(s, g) {
  const au = s.auto || {}, sv = (au.svc || {})[g];
  if (g === 'IG') { const a = au.ig || {}; return a.off ? ['off', ''] : a.pin ? ['pin', a.pin] : ['auto', '']; }
  if (g === 'GOOGLE' || g === 'YTM') { const p = au.pins && au.pins[g]; return p ? ['pin', p] : ['auto', '']; }
  return sv ? [sv.mode, sv.pin || ''] : [IGWIDE.includes(g) && !['ADULT', 'SPOTIFY', 'SCLOUD', 'SNAP', 'CUSTOM'].includes(g) ? 'auto' : 'manual', ''];
}
// [class ok|bad|warn|'', short text, tooltip] of one service's last check
function igsvCheck(s, g) {
  const i = s.info || {}, sv = ((s.auto || {}).svc || {})[g];
  const seen = (cc) => L('seen from ', 'دیده‌شده از ') + igCCName(cc);
  if (g === 'IG' || g === 'GOOGLE') {
    if (i[g.toLowerCase()] === undefined) return ['', '·', ''];
    const [lvl] = igLine(s, g);
    let cc = '';
    if (g === 'IG' && igSet(i.igcc)) cc = i.igcc; else if (g === 'GOOGLE' && igSet(i.gdom)) cc = igDomCC(i.gdom) || '.' + i.gdom;
    return [lvl, (lvl === 'ok' ? '✓' : '⚠') + (cc ? ' ' + cc : ''), cc ? (cc.startsWith('.') ? 'google' + cc : seen(cc)) : ''];
  }
  if (g === 'CUSTOM' || g === 'ADULT' || !sv || !sv.ok) return ['', '·', L('not checked yet', 'هنوز بررسی نشده')];
  if (sv.ok === 'ok') return ['ok', '✓' + (sv.cc ? ' ' + sv.cc : ''), (sv.cc ? seen(sv.cc) + ' · ' : '') + L('opens on the users\' route', 'روی مسیر کاربران باز می‌شود')];
  return ['bad', '⚠', L(`doesn't open on the users' route (http ${sv.code})`, `روی مسیر کاربران باز نمی‌شود (http ${sv.code})`)];
}
function igsvChip(s, g) {
  const i = s.info || {}, v = i[g.toLowerCase()], [mode, pin] = igsvMode(s, g), [cc, ct, tip] = igsvCheck(s, g), [, mono, col] = IGSVC[g];
  const old = v === undefined; // the agent here doesn't know this service yet
  const sv = ((s.auto || {}).svc || {})[g] || {}, moved = (g === 'IG' ? (s.auto && s.auto.ig && s.auto.ig.cur) : sv.cur) || '';
  const pill = old ? L('needs update', 'نیاز به آپدیت') : (mode === 'auto' ? `${L('Auto', 'خودکار')} · ` : mode === 'pin' ? '📌 ' : '') + esc(igsvVia(v));
  const pc = old ? 'v-old' : mode === 'auto' ? 'v-auto' : igViaC(v);
  const items = old ? '' : igsvOpts(s, g).map(([k, t]) => {
    const on = k === 'auto' ? mode === 'auto' : k === 'off' ? mode === 'off' : mode !== 'auto' && mode !== 'off' && k === (pin || v);
    return `<button class="mi${on ? ' on' : ''}" data-sv="${g}" data-to="${esc(k)}">${on ? '✓ ' : ''}${t}</button>`;
  }).join('');
  return `<details class="more igsv${old ? ' old' : ''}" data-k="${g}">
    <summary class="igsv-c ${cc}" title="${esc(tip || '')}"><span class="igsv-ic" style="--bc:${col}" aria-hidden="true">${mono}</span>
      <span class="igsv-b"><span class="igsv-n" data-notr>${esc(igsvName(g, i))}</span><span class="igsv-r"><span class="igsv-p ${pc}" data-notr>${pill}</span>${moved ? `<span class="igsv-mv" title="${esc(L('its usual exit failed: Auto moved it for now', 'خروجی همیشگی‌اش خراب شد: خودکار موقتاً جابه‌جایش کرد'))}">↻</span>` : ''}<span class="igsv-s ${cc}" data-notr>${ct}</span></span></span></summary>
    ${old ? '' : `<div class="pop"><div class="igsv-h" data-notr>${esc(igsvName(g, i))}</div>${items}</div>`}</details>`;
}
// the exits one service can take on this server: [value, label]
function igsvOpts(s, g) {
  const i = s.info || {}, wide = IGWIDE.includes(g), o = [];
  if (igsvHasAuto(g)) o.push(['auto', L('Auto (recommended)', 'خودکار (پیشنهادی)')]);
  o.push(['warp', 'WARP' + (+i.warps ? '' : L(' — none on this server', ' — این سرور ندارد'))]);
  if (!wide) o.push(['warp6', 'WARP IPv6']);
  o.push(['proxy', L('Proxy (fastest)', 'پراکسی (سریع‌ترین)') + (+i.proxies ? '' : L(' — none on this server', ' — این سرور ندارد'))]);
  for (let k = 1; k <= (+i.proxies || 0); k++) { const r = igRelayOf(i, 'proxy' + k); o.push(['proxy' + k, L('Only proxy ', 'فقط پراکسی ') + k + (r ? ' · ' + esc(r) : '')]); }
  if (!wide) o.push(['ipv6', L("Server's IPv6", 'IPv6 سرور')]);
  o.push(['direct', L("Direct (server's own IP)", 'مستقیم (IP خود سرور)')]);
  if (g === 'IG') o.push(['off', L("Don't fix automatically", 'خودکار درست نکن')]);
  return o;
}
async function igsvSet(s, set) {
  if (set.IG === 'off') { delete set.IG; await igAutoSet(s, 'IG', 'off'); }
  if (!Object.keys(set).length) return;
  toast(L('Applying…', 'در حال اعمال…'));
  try {
    s.auto = Object.assign(s.auto || {}, await api('/igproxy/svc', { ID: s.id, Set: set }));
    toast(L('Done — applied without cutting users', 'انجام شد — بدون قطع کاربران اعمال شد'));
    igRefreshAfter({ srv: s.id });
  } catch (e) { toast(e.message); }
}
const IGSVQ = { q: '' };
function igsvDraw() {
  const s = IG.cur, i = s.info || {}, box = $('#igtab');
  const q = IGSVQ.q.trim().toLowerCase();
  const old = i.openai === undefined;
  const all = IGCATS.flatMap(c => c[3]), bad = all.filter(g => igsvCheck(s, g)[0] === 'bad').length;
  const bulk = (c) => `<details class="more igsv-bulk"><summary class="btn sm ghost" title="${esc(L('the whole group at once', 'همهٔ این گروه با هم'))}">${L('All', 'همه')} ▾</summary><div class="pop">
    ${[['auto', L('All → Auto', 'همه ← خودکار')], ['warp', L('All → WARP', 'همه ← WARP')], ['proxy', L('All → Proxy', 'همه ← پراکسی')], ['direct', L('All → Direct', 'همه ← مستقیم')]]
      .map(([k, t]) => `<button class="mi" data-bulk="${c[0]}" data-to="${k}">${t}</button>`).join('')}</div></details>`;
  box.innerHTML = `<div class="card pad igsvw">
    <div class="igsv-top"><input class="inp" id="igsvq" type="search" placeholder="${esc(L('Search services…', 'جستجوی سرویس…'))}" value="${esc(IGSVQ.q)}" autocomplete="off">
      <span class="igsv-sum">${all.length} ${L('services', 'سرویس')}${bad ? ` · <b class="bad">${bad} ⚠</b>` : ''}</span>
      <details class="igsv-help"><summary title="${esc(L('What the exits mean', 'معنی خروجی‌ها'))}" aria-label="?">ⓘ</summary><div class="igsv-tip">${L(
        '<b>Auto</b> — the panel picks a working exit and fixes it by itself. <b>WARP</b> — Cloudflare WARP. <b>Proxy</b> — the fastest working proxy. <b>IPv6</b> — the server\'s own IPv6. <b>Direct</b> — the server\'s own IP. ✓ = opens for users (with the country it is seen from), ⚠ = doesn\'t. Changes apply at once without cutting users.',
        '<b>خودکار</b> — پنل خروجی سالم را انتخاب و خودش درستش می‌کند. <b>WARP</b> — WARP کلادفلر. <b>پراکسی</b> — سریع‌ترین پراکسی سالم. <b>IPv6</b> — IPv6 خود سرور. <b>مستقیم</b> — IP خود سرور. ✓ = برای کاربران باز می‌شود (با کشوری که دیده می‌شود)، ⚠ = باز نمی‌شود. تغییرها فوری و بدون قطع کاربران اعمال می‌شوند.')}</div></details></div>
    ${old ? `<div class="igsv-old"><span>${L('This server\'s agent is older: ChatGPT, Claude, Telegram, Netflix and the other new services work after an update.', 'agent این سرور قدیمی است: ChatGPT، Claude، تلگرام، نتفلیکس و سرویس‌های جدید دیگر بعد از به‌روزرسانی کار می‌کنند.')}</span><button class="btn sm pri" data-igsvdep>${L('Update agent', 'به‌روزرسانی agent')}</button></div>` : ''}
    ${(() => { // groups of one chip (developers, adult, my sites) share one row
      const secs = IGCATS.map(c => [c, c[3].filter(g => !q || (igsvName(g, i) + ' ' + g + ' ' + c[1] + ' ' + c[2]).toLowerCase().includes(q))]).filter(x => x[1].length);
      const sec = ([c, keys]) => `<section class="igsv-cat"><div class="igsv-ch"><h4>${L(c[1], c[2])}</h4><span class="count">${keys.length}</span><span class="grow"></span>${keys.length > 1 && !old ? bulk(c) : ''}</div>
        <div class="igsv-g">${keys.map(g => igsvChip(s, g)).join('')}</div></section>`;
      let h = '', row = [];
      const flush = () => { if (row.length) h += row.length > 1 ? `<div class="igsv-row">${row.map(sec).join('')}</div>` : sec(row[0]); row = []; };
      secs.forEach(x => { if (x[1].length === 1) row.push(x); else { flush(); h += sec(x); } });
      flush();
      return h || `<p class="muted">${L('No service matches.', 'سرویسی پیدا نشد.')}</p>`;
    })()}
    <div class="igsv-foot"><button class="btn sm" id="igrd">${L('Route details', 'جزئیات مسیرها')}</button></div></div>`;
  const qi = $('#igsvq', box);
  qi.oninput = () => { IGSVQ.q = qi.value; const p = qi.selectionStart; igsvDraw(); const n = $('#igsvq'); n.focus(); try { n.setSelectionRange(p, p); } catch (e) { } };
  $$('[data-sv]', box).forEach(b => b.onclick = () => {
    const g = b.dataset.sv, to = b.dataset.to; b.closest('details').removeAttribute('open');
    const [mode, pin] = igsvMode(s, g);
    if ((to === 'auto' && mode === 'auto') || (to === 'off' && mode === 'off') || (to === (pin || i[g.toLowerCase()]) && mode !== 'auto' && mode !== 'off')) return;
    igsvSet(s, { [g]: to });
  });
  $$('[data-bulk]', box).forEach(b => b.onclick = () => {
    const c = IGCATS.find(x => x[0] === b.dataset.bulk), to = b.dataset.to; b.closest('details').removeAttribute('open');
    const set = {}; c[3].forEach(g => { if (i[g.toLowerCase()] !== undefined && (to !== 'auto' || igsvHasAuto(g))) set[g] = to; });
    const name = L(c[1], c[2]), word = { auto: L('Auto', 'خودکار'), warp: 'WARP', proxy: L('Proxy', 'پراکسی'), direct: L('Direct', 'مستقیم') }[to];
    if (!confirm(L(`All of "${name}" (${Object.keys(set).length} services) → ${word}?`, `همهٔ «${name}» (${Object.keys(set).length} سرویس) ← ${word}؟`))) return;
    igsvSet(s, set);
  });
  $$('[data-igsvdep]', box).forEach(b => b.onclick = () => igAct(igS({ action: 'deploy' }), `Install / update the agent on ${s.name}? A few seconds without routing; settings and WARPs are kept.`));
  $('#igrd', box).onclick = () => igAct(igS({ action: 'routes' }), null, { refresh: false });
}
// ---- My sites: one card per site (its own domain + every subdomain, and the other domains it
// loads), delete = all of them; adding finds those other domains first (igsites.go).
const IGSITE = { find: null, busy: false, seq: 0 };
const igsRoute = (r, i) => r ? igsvVia(r) : L('My sites route', 'مسیر سایت‌های من') + ' (' + igsvVia(i.custom) + ')';
const igsSub = (d) => `<span class="mono" dir="ltr" data-notr>${esc(d)}</span> <span class="faint">${L('+ all subdomains', '+ همه‌ی زیردامنه‌ها')}</span>`;
function igSitesTab() {
  const s = IG.cur, i = s.info || {};
  const nprox = +i.proxies || 0;
  $('#igtab').innerHTML = `<div class="card pad sec igs-add"><h3>${L('Add a site', 'افزودن سایت')}</h3>
     <p class="muted igs-p">${L('Type the site or paste any link of it: the whole site is routed — its domain, every subdomain, and the other domains it loads (CDN, API, images, login).', 'نام سایت یا هر لینکی از آن را بنویسید: کل سایت مسیر می‌گیرد — دامنه‌اش، همه‌ی زیردامنه‌ها، و دامنه‌های دیگری که بارگذاری می‌کند (CDN، API، تصاویر، ورود).')}</p>
     <div class="igs-row"><input id="igcs" class="inp mono" dir="ltr" placeholder="example.com / https://…" autocomplete="off" spellcheck="false"><button class="btn" id="igcf">${L('Find', 'پیدا کن')}</button></div>
     <div id="igsfind"></div>
     <div class="ff igs-opt"><label class="f">${L('Route', 'مسیر')}<select id="igcr" class="inp"><option value="">${esc(igsRoute('', i))}</option><option value="warp">WARP</option><option value="proxy">${L('Proxy (fastest)', 'پراکسی (سریع‌ترین)')}</option>
       ${Array.from({ length: nprox }, (_, k) => `<option value="proxy${k + 1}">${L('Only proxy ', 'فقط پراکسی ')}${k + 1}</option>`).join('')}<option value="direct">${L('Direct', 'مستقیم')}</option></select></label>
     <label class="f row"><input type="checkbox" id="igcall"> ${L('On every server in view', 'روی همه سرورهای نمایش‌داده‌شده')}</label></div>
     <div class="actions" style="margin-top:12px"><button class="btn pri" id="igcadd" disabled>${L('Add', 'افزودن')}</button></div></div>
   <div class="card pad sec"><h3>${L('My sites', 'سایت‌های من')} <span id="igsn" class="count"></span></h3><div id="igsl"><div class="skel" style="height:60px"></div></div></div>`;
  const inp = $('#igcs'), go = $('#igcf');
  const find = async () => {
    const v = inp.value.trim(); if (!v) return;
    const seq = ++IGSITE.seq;
    go.disabled = true; go.textContent = L('Looking…', 'در حال بررسی…');
    $('#igsfind').innerHTML = `<div class="skel" style="height:44px;margin-top:10px"></div>`;
    try { const f = await api('/igproxy/sites/find', { Site: v }); if (seq === IGSITE.seq) { IGSITE.find = f; igsFindDraw(); } }
    catch (e) { if (seq === IGSITE.seq) { IGSITE.find = null; $('#igsfind').innerHTML = `<div class="mwarn igs-w">${esc(e.message)}</div>`; $('#igcadd').disabled = true; } }
    go.disabled = false; go.textContent = L('Find', 'پیدا کن');
  };
  go.onclick = find;
  inp.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); find(); } };
  inp.oninput = () => { if (IGSITE.find) { IGSITE.find = null; $('#igsfind').innerHTML = ''; $('#igcadd').disabled = true; } };
  $('#igcadd').onclick = async () => {
    const f = IGSITE.find; if (!f) return;
    const doms = $$('#igsfind input[data-d]:checked').map(x => x.dataset.d), all = $('#igcall').checked;
    const b = $('#igcadd'); b.disabled = true; b.textContent = L('Adding…', 'در حال افزودن…');
    try {
      const r = await api('/igproxy/sites/add', { Srv: all ? 'all' : s.id, View: igView(), Site: f.site, Route: $('#igcr').value, Domains: doms });
      const bad = (r.results || []).filter(x => !x.ok);
      toast(bad.length ? bad.map(x => x.name + ': ' + x.msg).join(' · ') : L(`Added: ${f.site} + ${doms.length} related domains`, `افزوده شد: ${f.site} + ${doms.length} دامنه‌ی مرتبط`));
      inp.value = ''; IGSITE.find = null; $('#igsfind').innerHTML = '';
      igSitesLoad();
    } catch (e) { toast(e.message); }
    b.textContent = L('Add', 'افزودن'); b.disabled = !IGSITE.find;
  };
  if (IGSITE.find) igsFindDraw();
  igSitesLoad();
}
function igsFindDraw() {
  const f = IGSITE.find, box = $('#igsfind'); if (!box || !f) return;
  const rel = f.related || [];
  box.innerHTML = `<div class="igs-found"><div class="igs-main">✓ ${igsSub(f.site)}</div>
    ${f.google ? `<div class="mwarn igs-w">${L('This is a Google domain: Google has its own route (Routes tab → Gemini · Google). Adding it here moves it ahead of that.', 'این دامنه‌ی Google است: Google مسیر خودش را دارد (تب مسیرها ← Gemini · Google). اضافه‌کردن اینجا جلوتر از آن می‌نشیند.')}</div>` : ''}
    ${f.err ? `<div class="faint igs-note">${L("The panel couldn't open the site to look for its other domains — only its own domain is added.", 'پنل نتوانست سایت را برای پیداکردن دامنه‌های دیگرش باز کند — فقط دامنه‌ی خودش اضافه می‌شود.')}</div>` : ''}
    ${rel.length ? `<div class="igs-rh">${L('It also loads these — keep them on the same route so the site works fully:', 'این‌ها را هم بارگذاری می‌کند — همین مسیر بمانند تا سایت کامل کار کند:')}</div>
      <div class="igs-rel">${rel.map(r => `<label class="igs-ck${r.sure ? '' : ' maybe'}" title="${esc(r.hit || '')}"><input type="checkbox" data-d="${esc(r.d)}"${r.sure ? ' checked' : ''}> ${igsSub(r.d)}${r.sure ? '' : ` <span class="chip">${L('maybe', 'شاید')}</span>`}</label>`).join('')}</div>`
      : f.err ? '' : `<div class="faint igs-note">${L('No other domain found: the site loads everything from its own domain.', 'دامنه‌ی دیگری پیدا نشد: سایت همه‌چیز را از دامنه‌ی خودش بارگذاری می‌کند.')}</div>`}
    ${f.left ? `<div class="faint igs-note">${L(`${f.left} shared libraries / analytics / Google domains left out (routing them would move other sites too).`, `${f.left} کتابخانه‌ی مشترک / آنالیتیکس / دامنه‌ی Google کنار گذاشته شد (مسیر دادن به آن‌ها سایت‌های دیگر را هم جابه‌جا می‌کند).`)}</div>` : ''}</div>`;
  $('#igcadd').disabled = false;
}
async function igSitesLoad() {
  const s = IG.cur, i = s.info || {}, box = $('#igsl'); if (!box) return;
  let r;
  try { r = await api('/igproxy/sites?id=' + encodeURIComponent(s.id)); } catch (e) { box.innerHTML = `<p class="muted">${esc(e.message)}</p>`; return; }
  if (!$('#igsl') || IG.cur !== s) return;
  const sites = r.sites || [];
  $('#igsn').textContent = sites.length;
  if (!sites.length) { box.innerHTML = `<p class="muted">${L('No site yet.', 'هنوز سایتی نیست.')}</p>`; return; }
  box.innerHTML = `<div class="igs-list">${sites.map((c, n) => {
    const warn = c.doms.some(d => (d.also || []).length || d.covered);
    return `<details class="igs-card"><summary><span class="igsv-ic" style="--bc:#5357f0" aria-hidden="true">${esc((c.site[0] || '?').toUpperCase())}</span>
      <span class="igs-b"><span class="igs-n" data-notr><bdi>${esc(c.site)}</bdi></span><span class="faint igs-s">${L('+ all subdomains', '+ همه‌ی زیردامنه‌ها')}${c.doms.length > 1 ? ` · ${c.doms.length} ${L('domains', 'دامنه')}` : ''}${warn ? ' · <b class="igs-ov">⚠ ' + L('overlap', 'هم‌پوشانی') + '</b>' : ''}</span></span>
      <span class="igsv-p igs-rp ${c.route ? igViaC(c.route) : 'v-auto'}" data-notr title="${esc(igsRoute(c.route, i))}">${esc(c.route ? igsvVia(c.route) : L('Default', 'پیش‌فرض') + ': ' + igsvVia(i.custom))}</span>
      <button class="btn sm ghost danger igs-del" data-del="${n}" title="${esc(L('Delete the site and all its domains', 'حذف سایت با همه‌ی دامنه‌هایش'))}">✕</button></summary>
      <div class="igs-doms">${c.doms.map(d => `<div class="igs-d"><span>${d.rule.startsWith('domain:') ? igsSub(d.d) : `<span class="mono" dir="ltr" data-notr>${esc(d.rule)}</span>`}</span>
        ${d.route !== c.route ? `<span class="igsv-p ${d.route ? igViaC(d.route) : 'v-auto'}" data-notr>${esc(igsRoute(d.route, i))}</span>` : ''}
        ${(d.also || []).length ? `<span class="chip warn" title="${esc(L('My sites wins over the service\'s route for this domain', 'برای این دامنه، سایت‌های من بر مسیر سرویس مقدم است'))}">${L('also in', 'در لیست')} ${esc(d.also.map(x => (IGSVC[x] && IGSVC[x][0]) || igsvName(x, i)).join(', '))}${L('', ' هم هست')}</span>` : ''}
        ${d.covered ? `<span class="chip" title="${esc(L('already covered by that domain', 'آن دامنه همین را پوشش می‌دهد'))}">${L('inside', 'داخل')} <span dir="ltr" data-notr>${esc(d.covered)}</span></span>` : ''}</div>`).join('')}</div></details>`;
  }).join('')}</div>`;
  $$('[data-del]', box).forEach(b => b.onclick = async (e) => {
    e.preventDefault(); e.stopPropagation();
    const c = sites[+b.dataset.del];
    if (!confirm(L(`Delete ${c.site} and all its ${c.doms.length} domain(s)? They go back to their normal route at once.`, `${c.site} با همه‌ی ${c.doms.length} دامنه‌اش حذف شود؟ فوراً به مسیر عادی برمی‌گردند.`))) return;
    try { await api('/igproxy/sites/del', { ID: s.id, Site: c.site }); toast(L('Deleted', 'حذف شد')); igSitesLoad(); igRefreshAfter({ srv: s.id }); } catch (er) { toast(er.message); }
  });
}
const igSecret = 'type="text" class="inp mono secret" autocomplete="off" data-lpignore="true" data-1p-ignore spellcheck="false"';
const IGTAB = {
  routes() { igsvDraw(); },
  proxies() { igpxTab(); },
  warp() {
    const i = IG.cur.info, gA = i.gw !== undefined, id = IG.cur.id, wp = (IG.cur.auto && IG.cur.auto.warp) || {};
    const items = [
      { label: L('Test every WARP now', 'تست همهٔ WARPها الان'), attr: 'id="igwt"' },
      { label: L('Add a WARP by hand…', 'افزودن دستی WARP…'), attr: 'id="igwa"' },
      wp.off ? { label: L('✓ By hand · switch to automatic', '✓ دستی · خودکار کن'), attr: 'data-wpm="auto"' } : { label: L('Manage WARPs by hand…', 'مدیریت دستی WARPها…'), attr: 'data-wpm="off"' },
      { label: L('Google → fresh IP', 'Google → IP تازه'), attr: 'id="igwr"' },
      gA && { label: L('Country per WARP (Google)', 'کشور هر WARP (Google)'), attr: 'id="igwc"' }];
    $('#igtab').innerHTML = `<div class="card pad sec igw"><div class="wtop"><div id="igwline">${igWarpLine(IG.cur)}</div><span class="wact">${moreMenu(items)}</span></div>
     <div class="wsum">${igWarpSvc(i)}</div>
     <details class="igst-more wdet" id="igwdet"${IG.wdetOpen ? ' open' : ''}><summary><span data-notr>${L('WARP accounts', 'حساب‌های WARP')}</span><span id="igwsum" class="wchips"></span></summary>
     <div id="igwl" class="wlist"></div>
     <div class="mdesc" data-notr>${L('The panel keeps as many WARP accounts as this server needs: it makes new ones when good ones are missing (a few at a time, so Cloudflare never blocks the server), tests the spares in the background, and removes the extra and broken ones at night. Broken WARPs are repaired and the best one (music OK, fastest) is chosen automatically.',
       'پنل به اندازهٔ نیاز این سرور حساب WARP نگه می‌دارد: وقتی حساب سالم کم باشد خودش حساب تازه می‌سازد (چندتا چندتا، تا Cloudflare سرور را نبندد)، یدک‌ها را در پس‌زمینه تست می‌کند و اضافه‌ها و خراب‌ها را شب حذف می‌کند. WARP خراب خودکار تعمیر و بهترینش (موزیک سالم، سریع‌تر) انتخاب می‌شود.')}</div></details></div>`;
    $('#igwdet').ontoggle = () => { IG.wdetOpen = $('#igwdet').open; };
    $('#igwa').onclick = () => igAct(igS({ action: 'warp_add' }), L('Make a new WARP account on ' + IG.cur.name + ' by hand? The panel then leaves the number of WARPs here alone for a day.', 'یک حساب WARP تازه دستی روی ' + IG.cur.name + ' ساخته شود؟ پنل تا یک روز تعداد WARPهای این سرور را دست نمی‌زند.'), { title: L('New WARP account', 'حساب WARP تازه') });
    $('#igwr').onclick = () => igAct(igS({ action: 'google_rotate' }));
    $('#igwt').onclick = async () => { const b = $('#igwt'); b.disabled = true; toast(L('Testing every WARP… (up to 3 min)', 'در حال تست همهٔ WARPها… (تا ۳ دقیقه)')); try { await igQuiet(igS({ action: 'warp_list' })); } catch (e) { toast(e.message); } igWarpLoad(id, true); };
    $$('[data-wpm]').forEach(b => b.onclick = () => igWarpMode(IG.cur, b.dataset.wpm));
    if (gA) $('#igwc').onclick = () => igWarpCountries(id);
    igWarpDraw(IG.wcache && IG.wcache[id]);
    igWarpLoad(id);
  },
  sites() { igSitesTab(); },
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
  const det = [igtMs(s.ms), s.loc ? `<span>Gemini: <b>${esc(s.loc)}</b> <span class="faint">(browser check)</span></span>` : igSet(cc) && cc !== 'PROXY' ? `<span>${s.k === 'IG' ? 'Instagram' : 'Google'} sees <b class="mono">${esc(cc)}</b></span>` : ''].join('');
  let btn = '';
  if (!s.ok) btn = s.k === 'IG' ? igtTo(/^warp/.test(i.ig || '') ? 'warp' : /^proxy/.test(i.ig || '') ? 'proxies' : 'routes', /^warp/.test(i.ig || '') ? 'WARP tab' : /^proxy/.test(i.ig || '') ? 'Proxies tab' : 'Routes tab') : '<button class="btn sm" data-tt="diag">Diagnose</button>';
  return igtRow(s.ok ? (s.warn ? 'warn' : 'ok') : 'bad', name, via(g), det, s.ok && !s.warn ? '' : esc(s.why), btn);
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
  const bad = h.svcs.filter(s => !s.ok).length + h.exits.filter(e => !e.ok && !e.idle).length, warn = h.exits.filter(e => e.ok && e.warn).length + h.svcs.filter(s => s.ok && s.warn).length;
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
// the number of WARP accounts is the panel's (warppool.go, WARP tab): minwarps / warpauto are not offered here any more
const IGO_SEC = [['pool', 'WARP accounts', ['minspeed']], ['google', 'Google · Gemini', ['gwarps', 'gcountries', 'gspread', 'grotate', 'gall']],
  ['ig', 'Instagram', ['guard', 'musiccheck']], ['adv', 'Advanced', ['mode', 'autokey', 'geosite', 'kwg']]];
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
  if (k === 'mode' && val('mode') === 'balance') return ['info', 'Recommended. Only WARPs that leave from the same exit IP carry Instagram, so users keep one IP and music works; Google keeps its own WARP.'];
  if (k === 'mode' && val('mode') === 'failover') return ['warn', 'The panel sets this back to "Spread the load" at night (03-06), unless the WARPs here are managed by hand.'];
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
// the automatic WARP pool in one line (warppool.go): "WARP: auto · 2 of 2 working · Instagram sees DE"
function igWarpLine(s, d) {
  const i = s.info || {}, p = (s.auto && s.auto.warp) || {}, now = Date.now() / 1000, fa = window.tpLang === 'fa';
  const N = (n) => fa ? faNum(n) : String(n), dur = (x) => x < 5400 ? L(Math.max(1, Math.round(x / 60)) + ' min', faNum(Math.max(1, Math.round(x / 60))) + ' دقیقه') : L(Math.round(x / 3600) + ' h', faNum(Math.round(x / 3600)) + ' ساعت');
  const ws = d ? d.warps : null, have = ws ? ws.length : (+i.warps || 0), work = ws ? ws.filter(w => w.state === 'ok').length : null;
  const igOn = /^warp/.test(i.ig || ''), cc = igOn && i.igcc && i.igcc !== '-' ? i.igcc : '', gcc = /^warp/.test(i.google || '') && i.gcc && !['-', 'PROXY', '?'].includes(i.gcc) ? i.gcc : '';
  const auto = L('auto', 'خودکار');
  let lvl = 'on', head, sub = [];
  if (p.off) {
    lvl = 'acc'; head = `WARP: ${L('by hand', 'دستی')} · ${L(N(have) + ' accounts', N(have) + ' حساب')}${work !== null ? ` · ${L(N(work) + ' working', N(work) + ' فعال')}` : ''}`;
    sub.push(L('The panel does not add or remove WARPs here. ⋯ → switch to automatic.', 'پنل اینجا WARP اضافه یا حذف نمی‌کند. ⋯ ← خودکار کن.'));
  } else if (!p.at) {
    lvl = 'acc'; head = `WARP: ${auto} · ${L('checking…', 'در حال بررسی…')}`;
    sub.push(L('The panel looks at this server within 15 minutes.', 'پنل تا ۱۵ دقیقه این سرور را بررسی می‌کند.'));
  } else if (!p.used) {
    lvl = have ? 'acc' : 'on'; head = `WARP: ${auto} · ${L('not in use', 'استفاده نمی‌شود')}`;
    sub.push(have ? L(`No service goes through WARP: the ${N(have)} accounts are removed tonight.`, `هیچ سرویسی از WARP نمی‌رود: ${N(have)} حساب امشب حذف می‌شود.`) : L('No service goes through WARP, so no account is needed. One is made when a service moves to WARP.', 'هیچ سرویسی از WARP نمی‌رود، پس حسابی لازم نیست. وقتی سرویسی به WARP برود ساخته می‌شود.'));
  } else if (p.noExit) {
    lvl = 'warn'; head = `WARP: ${auto} · ${L('no music country here', 'کشور با موزیک ندارد')} (${p.noExit})`;
    sub.push(L(`Every new WARP of this server reads ${p.noExit}, so no more are made for now and Instagram goes through ${igExitWord(i.ig, i)}. WARP is tried again in ${dur(p.wait || 0)}.`,
      `هر WARP تازهٔ این سرور ${p.noExit} خوانده می‌شود، پس فعلاً ساخته نمی‌شود و Instagram از ${igExitWord(i.ig, i)} می‌رود. ${dur(p.wait || 0)} دیگر دوباره WARP امتحان می‌شود.`));
  } else {
    const g = Math.min(p.good, p.need);
    lvl = p.good >= p.need ? 'on' : 'warn';
    head = `WARP: ${auto} · ${L(`${N(g)} of ${N(p.need)} working`, `${N(g)} از ${N(p.need)} فعال`)}${cc ? ` · ${L('Instagram sees', 'Instagram می‌بیند')} ${cc}` : ''}${gcc ? ` · ${L('Google sees', 'Google می‌بیند')} ${gcc}` : ''}`;
    const parts = [p.carry ? L(`${N(p.carry)} for ${igOn ? 'Instagram' : 'the services on WARP'}`, `${N(p.carry)} برای ${igOn ? 'Instagram' : 'سرویس‌های روی WARP'}`) : '', p.spare ? L(`${N(p.spare)} spare`, `${N(p.spare)} یدک`) : '', p.g ? L(`${N(p.g)} Google's own`, `${N(p.g)} مخصوص Google`) : ''].filter(Boolean);
    sub.push(L('Needed: ', 'لازم: ') + parts.join(' + '));
    if (p.short) sub.push(p.wait > 0 ? L(`Making new accounts — next try in ${dur(p.wait)}.`, `در حال ساخت حساب تازه — تلاش بعدی ${dur(p.wait)} دیگر.`) : L('Making new accounts now.', 'در حال ساخت حساب تازه.'));
    if (p.untest) sub.push(L(`Testing ${N(p.untest)} spare${p.untest === 1 ? '' : 's'}.`, `در حال تست ${N(p.untest)} یدک.`));
  }
  if (!p.off && p.at && p.hold > now) sub.push(L('Changed by hand — the panel leaves the count alone until ', 'دستی تغییر کرد — پنل تا این زمان تعداد را دست نمی‌زند: ') + new Date(p.hold * 1000).toLocaleString(fa ? 'fa-IR' : undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }));
  else if (!p.off && p.at && p.used && (p.extra || 0) + (p.bad || 0) > 0) sub.push(L(`${N(p.extra + p.bad)} not needed — removed tonight (03–06; the router restarts for a few seconds).`, `${N(p.extra + p.bad)} لازم نیست — امشب حذف می‌شود (۳ تا ۶ صبح؛ روتر چند ثانیه ری‌استارت می‌شود).`));
  return `<div class="igst wline ${lvl}" data-notr><div class="igst-top"><span class="igst-dot"></span><div class="igst-t"><b>${esc(head)}</b>${sub.map(x => `<small>${esc(x)}</small>`).join('')}</div></div></div>`;
}
async function igWarpMode(s, mode) {
  if (mode === 'off' && !confirm(L('Manage the WARPs of ' + s.name + ' by hand? The panel then never adds or removes a WARP here.', 'WARPهای ' + s.name + ' دستی مدیریت شود؟ پنل دیگر اینجا WARP اضافه یا حذف نمی‌کند.'))) return;
  try {
    s.auto = Object.assign(s.auto || {}, await api('/igproxy/auto', { ID: s.id, Svc: 'WARP', Mode: mode }));
    toast(mode === 'auto' ? L('WARP: automatic', 'WARP: خودکار') : L('WARP: by hand', 'WARP: دستی'));
    if (IG.cur && IG.cur.id === s.id && IG.tab === 'warp') IGTAB.warp();
  } catch (e) { toast(e.message); }
}
// how Instagram and Google leave now, in words
function igWarpSvc(i, d) {
  const bal = i.mode === 'BALANCE', igw = /^warp/.test(i.ig || ''), gw = /^warp/.test(i.google || '');
  const pool = d ? d.warps.filter(w => w.state === 'ok' && !igGw(i).includes(w.n)).length : +(i.pool || '').split('/')[0] || 0;
  const kind = i.ig === 'warp6' ? 'WARP IPv6' : 'WARP';
  const ig = !igw ? 'not on WARP' : bal ? `${kind} · ${pool} WARP${pool === 1 ? '' : 's'} share it` : `${kind} ${+i.active ? +i.active : '—'}`;
  const g = !gw ? 'not on WARP' : i.gcc === 'PROXY' ? 'proxy for now' : +i.gact ? `WARP ${+i.gact}` : 'with Instagram';
  const cell = (k, v, sub, cls) => `<div class="svc"><small>${k}</small><b class="${cls || ''}">${esc(v)}</b>${sub ? `<span class="note">${sub}</span>` : ''}</div>`;
  return `<div class="svcs">${cell('Instagram', ig, igw ? (i.igcc && i.igcc !== '-' ? `Instagram sees <b class="mono">${esc(i.igcc)}</b>` : '') : `goes ${esc(igViaW(i.ig, i))} → Routes tab`, igw ? 'v-warp' : 'v-direct')}
    ${cell('Google / Gemini', g, gw ? (i.gcc === 'PROXY' ? 'no WARP in an allowed country' : i.gcc && i.gcc !== '-' ? `Google sees <b class="mono">${esc(i.gcc)}</b>` : '') : `goes ${esc(igViaW(i.google, i))} → Routes tab`, gw && i.gcc !== 'PROXY' ? 'v-warp' : i.gcc === 'PROXY' ? 'v-proxy' : 'v-direct')}
    </div>`;
}
const IGWOUT = { ip: 'Spare', ipnew: 'Getting a new IP', music: 'Parked: no Instagram music', down: 'Parked: down' };
// a spare (out of the pool: on warp6 every account has its own exit) as the panel's last test saw it
const igWarpSpare = (w) => w.test === 'ok' ? ['Spare · ready', 'idle'] : w.test === 'no' ? [`No music country`, 'bad'] : w.test === 'down' ? ['Spare · not working', 'warn'] : ['Spare · not tested yet', 'idle'];
function igWarpRow(i, d, w) {
  const gws = igGw(i), own = gws.includes(w.n), bal = i.mode === 'BALANCE';
  const igOn = /^warp/.test(i.ig || '') && !own && w.state === 'ok' && (bal || d.active === w.n);
  const gOn = /^warp/.test(i.google || '') && i.gcc !== 'PROXY' && (d.gact ? d.gact === w.n : !gws.length && igOn);
  const st = w.state === 'ok' ? ['Working', 'ok'] : w.state === 'out' ? (w.why === 'ip' ? igWarpSpare(w) : [IGWOUT[w.why] || 'Not in use: ' + w.why, 'warn'])
    : w.state === 'repair' ? ['Being repaired' + (w.fails ? ` (try ${w.fails})` : ''), 'warn'] : ['Down', 'bad'];
  const tIP = !w.ip && w.testIP, eIP = w.ip || w.testIP || '', eLoc = w.ip ? w.loc : w.testLoc;
  const exit = eIP ? `<span class="mono" title="${esc(eIP)}">${eLoc ? esc(eLoc) + ' · ' : ''}${esc(eIP)}</span> <span class="tag">${eIP.includes(':') ? 'IPv6' : 'IPv4'}</span>`
    : `<span class="faint">${w.state === 'out' ? (w.test === 'down' ? 'no exit in its test' : 'tested soon') : 'no exit now'}</span>`;
  const tst = (w.testCC ? `<span>Instagram sees <b class="mono${w.test === 'no' ? ' bad' : ''}">${esc(w.testCC)}</b></span>` : '') + (tIP && w.testAt ? `<span class="faint">tested ${igAgo(Math.round(Date.now() / 1000 - w.testAt))}</span>` : '');
  const music = w.music === 'ok' ? '<span class="good">music OK</span>' : w.music === 'no' ? `<span class="bad" title="${esc(w.musicWhy || '')}">no music</span>` : w.music === 'down' ? '<span class="bad">was down</span>' : '<span class="faint">music not tested</span>';
  const test = w.music ? `<span>${music}${w.mbps ? ` · <b class="mono">${w.mbps}</b> Mbps` : ''}</span><span class="faint">${igAgo(w.testAge)}</span>` : w.state === 'out' ? '' : '<span class="faint">no speed test yet</span>';
  const roles = (igOn ? '<span class="chip fo">Instagram</span>' : '') + (gOn ? '<span class="chip fo">Google</span>' : '') + (own && !gOn ? '<span class="chip">Google\'s reserve</span>' : '');
  const useG = own && i.gw !== undefined, inUse = useG ? gOn : (igOn && (bal || d.active === w.n));
  const prim = inUse || w.state !== 'ok' ? '' : `<button class="btn sm" data-${useG ? 'wg' : 'wu'}="${w.n}">${useG ? 'Use for Google' : 'Use'}</button>`;
  const menu = moreMenu([{ label: 'Delete WARP ' + w.n + '…', attr: `data-wd="${w.n}"`, danger: true }]);
  return `<div class="wrow${igOn || gOn ? ' on' : ''}${w.state === 'ok' ? '' : ' dim'}">
    <div class="wn mono">${w.n}</div>
    <div class="wb"><div class="w1"><span class="igd ${st[1] === 'ok' ? 'ok' : st[1] === 'bad' ? 'bad' : ''}"></span><b class="wst ${st[1]}">${st[0]}</b>
      <span class="tag${w.plus ? ' plus' : ''}">${w.plus ? 'WARP+' : 'Free'}</span>${roles}</div>
      <div class="w2"><span>${exit}</span>${tst}${w.gcc ? `<span>Google sees <b class="mono">${esc(w.gcc)}</b></span>` : ''}${test}</div>
      ${w.next && w.state === 'ok' ? `<div class="w3">gets a new account soon: ${esc(w.next)}</div>` : ''}${w.old ? '<div class="w3">old account: delete and add again for automatic WARP+ keys</div>' : ''}</div>
    <div class="wa${prim ? ' p' : ''}">${inUse ? '<span class="inuse" title="in use">✓<span class="t"> in use</span></span>' : prim}${menu}</div></div>`;
}
function igWarpDraw(d, err) {
  const box = $('#igwl'); if (!box || !IG.cur) return;
  const i = IG.cur.info;
  if (err && !d) { box.innerHTML = `<div class="mcrit" style="margin:0">Couldn't read the WARPs: ${esc(err)} <button class="btn sm" id="igwrt">Try again</button></div>`; $('#igwrt').onclick = () => { igWarpDraw(); igWarpLoad(IG.cur.id); }; return; }
  if (!d) { box.innerHTML = '<div class="skel" style="height:64px"></div>'.repeat(Math.min(8, Math.max(2, +i.warps || 3))); return; }
  const ws = d.warps, ok = ws.filter(w => w.state === 'ok').length, idle = ws.filter(w => w.state === 'out').length, bad = ws.length - ok - idle;
  $('#igwsum').innerHTML = ws.length ? `<span class="chip" data-notr>${ws.length}</span>${bad ? `<span class="chip bad" data-notr>${L(bad + ' down', faNum(bad) + ' قطع')}</span>` : ''}` : '';
  $('.igw .wsum').innerHTML = igWarpSvc(i, d);
  if ($('#igwline')) $('#igwline').innerHTML = igWarpLine(IG.cur, d);
  if (!ws.length) { box.innerHTML = `<div class="empty" style="padding:18px 10px"><div class="big">☁️</div>${L('No WARP account on this server. The panel makes them by itself when a service goes through WARP.', 'این سرور حساب WARP ندارد. وقتی سرویسی از WARP برود پنل خودش می‌سازد.')}</div>`; return; }
  box.innerHTML = (err ? `<div class="mwarn">Couldn't refresh (${esc(err)}) — showing what was read ${igAgo(Math.round(Date.now() / 1000 - d.at))}.</div>` : '')
    + (d.sel === 'none' ? '<div class="mwarn">No WARP has Instagram music and the minimum speed now, so the current one is kept. The panel looks for a better IP by itself.</div>' : '')
    + ws.map(w => igWarpRow(i, d, w)).join('')
    + (i.mode === 'BALANCE' && /^warp/.test(i.ig || '') && d.poolIP ? `<div class="mdesc">Instagram leaves from one exit IP (<span class="mono">${esc(d.poolIP)}</span>). The other accounts are spares: they take over when it fails.</div>` : '');
  $$('[data-wu]', box).forEach(b => b.onclick = () => igAct(igS({ action: 'warp_use', n: b.dataset.wu })));
  $$('[data-wg]', box).forEach(b => b.onclick = () => igAct(igS({ action: 'google_use', n: b.dataset.wg })));
  $$('[data-wd]', box).forEach(b => b.onclick = () => igAct(igS({ action: 'warp_del', n: b.dataset.wd }), `Delete WARP ${b.dataset.wd} on ${IG.cur.name}? Its account is removed and the WARPs after it move up one number. The panel then leaves the number of WARPs here alone for a day.`, { title: 'Delete WARP' }));
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
const IGPX = { srv: null, rows: null, err: '', busy: {}, open: false, form: {}, res: null, auto: {}, sel: new Set() };
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
    const have = new Set(IGPX.rows.map(x => x.key)); IGPX.sel.forEach(k => { if (!have.has(k)) IGPX.sel.delete(k); });
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
  if (IGPX.srv !== IG.cur.id) { IGPX.open = false; IGPX.res = null; IGPX.form = {}; IGPX.ferr = ''; IGPX.sel = new Set(); igpxLoad(); return; }
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
  const sel = IGPX.sel.has(r.key);
  return `<div class="wrow${uses.length ? ' on' : ''}${sel ? ' sel' : ''}${t && !t.ok && !busy ? ' dim' : ''}${busy ? ' busy' : ''}" data-k="${esc(r.key)}">
    <label class="igx-ck" title="Select"><input type="checkbox" data-sel aria-label="Select proxy ${+r.n}"${sel ? ' checked' : ''}></label>
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
    ${n ? igpxSelBar(i) : ''}
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
// ---- selecting several proxies: test them together, or delete them in one go
// failing: Instagram rejects its IP, the proxy doesn't work, or Instagram doesn't answer through it
const igpxFailing = (r) => !!(r.bad || (r.test && (!r.test.ok || !r.test.ms)));
// the second line of one host, port and user (one HTTP, one SOCKS5 …): each group keeps the one in
// use, else a working one, else the fastest, else the lowest number; the rest are picked
function igpxDupes(i) {
  const g = {};
  (IGPX.rows || []).forEach(r => { (g[r.twin || r.key] = g[r.twin || r.key] || []).push(r); });
  const score = (r) => [igpxUses(i, r).length ? 0 : 1, igpxFailing(r) || !r.test ? 1 : 0, r.test && r.test.ms ? r.test.ms : 1e9, r.n];
  const cmp = (a, b) => { const x = score(a), y = score(b); for (let k = 0; k < x.length; k++) if (x[k] !== y[k]) return x[k] - y[k]; return 0; };
  return Object.values(g).filter(l => l.length > 1).flatMap(l => l.slice().sort(cmp).slice(1));
}
function igpxSelBar(i) {
  const rows = IGPX.rows || [], k = IGPX.sel.size, all = k && k === rows.length;
  const testing = Object.keys(IGPX.busy).length > 0, busy = testing || IGPX.deleting;
  const box = `<label class="igx-ck"><input type="checkbox" id="igxselall" aria-label="Select all"${all ? ' checked' : ''}></label>`;
  if (!k) {
    const fail = rows.filter(igpxFailing).length, dup = igpxDupes(i).length;
    return `<div class="igx-sel">${box}<label for="igxselall" class="igx-sl">Select all</label><span class="grow"></span>
      ${fail ? `<button class="btn sm ghost" id="igxpfail" title="the ones Instagram rejects, that don't work, or that Instagram doesn't answer through"><span>Select failing</span> <span class="chip">${fail}</span></button>` : ''}
      ${dup ? `<button class="btn sm ghost" id="igxpdup" title="the same host, port and user twice (for example once HTTP, once SOCKS5): keeps the one in use or the fastest"><span>Select duplicates</span> <span class="chip">${dup}</span></button>` : ''}</div>`;
  }
  return `<div class="igx-sel on">${box}<b class="mono">${k}</b><span>selected</span><span class="grow"></span>
    <button class="btn sm" id="igxstest" ${busy ? 'disabled' : ''}>${testing ? 'Testing…' : 'Test'}</button>
    <button class="btn sm danger" id="igxsdel" ${busy ? 'disabled' : ''}>${IGPX.deleting ? 'Deleting…' : 'Delete'}</button>
    <button class="btn sm ghost" id="igxsclr" title="Clear the selection" aria-label="Clear the selection">✕<span class="igx-clt"> Clear</span></button></div>`;
}
async function igpxBulkTest() {
  const id = IGPX.srv, ns = (IGPX.rows || []).filter(r => IGPX.sel.has(r.key)).map(r => r.n);
  if (!ns.length) return;
  ns.forEach(n => { IGPX.busy[n] = true; }); igpxDraw();
  try {
    const r = await api('/igproxy/proxies', { srv: id, test: 1, ns: ns.join(',') });
    if (IGPX.srv !== id) return;
    IGPX.rows = r.proxies || [];
  } catch (e) { toast(e.message); }
  finally { ns.forEach(n => delete IGPX.busy[n]); }
  igpxDraw();
}
// what deleting these would leave without a way out (the server checks the same):
// a service on a deleted proxy alone, or on "all proxies" with none left
function igpxAffected(i, del, left) {
  return Object.keys(IGSV).map(g => {
    const v = i[g.toLowerCase()] || '', m = /^proxy(\d+)$/.exec(v);
    if (v === 'proxy' && !left) return [g, 'pool'];
    if (m && del.has(+m[1])) return [g, 'only', +m[1]];
    return null;
  }).filter(Boolean);
}
const igpxLine = (r) => `<span class="mono" dir="ltr" data-notr>#${+r.n} ${igpxType(r.type)} ${esc(r.host)}:${esc(r.port)}</span>${r.test && r.test.ok ? ` <span class="faint mono" dir="ltr" data-notr>${esc(r.test.loc || '')}${r.test.ms ? ' · ' + (+r.test.ms) + ' ms' : ''}</span>` : ''}${r.bad ? ' <span class="chip warn">Instagram rejects its IP</span>' : r.test && !r.test.ok ? ' <span class="chip warn">Not working</span>' : ''}`;
function igpxBulkDel() {
  const s = IG.cur, id = s.id, i = s.info || {}, rows = IGPX.rows || [];
  const del = rows.filter(r => IGPX.sel.has(r.key)), keep = rows.filter(r => !IGPX.sel.has(r.key));
  if (!del.length) return;
  const dn = new Set(del.map(r => r.n)), aff = igpxAffected(i, dn, keep.length);
  const good = keep.filter(r => !igpxFailing(r) && r.test).sort((a, b) => (a.test.ms || 1e9) - (b.test.ms || 1e9));
  // where an affected service goes: the fastest working proxy that stays, unless another is picked
  const opts = (g) => {
    const o = good.map((r, k) => [`key:${r.key}`, `Proxy ${r.n} · ${igpxType(r.type)}${r.test.loc ? ' · ' + r.test.loc : ''}${r.test.ms ? ' · ' + r.test.ms + ' ms' : ''}${k ? '' : ' · fastest'}`]);
    if (keep.length) o.push(['proxy', 'All the other proxies']);
    o.push(['warp', 'WARP'], ['direct', "Direct (the server's own IP)"]);
    const def = good.length ? `key:${good[0].key}` : '';
    return `<select class="inp" data-mv="${g}">${def ? '' : '<option value="" selected>— choose —</option>'}${o.map(x => `<option value="${esc(x[0])}"${x[0] === def ? ' selected' : ''}>${esc(x[1])}</option>`).join('')}</select>`;
  };
  const poolLeft = keep.filter(r => !igpxFailing(r)).length;
  const pool = Object.keys(IGSV).filter(g => i[g.toLowerCase()] === 'proxy' && keep.length && !poolLeft);
  const gfb = /^warp/.test(i.google || '') && i.gcc === 'PROXY' && dn.has(1);
  const m = modal(`<h2><span>Delete</span> <span class="mono">${del.length}</span> <span>${del.length === 1 ? 'proxy' : 'proxies'}</span>?</h2>
    <p class="muted igx-dsub"><span>from</span> <b data-notr>${esc(s.name)}</b></p>
    <div class="igx-dl">${del.map(r => `<div>${igpxLine(r)}${igpxUses(i, r).filter(u => u[1] === 'only').map(u => ` <span class="chip fo">${esc(IGSV[u[0]])}</span>`).join('')}</div>`).join('')}</div>
    ${aff.length ? `<div class="igx-dw"><b>⚠ In use — moved first, so no user is cut</b>${aff.map(a => `<label class="f"><span><b>${esc(IGSV[a[0]])}</b> <span>${a[1] === 'pool' ? 'goes through all the proxies, and none is left' : 'goes out only through a proxy you are deleting'}</span>${a[2] ? ` <span class="mono" dir="ltr" data-notr>(#${a[2]})</span>` : ''}</span><span class="igx-mv"><span>Move it to</span>${opts(a[0])}</span></label>`).join('')}</div>` : ''}
    ${pool.length ? `<div class="mcrit"><b>${esc(pool.map(g => IGSV[g]).join(', '))}</b> <span>go through all the proxies: none of the ones left works now.</span></div>` : ''}
    ${gfb ? `<div class="mdesc">${keep.length ? "Proxy 1 is Google's fallback: the next proxy takes its place." : "Proxy 1 is Google's fallback: with no proxy left, Google has no fallback."}</div>` : ''}
    <div class="mdesc">The proxies are deleted one by one; the router reloads for a few seconds each time. Nothing is deleted if the list changed on the server meanwhile.</div>
    <div class="mcrit igx-err" id="igxderr" hidden></div>
    <div class="actions igx-da"><button class="btn" id="igxdno">Cancel</button><button class="btn danger" id="igxdgo"><span>Delete</span> <span class="mono">${del.length}</span></button></div>`);
  m.classList.add('igx-dm');
  const go = $('#igxdgo', m), ready = () => { go.disabled = $$('[data-mv]', m).some(x => !x.value); };
  $$('[data-mv]', m).forEach(x => x.onchange = ready); ready();
  $('#igxdno', m).onclick = () => m.remove();
  go.onclick = async () => {
    const moves = {}; $$('[data-mv]', m).forEach(x => { moves[x.dataset.mv] = x.value; });
    go.disabled = true; $('#igxdno', m).disabled = true; go.innerHTML = '<span>Deleting…</span>'; IGPX.deleting = true; igpxDraw();
    try {
      const r = await api('/igproxy/proxy/bulk', { srv: id, do: 'del', keys: del.map(x => x.key), moves });
      m.remove();
      if (r.ok) toast(`Deleted: ${r.deleted.length}` + (r.moved && r.moved.length ? ' · ' + r.moved.map(x => x.replace(/^(\w+) -> /, (q, g) => (IGSV[g] || g) + ' → ')).join(' · ') : ''));
      else alertModal('Not everything was deleted', [r.msg, r.deleted.length ? 'Deleted: ' + r.deleted.join(', ') : '', r.left && r.left.length ? 'Still there: ' + r.left.join(', ') : '', ...(r.out || []).slice(-6)].filter(Boolean).join('\n'));
      IGPX.sel = new Set();
    } catch (e) {
      const er = $('#igxderr', m);
      if (er && m.isConnected) { er.textContent = e.message; er.hidden = false; go.disabled = false; $('#igxdno', m).disabled = false; go.innerHTML = '<span>Delete</span>'; } else toast(e.message);
    }
    IGPX.deleting = false;
    if (IGPX.srv === id) { await igpxInfo(); igpxLoad(); }
  };
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
  const pick = (l) => { IGPX.sel = new Set(l.map(r => r.key)); igpxDraw(); };
  $('#igxselall', box) && ($('#igxselall', box).onchange = (e) => pick(e.target.checked ? IGPX.rows || [] : []));
  $('#igxpfail', box) && ($('#igxpfail', box).onclick = () => pick((IGPX.rows || []).filter(igpxFailing)));
  $('#igxpdup', box) && ($('#igxpdup', box).onclick = () => pick(igpxDupes(s.info || {})));
  $('#igxsclr', box) && ($('#igxsclr', box).onclick = () => pick([]));
  $('#igxstest', box) && ($('#igxstest', box).onclick = igpxBulkTest);
  $('#igxsdel', box) && ($('#igxsdel', box).onclick = igpxBulkDel);
  // "select all" shows a dash while only some are picked
  $('#igxselall', box) && ($('#igxselall', box).indeterminate = IGPX.sel.size > 0 && IGPX.sel.size < (IGPX.rows || []).length);
  $$('.wrow', box).forEach(row => {
    const r = (IGPX.rows || []).find(x => x.key === row.dataset.k); if (!r) return;
    const name = `${igpxType(r.type)} ${r.host}:${r.port}`;
    $('[data-sel]', row).onchange = (e) => { if (e.target.checked) IGPX.sel.add(r.key); else IGPX.sel.delete(r.key); igpxDraw(); };
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

// ---- route table: every server × service. Changes wait in IG.pend (not in the page: a refresh of
// the list redrew the table and threw them away) until one Apply; each cell has a dot from the
// agent's own checks and from what the server can really do (paused, no proxy, no WARP …).
const IGSHORT = { IG: ['📸', 'Instagram'], GOOGLE: ['✨', 'Google'], YTM: ['🎵', 'YT Music'], ADULT: ['🔞', 'Adult'], SPOTIFY: ['🎧', 'Spotify'], SCLOUD: ['☁️', 'SoundCloud'], SNAP: ['👻', 'Snapchat'], CUSTOM: ['🌐', 'My sites'] };
const igViaS = (v) => { v = v || ''; if (v === 'proxy') return 'Proxy'; if (/^proxy\d+$/.test(v)) return 'Proxy ' + v.slice(5); return { warp: 'WARP', warp6: 'WARP IPv6', ipv6: 'IPv6', direct: 'Direct' }[v] || v || '—'; };
// [dot class, why] of one service's route on one server: '' = nothing to say (direct, not checked)
function igCellHealth(s, g, v) {
  const i = s.info || {};
  if (v !== 'direct') {
    if (i.paused === 'YES') return ['bad', "igproxy is paused here: it leaves through the server's own IP"];
    if (i.router !== 'active' || i.redirect !== 'ON') return ['bad', "The router isn't running here: it leaves through the server's own IP"];
    if (/^proxy/.test(v) && !(+i.proxies > 0)) return ['bad', 'No proxy on this server: it leaves direct until one is added'];
    if (/^proxy\d+$/.test(v) && +v.slice(5) > +i.proxies) return ['bad', 'There is no such proxy on this server'];
    if (/^warp/.test(v) && !(+i.warps > 0)) return ['bad', 'No WARP account on this server'];
    if (IGWIDE.includes(g) && i.wide === 'OFF') return ['bad', 'Wide catch is off on this server (its kernel lacks the iptables modules): it leaves direct'];
  }
  if (g === 'GOOGLE' && /^warp/.test(v) && i.gcc === 'PROXY') return ['warn', 'No allowed WARP for Google: it goes through a proxy for now'];
  const ck = g === 'IG' ? i.igp : g === 'GOOGLE' ? i.gem : '';
  if (ck === 'OK') return ['ok', g === 'IG' ? 'Instagram opens on this route (checked every minute)' : 'Gemini opens on this route (checked every minute)'];
  if (ck === 'FAIL') return ['bad', g === 'IG' ? "Instagram doesn't open on this route (checked every minute)" : "Gemini doesn't open on this route (checked every minute)"];
  return v === 'direct' ? ['', ''] : ['none', 'not checked by the agent'];
}
const igMatCur = (s, g) => (s.info || {})[g.toLowerCase()] || 'direct';
const igMatVal = (s, g) => ((IG.pend || {})[s.id] || {})[g] || igMatCur(s, g);
function igMatOpts(s, g, cur) {
  const n = +s.info.proxies || 0, o = ['direct', 'warp']; if (!IGWIDE.includes(g)) o.push('warp6', 'ipv6'); o.push('proxy'); for (let k = 1; k <= n; k++) o.push('proxy' + k);
  if (cur && !o.includes(cur)) o.push(cur);
  return o;
}
function igPendSet(s, g, v) {
  IG.pend = IG.pend || {};
  const p = IG.pend[s.id] = IG.pend[s.id] || {};
  if (v === igMatCur(s, g)) delete p[g]; else p[g] = v;
  if (!Object.keys(p).length) delete IG.pend[s.id];
}
const igPendList = (L) => L.flatMap(s => Object.entries((IG.pend || {})[s.id] || {}).map(([g, v]) => ({ s, g, v })));
// the "all servers" choice of one column: who changes, who is left as is and why
function igAllPlan(L, g, v) {
  const ch = [], same = [], skip = [];
  L.forEach(s => {
    if (!igMatOpts(s, g, '').includes(v)) skip.push([s, /^proxy\d+$/.test(v) ? `has ${+s.info.proxies || 0} proxies` : 'not possible here']);
    else if (igMatCur(s, g) === v) same.push(s); else ch.push(s);
  });
  return { ch, same, skip };
}
function igMatrix(box) {
  if (!IG.data) { box.innerHTML = '<div class="skel" style="height:200px"></div>'; return; }
  const L = igList().filter(s => s.info.ig), off = igList().filter(s => !s.info.ig);
  if (!L.length) { box.innerHTML = '<div class="card empty"><div class="big">🔀</div>No server with a running agent to route.</div>'; return; }
  IG.pend = IG.pend || {}; IG.allSel = IG.allSel || {};
  // pending changes of servers no longer here (other View, agent gone) are dropped
  Object.keys(IG.pend).forEach(id => { if (!L.some(s => s.id === id)) delete IG.pend[id]; });
  const phone = matchMedia('(max-width: 720px)').matches, more = recall('tp-igmore') === '1';
  const cols = more ? Object.keys(IGSV) : ['IG', 'GOOGLE', 'YTM'];
  const cell = (s, g) => {
    const v = igMatVal(s, g), cur = igMatCur(s, g), chg = v !== cur, [hc, ht] = igCellHealth(s, g, v);
    const tip = (chg ? `now: ${igViaW(cur, s.info)} → after Apply: ${igViaW(v, s.info)}` : igViaW(v, s.info)) + (ht ? ' · ' + ht : '');
    return `<span class="mc${v === 'direct' && !chg ? ' q' : ''}${chg ? ' chg' : ''}" title="${esc(tip)}"><i class="igd ${chg ? 'pend' : hc}"></i><select data-s="${esc(s.id)}" data-g="${g}" class="${igViaC(v)}" aria-label="${esc(IGSV[g])}">${igMatOpts(s, g, cur).map(o => `<option value="${o}"${o === v ? ' selected' : ''}>${esc(igViaS(o))}</option>`).join('')}</select></span>`;
  };
  // the folded services in one cell: only the ones not direct
  const rest = (s) => {
    const x = IGWIDE.filter(g => igMatVal(s, g) !== 'direct' || (IG.pend[s.id] || {})[g]);
    return x.length ? x.map(g => { const v = igMatVal(s, g), [hc] = igCellHealth(s, g, v); return `<span class="mrest${(IG.pend[s.id] || {})[g] ? ' chg' : ''}" title="${esc(IGSV[g] + ': ' + igViaW(v, s.info))}">${IGSHORT[g][0]} <b class="${igViaC(v)}">${esc(igViaS(v))}</b>${hc === 'bad' || hc === 'warn' ? `<i class="igd ${hc}"></i>` : ''}</span>`; }).join('') : '<span class="faint">all direct</span>';
  };
  const allSel = (g) => {
    const v = IG.allSel[g] || '', pl = v && igAllPlan(L, g, v);
    const opts = ['direct', 'warp', 'warp6', 'ipv6', 'proxy'].concat(Array.from({ length: Math.max(0, ...L.map(s => +s.info.proxies || 0)) }, (_, k) => 'proxy' + (k + 1))).filter(o => !(IGWIDE.includes(g) && ['warp6', 'ipv6'].includes(o)));
    return `<span class="mc all${v ? ' chg' : ''}"><select data-all="${g}" aria-label="${esc(IGSV[g])}"><option value="">all…</option>${opts.map(o => `<option value="${o}"${o === v ? ' selected' : ''}>${esc(igViaS(o))}</option>`).join('')}</select></span>${pl ? `<small class="mprev" title="${esc(pl.skip.map(([s, w]) => s.name + ': ' + w).join('\n'))}"><b data-notr>${pl.ch.length}</b> <span>to change</span>${pl.skip.length ? ` · <b data-notr>${pl.skip.length}</b> <span>left as is</span>` : ''}</small>` : ''}`;
  };
  const srvDot = (s) => { const w = IGST[s.info.state] || [s.info.state, 'bad']; return `<i class="igd ${w[1] === 'on' ? 'ok' : w[1] === 'warn' ? 'warn' : w[1] === 'acc' ? 'none' : 'bad'}" title="${esc(w[0])}"></i>`; };
  const P = igPendList(L), nsrv = new Set(P.map(x => x.s.id)).size;
  const R = (IG.runs || {}).routes;
  const lastRun = R ? `<button class="linkb" data-igrlast title="the result of the last Apply"><span>last Apply</span> <span>${esc(igAgo(Date.now() / 1000 - (R.end || R.at)))}</span> ${igRunSum(R)}</button>` : '';
  const head = `<div class="mhead"><span class="mlegend"><span><i class="igd ok"></i>works</span><span><i class="igd bad"></i>fails</span><span><i class="igd none"></i>not checked</span><span><i class="igd pend"></i>not applied yet</span></span><span class="grow"></span>${lastRun}
    <button class="btn sm" data-igmore>${more ? 'Fewer services' : 'All services'}</button></div>`;
  const bar = P.length ? `<div class="mbar"><span><b data-notr>${P.length}</b> <span>${P.length > 1 ? 'changes' : 'change'}</span> · <b data-notr>${nsrv}</b> <span>${nsrv > 1 ? 'servers' : 'server'}</span></span><span class="grow"></span><button class="btn sm" data-igreset>Reset</button><button class="btn sm pri" data-igrev>Review & apply</button></div>` : '';
  const offTxt = off.length ? `<div class="mdesc"><span>Not in the table (offline or no agent):</span> <span data-notr>${esc(off.map(s => s.name).join(', '))}</span></div>` : '';
  if (phone) {
    box.innerHTML = `<div class="card pad mat mlist">${head}
      <details class="mall"${Object.values(IG.allSel).some(Boolean) ? ' open' : ''}><summary>Set one service on every server</summary><div class="mrows">${cols.map(g => `<div class="mrow"><span class="ml">${IGSHORT[g][0]} ${esc(IGSV[g])}</span><span class="mv">${allSel(g)}</span></div>`).join('')}</div></details>
      ${L.map(s => `<div class="msrv${IG.pend[s.id] ? ' chg' : ''}"><div class="mname">${srvDot(s)}<b data-notr>${esc(s.name)}</b> ${igOwner(s)}</div><div class="mrows">${cols.map(g => `<div class="mrow"><span class="ml">${IGSHORT[g][0]} ${esc(IGSV[g])}</span><span class="mv">${cell(s, g)}</span></div>`).join('')}
        ${more ? '' : `<div class="mrow"><span class="ml faint">Others</span><span class="mv mrestc">${rest(s)}</span></div>`}</div></div>`).join('')}
      ${offTxt}${bar}</div>`;
  } else {
    box.innerHTML = `<div class="card pad mat">${head}<div class="mscroll"><table class="mtab"><thead><tr><th class="ms">Server</th>${cols.map(g => `<th title="${esc(IGSV[g])}"><span class="mi">${IGSHORT[g][0]}</span> ${esc(IGSHORT[g][1])}</th>`).join('')}${more ? '' : `<th title="${esc(IGWIDE.map(g => IGSV[g]).join(' · '))}">Others</th>`}</tr></thead><tbody>
      <tr class="mallr"><th class="ms">All servers →</th>${cols.map(g => `<td>${allSel(g)}</td>`).join('')}${more ? '' : '<td></td>'}</tr>
      ${L.map(s => `<tr${IG.pend[s.id] ? ' class="chg"' : ''}><th class="ms">${srvDot(s)}<b data-notr>${esc(s.name)}</b>${isAdmin() && s.owner ? ` <small class="faint" data-notr>${esc(s.owner)}</small>` : ''}</th>${cols.map(g => `<td>${cell(s, g)}</td>`).join('')}${more ? '' : `<td class="mrestc">${rest(s)}</td>`}</tr>`).join('')}</tbody></table></div>
      ${offTxt}${bar}</div>`;
  }
  const redraw = () => { const y = scrollY; igMatrix(box); scrollTo(0, y); };
  $$('select[data-s]', box).forEach(x => x.onchange = () => { const s = L.find(s => s.id === x.dataset.s); igPendSet(s, x.dataset.g, x.value); redraw(); });
  $$('select[data-all]', box).forEach(x => x.onchange = () => {
    const g = x.dataset.all, v = x.value; IG.allSel[g] = v;
    // back to "all…": the column's changes are undone; a value: every server that can take it gets it
    L.forEach(s => igPendSet(s, g, v && igMatOpts(s, g, '').includes(v) ? v : igMatCur(s, g)));
    redraw();
  });
  $$('[data-igmore]', box).forEach(b => b.onclick = () => { remember('tp-igmore', more ? '' : '1'); redraw(); });
  $$('[data-igreset]', box).forEach(b => b.onclick = () => { IG.pend = {}; IG.allSel = {}; redraw(); });
  $$('[data-igrev]', box).forEach(b => b.onclick = () => igMatReview(L, box));
  $$('[data-igrlast]', box).forEach(b => b.onclick = () => igResults(R.job, 'Route changes', { stored: R }));
  if (!IG.runs) igRunsLoad().then(() => { if (IG.sub === 'matrix' && box.isConnected && IG.runs.routes) redraw(); });
  if (!IG.mqWired) { IG.mqWired = true; matchMedia('(max-width: 720px)').addEventListener('change', () => { if (STATE.view === 'igproxy' && !IG.cur && IG.sub === 'matrix') igRender(); }); }
}
// the changes, grouped by server, before they go out
function igMatReview(L, box) {
  const P = igPendList(L), by = [];
  P.forEach(x => { const b = by.find(b => b.s === x.s); b ? b.l.push(x) : by.push({ s: x.s, l: [x] }); });
  const warn = (x) => { const [hc, ht] = igCellHealth(x.s, x.g, x.v); return hc === 'bad' ? `<small class="bad">${esc(ht)}</small>` : ''; };
  const m = modal(`<h2>Apply route changes</h2>
    <div class="igrv">${by.map(b => `<div class="igrv-s"><b data-notr>${esc(b.s.name)}</b>${b.l.map(x => `<div class="igrv-r"><span class="igrv-g">${IGSHORT[x.g][0]} ${esc(IGSV[x.g])}</span><span class="${igViaC(igMatCur(x.s, x.g))}">${esc(igViaS(igMatCur(x.s, x.g)))}</span><span class="faint">→</span><b class="${igViaC(x.v)}">${esc(igViaS(x.v))}</b>${warn(x)}</div>`).join('')}</div>`).join('')}</div>
    <p class="muted" style="font-size:12.5px">Each server's router restarts for a few seconds per change. Afterwards every server is read again and each change is checked against what the agent really uses.</p>
    <div class="actions" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="igrvno">Cancel</button><button class="btn pri" id="igrvgo">Apply</button></div>`, true);
  $('#igrvno', m).onclick = () => m.remove();
  $('#igrvgo', m).onclick = async () => {
    const b = $('#igrvgo', m); if (b.disabled) return; b.disabled = true;
    let r; try { r = await api('/igproxy/routes', { changes: P.map(x => ({ srv: x.s.id, svc: x.g, via: x.v })) }); } catch (e) { b.disabled = false; return toast(e.message); }
    m.remove(); IG.pend = {}; IG.allSel = {};
    igResults(r.job, 'Route changes', { onDone: () => { igRunsLoad(); igLoad(true); } });
    if (box.isConnected) igMatrix(box);
  };
}

// ---- one panel for the result of a job over several servers: a row per server (✓ / ! / ✕ and what
// it did, its own lines a click away), progress while it runs; the whole log is still one click away.
// The job's lines: ">> N servers", then per server "== name", its output, "<< ✓ name — what it did".
function igParseRun(lines) {
  const R = { total: 0, rows: [], post: [] };
  let cur = null;
  lines.forEach(l => {
    let m;
    if ((m = /^>> (\d+) servers?$/.exec(l))) { R.total = +m[1]; return; }
    if ((m = /^== (.+)$/.exec(l)) && m[1] !== 'Summary') { cur = { name: m[1], st: '', say: '', lines: [] }; R.rows.push(cur); return; }
    if ((m = /^<< (✓|!|✕|–) (.+?)(?: — ([\s\S]*))?$/.exec(l))) {
      let row = cur && cur.name === m[2] ? cur : R.rows.find(r => r.name === m[2] && !r.st);
      if (!row) { row = { name: m[2], lines: [] }; R.rows.push(row); }
      row.st = { '✓': 'ok', '!': 'warn', '✕': 'fail', '–': 'skip' }[m[1]]; row.say = m[3] || ''; cur = null; return;
    }
    if (!l.trim()) return;
    if (cur) cur.lines.push(l); else if (R.rows.length) R.post.push(l);
  });
  return R;
}
const IGRST = { ok: ['ok', '✓'], warn: ['warn', '!'], fail: ['bad', '✕'], skip: ['none', '–'] };
const igRunSum = (r) => {
  if (r.status === 'running') return '<span class="rsum"><span class="acc">running…</span></span>';
  const c = { ok: 0, warn: 0, fail: 0, skip: 0 }; (r.res || []).forEach(x => { c[x.st] = (c[x.st] || 0) + 1; });
  return `<span class="rsum">${c.ok ? `<span class="ok" title="done">✓<b data-notr>${c.ok}</b></span>` : ''}${c.warn ? `<span class="warn" title="needs a look">!<b data-notr>${c.warn}</b></span>` : ''}${c.fail ? `<span class="bad" title="failed">✕<b data-notr>${c.fail}</b></span>` : ''}${c.skip ? `<span class="faint" title="nothing to do there">–<b data-notr>${c.skip}</b></span>` : ''}${r.status === 'cancelled' ? '<span class="faint">stopped</span>' : ''}</span>`;
};
async function igRunsLoad() { try { IG.runs = await api('/igproxy/runs'); } catch (e) { IG.runs = IG.runs || {}; } return IG.runs; }
function igResults(jobId, title, opt = {}) {
  const d = h(`<div class="drawer igres"><div class="panel"><div class="dh"><div class="igr-t"><span class="pill acc" id="irst"><span class="led"></span>running…</span><b>${esc(title)}</b></div>
    <div class="actions"><button class="btn sm" id="ircopy" title="Copy the output">⧉</button><button class="btn danger sm" id="irstop" title="Stop the job (servers already done stay done)">Stop the job</button><button class="btn sm" id="irclose">Close ✕</button></div></div>
    <div class="igr-prog" id="irprog"></div><div class="igr-body"><div id="irrows" class="igr-rows"></div><div id="irpost"></div>
    <details class="igr-raw"><summary>The whole log</summary><div class="logbox" id="irlog"></div></details></div></div></div>`);
  document.body.appendChild(d);
  let closed = false, txt = '', fails = 0, last = [[], 'running'];
  const open = new Set();
  const close = () => { if (closed) return; closed = true; d.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  $('#irclose', d).onclick = close; d.onclick = (e) => { if (e.target === d) close(); };
  $('#ircopy', d).onclick = (e) => copy(txt, e.target);
  $('#irstop', d).onclick = () => api('/jobs/cancel', { ID: jobId }).catch(e => toast(e.message));
  $('#irrows', d).onclick = (e) => { const b = e.target.closest('.igr-h'); if (!b) return; const k = +b.parentElement.dataset.k; open.has(k) ? open.delete(k) : open.add(k); draw(...last); };
  const draw = (ls, status) => {
    last = [ls, status]; txt = ls.join('\n');
    const R = igParseRun(ls), running = status === 'running';
    const done = R.rows.filter(r => r.st).length, total = R.total || R.rows.length;
    $('#irprog', d).innerHTML = total ? `<div class="igr-bar"><i style="width:${Math.round(100 * done / Math.max(1, total))}%"></i></div><span class="igr-n"><b data-notr>${done}</b> / <b data-notr>${total}</b> <span>servers</span></span>` : '';
    $('#irrows', d).innerHTML = R.rows.map((r, k) => {
      const st = r.st ? IGRST[r.st] : running ? ['run', '…'] : ['bad', '✕'], say = r.st ? r.say : running ? (r.lines[r.lines.length - 1] || 'running…') : 'did not finish';
      return `<div class="igr-r ${st[0]}${open.has(k) ? ' open' : ''}" data-k="${k}"><button class="igr-h" aria-expanded="${open.has(k)}"><span class="igr-st">${st[1]}</span><b data-notr>${esc(r.name)}</b><span class="igr-say">${esc(say)}</span><span class="igr-c">▸</span></button>
        ${open.has(k) ? `<div class="logbox igr-log">${r.lines.map(l => `<div class="ln ${igColor(l)}">${esc(l)}</div>`).join('') || '<span class="faint">—</span>'}</div>` : ''}</div>`;
    }).join('') || (running ? '<div class="skel" style="height:44px"></div>' : '<div class="faint">No per-server result in this job.</div>');
    $('#irpost', d).innerHTML = R.post.length ? `<div class="igr-post">${R.post.map(l => `<div class="ln ${igColor(l)}">${esc(l)}</div>`).join('')}</div>` : '';
    const lb = $('#irlog', d), stick = lb.scrollTop + lb.clientHeight >= lb.scrollHeight - 30;
    lb.innerHTML = ls.map(l => `<div class="ln ${igColor(l)}">${esc(l) || '&nbsp;'}</div>`).join('');
    if (stick) lb.scrollTop = lb.scrollHeight;
    if (!running) {
      $('#irstop', d)?.remove();
      const bad = R.rows.some(r => r.st === 'fail' || r.st === 'warn' || !r.st);
      $('#irst', d).className = 'pill ' + (status === 'ok' && !bad ? 'on' : status === 'cancelled' ? 'warn' : 'bad');
      $('#irst', d).innerHTML = '<span class="led"></span>' + (status === 'cancelled' ? 'stopped' : status === 'ok' && !bad ? 'finished' : 'finished with problems');
    }
  };
  // a stored run whose job the panel no longer has (restarted, or long ago): its saved rows
  const M = { ok: '✓', warn: '!', fail: '✕', skip: '–' };
  const fromStored = (r) => [`>> ${(r.res || []).length} servers`].concat((r.res || []).flatMap(x => ['== ' + x.name, `<< ${M[x.st] || '✕'} ${x.name}${x.say ? ' — ' + x.say : ''}`]));
  const tick = async () => {
    if (closed) return;
    let j; try { j = await api('/jobs?id=' + jobId); fails = 0; } catch (e) {
      if (closed) return;
      if (opt.stored) { draw(fromStored(opt.stored), opt.stored.status === 'running' ? 'error' : opt.stored.status); $('#irlog', d).insertAdjacentHTML('afterbegin', '<div class="ln">(the full log of this run is gone: the panel restarted or ran many jobs since)</div>'); return; }
      if (++fails < 6) { setTimeout(tick, 2000); return; }
      toast(e.message); $('#irstop', d)?.remove(); $('#irst', d).className = 'pill bad'; $('#irst', d).innerHTML = '<span class="led"></span>no answer from the panel'; return;
    }
    if (closed) return;
    draw(igLines(j), j.status);
    if (j.status !== 'running') { if (opt.onDone) opt.onDone(j); return; }
    setTimeout(tick, 900);
  };
  tick();
}
const igBulkRedraw = () => igRunsLoad().then(() => { if (STATE.view === 'igproxy' && !IG.cur && IG.sub === 'bulk' && $('#igbody')) igBulkDraw($('#igbody')); });
async function igActRes(p, title, onDone) {
  if (p.srv === 'all' && p.view === undefined) p = Object.assign({ view: igView() }, p);
  let r; try { r = await api('/igproxy/action', p); } catch (e) { return toast(e.message); }
  igResults(r.job, title, { onDone: () => { igBulkRedraw(); if (onDone) onDone(); } });
  igBulkRedraw();
}
// before a job that changes servers: the servers it will touch (ticked), the ones it leaves and why
function igBulkConfirm(o) {
  return new Promise(res => {
    const m = modal(`<h2>${o.icon} ${esc(o.title)}</h2><p class="muted" style="font-size:13px;margin-top:0">${esc(o.text)}</p>
      <div class="igbc"><small>Runs on</small>${o.on.map(s => `<label class="igbc-s"><input type="checkbox" value="${esc(s.id)}" checked><b data-notr>${esc(s.name)}</b>${s.note ? `<span class="faint" data-notr>${esc(s.note)}</span>` : ''}</label>`).join('')}</div>
      ${o.left.length ? `<div class="igbc left"><small>Left as they are</small>${o.left.map(([s, w]) => `<div class="igbc-s"><span data-notr>${esc(s.name)}</span><span class="faint">${esc(w)}</span></div>`).join('')}</div>` : ''}
      <div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="igbcno">Cancel</button><button class="btn pri" id="igbcgo">${esc(o.go)}</button></div>`, true);
    const go = $('#igbcgo', m), done = (v) => { m.remove(); res(v); };
    $$('.igbc input', m).forEach(x => x.onchange = () => { go.disabled = !$$('.igbc input:checked', m).length; });
    $('#igbcno', m).onclick = () => done(null);
    $('.mclose', m).onclick = () => done(null);
    go.onclick = () => done($$('.igbc input:checked', m).map(x => x.value));
  });
}

// ---- every server at once: one compact list; each action says when it last ran and what it found,
// the ones that change servers first say which servers they touch
const IGBULK = [
  { id: 'test', act: 'status_short', icon: '🧪', name: 'Test all', hint: 'Tests every proxy and WARP of every server.' },
  { id: 'gem', act: 'gemusers', icon: '👥', name: 'Gemini users', hint: 'Gemini connections of the last 10 minutes, per exit.', p: { n: 10 } },
  { id: 'logs', act: 'logs', icon: '📜', name: 'Logs of all', hint: 'The last 40 igproxy log lines of each server.', p: { n: 40 } },
  { id: 'rotate', act: 'google_rotate', icon: '🔄', name: 'Fresh Google IP everywhere', change: true,
    hint: 'When users complain about Gemini: on each server where Google goes through WARP, it moves to a fresh WARP IP now. The summary at the end says where it moved and where not.' },
  { id: 'deploy', act: 'deploy', icon: '⬆️', name: 'Update old agents', change: true, hint: 'Installs the current agent where an old one runs (a few seconds per server).' },
  { id: 'fix', act: 'panel_fix', icon: '🛠', name: 'Fix panels', change: true, hint: 'Where the x-ui panel diverts Google, adds one rule at the top of its routing.' },
];
const igPanelBad = (s) => s.info.state === 'PANEL' || ['BLOCK', 'AWAY', 'MARK', 'V6', 'SOME'].includes(s.info.panel);
function igBulk(box) {
  igBulkDraw(box);
  igBulkRedraw();
}
function igBulkDraw(box) {
  const L = igList(), runs = IG.runs || {};
  const row = (b) => {
    const r = runs[b.act];
    const last = r ? `<button class="linkb igb-last" data-last="${b.id}" title="open the result">${r.status === 'running' ? '' : `<span>${esc(igAgo(Date.now() / 1000 - (r.end || r.at)))}</span>`} ${igRunSum(r)}</button>` : '<span class="faint igb-last">never run</span>';
    return `<div class="igb-row${b.change ? ' chg' : ''}"><span class="igb-i">${b.icon}</span><div class="igb-d"><b>${esc(b.name)}</b><small title="${esc(b.hint)}">${esc(b.hint)}</small></div>${last}
      <button class="btn sm${b.change ? '' : ' pri'}" data-b="${b.id}">${r && r.status === 'running' ? 'Follow' : b.change ? 'Run…' : 'Run'}</button></div>`;
  };
  box.innerHTML = `<div class="card pad igb"><div class="igb-sec"><small>Read only</small><span class="faint"><span>on every server in view, one after the other</span> · <b data-notr>${L.length}</b></span></div>
    ${IGBULK.filter(b => !b.change).map(row).join('')}
    <div class="igb-sec"><small>Changes servers</small><span class="faint">asks first and shows which servers</span></div>
    ${IGBULK.filter(b => b.change).map(row).join('')}</div>`;
  $$('[data-last]', box).forEach(x => x.onclick = () => { const b = IGBULK.find(b => b.id === x.dataset.last), r = runs[b.act]; igResults(r.job, b.name, { stored: r }); });
  $$('[data-b]', box).forEach(x => x.onclick = () => igBulkRun(IGBULK.find(b => b.id === x.dataset.b)));
}
async function igBulkRun(b) {
  const L = igList(), r = (IG.runs || {})[b.act];
  if (r && r.status === 'running') return igResults(r.job, b.name, { stored: r });
  if (!b.change) return igActRes(Object.assign({ srv: 'all', action: b.act }, b.p || {}), b.name);
  const live = L.filter(s => s.info.ig), on = [], st = (s) => (IGST[s.info.state] || [s.info.state])[0];
  let left = b.id === 'deploy' ? [] : L.filter(s => !s.info.ig).map(s => [s, st(s)]), text = '', extra = {};
  if (b.id === 'rotate') {
    live.forEach(s => /^warp/.test(s.info.google || '') ? on.push({ id: s.id, name: s.name, note: igSet(s.info.gact) ? 'WARP ' + s.info.gact : '' }) : left.push([s, 'Google is not on WARP here']));
    text = 'Gemini chats open on the old IPs are cut and reconnect on the new one. Servers where Google is not on WARP are left as they are.';
  } else if (b.id === 'deploy') {
    L.forEach(s => ['UPDATE', 'NOAGENT'].includes(s.info.state) || s.info.outdated === '1' ? on.push({ id: s.id, name: s.name, note: s.info.sum || '' }) : left.push([s, s.info.ig ? 'runs the current agent' : st(s)]));
    text = 'Each server routes everything direct for a few seconds; settings and WARPs are kept.'; extra = { old: 1 };
  } else if (b.id === 'fix') {
    live.forEach(s => igPanelBad(s) ? on.push({ id: s.id, name: s.name, note: 'x-ui ' + (s.info.panel || '') }) : left.push([s, s.info.panel === 'OK' ? 'its panel passes Google' : 'no x-ui panel']));
    text = "Each panel's Xray restarts for 2-3 seconds.";
  }
  if (!on.length) return toast(b.id === 'rotate' ? 'Google is not on WARP on any server in view — nothing to move' : b.id === 'deploy' ? 'Every server runs the current agent' : 'Every panel lets Google reach igproxy — nothing to fix');
  const ids = await igBulkConfirm({ icon: b.icon, title: b.name, text, on, left, go: b.id === 'rotate' ? 'Move Google' : b.id === 'deploy' ? 'Update' : 'Fix' });
  if (ids && ids.length) igActRes(Object.assign({ srv: ids, action: b.act }, extra), b.name, () => igLoad(true));
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
