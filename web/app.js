"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const STATE = { user: null, methods: [], servers: [], tunnels: [], settings: {}, agentPin: '', view: 'tunnels' };

async function api(path, body, method) {
  const opt = { method: method || (body ? 'POST' : 'GET'), headers: {} };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch('/api' + path, opt);
  const txt = await r.text();
  let data = {}; try { data = txt ? JSON.parse(txt) : {}; } catch (e) { data = { error: txt }; }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}
function toast(msg) { const t = h(`<div class="toast">${esc(msg)}</div>`); document.body.appendChild(t); setTimeout(() => t.remove(), 2800); }
function copy(text, el) {
  const done = () => { if (el) { const o = el.textContent; el.textContent = 'Copied'; setTimeout(() => el.textContent = o, 1200); } };
  if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done) { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); } catch (e) {} t.remove(); done && done(); }

/* ---------------- boot ---------------- */
async function boot() {
  try {
    const s = await api('/setup-state');
    document.title = s.panelName || 'Tunnel Panel';
    if (!s.configured) return renderAuth('register', s.panelName);
    const me = await api('/me');
    if (!me.user) return renderAuth('login', s.panelName);
    STATE.user = me.user;
    await loadAll();
    renderShell();
  } catch (e) { renderAuth('login'); }
}
async function loadAll() {
  const [methods, servers, tunnels, settings] = await Promise.all([
    api('/methods'), api('/servers'), api('/tunnels'), api('/settings')]);
  STATE.methods = methods; STATE.servers = servers; STATE.tunnels = tunnels;
  STATE.settings = settings.settings; STATE.agentPin = settings.agentPin; STATE.agentPort = settings.agentPort;
}
const iranServers = () => STATE.servers.filter(s => (s.role || 'iran') === 'iran');
const foreignServers = () => STATE.servers.filter(s => s.role === 'foreign');
const methodsFor = (fam) => STATE.methods.filter(m => m.families.includes(fam));
const serverById = (id) => STATE.servers.find(s => s.id === id);
const serverName = (id) => id ? (serverById(id)?.name || '(deleted)') : 'this panel host';
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
function renderAuth(mode, name) {
  const reg = mode === 'register';
  document.body.innerHTML = '';
  const el = h(`<div class="auth"><div class="card">
    <div class="brand"><div class="dot"></div><div><b>${esc(name || 'Tunnel Panel')}</b><small>server link manager</small></div></div>
    <h2 style="text-align:center;margin-bottom:6px">${reg ? 'Create admin account' : 'Sign in'}</h2>
    <p class="muted" style="text-align:center;margin:0 0 18px">${reg ? 'First run — set your panel login.' : 'Enter your credentials.'}</p>
    <form class="ff" id="af">
      <label class="f">Username<input name="u" autocomplete="username" required></label>
      <label class="f">Password<input name="p" type="password" autocomplete="${reg ? 'new-password' : 'current-password'}" required></label>
      <button class="btn pri" style="justify-content:center;padding:11px">${reg ? 'Create account' : 'Sign in'}</button>
      <div id="aerr" style="color:var(--crit);min-height:16px;font-size:13px"></div>
    </form></div></div>`);
  document.body.appendChild(el);
  $('#af').onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api(reg ? '/register' : '/login', { username: ev.target.u.value, password: ev.target.p.value }); location.reload(); }
    catch (e) { $('#aerr').textContent = e.message; }
  };
}

/* ---------------- shell ---------------- */
function renderShell() {
  document.body.innerHTML = '';
  const nav = [['tunnels', 'Tunnels', '🛰'], ['servers', 'Servers', '🖥'], ['bench', 'Benchmark', '📊'], ['settings', 'Settings', '⚙']];
  const shell = h(`<div class="shell">
    <aside class="side" id="side">
      <div class="brand"><div class="dot"></div><div><b>${esc(STATE.settings.panelName || 'Tunnel Panel')}</b><small>server link manager</small></div></div>
      <nav class="nav">${nav.map(n => `<button data-v="${n[0]}"><span>${n[2]}</span>${n[1]}</button>`).join('')}</nav>
      <div class="foot">
        <button class="btn ghost sm" id="themeBtn">◐ Theme</button>
        <div class="faint" style="font-size:11px;padding:0 8px">Signed in as <b>${esc(STATE.user)}</b></div>
        <button class="btn ghost sm" id="logout">Sign out</button>
      </div></aside>
    <main class="main" id="work"></main></div>`);
  document.body.appendChild(shell);
  $$('.nav button', shell).forEach(b => b.onclick = () => { STATE.view = b.dataset.v; paintNav(); renderView(); $('#side').classList.remove('open'); });
  $('#logout').onclick = async () => { await api('/logout', {}); location.reload(); };
  $('#themeBtn').onclick = toggleTheme;
  paintNav(); renderView();
}
function paintNav() { $$('.nav button').forEach(b => b.classList.toggle('on', b.dataset.v === STATE.view)); }
function toggleTheme() {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('tp-theme', next); } catch (e) {}
}
try { const t = localStorage.getItem('tp-theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch (e) {}

function renderView() {
  const w = $('#work'); w.innerHTML = '';
  ({ tunnels: viewTunnels, servers: viewServers, bench: viewBench, settings: viewSettings }[STATE.view])(w);
}
function topbar(title, sub, actions) {
  return `<div class="topbar"><div style="display:flex;align-items:center;gap:12px">
    <button class="btn ghost sm menu-toggle" onclick="document.getElementById('side').classList.toggle('open')">☰</button>
    <div><h1>${esc(title)}</h1><p>${esc(sub)}</p></div></div><div class="actions">${actions || ''}</div></div>`;
}
function modal(inner, wide) {
  const m = h(`<div class="modal"><div class="card"${wide ? ' style="max-width:640px"' : ''}>${inner}</div></div>`);
  document.body.appendChild(m);
  m.onclick = (e) => { if (e.target === m) m.remove(); };
  return m;
}
function alertModal(title, msg) {
  const m = modal(`<h2>${esc(title)}</h2><pre class="pre">${esc(msg)}</pre><div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn pri" id="ok">OK</button></div>`);
  $('#ok', m).onclick = () => m.remove();
}
function confirmInline(btn, msg) { if (btn.dataset.armed) return true; btn.dataset.armed = '1'; const o = btn.textContent; btn.textContent = msg; setTimeout(() => { if (btn.isConnected) { btn.textContent = o; delete btn.dataset.armed; } }, 2500); return false; }

/* ---------------- settings ---------------- */
function viewSettings(w) {
  const s = STATE.settings;
  w.innerHTML = topbar('Settings', 'This panel host, downloads, the dial-back agent and Telegram.');
  const card = h(`<div class="grid" style="max-width:660px;gap:16px">
    <form class="card pad ff" id="sf">
      <h3>Panel & this host</h3>
      <label class="f">Panel name<input name="panelName" value="${esc(s.panelName || '')}"></label>
      <div class="two">
        <label class="f">This host · public IPv4<input name="localIPv4" class="mono" value="${esc(s.localIPv4 || '')}"></label>
        <label class="f">This host · public IPv6<input name="localIPv6" class="mono" value="${esc(s.localIPv6 || '')}"></label>
      </div>
      <label class="f">Agent dial-back address <span class="faint">host:port Iran agents connect to (blank = this host's IPv4 : ${STATE.agentPort})</span><input name="agentConnect" class="mono" value="${esc(s.agentConnect || '')}" placeholder="203.0.113.5:${STATE.agentPort}"></label>
      <div class="two">
        <label class="f">FRP version <span class="faint">(blank = latest)</span><input name="frpVersion" class="mono" value="${esc(s.frpVersion || '')}"></label>
        <label class="f">GitHub download prefix<input name="githubProxy" class="mono" value="${esc(s.githubProxy || '')}" placeholder="https://ghproxy.net/"></label>
      </div>
      <h3 style="margin-top:6px">Telegram bot</h3>
      <div class="two">
        <label class="f">Bot token<input name="telegramTok" class="mono" value="${esc(s.telegramTok || '')}" placeholder="123456:ABC..."></label>
        <label class="f">Admin chat id(s)<input name="telegramAdmin" class="mono" value="${esc(s.telegramAdmin || '')}" placeholder="comma-separated"></label>
      </div>
      <div class="faint" style="font-size:12px">Message your bot <b>/start</b>; it replies with your chat id if you're not yet an admin. The bot can start, stop and switch every tunnel.</div>
      <div><button class="btn pri">Save settings</button></div>
    </form>
    <div class="card pad">
      <h3>Agent certificate pin</h3>
      <p class="muted" style="font-size:13px;margin:6px 0">Agents verify the panel with this pin. It never changes unless you delete the panel's agent key.</p>
      <div class="codebox"><code>${esc(STATE.agentPin)}</code></div>
    </div>
    <form class="card pad ff" id="pf">
      <h3>Change password</h3>
      <label class="f">Current<input name="old" type="password" autocomplete="current-password"></label>
      <label class="f">New (min 8)<input name="new" type="password" autocomplete="new-password"></label>
      <div><button class="btn">Update password</button></div>
    </form>
    <div class="card pad" id="helperCard"><h3>Helper binaries</h3><div class="muted" style="font-size:13px">Loading…</div></div>
  </div>`);
  w.appendChild(card);
  $('#sf').onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try { await api('/settings', fd); await loadAll(); toast('Settings saved'); renderView(); } catch (e) { alertModal('Error', e.message); }
  };
  $('#pf').onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try { await api('/password', { Old: fd.old, New: fd.new }); ev.target.reset(); toast('Password updated'); } catch (e) { alertModal('Error', e.message); }
  };
  loadHelpers($('#helperCard', card));
}

async function loadHelpers(card) {
  let list = [];
  try { list = await api('/helpers'); } catch (e) {}
  card.innerHTML = `<h3>Helper binaries</h3>
    <p class="muted" style="font-size:13px;margin:6px 0">Closed binaries the panel uploads to hosts (e.g. the Backhaul Premium core). Upload the amd64/arm64 build once; it is never fetched over HTTP.</p>
    <table class="tbl"><thead><tr><th>name</th><th>source</th><th>size</th></tr></thead><tbody>
    ${list.map(x => `<tr><td class="mono">${esc(x.name)}</td><td>${esc(x.source)}</td><td>${(x.size / 1048576).toFixed(1)} MB</td></tr>`).join('') || '<tr><td colspan=3 class="muted">none</td></tr>'}
    </tbody></table>
    <div class="actions" style="margin-top:12px">
      <input type="text" id="hname" class="inp mono" placeholder="backhaul_premium-amd64" style="flex:1">
      <input type="file" id="hfile" hidden><button class="btn" id="hpick">Choose file</button>
      <button class="btn pri" id="hup" disabled>Upload</button>
    </div><div class="faint" id="hstat" style="font-size:12px;margin-top:6px"></div>`;
  const file = $('#hfile', card); let chosen = null;
  $('#hpick', card).onclick = () => file.click();
  file.onchange = () => { chosen = file.files[0]; if (chosen) { $('#hstat', card).textContent = chosen.name + ' (' + (chosen.size / 1048576).toFixed(1) + ' MB)'; $('#hup', card).disabled = false; if (!$('#hname', card).value) $('#hname', card).value = chosen.name.replace(/[^a-z0-9_.-]/gi, ''); } };
  $('#hup', card).onclick = async () => {
    const name = $('#hname', card).value.trim();
    if (!chosen || !/^[a-z0-9_.-]+-(amd64|arm64)$/.test(name)) { alertModal('Name', 'Name must look like backhaul_premium-amd64 (…-amd64 or …-arm64).'); return; }
    $('#hup', card).disabled = true; $('#hstat', card).textContent = 'Uploading…';
    try {
      const r = await fetch('/api/helpers/upload?name=' + encodeURIComponent(name), { method: 'POST', headers: { 'X-TP-Upload': '1' }, body: chosen });
      if (!r.ok) throw new Error(await r.text());
      toast('Uploaded'); loadHelpers(card);
    } catch (e) { alertModal('Upload failed', e.message); $('#hup', card).disabled = false; }
  };
}

/* ---------------- servers ---------------- */
function viewServers(w) {
  w.innerHTML = topbar('Servers', 'Iran and foreign servers. The panel reaches them by agent, direct SSH, jump or proxy — whichever works.',
    `<button class="btn pri" id="addSrv">+ Add server</button>`);
  const wrap = h(`<div class="grid cards"></div>`);
  if (!STATE.servers.length) wrap.appendChild(h(`<div class="card empty"><div class="big">🖥</div>No servers yet. Add your Iran relay server to begin.</div>`));
  STATE.servers.forEach(s => wrap.appendChild(serverCard(s)));
  w.appendChild(wrap);
  $('#addSrv').onclick = () => serverModal();
  $$('[data-edit]', wrap).forEach(b => b.onclick = () => serverModal(STATE.servers.find(x => x.id === b.dataset.edit)));
  $$('[data-del]', wrap).forEach(b => b.onclick = async () => { if (!confirmInline(b, 'Delete?')) return; try { await api('/servers/delete', { ID: b.dataset.del }); await loadAll(); renderView(); } catch (e) { alertModal('Error', e.message); } });
  $$('[data-test]', wrap).forEach(b => b.onclick = () => testServer(b.dataset.test, b));
  $$('[data-agent]', wrap).forEach(b => b.onclick = () => agentModal(b.dataset.agent));
  $$('[data-bridge]', wrap).forEach(b => b.onclick = () => bridgeModal(b.dataset.bridge));
}
function serverCard(s) {
  const online = s.agentOnline ? `<span class="pill on"><span class="led"></span>agent online</span>`
    : s.prepared ? `<span class="pill ok2"><span class="led"></span>reachable</span>`
    : `<span class="pill off"><span class="led"></span>untested</span>`;
  const roleP = `<span class="pill ${s.role === 'foreign' ? 'acc' : 'neutral'}">${s.role || 'iran'}</span>`;
  return h(`<div class="card pad">
    <div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start"><h3>${s.country ? flag(s.country) + ' ' : ''}${esc(s.name || '(unnamed)')}${s.city ? ` <span class="faint" style="font-weight:400;font-size:12px">${esc(s.city)}</span>` : ''}</h3><div style="display:flex;gap:6px">${roleP}${online}</div></div>
    <div class="mono muted" style="margin:8px 0;font-size:12.5px;line-height:1.7">
      ${s.ipv4 ? `v4 ${esc(s.ipv4)}<br>` : ''}${s.ipv6 ? `v6 ${esc(s.ipv6)}<br>` : ''}
      ssh ${esc(s.sshUser || 'root')}@${esc(s.sshHost || s.ipv4 || s.ipv6 || '?')}:${s.sshPort || 22}
      ${s.proxy ? `<br>proxy ${esc(s.proxy)}` : ''}${s.lastPath ? `<br>last path: ${esc(s.lastPath)}` : ''}${s.arch ? `<br>${esc(s.os || '')} ${esc(s.arch)}` : ''}</div>
    <div class="actions">
      <button class="btn sm" data-test="${s.id}">Test paths</button>
      <button class="btn sm" data-agent="${s.id}">Agent install</button>
      <button class="btn sm" data-bridge="${s.id}">SSH bridge</button>
      <button class="btn sm" data-edit="${s.id}">Edit</button>
      <button class="btn sm danger" data-del="${s.id}">Delete</button>
    </div><div data-paths="${s.id}"></div></div>`);
}
async function testServer(id, btn) {
  btn.disabled = true; const o = btn.textContent; btn.textContent = 'Testing…';
  const box = $(`[data-paths="${id}"]`);
  try {
    const r = await api('/servers/test', { ID: id });
    box.innerHTML = `<div class="paths">${r.paths.map(p => `<div class="path ${p.ok ? 'ok' : 'bad'}"><span>${p.ok ? '✓' : '✕'} ${esc(p.path)}</span><span class="faint">${esc(p.info)}</span></div>`).join('')}</div>`;
    if (r.ok) { toast('Best path: ' + r.best); await loadAll(); }
  } catch (e) { alertModal('Test failed', e.message); }
  btn.disabled = false; btn.textContent = o;
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
function serverModal(s) {
  s = s || {};
  const m = modal(`<h2>${s.id ? 'Edit server' : 'Add server'}</h2>
    <form class="ff" id="srvf">
      <div class="two">
        <label class="f">Name<input name="name" value="${esc(s.name || '')}" required></label>
        <label class="f">Role<select name="role"><option value="iran"${s.role === 'foreign' ? '' : ' selected'}>Iran (relay entry)</option><option value="foreign"${s.role === 'foreign' ? ' selected' : ''}>Foreign (exit)</option></select></label>
      </div>
      <div class="two">
        <label class="f">Public IPv4<input name="ipv4" class="mono" value="${esc(s.ipv4 || '')}"></label>
        <label class="f">Public IPv6<input name="ipv6" class="mono" value="${esc(s.ipv6 || '')}"></label>
      </div>
      <div class="two">
        <label class="f">SSH host <span class="faint">(blank=IPv4)</span><input name="sshHost" class="mono" value="${esc(s.sshHost || '')}"></label>
        <label class="f">SSH port<input name="sshPort" type="number" class="mono" value="${s.sshPort || 22}"></label>
      </div>
      <div class="two"><label class="f">SSH user<input name="sshUser" class="mono" value="${esc(s.sshUser || 'root')}"></label><label class="f">Country <span class="faint">(auto; 2-letter override)</span><input name="country" class="mono" maxlength="2" value="${esc(s.country || '')}" placeholder="auto"></label></div>
      <label class="f">Password <span class="faint">(leave blank to keep)</span><input name="password" type="password" value="${esc(s.password || '')}"></label>
      <label class="f">or Private key (PEM)<textarea name="privateKey" rows="2" class="mono">${esc(s.privateKey || '')}</textarea></label>
      <details><summary class="muted" style="font-size:13px;cursor:pointer">Advanced reach options</summary>
        <div class="ff" style="margin-top:10px">
          <label class="f">Proxy for SSH <span class="faint">socks5:// or http://</span><input name="proxy" class="mono" value="${esc(s.proxy || '')}"></label>
          <label class="f">Force jump via<select name="via"><option value="">auto (try all servers)</option>${STATE.servers.filter(x => x.id !== s.id).map(x => `<option value="${x.id}"${s.via === x.id ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}</select></label>
        </div></details>
      <div class="actions" style="justify-content:flex-end"><button type="button" class="btn ghost" id="cancel">Cancel</button><button class="btn pri">Save</button></div>
    </form>`, true);
  $('#cancel', m).onclick = () => m.remove();
  $('#srvf', m).onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    fd.sshPort = parseInt(fd.sshPort || '22', 10);
    if (s.id) fd.ID = s.id;
    try { await api('/servers', fd); m.remove(); await loadAll(); renderView(); toast('Server saved'); } catch (e) { alertModal('Error', e.message); }
  };
}

/* ---------------- tunnels ---------------- */
function viewTunnels(w) {
  w.innerHTML = topbar('Tunnels', 'One card per route. Pick a connection method and switch any time.',
    `<button class="btn pri" id="addTun"${iranServers().length ? '' : ' disabled title="Add an Iran server first"'}>+ New tunnel</button>`);
  const grid = h(`<div class="grid tgrid"></div>`);
  if (!STATE.tunnels.length) grid.appendChild(h(`<div class="card empty"><div class="big">🛰</div>No tunnels yet.${iranServers().length ? '' : ' Add an Iran server first, then'} create a tunnel.</div>`));
  STATE.tunnels.forEach(t => grid.appendChild(tunnelCard(t)));
  w.appendChild(grid);
  $('#addTun').onclick = () => { if (iranServers().length) tunnelModal(); };
}
function tunnelCard(t) {
  const avail = methodsFor(t.family);
  const active = STATE.methods.find(m => m.id === t.active);
  const sel = (t.selected && avail.find(m => m.id === t.selected)) ? t.selected : (t.active || avail[0]?.id || '');
  const card = h(`<div class="card tcard" data-id="${t.id}">
    <div class="hd">
      <div><h3>${esc(t.name)}</h3>
        <div class="route"><span class="node">${serverFlag(t.serverId)}${esc(serverName(t.serverId))}</span><span class="arrow">⇄</span><span class="node">${serverFlag(t.foreignId)}${esc(serverName(t.foreignId))}</span><span class="pill ${t.family === 'v6' ? 'acc' : 'neutral'}">${t.family}</span></div></div>
      <div>${active ? `<span class="pill on"><span class="led"></span>${esc(active.title)}</span>` : `<span class="pill off"><span class="led"></span>stopped</span>`}</div>
    </div>
    <div class="body">
      <div class="statline"><span>Ports <b class="mono">${esc(t.ports)}</b></span><span>Iran <b data-ir>—</b></span><span>Foreign <b data-fg>—</b></span></div>
      <div class="method-row"><select data-method>${avail.map(m => `<option value="${m.id}"${m.id === sel ? ' selected' : ''}>${esc(m.title)} · ${esc(m.encrypt)}</option>`).join('')}</select><button class="btn sm" data-opts title="Options">⚙</button></div>
      <div class="mdesc" data-desc></div>
      <div data-optbox hidden></div>
      <div class="actions">
        <button class="btn pri sm" data-apply></button>
        <button class="btn sm" data-stop ${t.active ? '' : 'disabled'}>Stop</button>
        <button class="btn sm" data-log>Logs</button>
        <button class="btn ghost sm" data-edit>Edit</button>
        <button class="btn ghost sm danger" data-del>Delete</button>
      </div></div></div>`);
  const selEl = $('[data-method]', card), descEl = $('[data-desc]', card), optBox = $('[data-optbox]', card), applyBtn = $('[data-apply]', card);
  const refresh = () => { const m = STATE.methods.find(x => x.id === selEl.value); descEl.textContent = m ? m.desc : ''; applyBtn.textContent = (t.active === selEl.value) ? 'Re-apply' : (t.active ? 'Switch to this' : 'Start'); };
  selEl.onchange = () => { optBox.hidden = true; refresh(); saveTunnel(t, { selected: selEl.value }); };
  refresh();
  $('[data-opts]', card).onclick = () => { if (!optBox.hidden) { optBox.hidden = true; return; } renderOpts(optBox, t, selEl.value); optBox.hidden = false; };
  applyBtn.onclick = async () => { applyBtn.disabled = true; try { const r = await api('/tunnels/apply', { ID: t.id, Method: selEl.value }); openLog(t, r.job); } catch (e) { alertModal('Error', e.message); applyBtn.disabled = false; } };
  $('[data-stop]', card).onclick = async () => { try { const r = await api('/tunnels/stop', { ID: t.id }); openLog(t, r.job); } catch (e) { alertModal('Error', e.message); } };
  $('[data-log]', card).onclick = () => openLog(t, null);
  $('[data-edit]', card).onclick = () => tunnelModal(t);
  $('[data-del]', card).onclick = async (e) => { if (!confirmInline(e.target, 'Confirm delete')) return; try { await api('/tunnels/delete', { ID: t.id }); await loadAll(); renderView(); } catch (er) { alertModal('Error', er.message); } };
  refreshStatus(t, card);
  return card;
}
async function refreshStatus(t, card) {
  if (!t.active) { $('[data-ir]', card).textContent = '—'; $('[data-fg]', card).textContent = '—'; return; }
  try {
    const r = await api('/tunnels/status?id=' + t.id);
    const paint = (el, v) => { el.textContent = v; el.style.color = v === 'active' ? 'var(--good)' : (v === 'stopped' || v === '—' ? 'var(--faint)' : 'var(--crit)'); };
    paint($('[data-ir]', card), r.iran); paint($('[data-fg]', card), r.foreign);
  } catch (e) {}
}
async function saveTunnel(t, patch) {
  const body = { ID: t.id, name: t.name, serverId: t.serverId, foreignId: t.foreignId, family: t.family, ports: t.ports, note: t.note, ...patch };
  try { await api('/tunnels/save', body); Object.assign(t, patch); } catch (e) {}
}
function renderOpts(box, t, mid) {
  const m = STATE.methods.find(x => x.id === mid);
  if (!m || !m.fields?.length) { box.innerHTML = `<div class="opts one"><div class="muted">No options for this method.</div></div>`; return; }
  const saved = (t.options && t.options[mid]) || {};
  box.innerHTML = `<div class="opts${m.fields.length < 2 ? ' one' : ''}">${m.fields.map(f => {
    const v = saved[f.key] !== undefined ? saved[f.key] : f.default;
    if (f.type === 'bool') return `<label class="row f" style="grid-column:1/-1"><input type="checkbox" data-k="${f.key}"${String(v) === 'true' ? ' checked' : ''}> ${esc(f.label)}</label>`;
    if (f.type === 'select') return `<label class="f">${esc(f.label)}<select data-k="${f.key}">${f.options.map(o => `<option${o === v ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select></label>`;
    return `<label class="f">${esc(f.label)}${f.help ? ` <span class="faint">${esc(f.help)}</span>` : ''}<input data-k="${f.key}" class="mono" value="${esc(v)}"></label>`;
  }).join('')}<div style="grid-column:1/-1;display:flex;justify-content:flex-end"><button class="btn sm pri" data-save>Save options</button></div></div>`;
  $('[data-save]', box).onclick = async () => {
    const opts = {}; $$('[data-k]', box).forEach(el => opts[el.dataset.k] = el.type === 'checkbox' ? String(el.checked) : el.value);
    try { await api('/tunnels/save', { ID: t.id, name: t.name, serverId: t.serverId, foreignId: t.foreignId, family: t.family, ports: t.ports, note: t.note, options: { [mid]: opts } }); await loadAll(); renderView(); toast('Options saved'); } catch (e) { alertModal('Error', e.message); }
  };
}
function tunnelModal(t) {
  t = t || {};
  const sh = t.shape || {};
  const foreignOpts = `<option value="">this panel host</option>` + foreignServers().map(s => `<option value="${s.id}"${t.foreignId === s.id ? ' selected' : ''}>${esc(serverLabel(s))}</option>`).join('');
  const m = modal(`<h2>${t.id ? 'Edit tunnel' : 'New tunnel'}</h2>
    <form class="ff" id="tf">
      <label class="f">Name<input name="name" value="${esc(t.name || '')}" required></label>
      <div class="two">
        <label class="f">Iran server<select name="serverId" required>${iranServers().map(s => `<option value="${s.id}"${s.id === t.serverId ? ' selected' : ''}>${esc(serverLabel(s))}</option>`).join('')}</select></label>
        <label class="f">Foreign server<select name="foreignId">${foreignOpts}</select></label>
      </div>
      <div class="two">
        <label class="f">Address family<select name="family"><option value="v4"${t.family === 'v6' ? '' : ' selected'}>IPv4 underlay</option><option value="v6"${t.family === 'v6' ? ' selected' : ''}>IPv6 underlay</option></select></label>
        <label class="f">Ports <span class="faint">443,8080=80,2000-2010</span><input name="ports" class="mono" value="${esc(t.ports || '443')}"></label>
      </div>
      <label class="f">Note<input name="note" value="${esc(t.note || '')}"></label>
      <details${sh.enabled ? ' open' : ''}><summary class="muted" style="font-size:13px;cursor:pointer">Traffic shaping / link tuning</summary>
        <div class="ff" style="margin-top:10px;padding:12px;background:var(--panel-2);border-radius:10px">
          <label class="row f"><input type="checkbox" id="shEnabled"${sh.enabled ? ' checked' : ''}> Enable shaping on the Iran egress (CAKE/HTB/… qdisc)</label>
          <div class="two">
            <label class="f">Queue discipline<select id="shQdisc">${['cake', 'htb', 'tbf', 'fq_codel'].map(q => `<option${sh.qdisc === q ? ' selected' : ''}>${q}</option>`).join('')}</select></label>
            <label class="f">MSS clamp <span class="faint">(0 = off)</span><input id="shMss" type="number" class="mono" value="${sh.mss || 0}"></label>
          </div>
          <label class="f">Egress interface <span class="faint">(blank = default route)</span><input id="shIface" class="mono" value="${esc(sh.iface || '')}"></label>
          <label class="row f"><input type="checkbox" id="shJitter"${sh.jitter ? ' checked' : ''}> Add timing jitter (netem)</label>
          <label class="row f"><input type="checkbox" id="shBoth"${sh.onBoth ? ' checked' : ''}> Also shape the foreign egress</label>
          <div class="faint" style="font-size:12px">Applied as a separate systemd unit after the tunnel starts. Change takes effect on the next Start/Switch.</div>
        </div></details>
      <div class="muted" style="font-size:12px">Users hit the Iran server on these ports; traffic is forwarded to the foreign server over the tunnel.</div>
      <div class="actions" style="justify-content:flex-end"><button type="button" class="btn ghost" id="cancel">Cancel</button><button class="btn pri">Save</button></div>
    </form>`, true);
  $('#cancel', m).onclick = () => m.remove();
  $('#tf', m).onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    if (t.id) fd.ID = t.id;
    fd.shape = {
      enabled: $('#shEnabled', m).checked, qdisc: $('#shQdisc', m).value,
      mss: parseInt($('#shMss', m).value || '0', 10), iface: $('#shIface', m).value.trim(),
      jitter: $('#shJitter', m).checked, onBoth: $('#shBoth', m).checked,
    };
    try { await api('/tunnels/save', fd); m.remove(); await loadAll(); renderView(); toast('Tunnel saved'); } catch (e) { alertModal('Error', e.message); }
  };
}

/* ---------------- benchmark ---------------- */
function viewBench(w) {
  w.innerHTML = topbar('Route benchmark', 'Measure every method between two servers — latency, jitter, loss and throughput — and get a recommendation.');
  const card = h(`<div class="grid" style="gap:16px">
    <form class="card pad ff" id="bf" style="max-width:640px">
      <div class="two">
        <label class="f">Iran server<select name="iran">${iranServers().map(s => `<option value="${s.id}">${esc(serverLabel(s))}</option>`).join('')}</select></label>
        <label class="f">Foreign server<select name="foreign"><option value="">this panel host</option>${foreignServers().map(s => `<option value="${s.id}">${esc(serverLabel(s))}</option>`).join('')}</select></label>
      </div>
      <div class="two">
        <label class="f">Family<select name="family"><option value="v4">IPv4</option><option value="v6">IPv6</option></select></label>
        <label class="f">Throughput probe (s)<input name="seconds" type="number" class="mono" value="5"></label>
      </div>
      <div class="faint" style="font-size:12px">Each method is deployed on a temporary tunnel, measured, then removed. This takes a few minutes and briefly uses bandwidth.</div>
      <div><button class="btn pri">Run benchmark</button></div>
    </form>
    <div id="bres"></div></div>`);
  w.appendChild(card);
  $('#bf').onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try { const r = await api('/bench/start', { iranId: fd.iran, foreignId: fd.foreign, family: fd.family, seconds: parseInt(fd.seconds || '5', 10) }); benchLog(fd, r.job); }
    catch (e) { alertModal('Error', e.message); }
  };
}
function benchLog(fd, job) {
  const box = $('#bres'); box.innerHTML = `<div class="card pad"><h3>Running…</h3><div class="logbox" id="blog" style="height:220px"></div></div>`;
  const log = $('#blog');
  const tick = async () => {
    try {
      const j = await api('/jobs?id=' + job);
      log.innerHTML = j.lines.map(l => `<div class="ln ${/ERROR/.test(l) ? 'err' : /DONE|best/.test(l) ? 'ok' : ''}">${esc(l)}</div>`).join('');
      log.scrollTop = log.scrollHeight;
      if (j.status !== 'running') { clearInterval(iv); showBenchResults(fd); }
    } catch (e) {}
  };
  const iv = setInterval(tick, 1200); tick();
}
async function showBenchResults(fd) {
  let res = [];
  try { res = await api(`/bench/results?iran=${fd.iran}&foreign=${fd.foreign || ''}&family=${fd.family}`); } catch (e) {}
  const box = $('#bres');
  const rows = res.map(r => `<tr class="${r.recommended ? 'best' : ''}">
    <td>${r.recommended ? '★ ' : ''}${esc(r.title)}</td>
    <td>${r.ok ? r.mbps.toFixed(1) : '—'}</td><td>${r.ok ? r.rttMs.toFixed(1) : '—'}</td>
    <td>${r.ok ? r.jitterMs.toFixed(1) : '—'}</td><td>${r.ok ? r.lossPct.toFixed(0) + '%' : '—'}</td>
    <td>${r.ok ? r.score.toFixed(0) : esc((r.error || '').slice(0, 40))}</td>
    <td>${r.ok ? `<button class="btn sm pri" data-use="${r.method}">Apply to tunnel</button>` : ''}</td></tr>`).join('');
  box.innerHTML = `<div class="card pad"><h3>Results</h3>
    <table class="tbl bench"><thead><tr><th>method</th><th>Mbps</th><th>RTT ms</th><th>jitter</th><th>loss</th><th>score</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan=7 class="muted">no results</td></tr>'}</tbody></table></div>`;
  $$('[data-use]', box).forEach(b => b.onclick = () => applyBenchToTunnel(fd, b.dataset.use));
}
function applyBenchToTunnel(fd, method) {
  const opts = STATE.tunnels.filter(t => t.serverId === fd.iran && (t.foreignId || '') === (fd.foreign || '') && t.family === fd.family);
  if (!opts.length) { alertModal('No tunnel', 'Create a tunnel for this exact route first, then apply the method from its card.'); return; }
  const m = modal(`<h2>Apply ${esc(methodTitle(method))}</h2><p class="muted">Pick the tunnel to switch to this method:</p>
    <div class="ff">${opts.map(t => `<button class="btn" data-t="${t.id}">${esc(t.name)}</button>`).join('')}</div>`, true);
  $$('[data-t]', m).forEach(b => b.onclick = async () => { try { const r = await api('/tunnels/apply', { ID: b.dataset.t, Method: method }); m.remove(); STATE.view = 'tunnels'; paintNav(); renderView(); const t = STATE.tunnels.find(x => x.id === b.dataset.t); openLog(t, r.job); } catch (e) { alertModal('Error', e.message); } });
}
const methodTitle = (id) => STATE.methods.find(m => m.id === id)?.title || id;

/* ---------------- log drawer ---------------- */
let logTimer = null;
function openLog(t, jobId) {
  closeLog();
  const d = h(`<div class="drawer"><div class="panel">
    <div class="dh"><div><h3>${esc(t.name)}</h3><div class="muted" style="font-size:12px" id="jobstat">${jobId ? 'running…' : 'last job'}</div></div><button class="btn ghost sm" id="closeLog">✕ Close</button></div>
    <div class="logbox" id="logbox"><span class="muted">${jobId ? 'Starting…' : 'Loading last job…'}</span></div></div></div>`);
  document.body.appendChild(d);
  $('#closeLog', d).onclick = closeLog;
  d.onclick = (e) => { if (e.target === d) closeLog(); };
  pollJob(jobId, t.id);
}
function closeLog() { if (logTimer) clearInterval(logTimer); logTimer = null; $$('.drawer').forEach(x => x.remove()); }
async function pollJob(jobId, tunnelId) {
  const box = $('#logbox'), stat = $('#jobstat');
  const url = jobId ? '/jobs?id=' + jobId : '/tunnels/lastjob?id=' + tunnelId;
  const tick = async () => {
    try {
      const j = await api(url);
      box.innerHTML = j.lines.map(l => { let c = /ERROR|failed/.test(l) ? 'err' : /DONE|is active|unit .*active/.test(l) ? 'ok' : /\[IR\]/.test(l) ? 'ir' : ''; return `<div class="ln ${c}">${esc(l)}</div>`; }).join('');
      box.scrollTop = box.scrollHeight;
      if (stat) stat.textContent = j.status === 'running' ? 'running…' : (j.status === 'ok' ? 'completed' : 'error');
      if (j.status !== 'running') { clearInterval(logTimer); logTimer = null; await loadAll(); if (STATE.view === 'tunnels') { const w = $('#work'); if (w && $('.drawer')) { /* keep drawer, repaint behind */ viewTunnels(w); } } }
    } catch (e) { if (!jobId) { box.innerHTML = '<span class="muted">No job yet.</span>'; clearInterval(logTimer); } }
  };
  await tick(); logTimer = setInterval(tick, 1200);
}

boot();
