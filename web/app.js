"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
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
    STATE.user = me.user; STATE.role = me.role || 'admin'; STATE.version = me.version || "";
    await loadAll();
    renderShell();
  } catch (e) { renderAuth('login'); }
}
async function loadAll() {
  const [methods, servers, tunnels, settings, helpers] = await Promise.all([
    api('/methods'), api('/servers'), api('/tunnels'), api('/settings'), api('/helpers').catch(() => [])]);
  STATE.helpers = (helpers || []).map(x => x.name); STATE.hostArch = (settings && settings.hostArch) || 'amd64';
  STATE.methods = methods || []; STATE.tunnels = tunnels || [];
  // a user also gets the admin's servers that carry their tunnels (shared, read-only): they
  // name where a tunnel runs but aren't the user's to manage
  STATE.servers = (servers || []).filter(s => !s.shared); STATE.shared = (servers || []).filter(s => s.shared);
  STATE.settings = (settings && settings.settings) || {}; STATE.agentPin = settings.agentPin || ''; STATE.agentPort = settings.agentPort || 7020;
  STATE.users = isAdmin() ? await api('/users').catch(() => []) : [];
  if (STATE.restored === undefined) { // once per page load: back to the page and account viewed before the refresh
    STATE.restored = true;
    const pg = recall('tp-page');
    if (['tunnels', 'servers', 'routes', 'igproxy', 'bench', 'settings'].includes(pg) || (pg === 'users' && isAdmin())) STATE.view = pg;
    const va = recall('tp-viewas');
    if (isAdmin() && va && (va === '-' || STATE.users.some(u => u.username === va))) STATE.ownerFilter = va;
  }
}
const iranServers = () => STATE.servers.filter(s => (s.role || 'iran') === 'iran');
const foreignServers = () => STATE.servers.filter(s => s.role === 'foreign');
const methodsFor = (fam) => STATE.methods.filter(m => m.families.includes(fam));
// method families, in the order the UI lists them (all Backhaul cores together)
const GROUPS = ['Backhaul', 'BackPack', 'Kernel GRE / IPsec', 'Other'];
const GROUP_ICON = { 'Backhaul': '🚀', 'BackPack': '🎒', 'Kernel GRE / IPsec': '🧩', 'Other': '🔧' };
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
// what a method still needs for this tunnel's two hosts ("" = ready): arch-specific helper binaries
function methodMissing(m, t) {
  if (!m || !m.helper) return '';
  const ir = serverById(t.serverId), fg = t.foreignId ? serverById(t.foreignId) : null;
  const arches = [archOf(ir && ir.arch), fg ? archOf(fg.arch) : STATE.hostArch].filter(Boolean);
  const miss = [...new Set(arches)].filter(a => !(STATE.helpers || []).includes(m.helper + '-' + a));
  return miss.map(a => m.helper + '-' + a).join(', ');
}
const serverById = (id) => STATE.servers.find(s => s.id === id) || (STATE.shared || []).find(s => s.id === id);
// the tunnel's own servers when they're shared ones (the pickers list only the user's servers)
const sharedOpts = (role, cur) => (STATE.shared || []).filter(s => s.id === cur && (s.role || 'iran') === role).map(s => `<option value="${s.id}" selected>${esc(serverLabel(s))} · shared</option>`).join('');
// accounts: the admin sees everything (and can narrow the view to one account); a user only
// ever gets their own servers and tunnels from the panel
const isAdmin = () => STATE.role !== 'user';
// the admin's account filter: '' = everything, '-' = the admin's own, else a username
const shownOwner = (o) => !isAdmin() || !STATE.ownerFilter || (STATE.ownerFilter === '-' ? !o : o === STATE.ownerFilter);
const ownerChip = (o) => isAdmin() && o ? `<span class="chip own" title="belongs to the account ${esc(o)}">👤 ${esc(o)}</span>` : '';
const panelHostOpt = () => isAdmin() ? '<option value="">this panel host</option>' : '';
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
  quantumBg.start();
  wirePasswordUX(el);
  $('#af').onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api(reg ? '/register' : '/login', { username: ev.target.u.value, password: ev.target.p.value, code: reg ? ev.target.c.value : '' }); location.reload(); }
    catch (e) { $('#aerr').textContent = e.message; }
  };
}

/* ---------------- live background: molten core + quantum orbits ---------------- */
// A slowly turning molten globe (an Earth's-core lava texture, rendered per pixel at low
// resolution and scaled up), electron-like quanta on tilted orbits around it that pass
// behind and in front of it, rising embers and faint drifting particles. ≤30 fps,
// paused while the tab is hidden, a still frame for prefers-reduced-motion, toggle in
// the sidebar.
const quantumBg = (() => {
  let cv, ctx, raf = 0, last = 0, W = 0, H = 0, dpr = 1, on = false, time = 0;
  // off unless turned on: a moving, glowing background tires the eyes on a page you watch for hours
  on = false; try { on = localStorage.getItem('tp-bg') === 'on'; } catch (e) {}
  const reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  // ---- molten texture (equirectangular, seamless in longitude) ----
  const TW = 512, TH = 256;
  let tex = null, pal = null;
  const hash = (x, y, s) => { let h = (x * 374761393 + y * 668265263 + s * 982451653) | 0; h = Math.imul(h ^ (h >>> 13), 1274126177); return ((h ^ (h >>> 16)) >>> 0) / 4294967295; };
  const sm = (t) => t * t * (3 - 2 * t);
  function noise(x, y, per, s) {
    const xi = Math.floor(x), yi = Math.floor(y), u = sm(x - xi), v = sm(y - yi), w = (k) => ((k % per) + per) % per;
    const a = hash(w(xi), yi, s), b = hash(w(xi + 1), yi, s), c = hash(w(xi), yi + 1, s), d = hash(w(xi + 1), yi + 1, s);
    return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
  }
  function fbm(x, y, per, s) { let t = 0, amp = .5, f = 1; for (let o = 0; o < 5; o++) { t += amp * noise(x * f, y * f, per * f, s + o); amp *= .5; f *= 2; } return t; }
  function buildTex() {
    tex = new Float32Array(TW * TH);
    for (let j = 0; j < TH; j++) for (let i = 0; i < TW; i++) {
      const x = i / TW, y = j / TH;
      const base = fbm(x * 6, y * 3, 6, 1);
      const r = 1 - Math.abs(2 * fbm(x * 12 + .3, y * 6 + 2, 12, 7) - 1);   // ridges → glowing cracks
      const veins = Math.pow(r, 7);
      // "continents": cooled dark crust plates with glowing cracks, in oceans of lava
      const k = fbm(x * 3, y * 1.5 + 20, 3, 11), cont = sm(Math.min(1, Math.max(0, (k - .47) / .08)));
      const lava = .42 + .42 * base + .45 * veins, crust = .04 + .12 * base + .95 * Math.pow(veins, 1.3);
      const polar = Math.pow(Math.abs(y - .5) * 2, 6) * .25;                  // slightly cooler poles
      tex[j * TW + i] = Math.min(1, Math.max(0, lava + (crust - lava) * cont - polar));
    }
    // black → deep red → orange → gold → white-hot
    const stops = [[0, 8, 2, 0], [.25, 70, 6, 0], [.45, 170, 28, 0], [.62, 240, 90, 8], [.78, 255, 160, 40], [.9, 255, 215, 110], [1, 255, 250, 225]];
    pal = new Uint8ClampedArray(256 * 3);
    for (let k = 0; k < 256; k++) {
      const t = k / 255; let i = 0; while (i < stops.length - 2 && t > stops[i + 1][0]) i++;
      const A = stops[i], B = stops[i + 1], f = (t - A[0]) / (B[0] - A[0]);
      for (let c = 0; c < 3; c++) pal[k * 3 + c] = A[c + 1] + (B[c + 1] - A[c + 1]) * f;
    }
  }
  // ---- globe buffer + per-pixel sphere lookup ----
  let G, g, GS = 0, img, lut, R = 0, cx = 0, cy = 0, rotA = 0, rotB = 0;
  function buildGlobe() {
    GS = W < 700 ? 170 : 240;
    G = document.createElement('canvas'); G.width = G.height = GS; g = G.getContext('2d');
    img = g.createImageData(GS, GS);
    const tilt = -0.41, ct = Math.cos(tilt), st = Math.sin(tilt), L = [];
    for (let py = 0; py < GS; py++) for (let px = 0; px < GS; px++) {
      const nx = (px + .5) / GS * 2 - 1, ny = (py + .5) / GS * 2 - 1, d2 = nx * nx + ny * ny;
      if (d2 >= 1) continue;
      const nz = Math.sqrt(1 - d2), rx = nx * ct - ny * st, ry = nx * st + ny * ct;
      const u = (Math.atan2(rx, nz) / (2 * Math.PI) + .5) * TW, v = (Math.asin(ry) / Math.PI + .5) * (TH - 1);
      const edge = Math.min(1, (1 - Math.sqrt(d2)) * 18);           // anti-aliased rim
      L.push(py * GS + px, u, v, .38 + .62 * Math.pow(nz, .55), edge);
    }
    lut = new Float32Array(L);
  }
  function renderGlobe() {
    const d = img.data, n = lut.length, pulse = .92 + .08 * Math.sin(time * .0011);
    // bilinear sample, wrapping in longitude
    const samp = (u, v) => {
      const x0 = Math.floor(u), y0 = Math.min(TH - 2, Math.floor(v)), fx = u - x0, fy = v - y0;
      const a = ((x0 % TW) + TW) % TW, b = (a + 1) % TW, r0 = y0 * TW, r1 = r0 + TW;
      const t0 = tex[r0 + a] + (tex[r0 + b] - tex[r0 + a]) * fx, t1 = tex[r1 + a] + (tex[r1 + b] - tex[r1 + a]) * fx;
      return t0 + (t1 - t0) * fy;
    };
    for (let k = 0; k < n; k += 5) {
      const p = lut[k] * 4, u = lut[k + 1], v = lut[k + 2], sh = lut[k + 3];
      // the crust drifts with the rotation; a second, faster lava layer churns underneath
      const i1 = samp(u + rotA, v);
      const i2 = samp(u + rotB + TW / 2, TH - 1.001 - v);
      const I = Math.max(i1, i2 * .55 + .1 * i1) * sh * pulse;
      const c = Math.min(255, (I * 255) | 0) * 3;
      d[p] = pal[c]; d[p + 1] = pal[c + 1]; d[p + 2] = pal[c + 2]; d[p + 3] = 255 * lut[k + 4];
    }
    g.putImageData(img, 0, 0);
  }
  // ---- scene objects ----
  let orbits = [], embers = [], dust = [];
  function layout() {
    dpr = Math.min(2, window.devicePixelRatio || 1); W = innerWidth; H = innerHeight;
    cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const narrow = W < 860;
    R = Math.min(W, H) * (narrow ? .3 : .25);
    cx = narrow ? W * .5 : 232 + (W - 232) * .7; cy = H * (narrow ? .64 : .56);
    buildGlobe();
    orbits = [[1.55, .36, -.42, 3, 1], [1.85, .52, .55, 2, -.7], [1.3, .3, 1.32, 2, 1.3]].map(([a, b, tilt, n, sp]) => ({
      a: R * a, b: R * a * b, tilt, sp: sp * .006, q: Array.from({ length: n }, (_, i) => ({ th: i * 6.283 / n + Math.random(), trail: [] })) }));
    dust = Array.from({ length: Math.round(Math.min(40, W * H / 40000)) }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .2, vy: (Math.random() - .5) * .2, ph: Math.random() * 6.3 }));
    embers = [];
  }
  const dark = () => { const t = document.documentElement.getAttribute('data-theme'); return t ? t === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; };
  function frame(ts) {
    raf = requestAnimationFrame(frame);
    if (document.hidden || ts - last < 33) return;
    const dt = Math.min(3, (ts - last) / 16.7); last = ts; time = ts;
    step(dt); draw();
  }
  function step(dt) {
    rotA = (rotA + .2 * dt) % TW; rotB = (rotB + .34 * dt) % TW;
    for (const o of orbits) for (const q of o.q) {
      q.th = (q.th + o.sp * dt * (1 + .4 * Math.sin(q.th * 2))) % 6.2832;
      q.trail.unshift(q.th); if (q.trail.length > 14) q.trail.pop();
    }
    if (embers.length < 46 && Math.random() < .5 * dt) {
      const an = Math.random() * 6.283, r0 = R * (.98 + Math.random() * .05);
      embers.push({ x: cx + Math.cos(an) * r0, y: cy + Math.sin(an) * r0, vx: Math.cos(an) * .35, vy: Math.sin(an) * .35 - .25, life: 1, s: .8 + Math.random() * 1.6 });
    }
    for (const e of embers) { e.x += e.vx * dt; e.y += e.vy * dt; e.vy -= .004 * dt; e.life -= .009 * dt; }
    embers = embers.filter(e => e.life > 0);
    for (const p of dust) { p.x += p.vx * dt; p.y += p.vy * dt; p.ph += .03 * dt; if (p.x < 0) p.x = W; if (p.x > W) p.x = 0; if (p.y < 0) p.y = H; if (p.y > H) p.y = 0; }
  }
  const qpos = (o, th) => { const x = o.a * Math.cos(th), y = o.b * Math.sin(th), c = Math.cos(o.tilt), s = Math.sin(o.tilt); return [cx + x * c - y * s, cy + x * s + y * c, Math.sin(th)]; };
  function drawOrbits(front) {
    ctx.lineWidth = 1.1;
    for (const o of orbits) {
      ctx.strokeStyle = front ? 'rgba(130,200,255,.38)' : 'rgba(130,200,255,.14)';
      ctx.beginPath(); ctx.ellipse(cx, cy, o.a, o.b, o.tilt, front ? 0 : Math.PI, front ? Math.PI : 2 * Math.PI); ctx.stroke();
      for (const q of o.q) {
        const [x, y, z] = qpos(o, q.th);
        if ((z > 0) !== front) continue;
        // probability smear: fading copies along the recent path
        q.trail.forEach((th, i) => {
          const [tx, ty] = qpos(o, th), al = (1 - i / q.trail.length) * .35;
          ctx.fillStyle = `rgba(150,170,255,${al})`; ctx.beginPath(); ctx.arc(tx, ty, 2.4 * (1 - i / q.trail.length) + .6, 0, 6.283); ctx.fill();
        });
        const gr = ctx.createRadialGradient(x, y, 0, x, y, 16);
        gr.addColorStop(0, 'rgba(220,240,255,.95)'); gr.addColorStop(.25, 'rgba(120,190,255,.6)'); gr.addColorStop(1, 'rgba(140,110,255,0)');
        ctx.fillStyle = gr; ctx.beginPath(); ctx.arc(x, y, 16, 0, 6.283); ctx.fill();
      }
    }
  }
  function draw() {
    const A = dark() ? 1 : .62;
    ctx.clearRect(0, 0, W, H);
    ctx.globalAlpha = A;
    // drifting dust, faint links
    for (let i = 0; i < dust.length; i++) {
      const p = dust[i];
      ctx.fillStyle = `rgba(255,150,70,${.18 + .2 * Math.sin(p.ph)})`; ctx.beginPath(); ctx.arc(p.x, p.y, 1.4, 0, 6.283); ctx.fill();
      for (let j = i + 1; j < dust.length; j++) { const q = dust[j], dx = p.x - q.x, dy = p.y - q.y, d2 = dx * dx + dy * dy; if (d2 < 120 * 120) { ctx.strokeStyle = `rgba(255,140,60,${(1 - Math.sqrt(d2) / 120) * .12})`; ctx.beginPath(); ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke(); } }
    }
    // heat haze around the core
    let gr = ctx.createRadialGradient(cx, cy, R * .6, cx, cy, R * 2.3);
    gr.addColorStop(0, 'rgba(255,110,20,.34)'); gr.addColorStop(.45, 'rgba(200,40,0,.12)'); gr.addColorStop(1, 'rgba(120,0,0,0)');
    ctx.fillStyle = gr; ctx.fillRect(cx - R * 2.4, cy - R * 2.4, R * 4.8, R * 4.8);
    drawOrbits(false);
    renderGlobe();
    ctx.imageSmoothingEnabled = true; ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(G, cx - R, cy - R, R * 2, R * 2);
    // glowing rim (corona)
    gr = ctx.createRadialGradient(cx, cy, R * .86, cx, cy, R * 1.12);
    gr.addColorStop(0, 'rgba(255,170,60,0)'); gr.addColorStop(.55, 'rgba(255,170,60,.38)'); gr.addColorStop(1, 'rgba(255,90,0,0)');
    ctx.fillStyle = gr; ctx.beginPath(); ctx.arc(cx, cy, R * 1.12, 0, 6.283); ctx.fill();
    // embers
    for (const e of embers) {
      ctx.fillStyle = `rgba(255,${120 + 100 * e.life | 0},40,${e.life * .8})`;
      ctx.beginPath(); ctx.arc(e.x, e.y, e.s * e.life + .3, 0, 6.283); ctx.fill();
    }
    drawOrbits(true);
    ctx.globalAlpha = 1;
  }
  function start() {
    if (!on) return;
    if (!cv) {
      cv = document.createElement('canvas'); cv.id = 'qbg'; cv.setAttribute('aria-hidden', 'true'); ctx = cv.getContext('2d');
      buildTex();
      addEventListener('resize', () => { if (cv.isConnected) { layout(); if (reduce) draw(); } });
    }
    if (!cv.isConnected) document.body.prepend(cv);
    layout();
    cancelAnimationFrame(raf);
    if (reduce) { step(0); draw(); } else raf = requestAnimationFrame(frame);
  }
  function stop() { cancelAnimationFrame(raf); raf = 0; if (cv) cv.remove(); }
  function toggle() { on = !on; try { localStorage.setItem('tp-bg', on ? 'on' : 'off'); } catch (e) {} on ? start() : stop(); toast(on ? 'Live background on' : 'Live background off'); }
  return { start, stop, toggle };
})();

/* ---------------- shell ---------------- */
function renderShell() {
  document.body.innerHTML = '';
  const nav = [['servers', 'Servers', '🖥'], ['tunnels', 'Tunnels', '🛰'], ['routes', 'Routes', '🔀'], ['igproxy', 'IG Routing', '🌐'], ['bench', 'Benchmark', '📊'],
    ...(isAdmin() ? [['users', 'Users', '👥'], ['settings', 'Settings', '⚙']] : [['settings', 'Account', '👤']])];
  const shell = h(`<div class="shell">
    <aside class="side" id="side">
      <div class="brand"><div class="dot"></div><div><b>${esc(STATE.settings.panelName || 'Tunnel Panel')}</b><small>server link manager</small></div></div>
      <nav class="nav">${nav.map(n => `<button data-v="${n[0]}"><span class="ni">${n[2]}</span><span class="nl">${n[1]}</span>${n[0] === 'tunnels' && STATE.tunnels.length ? `<em class="nb" title="running / all">${STATE.tunnels.filter(t => t.active && shownOwner(t.owner)).length}/${STATE.tunnels.filter(t => shownOwner(t.owner)).length}</em>` : ''}</button>`).join('')}</nav>
      <div class="foot">
        <div class="swatches" title="Accent colour">${ACCENTS.map(c => `<button type="button" class="sw" data-acc="${c}" style="--c:${c}" aria-label="accent ${c}"></button>`).join('')}</div>
        ${isAdmin() && (STATE.users || []).length > 1 ? `<label class="f vf" title="show the servers and tunnels of one account">👁 View<select id="ownerSel"><option value="">All accounts</option><option value="-">My own</option>${STATE.users.filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}">${esc(u.username)}</option>`).join('')}</select></label>` : ''}
        ${isAdmin() ? '' : '<!--'}<a class="btn sm bkbtn" href="/api/backup" download title="Download a backup of the whole panel: servers, tunnels, settings, users (keep the file private). Restore it under Settings.">💾 Backup now</a>${isAdmin() ? '' : '-->'}
        <button class="btn ghost sm" id="themeBtn">◐ Theme</button>
        <button class="btn ghost sm" id="bgBtn" title="Animated background on/off">✦ Live background</button>
        <div class="faint" style="font-size:11px;padding:0 8px">Signed in as <b>${esc(STATE.user)}</b>${isAdmin() ? ' <span class="chip own">admin</span>' : ''}${STATE.version ? `<br>version <span class="mono">${esc(STATE.version)}</span>` : ''}</div>
        <button class="btn ghost sm" id="logout">Sign out</button>
      </div></aside>
    <main class="main" id="work"></main></div>`);
  document.body.appendChild(shell);
  $$('.nav button', shell).forEach(b => b.onclick = () => { setView(b.dataset.v); paintNav(); renderView(); $('#side').classList.remove('open'); });
  $('#logout').onclick = async () => { await api('/logout', {}); location.reload(); };
  $('#themeBtn').onclick = toggleTheme;
  const os = $('#ownerSel', shell);
  if (os) { os.value = STATE.ownerFilter || ''; os.onchange = () => { setOwnerFilter(os.value); renderShell(); }; } // the sidebar's counts follow it too
  $$('[data-acc]', shell).forEach(b => b.onclick = () => setAccent(b.dataset.acc));
  paintAccent();
  $('#bgBtn').onclick = () => quantumBg.toggle();
  quantumBg.start();
  paintNav(); renderView();
}
function paintNav() { $$('.nav button').forEach(b => b.classList.toggle('on', b.dataset.v === STATE.view)); }
function toggleTheme() {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('tp-theme', next); } catch (e) {}
}
try { const t = localStorage.getItem('tp-theme'); if (t) document.documentElement.setAttribute('data-theme', t); } catch (e) {}
// accent colour (per browser): the theme's own, or one of these
const ACCENTS = ['', '#6d5dfc', '#0ea5e9', '#10b981', '#f59e0b', '#ec4899'];
function setAccent(c) {
  const r = document.documentElement.style;
  if (c) { r.setProperty('--accent', c); r.setProperty('--accent-soft', `color-mix(in srgb, ${c} 16%, var(--panel))`); r.setProperty('--accent-fg', '#fff'); }
  else { r.removeProperty('--accent'); r.removeProperty('--accent-soft'); r.removeProperty('--accent-fg'); }
  try { localStorage.setItem('tp-accent', c); } catch (e) {}
  paintAccent();
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
  w.classList.remove('igp');
  ({ tunnels: viewTunnels, servers: viewServers, routes: viewRoutes, igproxy: viewIg, bench: viewBench, settings: viewSettings, users: viewUsers }[STATE.view])(w);
  trafficWatch();
  healthWatch();
}

/* ---------------- routes ---------------- */
// One card per Iran ⇄ foreign pair: its tunnels and every path they run (hot standby: each
// path ✓/✕ and the one users are on), and the order the next Re-apply / hot standby /
// failover uses — the pair's latest benchmark ranking, per address family.
const ageTxt = (u) => { const s = Math.floor(Date.now() / 1000) - u; return s < 3600 ? `${Math.max(1, Math.floor(s / 60))} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
async function viewRoutes(w) {
  w.innerHTML = topbar('Routes', 'Each tunnel: the paths its users are on, and which methods it may use — switch them on or off, and measure them.');
  const box = h('<div class="grid" style="gap:18px"><div class="skel" style="height:120px"></div><div class="skel" style="height:220px"></div></div>');
  w.appendChild(box);
  let hist = [], skip = {};
  try { [hist, skip] = await Promise.all([api('/bench/history'), api('/routes/skip')]); } catch (e) {}
  const pairs = new Map();
  const key = (i, f) => i + '|' + (f || '');
  STATE.tunnels.filter(t => shownOwner(t.owner)).forEach(t => { const k = key(t.serverId, t.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: t.serverId, foreign: t.foreignId || '', tunnels: [] }); pairs.get(k).tunnels.push(t); });
  hist.filter(r => shownOwner((serverById(r.iranId) || {}).owner)).forEach(r => { const k = key(r.iranId, r.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: r.iranId, foreign: r.foreignId || '', tunnels: [] }); });
  box.innerHTML = '';
  if (!pairs.size) { box.appendChild(h('<div class="card empty"><div class="big">🔀</div>No tunnels or benchmarks yet.</div>')); return; }
  const srvLabel = (id, fb) => { const s = id ? serverById(id) : null; return s ? `${s.country ? flag(s.country) : ''} ${esc(s.name)}` : fb; };
  const hasFam = (id, f) => { const s = id ? serverById(id) : null; const st = STATE.settings; return f === 'v4' ? !!(s ? s.ipv4 : st.localIPv4 || true) : !!(s ? s.ipv6 : st.localIPv6); };
  // one card per tunnel (a measured pair with no tunnel gets one too); a switch re-draws the
  // cards in place (the page keeps its scroll)
  let repaint = () => {};
  const buildCard = (p) => {
    const fams = ['v4', 'v6'].filter(f => hasFam(p.iran, f) && hasFam(p.foreign, f));
    const off = skip[key(p.iran, p.foreign)] || [];
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
        ${p.tunnel ? '<span class="faint">now</span>' : `<b class="rt-name">${esc(t.name)}</b><span class="faint mono">:${esc(t.ports)}</span>`}
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
      const sw = `<label class="rt-sw" title="${isOff ? 'not used on this route — turn on to let hot standby and failover use it' : 'used on this route (hot standby, failover, benchmark) — turn off to leave it out'}"><input type="checkbox" data-use="${esc(mid)}|${f}"${isOff ? '' : ' checked'}><i></i></label>`;
      const c = rank[mid][f], x = c && c.r;
      let body;
      if (isOff) body = '<span class="faint">off</span>';
      else if (!x) body = '<span class="faint">not measured</span>';
      else if (x.skipped) body = '<span class="faint">not measurable</span>';
      else if (x.ok) {
        const carrier = x.opts ? Object.entries(x.opts).map(([k, v]) => `${k} ${v}`).join(', ') : '';
        body = `<span class="rt-rank${x.recommended ? ' top' : ''}">${x.recommended ? '★' : c.pos}</span><span class="rt-num">↓${x.downMbps.toFixed(0)} ↑${x.upMbps.toFixed(0)} <small>Mbps</small> · ${x.rttMs.toFixed(0)} <small>ms</small></span>${carrier ? `<span class="chip rt-car" title="the default carrier passes nothing here; this one does">${esc(carrier)}</span>` : ''}`;
      } else body = `<button type="button" class="rt-err" data-err="${esc(x.error || 'failed')}" title="${esc(x.error || 'failed')}">✕ ${esc(shortErr(x.error))}</button>`;
      return `<td class="rt-c ${isOff ? 'left' : x && x.ok ? 'good' : x && !x.skipped ? 'bad' : ''}" data-f="${famName(f)}">${sw}${body}</td>`;
    };
    const methodsTbl = mids.length ? `<table class="rt-tbl"><thead><tr><th>Method</th>${fams.map(f => `<th>${famName(f)}${bench[f] ? ` <span class="faint">· measured ${ageTxt(bench[f].at)}</span>` : ' <span class="faint">· not measured yet</span>'}</th>`).join('')}</tr></thead>
      <tbody>${mids.map((mid, i) => (i === 0 || gOf(mids[i - 1]) !== gOf(mid) ? `<tr class="rt-grp"><td colspan="${fams.length + 1}">${GROUP_ICON[gOf(mid)] || '🔧'} ${esc(gOf(mid))}</td></tr>` : '') +
        `<tr><td class="rt-mn">${esc(methodTitle(mid))}</td>${fams.map(f => cell(mid, f)).join('')}</tr>`).join('')}</tbody></table>
      <div class="faint rt-leg">Switch on = the route's tunnels may use it (hot standby keeps it ready, failover can move users to it); off = never used here. ★ best measured · numbers = the order they're tried · tap ✕ for the whole error · 📊 measures them all${fams.some(f => !bench[f]) ? ' — not measured yet: you can still choose' : ''}</div>`
      : '<div class="faint" style="font-size:12.5px">No method can run between these two servers over the address families they have.</div>';

    const cells = mids.flatMap(mid => { const m = STATE.methods.find(x => x.id === mid); return fams.filter(f => !m || m.families.includes(f)).map(f => mid + '|' + f); });
    const cellCount = cells.length, onCount = cells.filter(c => !off.includes(c)).length;
    const summary = [`${p.tunnels.length} tunnel${p.tunnels.length === 1 ? '' : 's'}`];
    if (up) summary.push(`<span class="ok">● ${up} connected</span>`);
    if (down) summary.push(`<span class="bad">● ${down} down</span>`);
    // a tunnel's card is titled with the tunnel (what people look for); a measured pair with no
    // tunnel keeps the servers as its title
    const route = `${srvLabel(p.iran, 'Iran')} <span class="faint">→</span> ${srvLabel(p.foreign, '🖥 this panel host')}`;
    const title = p.tunnel ? `<h3>${esc(p.tunnel.name)}</h3><div class="rt-sum">${route} · <span class="mono">:${esc(p.tunnel.ports)}</span></div>`
      : `<h3>${route}</h3><div class="rt-sum">${summary.join(' · ')} · measured, no tunnel yet</div>`;
    const sharedNote = p.shared && p.shared.length ? `<div class="faint rt-leg" style="margin:0 0 6px">These switches belong to the server pair, so they also apply to ${p.shared.map(esc).join(', ')}.</div>` : '';
    const card = h(`<div class="card rt-card">
      <div class="rt-head"><div>${title}</div>
        <div class="actions">${fams.map(f => `<button class="btn sm" data-rb="${f}" title="measure every method over ${famName(f)} between these two servers (a few minutes; live tunnels are not touched)">📊 Measure ${famName(f)}</button>`).join('')}</div></div>
      ${p.tunnel ? '' : '<div class="lbl">Tunnels</div>'}<div class="rt-rows">${tunnels}</div>
      <details class="rt-more"${p.tunnel || STATE.routeSel ? ' open' : ''}><summary><span class="lbl">Methods this tunnel may use</span> <span class="faint">${onCount} of ${cellCount} on — speeds and order</span></summary>${sharedNote}${methodsTbl}</details></div>`);
    const setSkip = async (v, on) => {
      const [method, family] = v.split('|');
      try {
        skip = await api('/routes/skip', { iran: p.iran, foreign: p.foreign, method, family, skip: on });
        repaint(); // the other tunnels on this pair show the same switches
        toast(on ? `${methodTitle(method)} (${famName(family)}) left out on this route — running hot-standby tunnels drop it in about 20 s` : `${methodTitle(method)} (${famName(family)}) is back on this route — running hot-standby tunnels add it in about 20 s`);
      } catch (er) { alertModal('Routes', er.message); }
    };
    $$('[data-use]', card).forEach(b => b.onchange = () => setSkip(b.dataset.use, !b.checked));
    $$('[data-err]', card).forEach(b => b.onclick = () => alertModal('Why it failed', b.dataset.err));
    $$('[data-rb]', card).forEach(b => b.onclick = async () => {
      try { const r = await api('/bench/start', { iranId: p.iran, foreignId: p.foreign, family: b.dataset.rb, seconds: 3 }); toast('Benchmark started'); openLog({ id: 'bench', name: 'Benchmark · ' + famName(b.dataset.rb) }, r.job); } catch (er) { alertModal('Benchmark', er.message); }
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
  const order = new Map(STATE.tunnels.map((t, i) => [t.id, i]));
  items.sort((a, b) => order.get(a.id) - order.get(b.id));
  const valid = (id) => id === '' || id === 'other' || items.some(x => x.id === id);
  if (STATE.routeSel === undefined) { try { STATE.routeSel = localStorage.getItem('tp-routesel') || ''; } catch (e) { STATE.routeSel = ''; } }
  if (!valid(STATE.routeSel)) STATE.routeSel = '';
  const dot = (t) => !t.active ? '' : t.health ? '<i class="bad">●</i>' : t.health === '' ? '<i class="ok">●</i>' : '';
  const tile = (it) => {
    const t = it.tunnel, s = serverById(it.foreign);
    return `<button type="button" class="rtile${STATE.routeSel === it.id ? ' on' : ''}" data-rsel="${it.id}" title="${esc(serverName(it.iran))} → ${esc(it.foreign ? serverName(it.foreign) : 'this panel host')}">
      <span class="rt-fl">${s && s.country ? flag(s.country) : '🛰'}</span>
      <span class="rt-tn"><b>${esc(t.name)}</b><small>${t.active ? esc(methodTitle(t.active)) : 'stopped'}</small></span>
      <span class="rt-dots">${dot(t)}</span></button>`;
  };
  const picker = h(`<div class="rpick"><button type="button" class="rtile${STATE.routeSel === '' ? ' on' : ''}" data-rsel=""><span class="rt-fl">🌐</span><span class="rt-tn"><b>All tunnels</b><small>${items.length} tunnel${items.length === 1 ? '' : 's'}</small></span></button>
    ${items.map(tile).join('')}${others.length ? `<button type="button" class="rtile${STATE.routeSel === 'other' ? ' on' : ''}" data-rsel="other"><span class="rt-fl">📊</span><span class="rt-tn"><b>Other routes</b><small>measured, no tunnel</small></span></button>` : ''}</div>`);
  box.before(picker);
  const paint = () => {
    $$('[data-rsel]', picker).forEach(b => b.classList.toggle('on', b.dataset.rsel === STATE.routeSel));
    // on a phone the tiles are one row: keep the chosen one in sight
    const on = $('.rtile.on', picker); if (on && picker.scrollWidth > picker.clientWidth) picker.scrollLeft = on.offsetLeft - picker.offsetLeft - 8;
    box.innerHTML = '';
    const shown = STATE.routeSel === '' ? items : STATE.routeSel === 'other' ? others : items.filter(x => x.id === STATE.routeSel);
    shown.forEach(p => {
      // one route that can't be drawn must not hide the ones after it
      try { box.appendChild(buildCard(p)); }
      catch (e) { box.appendChild(h(`<div class="card rt-card"><h3>${esc(serverName(p.iran))} → ${esc(p.foreign ? serverName(p.foreign) : 'this panel host')}</h3><div class="faint">${p.tunnels.map(t => esc(t.name)).join(' · ')} — this route couldn't be drawn (${esc(e.message)})</div></div>`)); console.error(e); }
    });
  };
  $$('[data-rsel]', picker).forEach(b => b.onclick = () => { STATE.routeSel = b.dataset.rsel; try { localStorage.setItem('tp-routesel', STATE.routeSel); } catch (e) {} paint(); });
  repaint = paint;
  paint();
}
// the gist of a benchmark error, for a table cell
function shortErr(e) {
  e = e || 'failed';
  if (/excluded on this route/.test(e)) return 'left out';
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
const fmtRate = (bps) => bps >= 1e9 ? (bps / 1e9).toFixed(2) + ' Gbps' : bps >= 1e6 ? (bps / 1e6).toFixed(1) + ' Mbps' : bps >= 1e3 ? (bps / 1e3).toFixed(0) + ' Kbps' : Math.round(bps) + ' bps';
const fmtBytes = (b) => b >= 2 ** 40 ? (b / 2 ** 40).toFixed(2) + ' TB' : b >= 2 ** 30 ? (b / 2 ** 30).toFixed(2) + ' GB' : b >= 2 ** 20 ? (b / 2 ** 20).toFixed(1) + ' MB' : b >= 1024 ? (b / 1024).toFixed(0) + ' KB' : b + ' B';
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
  let d; try { d = await api('/traffic'); } catch (e) { return; }
  const tun = d.tunnels || {}, srv = d.servers || {}, speed = d.speed || {};
  $$('[data-res]').forEach(el => renderRes(el, (d.res || {})[el.dataset.res]));
  // the totals follow the View selector, like the cards
  const shownIds = new Set(STATE.tunnels.filter(t => shownOwner(t.owner)).map(t => t.id));
  const sum = Object.entries(tun).reduce((a, [id, x]) => (x.error || !shownIds.has(id) ? a : [a[0] + x.down, a[1] + x.up]), [0, 0]);
  const sd = $('[data-sum-dn]'), su = $('[data-sum-up]');
  if (sd) sd.textContent = fmtRate(sum[0]);
  if (su) su.textContent = fmtRate(sum[1]);
  $$('[data-traf]').forEach(el => {
    const id = el.dataset.traf, s = tun[id], sp = speed[id];
    const rd = $('[data-rd]', el), ru = $('[data-ru]', el), src = $('[data-src]', el), tot = $('[data-tot]', el);
    el.classList.toggle('err', !!(s && s.error));
    if (!s) { rd.textContent = '…'; ru.textContent = '…'; src.textContent = 'reading counters…'; }
    else if (s.error) { rd.textContent = '—'; ru.textContent = '—'; src.textContent = s.error; src.style.color = 'var(--crit)'; }
    else {
      src.style.color = ''; rd.textContent = fmtRate(s.down); ru.textContent = fmtRate(s.up);
      src.textContent = s.source === 'iface' ? 'tunnel interface' : 'forwarded ports';
      tot.textContent = `total ↓ ${fmtBytes(s.totalDown)} · ↑ ${fmtBytes(s.totalUp)}`;
      drawSpark($('svg', el), s.hist || []);
    }
    const se = $('[data-speed]', el);
    if (sp) se.innerHTML = sp.ok ? `speed test ${ago(sp.at)}: <b style="color:var(--accent)">↓ ${sp.downMbps.toFixed(1)}</b> / <b style="color:var(--good)">↑ ${sp.upMbps.toFixed(1)}</b> Mbps · ${sp.rttMs.toFixed(0)} ms` : `<span style="color:var(--crit)" title="${esc(sp.error || '')}">speed test failed ${ago(sp.at)}</span>`;
  });
  $$('[data-nic]').forEach(el => {
    const s = srv[el.dataset.nic];
    if (!s) { el.innerHTML = el.dataset.nic === '' ? 'live traffic…' : ''; return; }
    if (s.error) { el.innerHTML = `<span class="faint">traffic: ${esc(s.error)}</span>`; return; }
    el.innerHTML = `<span class="faint">${esc((s.source || '').replace('nic ', 'NIC '))}</span> <span class="dn">↓ ${fmtRate(s.down)}</span> <span class="up">↑ ${fmtRate(s.up)}</span> <span class="faint">· since boot ↓ ${fmtBytes(s.totalDown)} ↑ ${fmtBytes(s.totalUp)}</span>`;
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
  if (r.error) { el.innerHTML = `<span class="faint" style="font-size:12px">resources: ${esc(r.error)}</span>`; return; }
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
        <label class="f">FRP version <span class="faint">(blank = latest)</span><input name="frpVersion" class="mono" value="${esc(s.frpVersion || '')}"></label>
        <label class="f">GitHub download prefix<input name="githubProxy" class="mono" value="${esc(s.githubProxy || '')}" placeholder="https://ghproxy.net/"></label>
        <label class="f">Automatic benchmark every … hours <span class="faint">(every route with a running tunnel, on the spare slot — live tunnels aren't touched; blank = 24, 0 = off; each method moves at most 3 MB each way)</span><input name="autoBench" class="mono" inputmode="numeric" value="${esc(s.autoBench || '')}" placeholder="24"></label>
      </div>
      <h3 style="margin-top:6px">Telegram bot</h3>
      <div class="two">
        <label class="f">Bot token<input name="telegramTok" class="mono" value="${esc(s.telegramTok || '')}" placeholder="123456:ABC..."></label>
        <label class="f">Admin chat id(s)<input name="telegramAdmin" class="mono" value="${esc(s.telegramAdmin || '')}" placeholder="comma-separated"></label>
      </div>
      <div class="faint" style="font-size:12px">Message your bot <b>/start</b>; it replies with your chat id if you're not yet an admin. The bot can start, stop and switch every tunnel.</div>
      <label class="row f"><input type="checkbox" name="telegramBackup" value="on" ${s.telegramBackup === 'on' ? 'checked' : ''}> Send the daily backup to the admin chat too</label>
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
    <div class="card pad" id="helperCard"><h3>Helper binaries</h3><div class="muted" style="font-size:13px">Loading…</div></div>
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
  loadHelpers($('#helperCard', card));
}

async function loadHelpers(card) {
  let list = [];
  try { list = await api('/helpers'); } catch (e) {}
  card.innerHTML = `<h3>Helper binaries</h3>
    <p class="muted" style="font-size:13px;margin:6px 0">Closed binaries the panel uploads to hosts (e.g. the Backhaul Premium core). Upload one per architecture your servers use: <span class="mono">-amd64</span> for x86 servers, <span class="mono">-arm64</span> for ARM servers. A vendor <span class="mono">.tar.gz</span> is unpacked automatically and the architecture is checked. This panel host is <b class="mono">${esc(STATE.hostArch || '')}</b>.</p>
    <table class="tbl"><thead><tr><th>name</th><th>source</th><th>size</th></tr></thead><tbody>
    ${list.map(x => `<tr><td class="mono">${esc(x.name)}</td><td>${esc(x.source)}</td><td>${(x.size / 1048576).toFixed(1)} MB</td></tr>`).join('') || '<tr><td colspan=3 class="muted">none</td></tr>'}
    </tbody></table>
    <div class="actions" style="margin-top:12px;align-items:center"><span class="muted" style="font-size:12.5px">Backhaul Premium from the vendor:</span>
      <button class="btn sm" data-fetch="backhaul_premium-amd64">⬇ amd64</button><button class="btn sm" data-fetch="backhaul_premium-arm64">⬇ arm64</button>
      <span class="faint" style="font-size:11.5px">plain HTTP like the vendor's installer; both mirrors are compared</span></div>
    <div class="actions" style="margin-top:12px">
      <input type="text" id="hname" class="inp mono" placeholder="backhaul_premium-amd64" style="flex:1">
      <input type="file" id="hfile" hidden><button class="btn" id="hpick">Choose file</button>
      <button class="btn pri" id="hup" disabled>Upload</button>
    </div><div class="faint" id="hstat" style="font-size:12px;margin-top:6px"></div>`;
  $$('[data-fetch]', card).forEach(b => b.onclick = () => fetchHelper(b.dataset.fetch, b, () => loadHelpers(card)));
  const file = $('#hfile', card); let chosen = null;
  $('#hpick', card).onclick = () => file.click();
  file.onchange = () => { chosen = file.files[0]; if (chosen) { $('#hstat', card).textContent = chosen.name + ' (' + (chosen.size / 1048576).toFixed(1) + ' MB)'; $('#hup', card).disabled = false; if (!$('#hname', card).value) $('#hname', card).value = chosen.name.replace(/\.(tar\.gz|tgz)$/i, '').replace(/_(amd64|arm64)$/i, '-$1').replace(/[^a-z0-9_.-]/gi, '').toLowerCase(); } };
  $('#hup', card).onclick = async () => {
    const name = $('#hname', card).value.trim();
    if (!chosen || !/^[a-z0-9_.-]+-(amd64|arm64)$/.test(name)) { alertModal('Name', 'Name must look like backhaul_premium-amd64 (…-amd64 or …-arm64).'); return; }
    $('#hup', card).disabled = true; $('#hstat', card).textContent = 'Uploading…';
    try {
      const r = await fetch('/api/helpers/upload?name=' + encodeURIComponent(name), { method: 'POST', headers: { 'X-TP-Upload': '1' }, body: chosen });
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json().catch(() => ({}));
      if (j.note) alertModal('Uploaded', j.note); else toast('Uploaded');
      loadHelpers(card);
    } catch (e) { alertModal('Upload failed', e.message); $('#hup', card).disabled = false; }
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
      <div class="ubody"><h3>${esc(u.username)} ${u.role === 'admin' ? '<span class="chip own">admin</span>' : '<span class="chip">user</span>'}${u.username === STATE.user ? ' <span class="faint">(you)</span>' : ''}</h3>
        <div class="faint" style="font-size:12.5px">${u.servers} server${u.servers === 1 ? '' : 's'} · ${u.tunnels} tunnel${u.tunnels === 1 ? '' : 's'}${u.role === 'admin' ? ' <span title="servers and tunnels with no account belong to the admins">· shared by the admins</span>' : ''}</div></div>
      <div class="uact">${u.username === STATE.user ? '' : `<button class="btn sm" data-view="${esc(u.username)}" title="show only this account's servers and tunnels">👁 View</button>
        <button class="btn sm" data-edit="${esc(u.username)}">✎ Edit</button><button class="btn sm ghost danger" data-del="${esc(u.username)}">🗑</button>`}</div></div>`)));
    $$('[data-view]', list).forEach(b => b.onclick = () => { setOwnerFilter(b.dataset.view); setView('tunnels'); renderShell(); });
    $$('[data-edit]', list).forEach(b => b.onclick = () => userModal(STATE.users.find(u => u.username === b.dataset.edit)));
    $$('[data-del]', list).forEach(b => b.onclick = async () => {
      if (!confirmInline(b, 'Delete?')) return;
      try { await api('/users/delete', { Username: b.dataset.del }); STATE.users = await api('/users'); paint(); toast('Account deleted'); } catch (e) { alertModal('Delete account', e.message); }
    });
  };
  paint();
  $('#addUser').onclick = () => userModal(null);
}
function userModal(u) {
  const m = modal(`<h2>${u ? 'Edit ' + esc(u.username) : 'New user'}</h2>
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
  $('#uf', m).onsubmit = async (ev) => {
    ev.preventDefault();
    const fd = Object.fromEntries(new FormData(ev.target));
    try { STATE.users = await api('/users', fd); m.remove(); toast(u ? 'Account saved' : 'Account created — give the user its servers with 👤 Account… on a server card'); renderShell(); }
    catch (e) { alertModal('Account', e.message); }
  };
}
// the admin moves a server or tunnel to another account
function ownerModal(kind, id) {
  const x = kind === 'server' ? serverById(id) : STATE.tunnels.find(t => t.id === id);
  if (!x) return;
  const m = modal(`<h2>👤 Account of ${esc(x.name)}</h2>
    <p class="muted" style="font-size:13px">That account sees it and can run it; other users don't see it. Admins always see everything.${kind === 'server' ? ' Its tunnels keep their own account — move them too.' : ''}</p>
    <label class="f">Account<select data-o><option value="">me (admin)</option>${(STATE.users || []).filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}"${x.owner === u.username ? ' selected' : ''}>${esc(u.username)}${u.role === 'admin' ? ' (admin)' : ''}</option>`).join('')}</select></label>
    <div class="actions" style="justify-content:flex-end;margin-top:14px"><button class="btn ghost" data-x>Cancel</button><button class="btn pri" data-s>Save</button></div>`);
  $('[data-x]', m).onclick = () => m.remove();
  $('[data-s]', m).onclick = async () => {
    try { await api('/owner', { Kind: kind, ID: id, Owner: $('[data-o]', m).value }); m.remove(); await loadAll(); renderView(); toast('Saved'); } catch (e) { alertModal('Account', e.message); }
  };
}

/* ---------------- servers ---------------- */
// Two clearly separate groups: Iran (entry) and foreign (exit, incl. this panel host).
function viewServers(w) {
  w.innerHTML = topbar('Servers', 'Iran servers (users connect here) and foreign servers (traffic exits there), with their live load.');
  const ir = iranServers().filter(x => shownOwner(x.owner)), fg = foreignServers().filter(x => shownOwner(x.owner));
  const hostShown = isAdmin() && (!STATE.ownerFilter || STATE.ownerFilter === '-'); // the panel host is the admin's
  const sec = (key, title, sub, n, add) => h(`<section class="group">
    <div class="ghd"><div><h2>${title} <span class="count">${n}</span></h2><p>${sub}</p></div><button class="btn pri sm" data-add="${key}">${add}</button></div>
    <div class="grid cards" data-list="${key}"></div></section>`);
  const irSec = sec('iran', '🇮🇷 Iran servers', 'Entry side — users connect here; the tunnel forwards their traffic abroad.', ir.length, '+ Add Iran server');
  const fgSec = sec('foreign', '🌍 Foreign servers', `Exit side — your services (xray/v2ray…) run here.${hostShown ? ' This panel host counts as one.' : ''}`, fg.length + (hostShown ? 1 : 0), '+ Add foreign server');
  const irList = $('[data-list=iran]', irSec), fgList = $('[data-list=foreign]', fgSec);
  if (!ir.length) irList.appendChild(h(`<div class="card empty small"><div class="big">🇮🇷</div>No Iran server yet — add one to start building tunnels.</div>`));
  ir.forEach(x => irList.appendChild(serverCard(x)));
  if (hostShown) fgList.appendChild(panelHostCard());
  fg.forEach(x => fgList.appendChild(serverCard(x)));
  w.appendChild(irSec); w.appendChild(fgSec);
  if (isAdmin()) w.appendChild(outageSection());
  $$('[data-add]', w).forEach(b => b.onclick = () => serverModal({ role: b.dataset.add }));
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
          <td>${icon} ${esc(o.name)}<div class="faint" style="font-size:11px">${o.kind}</div></td><td>${esc(o.reason)}${o.cause ? `<div class="faint" style="font-size:12px">${esc(o.cause)}</div>` : ''}</td></tr>`;
      }).join('')}</tbody></table>`;
    } catch (e) { $('[data-olist]', sec).innerHTML = `<div style="padding:14px;color:var(--crit)">${esc(e.message)}</div>`; }
  };
  $('[data-oref]', sec).onclick = load;
  $('[data-oclr]', sec).onclick = async (e) => { if (!confirmInline(e.target, 'Click again to clear')) return; await api('/outages', { Clear: true }); load(); };
  load();
  return sec;
}
// the panel's own machine, shown as the first foreign server
function panelHostCard() {
  const st = STATE.settings, n = STATE.tunnels.filter(t => !t.foreignId).length;
  return h(`<div class="card scard host">
    <div class="sh"><div class="sname"><span class="sflag">🖥</span><div><h3>This panel host</h3><small>the machine running this panel</small></div></div><span class="pill on"><span class="led"></span>local</span></div>
    <dl class="kv">
      <dt>IPv4</dt><dd class="mono">${esc(st.localIPv4 || 'auto-detecting…')}</dd>
      ${st.localIPv6 ? `<dt>IPv6</dt><dd class="mono">${esc(st.localIPv6)}</dd>` : ''}
      <dt>Tunnels</dt><dd>${n}</dd>
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
      <h3 style="margin-top:14px">Recommended /etc/sysctl.d/99-tunnel-panel-optz.conf</h3>
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
document.addEventListener('click', (e) => { if (e.target.closest && e.target.closest('.menu-toggle')) $('#side').classList.toggle('open'); });
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
  const n = STATE.tunnels.filter(t => t.serverId === s.id || t.foreignId === s.id).length;
  const sub = [s.city, s.os && s.arch ? `${s.os} ${s.arch}` : ''].filter(Boolean).join(' · ');
  return h(`<div class="card scard ${isIran ? 'ir' : 'fg'}">
    <div class="sh"><div class="sname"><span class="sflag">${s.country ? flag(s.country) : (isIran ? '🇮🇷' : '🌍')}</span><div><h3>${esc(s.name || '(unnamed)')} ${ownerChip(s.owner)}</h3><small>${esc(sub || (isIran ? 'Iran · entry' : 'foreign · exit'))}</small></div></div>${status}</div>
    <dl class="kv">
      <dt>IPv4</dt><dd class="mono">${esc(s.ipv4 || '—')}</dd>
      <dt>IPv6</dt><dd class="mono">${esc(s.ipv6 || (s.prepared ? 'none' : 'reading over SSH…'))}</dd>
      <dt>SSH</dt><dd class="mono">${esc(s.sshUser || 'root')}@${esc(s.sshHost || s.ipv4 || s.ipv6 || '?')}:${s.sshPort || 22}</dd>
      ${s.lastPath ? `<dt>Reached via</dt><dd>${esc(s.lastPath)}</dd>` : ''}
      ${s.proxy ? `<dt>Proxy</dt><dd class="mono">${esc(s.proxy)}</dd>` : ''}
      <dt>Tunnels</dt><dd>${n}</dd>
      <dt>Packages</dt><dd>${s.provisioned ? '<span style="color:var(--good)">✓ installed</span>' : '<span class="faint">not yet</span>'}</dd>
    </dl>
    <div class="nic" data-nic="${s.id}"></div>
    <div class="res" data-res="${s.id}"></div>
    <div class="sfoot">
      <button class="btn sm" data-test="${s.id}">Test connection</button>
      <button class="btn sm" data-prep="${s.id}" title="Pre-install every method's binaries and packages once, so switching methods is instant">${s.provisioned ? 'Update packages' : 'Install packages'}</button>
      <span class="grow"></span>
      ${moreMenu([
        { label: '⚡ Optimize kernel', attr: `data-optz="${s.id}"` },
        isIran ? { label: '📡 Agent install command', attr: `data-agent="${s.id}"` } : null,
        isAdmin() ? { label: '🔑 SSH bridge', attr: `data-bridge="${s.id}"` } : null,
        isAdmin() ? { label: '👤 Account…', attr: `data-own="${s.id}"` } : null,
        { label: '✎ Edit', attr: `data-edit="${s.id}"` },
        { label: '🗑 Delete', attr: `data-del="${s.id}"`, danger: true },
      ])}
    </div><div data-paths="${s.id}"></div></div>`);
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
      ${isAdmin() && !s.id && (STATE.users || []).length > 1 ? `<label class="f">Account <span class="faint">(who sees and runs it)</span><select name="owner"><option value="">me (admin)</option>${STATE.users.filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}"${STATE.ownerFilter === u.username ? ' selected' : ''}>${esc(u.username)}</option>`).join('')}</select></label>` : ''}
      <label class="f">Password <span class="faint">(leave blank to keep)</span><input name="password" type="password" value="${esc(s.password || '')}"></label>
      <label class="f">or Private key (PEM)<textarea name="privateKey" rows="2" class="mono">${esc(s.privateKey || '')}</textarea></label>
      <details><summary class="muted" style="font-size:13px;cursor:pointer">Advanced reach options</summary>
        <div class="ff" style="margin-top:10px">
          <label class="f">Proxy for SSH <span class="faint">socks5:// or http://</span><input name="proxy" class="mono" value="${esc(s.proxy || '')}"></label>
          <label class="f">Force jump via<select name="via"><option value="">auto (try all servers)</option>${STATE.servers.filter(x => x.id !== s.id && (x.owner || '') === (s.owner || (isAdmin() ? '' : STATE.user))).map(x => `<option value="${x.id}"${s.via === x.id ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}</select></label>
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
// Summary strip, then tunnels grouped by their Iran server.
function viewTunnels(w) {
  w.innerHTML = topbar('Tunnels', 'Each tunnel links one Iran server to one foreign server. Pick a connection method and switch any time.',
    `${isAdmin() ? '' : '<!--'}<button class="btn" id="repairTun" title="Apply again every running tunnel that has a problem (down, dead hot-standby paths, an older switcher or Golden relay); servers that are down are left alone">🛠 Repair</button>${isAdmin() ? '' : '-->'}<button class="btn pri" id="addTun"${iranServers().length ? '' : ' disabled title="Add an Iran server first"'}>+ New tunnel</button>`);
  // everything on this page follows the View selector (an admin looking at one account sees
  // that account's numbers and chips, not the whole panel's)
  const mine = STATE.tunnels.filter(t => shownOwner(t.owner));
  const run = mine.filter(t => t.active).length;
  const hostShown = isAdmin() && (!STATE.ownerFilter || STATE.ownerFilter === '-'); // the panel host is the admin's
  w.appendChild(h(`<div class="summary">
    <div class="stat"><i class="si">🛰</i><small>Running tunnels</small><b><span class="cu" data-cu="${run}">0</span><span> / ${mine.length}</span> <span class="downtxt" data-sum-down></span></b></div>
    <div class="stat"><i class="si">⬇</i><small>Live download</small><b class="dn" data-sum-dn>—</b></div>
    <div class="stat"><i class="si">⬆</i><small>Live upload</small><b class="up" data-sum-up>—</b></div>
    <div class="stat"><i class="si">🖥</i><small>Servers</small><b>${iranServers().filter(s => shownOwner(s.owner)).length}<span> Iran · </span>${foreignServers().filter(s => shownOwner(s.owner)).length + (hostShown ? 1 : 0)}<span> foreign</span></b></div>
  </div>`));
  countUp(w);
  if (!mine.length) {
    w.appendChild(h(`<div class="card empty"><div class="big">🛰</div>${iranServers().length ? 'No tunnels yet — press <b>+ New tunnel</b>.' : 'Start on the <b>Servers</b> page: add an Iran server, then create a tunnel here.'}</div>`));
  }
  // one dense grid; filter chips per Iran server instead of separate sections
  if (mine.length) {
    const counts = {};
    mine.forEach(t => counts[t.serverId] = (counts[t.serverId] || 0) + 1);
    const ids = Object.keys(counts).sort((x, y) => serverName(x).localeCompare(serverName(y)));
    if (STATE.tunFilter && !counts[STATE.tunFilter]) STATE.tunFilter = '';
    const bar = h(`<div class="filters">
      <input class="inp search" type="search" data-q placeholder="🔍 Search name, server, port, method…" value="${esc(STATE.tunSearch || '')}">
      <button class="fchip${STATE.tunRunning ? ' on' : ''}" data-run title="show only running tunnels">● Running <b>${run}</b></button>
      ${ids.length > 1 ? `<button class="fchip${!STATE.tunFilter ? ' on' : ''}" data-f="">All <b>${mine.length}</b></button>${ids.map(id => {
        const sv = serverById(id);
        return `<button class="fchip${STATE.tunFilter === id ? ' on' : ''}" data-f="${id}">${sv && sv.country ? flag(sv.country) : '🇮🇷'} ${esc(serverName(id))} <b>${counts[id]}</b></button>`;
      }).join('')}` : ''}</div>`);
    $$('[data-f]', bar).forEach(b => b.onclick = () => { STATE.tunFilter = b.dataset.f; renderView(); });
    $('[data-run]', bar).onclick = () => { STATE.tunRunning = !STATE.tunRunning; renderView(); };
    w.appendChild(bar);
    const grid = h(`<div class="grid tgrid"></div>`);
    // the search filters the cards in place (no redraw: the live traffic keeps running)
    const hay = (t) => [t.name, t.ports, serverName(t.serverId), serverName(t.foreignId), methodTitle(t.active || t.selected), groupOf(STATE.methods.find(x => x.id === (t.active || t.selected))), famName(t.family)].join(' ').toLowerCase();
    const applySearch = () => {
      const q = (STATE.tunSearch || '').trim().toLowerCase();
      let shown = 0;
      $$('.tc', grid).forEach(c => { const t = STATE.tunnels.find(x => x.id === c.dataset.id); const ok = !q || (t && hay(t).includes(q)); c.hidden = !ok; if (ok) shown++; });
      let none = $('.nomatch', w);
      if (!shown && !none) { none = h('<div class="card empty small nomatch">No tunnel matches this search.</div>'); grid.after(none); }
      if (shown && none) none.remove();
    };
    $('[data-q]', bar).oninput = (e) => { STATE.tunSearch = e.target.value; applySearch(); };
    STATE.tunnels.filter(t => shownOwner(t.owner) && (!STATE.tunFilter || t.serverId === STATE.tunFilter) && (!STATE.tunRunning || t.active))
      .sort((x, y) => (!!y.active - !!x.active) || x.name.localeCompare(y.name))
      .forEach(t => grid.appendChild(tunnelCard(t)));
    w.appendChild(grid);
    applySearch();
  }
  $('#addTun').onclick = () => { if (iranServers().length) tunnelModal(); };
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
  const card = h(`<div class="card tc${t.active ? ' live' : ''}" data-id="${t.id}">
    <div class="tc-h"><h3 title="${esc(t.name)}">${esc(t.name)}</h3>${ownerChip(t.owner)}${active ? `<span class="pill on"><span class="led"></span>running</span>` : `<span class="pill off"><span class="led"></span>stopped</span>`}</div>
    <div class="tc-r" title="${esc(serverName(t.serverId))} → ${esc(fg ? fg.name : 'this panel host')}">
      <span class="sd" data-ir></span><span class="nm">${fl(ir, '🇮🇷')} ${esc(serverName(t.serverId))}</span>
      <span class="ln${t.active ? ' on' : ''}"></span>
      <span class="nm r">${fl(fg, fg ? '🌍' : '🖥')} ${esc(fg ? fg.name : 'panel host')}</span><span class="sd" data-fg></span>
    </div>
    <div class="tc-m"><span class="chip mth" title="${esc(groupOf(shownM) + ' · ' + (shownM?.title || ''))}">${shownM ? groupIcon(shownM) + ' ' : ''}${esc(shownM?.title || '—')}</span><span class="chip mono">:${esc(t.ports)}</span><span class="chip">${famName(shownFam)}</span>${mainFail ? `<span class="chip warn" title="${esc(mainFail.failed)} — tried again every hour">⚠ ${esc(methodTitle(t.active))} didn't start here</span>` : ''}${miss ? `<span class="chip warn" title="needs ${esc(miss)}">⚠ needs upload</span>` : ''}${t.clash ? `<span class="chip bad" title="${esc(t.clash)}">⚠ port clash</span>` : ''}${t.failover ? `<span class="chip fo" title="original ${esc(methodTitle(t.failover.method))} (${t.failover.family}) failed: ${esc(t.failover.reason || '')} — re-checked every hour">🔁 backup path · original ${esc(methodTitle(t.failover.method))} ${t.failover.family}</span>` : ''}${t.hotStandby ? hsChip(t) : (t.noFailover ? '' : '<span class="chip" title="automatic failover is on">🔁 auto</span>')}</div>
    ${t.active ? `<div class="traf mini" data-traf="${t.id}">
      <div class="rates"><span class="dn" title="foreign → Iran (download)">↓ <b data-rd>…</b></span><span class="up" title="Iran → foreign (upload)">↑ <b data-ru>…</b></span></div>
      <svg class="spark" viewBox="0 0 100 38" preserveAspectRatio="none" aria-hidden="true"><path class="ad"/><path class="pd"/><path class="pu"/></svg>
      <div class="meta"><span data-tot></span><span data-src></span></div><div class="meta" data-speed></div></div>`
      : `<div class="tc-idle">Not running${selM ? ` · selected: <b>${esc(selM.title)}</b>` : ''}</div>`}
    <div class="tc-f">
      <button class="btn sm pri" data-manage>⚙ Manage</button>
      ${t.active ? `<button class="btn sm" data-stop>■ Stop</button>` : `<button class="btn sm" data-start>▶ Start</button>`}
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
  on('[data-del]', async (e) => { if (!confirmInline(e.target, 'Click again to delete')) return; try { const r = await api('/tunnels/delete', { ID: t.id }); await loadAll(); renderView(); if (r.warning) alertModal('Deleted — with a warning', r.warning); } catch (er) { alertModal('Error', er.message); } });
  refreshStatus(t, card);
  return card;
}
async function applyMethod(t, mid, fam) {
  try { const r = await api('/tunnels/apply', { ID: t.id, Method: mid, Family: fam || t.family }); openLog(t, r.job); return true; }
  catch (e) { busyOrError(t, e); return false; }
}
async function tunnelJob(t, path, label) {
  try { const r = await api(path, { ID: t.id }); openLog({ id: t.id, name: label + ' · ' + t.name }, r.job); } catch (e) { busyOrError(t, e); }
}
// hot standby: which path carries the users now, and how many work
function hsChip(t) {
  const v = t.hs;
  if (!v || !v.paths || !v.paths.length) return '<span class="chip" title="hot standby — starts on the next Start/Re-apply">⚡ standby</span>';
  const n = v.ok.filter(Boolean).length, cur = v.paths[v.active] || '—';
  return `<span class="chip${n ? '' : ' bad'}" title="${esc(v.paths.map((p, i) => (v.ok[i] ? '✓ ' : '✕ ') + p + (i === v.active ? ' ← users' : '')).join('\n'))}">⚡ ${n}/${v.paths.length} paths · on ${esc(cur)}</span>`;
}
function hsBox(t) {
  const v = t.hs;
  if (!t.hotStandby) return '';
  const auto = !!t.hsAuto;
  const seg = `<div class="seg" data-hsmode><button type="button" data-auto="0" class="${auto ? '' : 'on'}" title="${esc('Manual: ' + 'users stay on the chosen path and move only when it is down (3 failed checks). They come back after 60 s of stability — longer for a path that keeps dropping (doubled per drop in 30 min, up to 30 min). At most 3 planned moves an hour.')}">✋ Manual</button><button type="button" data-auto="1" class="${auto ? 'on' : ''}" title="${esc('Auto: ' + "Latency and loss are watched all the time, the speed of the users' path every 2 hours (2 MB). When it gets slow or lossy the best few paths are measured and users move to a clearly better one. No ping-pong: 10 min wait after a move, at most 3 planned moves an hour. Light on traffic: standby paths are checked every 10 s.")}">🤖 Auto · best path</button></div>
    <div class="faint" style="font-size:12px;margin:-4px 0 6px">${auto ? 'Moves users to a clearly better path when theirs gets slow or lossy.' : 'Users stay on the chosen path; they move only when it is down.'} <span title="${esc(auto ? "Latency and loss are watched all the time, the speed of the users' path every 2 hours (2 MB). When it gets slow or lossy the best few paths are measured and users move to a clearly better one. No ping-pong: 10 min wait after a move, at most 3 planned moves an hour. Light on traffic: standby paths are checked every 10 s." : 'users stay on the chosen path and move only when it is down (3 failed checks). They come back after 60 s of stability — longer for a path that keeps dropping (doubled per drop in 30 min, up to 30 min). At most 3 planned moves an hour.')}" style="cursor:help">ⓘ</span></div>`;
  if (!v || !v.paths) return `<div class="lbl">⚡ Hot standby</div>${seg}<div class="faint" style="font-size:12px">every compatible path starts on the next Start/Re-apply.</div>`;
  const q = (i) => {
    const out = [];
    if (v.rtt && v.rtt[i] >= 0) out.push(v.rtt[i] + ' ms');
    if (v.loss && v.loss[i] >= 0) out.push(v.loss[i].toFixed(1) + '% loss');
    if (v.kbps && v.kbps[i] > 0) out.push((v.kbps[i] / 1000).toFixed(1) + ' Mbps');
    return out.length ? ` <span class="faint">${out.join(' · ')}</span>` : '';
  };
  return `<div class="lbl">⚡ Hot standby paths <span class="faint">(switcher order; the users' path is checked every 2 s on the Iran server)</span></div>${seg}<div class="hsl">${v.paths.map((p, i) =>
    `<div class="${v.ok[i] ? 'ok' : 'bad'}${i === v.active ? ' cur' : ''}">${v.ok[i] ? '✓' : '✕'} ${esc(p)}${q(i)}${i === v.pin ? ' <span class="faint">📌 chosen</span>' : ''}${i === v.active ? ' <b>← users</b>' : (v.ok[i] && v.keys ? ` <button type="button" class="btn sm ghost" data-hspin="${esc(v.keys[i])}" title="move the users here now — open connections finish where they are, nobody is cut">use</button>` : '')}</div>`).join('')}</div>
    <div class="faint" style="font-size:11.5px;margin-top:4px" title="New connections take the new path; open ones finish on the old one (it keeps running). Only a path that died has its connections reset, so clients reconnect at once.">Switching is seamless — nobody is cut. ⓘ</div>`;
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
    <div class="mg-h"><div><h2 style="margin:0">${esc(t.name)}</h2><div class="faint" style="font-size:12.5px">${(ir && ir.country) ? flag(ir.country) : '🇮🇷'} ${esc(serverName(t.serverId))} → ${fg && fg.country ? flag(fg.country) : (fg ? '🌍' : '🖥')} ${esc(fg ? fg.name : 'this panel host')} · ports <span class="mono">${esc(t.ports)}</span></div></div>
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
    selEl.innerHTML = groupedOptions(choices.filter(c => c.fam === fam).map(c => c.m), x => { const v = `${x.id}|${fam}`; return `<option value="${v}"${x.id === want ? ' selected' : ''}>${esc(x.title)} · ${esc(x.encrypt)}${methodMissing(x, t) ? ' ⚠ needs upload' : ''}${x.id === t.active && fam === t.family ? ' ✓ running' : ''}</option>`; });
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
      warnEl.innerHTML = `⚠ This method needs <b class="mono">${esc(miss)}</b> for this tunnel's servers.
        ${x.helper === 'backhaul_premium' ? miss.split(', ').map(n => `<button class="btn sm" data-fetch="${esc(n)}">⬇ Fetch ${esc(n)} from the vendor</button>`).join(' ') + ' or ' : ''}upload it under <a href="#" data-goset>Settings → Helper binaries</a>.`;
      $$('[data-fetch]', warnEl).forEach(b => b.onclick = () => fetchHelper(b.dataset.fetch, b, () => { m.remove(); manageTunnel(t); }));
      const gs = $('[data-goset]', warnEl); if (gs) gs.onclick = (e) => { e.preventDefault(); m.remove(); STATE.view = 'settings'; paintNav(); renderView(); };
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
// Download a vendor helper (Backhaul Premium core) on the panel host.
async function fetchHelper(name, btn, done) {
  const o = btn.textContent; btn.disabled = true; btn.textContent = 'Downloading…';
  try {
    const r = await api('/helpers/fetch', { Name: name });
    await loadAll();
    alertModal('Downloaded ' + name, `${(r.size / 1048576).toFixed(1)} MB from ${r.source}\nsha256 ${r.sha256}\n${r.note}`);
    if (done) done();
  } catch (e) { alertModal('Download failed', e.message + '\n\nYou can also download it yourself and upload it under Settings → Helper binaries.'); }
  btn.disabled = false; btn.textContent = o;
}
// A tunnel runs one job at a time. When another one is still going, offer to watch or cancel it.
function busyOrError(t, e) {
  const mm = /another job \(([0-9a-f]+)\)/.exec(e.message || '');
  if (!mm) { alertModal('Error', e.message); return; }
  const m = modal(`<h2>A job is still running</h2><p class="muted">Another job is still running on <b>${esc(t.name)}</b> (${esc(mm[1])}). Watch it, or cancel it to free the tunnel. Stop always works — it cancels the running job first.</p>
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
    card.classList.toggle('down', !!why);
    const pill = $('.tc-h .pill', card);
    if (pill) pill.outerHTML = why ? `<span class="pill bad" title="${esc(why)}"><span class="led"></span>down</span>` : `<span class="pill on"><span class="led"></span>running</span>`;
    let bar = $('.downbar', card);
    if (why && !bar) { bar = h(`<div class="downbar"></div>`); $('.tc-r', card).after(bar); }
    if (bar) { if (why) bar.innerHTML = `⚠ ${esc(why)} <a href="#" data-dg>Diagnose</a>`; else bar.remove(); }
    const dg = $('[data-dg]', card); if (dg) dg.onclick = (e) => { e.preventDefault(); tunnelJob(t, '/tunnels/diagnose', 'Diagnose'); };
    t._down = !!why;
    const n = STATE.tunnels.filter(x => x._down && shownOwner(x.owner)).length, el = $('[data-sum-down]');
    if (el) { el.textContent = n ? `· ${n} down` : ''; }
  } catch (e) {} finally { card._busy = false; }
}
let healthTimer = null;
function healthWatch() {
  if (healthTimer) clearInterval(healthTimer);
  healthTimer = null;
  if (STATE.view !== 'tunnels') return;
  healthTimer = setInterval(() => {
    if (STATE.view !== 'tunnels') { clearInterval(healthTimer); healthTimer = null; return; }
    if (document.hidden) return;
    $$('.tc.live').forEach(card => { const t = STATE.tunnels.find(x => x.id === card.dataset.id); if (t) refreshStatus(t, card); });
  }, 15000);
}
// The save endpoint replaces the editable fields, so every save sends all of them
// (sending a partial tunnel used to wipe its traffic-shaping settings).
const tunnelBody = (t, patch) => ({ ID: t.id, name: t.name, serverId: t.serverId, foreignId: t.foreignId, family: t.family,
  ports: t.ports, note: t.note, shape: t.shape || {}, noFailover: !!t.noFailover, hotStandby: !!t.hotStandby, hsAuto: !!t.hsAuto, selected: t.selected || '', ...patch });
async function saveTunnel(t, patch) {
  try { await api('/tunnels/save', tunnelBody(t, patch)); Object.assign(t, patch); } catch (e) {}
}
function renderOpts(box, t, mid) {
  const m = STATE.methods.find(x => x.id === mid);
  if (!m || !m.fields?.length) { box.innerHTML = `<div class="opts one"><div class="muted">No options for this method.</div></div>`; return; }
  const saved = (t.options && t.options[mid]) || {};
  const field = (f) => {
    const v = saved[f.key] !== undefined ? saved[f.key] : f.default;
    const help = f.help ? `<small class="fhelp">${esc(f.help)}</small>` : '';
    if (f.type === 'bool') return `<label class="row f" style="grid-column:1/-1"><input type="checkbox" data-k="${f.key}"${String(v) === 'true' ? ' checked' : ''}> ${esc(f.label)}${help}</label>`;
    if (f.type === 'select') return `<label class="f">${esc(f.label)}<select data-k="${f.key}">${f.options.map(o => `<option${o === v ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>${help}</label>`;
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
  const foreignOpts = panelHostOpt() + sharedOpts('foreign', t.foreignId) + foreignServers().map(s => `<option value="${s.id}"${t.foreignId === s.id ? ' selected' : ''}>${esc(serverLabel(s))}</option>`).join('');
  const m = modal(`<h2>${t.id ? 'Edit tunnel' : 'New tunnel'}</h2>
    <form class="ff" id="tf">
      <label class="f">Name<input name="name" value="${esc(t.name || '')}" required></label>
      <div class="two">
        <label class="f">Iran server<select name="serverId" required>${sharedOpts('iran', t.serverId)}${iranServers().map(s => `<option value="${s.id}"${s.id === t.serverId ? ' selected' : ''}>${esc(serverLabel(s))}</option>`).join('')}</select></label>
        <label class="f">Foreign server<select name="foreignId">${foreignOpts}</select></label>
      </div>
      <div class="two">
        <label class="f">Address family<select name="family"><option value="v4"${t.family === 'v6' ? '' : ' selected'}>IPv4 underlay</option><option value="v6"${t.family === 'v6' ? ' selected' : ''}>IPv6 underlay</option></select></label>
        <label class="f">Ports <span class="faint">443,8080=80,2000-2010</span><input name="ports" class="mono" value="${esc(t.ports || '443')}"></label>
      </div>
      <label class="f">Note<input name="note" value="${esc(t.note || '')}"></label>
      ${isAdmin() && !t.id && (STATE.users || []).length > 1 ? `<label class="f">Account <span class="faint">(who sees and runs it — use that account's servers)</span><select name="owner"><option value="">me (admin)</option>${STATE.users.filter(u => u.username !== STATE.user).map(u => `<option value="${esc(u.username)}"${STATE.ownerFilter === u.username ? ' selected' : ''}>${esc(u.username)}</option>`).join('')}</select></label>` : ''}
      <label class="row f"><input type="checkbox" id="tFail"${t.noFailover ? '' : ' checked'}> 🔁 Automatic failover <span class="faint" style="font-weight:500">— if the tunnel is down for 5 min, switch to a working method / IPv4⇄IPv6 path; re-check the original every hour and switch back when it works</span></label>
      <label class="row f"><input type="checkbox" id="tHot"${t.hotStandby ? ' checked' : ''}> ⚡ Hot standby <span class="faint" style="font-weight:500">— keep every compatible method (IPv4 and IPv6) running; users go through the chosen one and a switcher on the Iran server moves them to the best working path within seconds (no SSH needed), and back after ${60}s of stability. Order: this route's benchmark. Applies on the next Start/Re-apply.</span></label>
      <label class="row f" style="margin-inline-start:22px"><input type="checkbox" id="tHsAuto"${t.hsAuto ? ' checked' : ''}> 🤖 Auto — also move users to a clearly better path when theirs gets slow or lossy <span class="faint" style="font-weight:500">(off = manual: the chosen path, left only while it is down; switchable any time from the tunnel's window or the bot)</span></label>
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
    fd.noFailover = !$('#tFail', m).checked;
    fd.hotStandby = $('#tHot', m).checked;
    fd.hsAuto = $('#tHsAuto', m).checked;
    if (t.selected) fd.selected = t.selected;
    fd.shape = {
      enabled: $('#shEnabled', m).checked, qdisc: $('#shQdisc', m).value,
      mss: parseInt($('#shMss', m).value || '0', 10), iface: $('#shIface', m).value.trim(),
      jitter: $('#shJitter', m).checked, onBoth: $('#shBoth', m).checked,
    };
    try { await api('/tunnels/save', fd); m.remove(); await loadAll(); renderView(); toast('Tunnel saved'); } catch (e) { alertModal('Error', e.message); }
  };
}

/* ---------------- benchmark ---------------- */
// The benchmark runs on the server; the page only watches it. benchWatch survives
// navigation, and /bench/active lets a fresh page (or reload) re-attach to a running job.
let benchTimer = null;
function viewBench(w) {
  w.innerHTML = topbar('Route benchmark', 'Measure every method between two servers and get a recommendation.');
  const card = h(`<div class="grid" style="gap:16px">
    <form class="card pad ff" id="bf" style="max-width:640px">
      <div class="two">
        <label class="f">Iran server<select name="iran">${[...iranServers(), ...(STATE.shared || []).filter(s => (s.role || 'iran') === 'iran')].map(s => `<option value="${s.id}">${esc(serverLabel(s))}${s.shared ? ' · shared' : ''}</option>`).join('')}</select></label>
        <label class="f">Foreign server<select name="foreign">${panelHostOpt()}${[...foreignServers(), ...(STATE.shared || []).filter(s => s.role === 'foreign')].map(s => `<option value="${s.id}">${esc(serverLabel(s))}${s.shared ? ' · shared' : ''}</option>`).join('')}</select></label>
      </div>
      <div class="two">
        <label class="f">Family<select name="family"><option value="v4">IPv4</option><option value="v6">IPv6</option></select></label>
        <label class="f">Throughput probe (s)<input name="seconds" type="number" class="mono" value="5"></label>
      </div>
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
    try { const r = await api('/bench/start', { iranId: fd.iran, foreignId: fd.foreign, family: fd.family, seconds: parseInt(fd.seconds || '5', 10) }); benchWatch(r.job, cur()); }
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
      <td>${fl(r.iranId, '🇮🇷')} ${esc(r.iranName)} <span class="faint">→</span> ${fl(r.foreignId, r.foreignId ? '🌍' : '🖥')} ${esc(r.foreignName)}</td>
      <td>${r.family === 'v6' ? 'IPv6' : 'IPv4'}</td>
      <td>${best ? `<b>${esc(best.title)}</b> <span class="faint">↓${best.downMbps.toFixed(0)} ↑${best.upMbps.toFixed(0)} Mbps · ${best.rttMs.toFixed(0)} ms</span>` : '<span class="faint">no method worked</span>'}</td>
      <td class="faint">${ok}/${(r.results || []).length} ok</td>
      <td><button class="btn sm" data-hv="${i}">View</button></td></tr>`;
  }).join('');
  box.innerHTML = `<div class="card pad"><div style="display:flex;justify-content:space-between;align-items:center"><h3>History</h3><button class="btn sm ghost danger" id="bhclear">Clear history</button></div>
    <div style="overflow-x:auto"><table class="tbl"><thead><tr><th>when</th><th>route</th><th>family</th><th>best</th><th>methods</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  $$('[data-hv]', box).forEach(b => b.onclick = () => {
    const r = hs[+b.dataset.hv];
    renderBenchTable(r.results || [], { iran: r.iranId, foreign: r.foreignId, family: r.family },
      `${esc(r.iranName)} → ${esc(r.foreignName)} · ${r.family} · ${new Date(r.at * 1000).toLocaleString()}`);
    $('#bres').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  $('#bhclear', box).onclick = async (e) => { if (!confirmInline(e.target, 'Click again to clear')) return; try { await api('/bench/history', { Clear: true }); loadBenchHistory(); } catch (er) {} };
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
    log.innerHTML = j.lines.map(l => `<div class="ln ${/ERROR|FAILED/.test(l) ? 'err' : /DONE|best| ok:/.test(l) ? 'ok' : ''}">${esc(l)}</div>`).join('');
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
    <div class="ff">${opts.map(t => `<button class="btn" data-t="${t.id}">${esc(t.name)}</button>`).join('')}</div>`, true);
  $$('[data-t]', m).forEach(b => b.onclick = async () => { try { const r = await api('/tunnels/apply', { ID: b.dataset.t, Method: method, Family: fd.family }); m.remove(); STATE.view = 'tunnels'; paintNav(); renderView(); const t = STATE.tunnels.find(x => x.id === b.dataset.t); openLog(t, r.job); } catch (e) { alertModal('Error', e.message); } });
}
const methodTitle = (id) => STATE.methods.find(m => m.id === id)?.title || id;

/* ---------------- log drawer ---------------- */
let logTimer = null;
function openLog(t, jobId) {
  closeLog();
  const d = h(`<div class="drawer"><div class="panel">
    <div class="dh"><div><h3>${esc(t.name)}</h3><div class="muted" style="font-size:12px" id="jobstat">${jobId ? 'running…' : 'last job'}</div></div><div style="display:flex;gap:6px"><button class="btn sm danger" id="cancelJob" hidden>■ Cancel job</button><button class="btn ghost sm" id="closeLog">✕ Close</button></div></div>
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
  // each drawer owns its timer, so quickly opening another one can't orphan or kill it
  let me = null, finished = false;
  const stop = () => { if (me) clearInterval(me); if (logTimer === me) logTimer = null; me = null; };
  const tick = async () => {
    if (!box.isConnected) { stop(); return; } // drawer closed or replaced
    try {
      const j = await api(url);
      if (!box.isConnected || finished) return;
      box.innerHTML = j.lines.map(l => { let c = /ERROR|failed| ✕ |WARNING|CANCELLED/.test(l) ? 'err' : /DONE|is active|unit .*active| ✓ /.test(l) ? 'ok' : /\[IR\]/.test(l) ? 'ir' : ''; return `<div class="ln ${c}">${esc(l)}</div>`; }).join('');
      box.scrollTop = box.scrollHeight;
      if (stat) stat.textContent = j.status === 'running' ? 'running…' : (j.status === 'ok' ? 'completed' : j.status === 'cancelled' ? 'cancelled' : 'error');
      const cb = $('#cancelJob');
      if (cb) { cb.hidden = j.status !== 'running'; cb.onclick = async () => { cb.disabled = true; try { await api('/jobs/cancel', { ID: j.id }); toast('Job cancelled'); } catch (e) { alertModal('Cancel', e.message); } cb.disabled = false; }; }
      if (j.status !== 'running') {
        finished = true; stop(); await loadAll();
        if (STATE.view === 'tunnels') { const w = $('#work'); if (w && $('.drawer')) viewTunnels(w); }
      }
    } catch (e) { if (!jobId) { box.innerHTML = '<span class="muted">No job yet.</span>'; stop(); } }
  };
  me = setInterval(tick, 1200); logTimer = me;
  tick();
}


/* ---------------- IG routing ---------------- */
// The igproxy agents on the foreign servers: which way Instagram, Google/Gemini, YouTube Music …
// leave each server (a proxy, Cloudflare WARP, the server's IPv6 or direct). Every action runs
// "igproxy <command>" on the server as one of the panel's jobs (output in a drawer).
const IG = { data: null, cur: null, tab: 'routes', sub: recall('tp-igsub') || 'servers', filter: 'all', q: '' };
const IGSV = { IG: 'Instagram', GOOGLE: 'Google / Gemini', YTM: 'YouTube Music', ADULT: 'Adult', SPOTIFY: 'Spotify', SCLOUD: 'SoundCloud', CUSTOM: 'My sites' };
const IGWIDE = ['ADULT', 'SPOTIFY', 'SCLOUD', 'CUSTOM'];
const IGST = { OK: ['healthy', 'on'], PANEL: ['x-ui panel diverts Google', 'bad'], GEMFAIL: ['Gemini failing', 'bad'], IGFAIL: ['Instagram failing', 'bad'], DOWN: ['router down', 'bad'],
  CHECKING: ['checking…', 'acc'], NOAGENT: ['not installed', 'warn'], SUDO: ['needs sudo without password', 'warn'], PAUSED: ['paused', 'warn'], UPDATE: ['old agent', 'warn'], OFFLINE: ['offline', 'bad'] };
const igBad = (s) => (IGST[s] || ['', 'bad'])[1] === 'bad';
const igViaW = (v) => { v = v || ''; if (v === 'proxy') return 'Proxy'; if (/^proxy\d+$/.test(v)) return 'Proxy ' + v.slice(5); return { warp: 'WARP', warp6: 'WARP IPv6', ipv6: 'IPv6', direct: 'Direct' }[v] || v || '—'; };
const igViaC = (v) => 'v-' + (String(v || '').replace(/\d+$/, '').replace('warp6', 'warp') || 'direct');
const igPill = (st) => { const w = IGST[st] || [st, 'bad']; return `<span class="pill ${w[1]}"><span class="led"></span>${esc(w[0])}</span>`; };
const igChk = (v) => v === 'OK' ? '<i class="igd ok"></i>OK' : v === 'FAIL' ? '<i class="igd bad"></i>fail' : '<i class="igd"></i>—';
const igOwner = (s) => isAdmin() && s.owner ? `<span class="chip">👤 ${esc(s.owner)}</span>` : '';
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
    let closed = false, done = false, txt = '';
    const close = () => { if (closed) return; closed = true; d.remove(); document.removeEventListener('keydown', onKey); if (onDone) onDone(); res({ out: txt, done }); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', onKey);
    $('#ijclose', d).onclick = close; d.onclick = (e) => { if (e.target === d) close(); };
    $('#ijcopy', d).onclick = (e) => copy(txt, e.target);
    $('#ijstop', d).onclick = () => api('/jobs/cancel', { ID: jobId }).catch(e => toast(e.message));
    const tick = async () => {
      if (closed) return;
      let j; try { j = await api('/jobs?id=' + jobId); } catch (e) { toast(e.message); return; }
      if (closed) return;
      const ls = igLines(j); txt = ls.join('\n');
      const box = $('#ijout', d), stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
      box.innerHTML = ls.map(l => `<div class="ln ${igColor(l)}">${esc(l) || '&nbsp;'}</div>`).join('') || '…';
      if (stick) box.scrollTop = box.scrollHeight;
      if (j.status !== 'running') {
        done = true; $('#ijstop', d)?.remove();
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
    `<button class="btn" data-igref onclick="igLoad(true)">↻ Refresh</button><button class="btn pri" onclick="igAddServer()">+ Add server</button>`)
    + `<div class="seg" id="igsub">${subs.map(([k, t]) => `<button data-s="${k}" class="${k === IG.sub ? 'on' : ''}">${t}</button>`).join('')}</div><div id="igbody"></div>`;
  $$('#igsub button', w).forEach(b => b.onclick = () => { IG.sub = b.dataset.s; remember('tp-igsub', IG.sub); igRender(); });
  const body = $('#igbody', w);
  ({ servers: igServers, matrix: igMatrix, bulk: igBulk, backup: igBackup }[IG.sub] || igServers)(body);
}

// ---- servers
function igServers(box) {
  const d = IG.data;
  if (!d) { box.innerHTML = '<div class="grid cards">' + '<div class="skel" style="height:150px"></div>'.repeat(4) + '</div>'; return; }
  const L = igList(), ok = L.filter(s => s.info.state === 'OK').length, conn = L.reduce((a, s) => a + (+s.info.caught || 0), 0);
  const bad = L.filter(s => s.info.state !== 'OK' && s.info.state !== 'CHECKING').length, old = L.filter(s => ['UPDATE', 'NOAGENT'].includes(s.info.state)).length;
  box.insertAdjacentHTML('beforeend', `<div class="summary">
    <div class="stat"><small>Servers</small><b>${L.length}</b></div><div class="stat"><small>Healthy</small><b>${ok}</b></div>
    <div class="stat"><small>Connections routed</small><b>${conn}</b></div><div class="stat"><small>Need attention</small><b>${bad}</b></div></div>`);
  if (old && d.agent) box.insertAdjacentHTML('beforeend', `<div class="mwarn">${old} server(s) don't run the current agent (<span class="mono">${esc(d.agent)}</span>). <button class="btn sm" id="igupd">Update them</button></div>`);
  if (!d.agent) box.insertAdjacentHTML('beforeend', `<div class="mwarn">The agent script isn't on the panel host (<span class="mono">/etc/igpm/igproxy.sh</span>), so install / update is unavailable. Everything else works.</div>`);
  $('#igupd', box) && ($('#igupd', box).onclick = () => igAct({ srv: 'all', action: 'deploy', old: 1 }, 'Update the agent on the servers with an old one? Each server routes everything direct for a few seconds; settings and WARPs are kept.', { title: 'Update agents' }));
  if (!L.length) {
    box.insertAdjacentHTML('beforeend', `<div class="card empty"><div class="big">🌐</div><h3>No servers here yet</h3><p class="muted">Add one of your foreign servers: the igproxy agent is installed on it, then you choose here which way each service leaves.</p><button class="btn pri" onclick="igAddServer()">+ Add server</button></div>`);
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
  $$('.scard', box).forEach(c => c.onclick = () => { IG.cur = IG.data.servers.find(x => x.id === c.dataset.id); IG.tab = 'routes'; igRender(); scrollTo(0, 0); });
}
function igCard(s) {
  const i = s.info;
  const svc = (g) => `<div class="svc"><small>${IGSV[g]}</small><b class="${igViaC(i[g.toLowerCase()])}">${igViaW(i[g.toLowerCase()])}</b>${g === 'GOOGLE' && /^warp/.test(i.google || '') && i.gcc && i.gcc !== '-' ? `<span class="note mono" style="color:${i.gcc === 'PROXY' ? 'var(--crit)' : 'var(--faint)'}">${i.gcc === 'PROXY' ? 'on a proxy for now' : 'country ' + esc(i.gcc)}</span>` : ''}</div>`;
  const n = igWarpNeed(i);
  return `<div class="card scard${igBad(i.state) ? ' bad' : ''}" data-id="${esc(s.id)}" style="cursor:pointer"><div class="sh"><div class="sname"><h3>${s.country ? flag(s.country) + ' ' : ''}${esc(s.name)} ${igOwner(s)}</h3><small class="mono">${esc(s.host)}</small></div>${igPill(i.state)}</div>
    ${i.ig ? `<div class="svcs">${svc('IG')}${svc('GOOGLE')}${svc('YTM')}</div>
    <div class="sfoot"><span>🔗 <b>${+i.caught || 0}</b></span><span>proxies <b>${+i.proxies || 0}</b></span><span>WARP <b>${+i.warps || 0}</b>${n ? `<span class="faint" title="suggested for the 24 h peak"> / ${n.total}</span>` : ''}</span><span class="grow"></span><span>Gemini ${igChk(i.gem)}</span><span>IG ${igChk(i.igp)}</span></div>`
    : i.state === 'CHECKING' ? '<div class="skel" style="height:64px;margin-top:10px"></div>' : `<div class="mcrit" style="margin:10px 0 0">${esc(i.err || (IGST[i.state] || [])[0] || '')}</div>`}</div>`;
}
// WARPs needed for the 24 h peak: one WARP keeps its speed up to ~2500 connections / 5 min, +1 spare (3-10), + Google's own
const igWarpNeed = (i) => { if (i.wpeak === undefined || i.wpeak === '-' || i.wpeak === '') return null; const p = +i.wpeak || 0, g = (i.gw || '').split(',').filter(Boolean).length;
  const ig = Math.min(10, Math.max(3, Math.ceil(p / 2500) + 1)); return { p, ig, g, total: ig + g, have: +i.warps || 0 }; };
const igPeakChip = (i) => { const n = igWarpNeed(i); if (!n) return ''; return `<span class="chip ${n.have < n.total ? 'bad' : ''}" title="most user connections on Instagram's WARPs in 24 h (every 5 min); one WARP keeps its speed up to ~2500">peak ${n.p} → ${n.ig} WARP${n.g ? ' + ' + n.g + ' Google' : ''} suggested${i.wauto === 'ON' ? ' (auto)' : ''}</span>`; };
const igGccChip = (i) => i.gcc === undefined || i.gcc === '-' || i.gcc === '' ? '' : i.gcc === 'PROXY' ? '<span class="chip bad" title="no allowed WARP for Google: Google goes through a proxy for now">no allowed WARP → proxy</span>' : `<span class="chip" title="the country Google sees for its current WARP">${esc(i.gcc)}</span>`;

async function igAddServer() {
  if (!IG.data) await igLoad();
  // the admin can add any account's server, whatever the View shows (on "My own" the list used to
  // be empty though other accounts had servers to add); the viewed account's come first
  const all = IG.data?.candidates || [];
  const c = all.filter(x => shownOwner(x.Owner)).concat(all.filter(x => !shownOwner(x.Owner)));
  const groups = [];
  c.forEach(x => { const g = groups.find(g => g.o === x.Owner); g ? g.l.push(x) : groups.push({ o: x.Owner, l: [x] }); });
  const opt = (x) => `<option value="${esc(x.ID)}">${esc(x.Name)} — ${esc(x.Host)}</option>`;
  const opts = isAdmin() ? groups.map(g => `<optgroup label="${g.o ? '👤 ' + esc(g.o) : 'admins'}">${g.l.map(opt).join('')}</optgroup>`).join('') : c.map(opt).join('');
  const m = modal(`<h2>Add a server to IG routing</h2>
    ${c.length ? `<div class="ff" style="grid-template-columns:1fr"><label class="f">Server<select id="igas">${opts}</select></label>
    <label class="f row"><input type="checkbox" id="igad"> Reinstall the agent even if it's already there</label></div>
    <p class="muted" style="font-size:13px">The panel reaches it the way it reaches it for tunnels (its saved SSH login or agent). If igproxy isn't on it yet, it's installed now.</p>
    <div class="actions" style="justify-content:flex-end;margin-top:12px"><button class="btn pri" id="igago">Add</button></div>`
    : `<p class="muted">Every foreign server${isAdmin() ? ' of every account' : ''} is already here. A new machine is added as a foreign server first, then here.</p>
    <div class="actions" style="justify-content:flex-end;margin-top:12px"><button class="btn pri" id="ignew">+ Add foreign server</button></div>`}`);
  const nw = $('#ignew', m);
  if (nw) nw.onclick = () => { m.remove(); serverModal({ role: 'foreign' }); };
  const go = $('#igago', m);
  if (go) go.onclick = async () => {
    const x = c.find(x => x.ID === $('#igas', m).value);
    try {
      const r = await api('/igproxy/enable', { ID: x.ID, On: true, Deploy: $('#igad', m).checked }); m.remove();
      await igRunJob(r.job, 'Add server — ' + x.Name, () => igLoad(true));
      if (!shownOwner(x.Owner)) toast(`${x.Name} belongs to ${x.Owner || 'the admins'}: switch View to see it`);
    } catch (e) { toast(e.message); }
  };
}

// ---- one server
const IGTABS = [['routes', 'Routes'], ['proxies', 'Proxies'], ['warp', 'WARP'], ['sites', 'My sites'], ['settings', 'Settings'], ['checks', 'Test account · Gemini · Telegram'], ['tools', 'Tests & diagnosis'], ['server', 'Server']];
function igDetail(w) {
  const s = IG.cur, i = s.info || {};
  w.innerHTML = topbar(s.name, s.host, `<button class="btn" id="igback">← All servers</button><button class="btn" id="igre">↻</button>`);
  $('#igback', w).onclick = () => { IG.cur = null; igRender(); };
  $('#igre', w).onclick = () => igRefreshAfter({ srv: s.id });
  w.insertAdjacentHTML('beforeend', `<div class="card pad"><div class="statline">${igPill(i.state)} ${igOwner(s)}
    ${i.ig ? `<span>router <b>${esc(i.router)}</b></span><span>redirect <b>${esc(i.redirect)}</b></span><span>🔗 connections <b>${+i.caught || 0}</b></span>
    <span>active WARP <b class="mono">${esc(i.active)}</b></span><span>Google's WARP <b class="mono">${esc(i.gact)}</b></span>
    <span>Gemini ${igChk(i.gem)}</span><span>Instagram ${igChk(i.igp)}</span><span>panel <b class="mono">${esc(i.panel || '-')}</b></span>
    ${i.guard !== undefined ? `<span>WARP guard <b style="${i.guard === 'DOWN' ? 'color:var(--crit)' : ''}">${i.guard === 'ON' ? 'on' : i.guard === 'DOWN' ? 'not running' : 'off'}</b></span>` : ''}
    <span>Gemini users (10 min) <b class="mono">${esc((i.gusers || '').replace(/,/g, ' ') || '—')}</b></span><span>agent <b class="mono">${esc(i.sum)}</b></span>`
    : `<span>${esc(i.err || '')}</span>`}</div>
    ${i.wide === 'ON' ? '<div class="mdesc">Wide catch is on: all web traffic of this server passes the igproxy router and is routed by domain.</div>' : ''}
    ${i.state === 'PANEL' ? '<div class="mcrit" style="margin:10px 0 0">The x-ui panel on this server blocks or diverts Google before igproxy sees it → Tests & diagnosis → Fix panel.</div>' : ''}
    ${['UPDATE', 'NOAGENT'].includes(i.state) ? '<div class="mwarn" style="margin:10px 0 0">The agent here is old or not installed → Server → Install / update.</div>' : ''}</div>
    <div class="seg igtabs">${IGTABS.map(([k, t]) => `<button data-t="${k}" class="${k === IG.tab ? 'on' : ''}">${t}</button>`).join('')}</div><div id="igtab"></div>`);
  $$('.igtabs button', w).forEach(b => b.onclick = () => { IG.tab = b.dataset.t; igRender(); });
  if (!i.ig && IG.tab !== 'tools' && IG.tab !== 'server') {
    $('#igtab').innerHTML = `<div class="card empty"><div class="big">${i.state === 'OFFLINE' ? '📡' : '📦'}</div><h3>${esc((IGST[i.state] || [i.state])[0])}</h3>
      <p class="muted">${i.state === 'OFFLINE' ? 'The panel can\'t reach this server right now.' : 'This part works once the agent is installed.'}</p>${i.state === 'OFFLINE' ? '' : `<button class="btn pri" id="igdep">Install / update agent</button>`}</div>`;
    $('#igdep') && ($('#igdep').onclick = () => igAct(igS({ action: 'deploy' })));
    return;
  }
  (IGTAB[IG.tab] || IGTAB.routes)();
}
function igViaOpts(svc, cur, nprox) {
  const o = ['proxy']; for (let k = 1; k <= nprox; k++) o.push('proxy' + k); o.push('warp'); if (!IGWIDE.includes(svc)) o.push('warp6', 'ipv6'); o.push('direct');
  if (cur && !o.includes(cur)) o.push(cur);
  return o.map(v => `<option value="${v}"${v === cur ? ' selected' : ''}>${igViaW(v)}</option>`).join('');
}
const igSecret = 'type="text" class="inp mono secret" autocomplete="off" data-lpignore="true" data-1p-ignore spellcheck="false"';
const IGTAB = {
  routes() {
    const i = IG.cur.info;
    $('#igtab').innerHTML = `<div class="card pad"><table class="tbl igt"><tr><th>Service</th><th>Goes out through</th><th></th></tr>
      ${Object.keys(IGSV).map(g => `<tr><td><b>${IGSV[g]}</b>${g === 'CUSTOM' ? ` <span class="faint">(${+i.ncustom || 0} sites)</span>` : ''}${g === 'GOOGLE' && /^warp/.test(i.google || '') ? ' ' + igGccChip(i) : ''}</td>
      <td><select data-g="${g}" data-cur="${esc(i[g.toLowerCase()])}">${igViaOpts(g, i[g.toLowerCase()], +i.proxies || 0)}</select></td>
      <td style="text-align:end"><button class="btn sm pri" data-ap="${g}" hidden>Apply</button></td></tr>`).join('')}</table>
      <div class="mdesc">Proxy = the fastest healthy proxy · "Proxy N" = only that one · WARP = Cloudflare WARP · IPv6 = the server's own IPv6 (Instagram, Google, YouTube Music only) · Direct = the server's own IP.
      The router restarts (a few seconds) only when a setting really changes.</div>
      <div class="actions" style="margin-top:12px"><button class="btn sm" id="igrd">Route details</button></div></div>`;
    $$('#igtab select[data-g]').forEach(sel => sel.onchange = () => { const ch = sel.value !== sel.dataset.cur; sel.classList.toggle('chg', ch); $(`[data-ap="${sel.dataset.g}"]`).hidden = !ch; });
    $$('[data-ap]').forEach(b => b.onclick = () => igAct(igS({ action: 'route', svc: b.dataset.ap, via: $(`select[data-g="${b.dataset.ap}"]`).value })));
    $('#igrd').onclick = () => igAct(igS({ action: 'routes' }), null, { refresh: false });
  },
  proxies() {
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>Proxies <span class="grow"></span><button class="btn sm" id="igpt">Test ping & location</button></h3><div id="igpl" class="lines"><div class="skel" style="height:80px"></div></div></div>
     <div class="card pad sec"><h3>Add a proxy</h3><div class="ff">
     <label class="f">Type<select id="igpty" class="inp"><option value="http">HTTP</option><option value="socks5">SOCKS5</option></select></label>
     <label class="f">Host<input id="igph" class="inp mono"></label><label class="f">Port<input id="igpp" class="inp mono" inputmode="numeric"></label>
     <label class="f">User (optional)<input id="igpu" class="inp mono" autocomplete="off"></label><label class="f">Password<input id="igpw" ${igSecret}></label>
     <label class="f row"><input type="checkbox" id="igpall"> On every server in view</label></div>
     <div class="actions" style="margin-top:12px"><button class="btn pri" id="igpadd">Add (tested first)</button></div></div>`;
    $('#igpadd').onclick = () => igAct({ srv: $('#igpall').checked ? 'all' : IG.cur.id, action: 'proxy_add', type: $('#igpty').value, host: $('#igph').value.trim(), port: $('#igpp').value.trim(), user: $('#igpu').value.trim(), pass: $('#igpw').value });
    $('#igpt').onclick = () => igListInto('#igpl', 'proxy_list', true, 'proxy_del');
    igListInto('#igpl', 'proxy_list', false, 'proxy_del');
  },
  warp() {
    const i = IG.cur.info, gA = i.gw !== undefined ? 'google_use' : null;
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>WARP accounts <span class="chip">active: <b class="mono">${esc(i.active)}</b></span><span class="chip">Google: <b class="mono">${esc(i.gact)}</b></span>${igPeakChip(i)}<span class="grow"></span><button class="btn sm" id="igwt">Test all (music & speed)</button></h3>
     <div id="igwl" class="lines"><div class="skel" style="height:80px"></div></div>
     <div class="actions" style="margin-top:12px"><button class="btn pri" id="igwa">+ New WARP account</button><button class="btn" id="igwr">Google → fresh IP</button></div>
     <div class="mdesc">Repairing a broken WARP, WARP+ keys and choosing the best WARP (music OK and fastest) are automatic. "Use" = this WARP serves Instagram and Google right now (live).</div></div>
     ${gA ? `<div class="card pad sec"><h3>Google on WARP <span class="chip">Google's own WARPs: <b class="mono">${esc(i.gw || '—')}</b></span>${igGccChip(i)}<span class="grow"></span><button class="btn sm" id="igwc">Country per WARP</button></h3>
      <div id="iggcl" class="lines"><div class="faint">"Country per WARP" shows which country Google sees for each WARP.</div></div>
      <div class="mdesc">"Google" moves only Google to that WARP (Instagram stays) and refuses a WARP outside the group or the allowed countries — those are under Settings.</div></div>` : ''}`;
    $('#igwa').onclick = () => igAct(igS({ action: 'warp_add' }));
    $('#igwr').onclick = () => igAct(igS({ action: 'google_rotate' }));
    $('#igwt').onclick = () => igListInto('#igwl', 'warp_list', true, 'warp_del', 'warp_use', gA);
    if (gA) $('#igwc').onclick = () => igListInto('#iggcl', 'google_countries', true, null, null, gA);
    igListInto('#igwl', 'warp_ls', false, 'warp_del', 'warp_use', gA);
  },
  sites() {
    const i = IG.cur.info;
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>My sites <span class="faint" style="font-size:12px;font-weight:500">each with all its subdomains</span></h3><div id="igcl" class="lines"><div class="skel" style="height:60px"></div></div></div>
     <div class="card pad sec"><h3>Add a site</h3><div class="ff"><label class="f">Site<input id="igcs" class="inp mono" placeholder="example.com"></label>
     <label class="f">Route<select id="igcr" class="inp"><option value="">the "My sites" route (${igViaW(i.custom)})</option><option value="proxy">Proxy</option><option value="warp">WARP</option><option value="direct">Direct</option></select></label>
     <label class="f row"><input type="checkbox" id="igcall"> On every server in view</label></div>
     <div class="actions" style="margin-top:12px"><button class="btn pri" id="igcadd">Add</button></div></div>`;
    $('#igcadd').onclick = () => igAct({ srv: $('#igcall').checked ? 'all' : IG.cur.id, action: 'custom_add', site: $('#igcs').value.trim(), route: $('#igcr').value });
    igListInto('#igcl', 'custom_list', false, 'custom_del');
  },
  settings() {
    const i = IG.cur.info;
    const tog = (k, label, v, help) => `<div class="set"><div class="d"><b>${label}</b><small>${help}</small></div><label class="sw2"><input type="checkbox" data-tg="${k}"${v === 'ON' ? ' checked' : ''}><i></i></label></div>`;
    const num = (k, label, v, help, unit) => `<div class="set"><div class="d"><b>${label}</b><small>${help}</small></div><input class="inp mono" style="width:90px" data-nv="${k}" value="${esc(v)}"><span class="faint">${unit || ''}</span><button class="btn sm" data-ns="${k}">Save</button></div>`;
    $('#igtab').innerHTML = `<div class="card pad">
      ${num('minspeed', 'Minimum WARP speed', i.min, 'best WARP = music OK and at least this fast; the fastest wins', 'Mbps')}
      ${num('minwarps', 'Minimum number of WARPs', i.minw, 'missing ones are made automatically (more users = more WARPs); 0 = off', '')}
      ${num('grotate', 'Fresh IP for Google every', i.grot, '10 to 1440 (20 suggested); 0 = only when the IP breaks', 'min')}
      ${i.guard !== undefined ? tog('guard', 'WARP guard (fast switch)', i.guard === 'OFF' ? 'OFF' : 'ON', 'the active WARP is checked every 5 s; down / no music / slow → live switch to the best other WARP' + (i.guard === 'DOWN' ? ' — <b style="color:var(--crit)">on, but its service isn\'t running</b>' : '')) : ''}
      ${i.gw !== undefined ? num('gwarps', 'WARPs only for Google', i.gwarps ?? (i.gw ? i.gw.split(',').length : ''), 'the last N WARP accounts serve only Google (0-9, default 2); Instagram uses the rest', '') : ''}
      ${i.gw !== undefined ? `<div class="set"><div class="d"><b>Allowed countries for Google</b><small>two-letter codes with spaces; a WARP that Google places in another country isn't used for Google. With none allowed, Google goes through a proxy for now.</small></div>
        <input class="inp mono" style="width:260px" id="iggcs" placeholder="US GB DE FR NL FI SE CH AT BE IT ES PL CA JP SG AU" value="${esc(i.gcountries || '')}"><button class="btn sm" id="iggcsave">Save</button></div>` : ''}
      ${i.mchk !== undefined ? num('musiccheck', 'Instagram music check every', i.mchk, '0 = off; only while Instagram is on WARP and a test account is set', 'min') : ''}
      <div class="set"><div class="d"><b>WARP mode</b><small>FAILOVER = the best one active, the rest stand by · BALANCE = spread the load (may break Instagram music)</small></div>
        <select class="inp" style="width:150px" id="igmode"><option value="failover"${i.mode !== 'BALANCE' ? ' selected' : ''}>FAILOVER</option><option value="balance"${i.mode === 'BALANCE' ? ' selected' : ''}>BALANCE</option></select></div>
      ${tog('autokey', 'Automatic WARP+ key', i.autokey, 'finds WARP+ keys in a public channel and tries them')}
      ${tog('geosite', 'geosite domain lists', i.geo, 'fuller domain lists (updated daily, loaded at night)')}
      ${tog('gspread', 'Google on every WARP', i.gspread, 'many users → spread Gemini over every WARP IP')}
      ${tog('gall', 'All of Google on Google\'s WARP', i.gall, 'all google.com / gstatic / googleapis (YouTube video stays direct)')}
      ${tog('warpauto', 'WARP count follows the load', i.wauto, 'from the 24 h peak: one WARP per ~2500 connections in 5 min, plus a spare (3-10) and Google\'s WARPs')}
      <div class="mdesc">These apply to this server only; for the others use Backup & copy → Copy settings.</div></div>`;
    $$('[data-tg]').forEach(c => c.onchange = () => igAct(igS({ action: 'set', key: c.dataset.tg, val: c.checked ? 'on' : 'off' })));
    $$('[data-ns]').forEach(b => b.onclick = () => igAct(igS({ action: 'set', key: b.dataset.ns, val: $(`[data-nv="${b.dataset.ns}"]`).value.trim() })));
    $('#igmode').onchange = (e) => igAct(igS({ action: 'set', key: 'mode', val: e.target.value }));
    $('#iggcsave') && ($('#iggcsave').onclick = () => { const v = $('#iggcs').value.trim().toUpperCase().replace(/[\s,]+/g, ' ');
      if (!/^[A-Z]{2}( [A-Z]{2})*$/.test(v)) return toast('Two-letter codes with spaces, like US GB DE'); igAct(igS({ action: 'set', key: 'gcountries', val: v })); });
  },
  checks() {
    const i = IG.cur.info, st = (v) => `<span class="pill ${v === 'SET' || v === 'ON' ? 'on' : 'off'}"><span class="led"></span>${v === 'SET' || v === 'ON' ? 'set' : 'not set'}</span>`;
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>Instagram test account (music) ${st(i.igacc)}</h3>
      <p class="muted">With a spare account (not a real one) the server tests on every exit IP whether Instagram music plays.</p>
      <div class="ff"><label class="f">sessionid cookie<input id="igsid" ${igSecret}></label></div>
      <div class="actions" style="margin-top:10px"><button class="btn pri" id="igsidgo">Save & test</button><button class="btn" id="igmt">Music test</button><button class="btn danger" id="igsdel">Remove</button></div></div>
     <div class="card pad sec"><h3>Gemini API key ${st(i.gkey)}</h3>
      <p class="muted">With a free aistudio.google.com key each server asks Gemini through its WARP IPs whether the region is blocked.</p>
      <div class="ff"><label class="f">Key (AIza…)<input id="iggk" ${igSecret}></label><label class="f row"><input type="checkbox" id="iggkall"> On every server in view</label></div>
      <div class="actions" style="margin-top:10px"><button class="btn pri" id="iggkgo">Save</button><button class="btn" id="iggkt">Test on every WARP</button><button class="btn danger" id="iggkdel">Remove</button></div></div>
     <div class="card pad sec"><h3>Telegram bot ${st(i.tg)}</h3>
      <p class="muted">Reports outages, repairs and proxy problems. Commands: /status /music /warp. After "Set up", send <b>/start</b> to the bot within 60 seconds.</p>
      <div class="ff"><label class="f">Token (from BotFather)<input id="igtt" ${igSecret}></label></div>
      <div class="actions" style="margin-top:10px"><button class="btn pri" id="igtgo">Set up</button><button class="btn" id="igtt2">Test message</button><button class="btn danger" id="igtdel">Remove</button></div></div>`;
    $('#igsidgo').onclick = () => igAct(igS({ action: 'ig_session', sid: $('#igsid').value.trim() }));
    $('#igmt').onclick = () => igAct(igS({ action: 'ig_test' }));
    $('#igsdel').onclick = () => igAct(igS({ action: 'ig_del' }), 'Remove the test account?');
    $('#iggkgo').onclick = () => igAct({ srv: $('#iggkall').checked ? 'all' : IG.cur.id, action: 'gemkey_set', key: $('#iggk').value.trim() });
    $('#iggkt').onclick = () => igAct(igS({ action: 'gemkey_test' }));
    $('#iggkdel').onclick = () => igAct(igS({ action: 'gemkey_del' }), 'Remove the key?');
    $('#igtgo').onclick = () => igAct(igS({ action: 'tg_setup', token: $('#igtt').value.trim() }));
    $('#igtt2').onclick = () => igAct(igS({ action: 'tg_test' }));
    $('#igtdel').onclick = () => igAct(igS({ action: 'tg_del' }), 'Remove the bot?');
  },
  tools() {
    const i = IG.cur.info, nr = { refresh: false };
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>Tests</h3><div class="actions">
      <button class="btn" data-a="status">Full test (every proxy and WARP)</button><button class="btn" data-a="speedtest">Speed test of every exit</button>
      <button class="btn" data-a="diag">Diagnose Gemini / Google</button><button class="btn" data-a="gemusers">Gemini users</button><button class="btn" data-a="logs">Logs</button></div></div>
     <div class="card pad sec"><h3>Traffic: domain → exit</h3><div class="ff"><label class="f">Only lines containing<input id="igtw" class="inp mono" placeholder="google, instagram …"></label></div>
      <div class="actions" style="margin-top:10px"><button class="btn" id="igrec">Last 40 connections</button><button class="btn pri" id="igwatch">Live (60 s)</button></div></div>
     <div class="card pad sec"><h3>The x-ui / xray panel on this server <span class="chip mono">${esc(i.panel || '-')}</span></h3>
      <p class="muted">If the panel blocks Google or sends it to another exit, igproxy never sees it. "Fix" adds one rule at the top of the panel's routing (tested first, backed up, undone automatically if it fails).</p>
      <div class="actions"><button class="btn" id="igpc">Check</button><button class="btn pri" id="igpf">Fix</button><button class="btn danger" id="igpu2">Undo</button></div></div>`;
    const P = { status: { action: 'status' }, speedtest: { action: 'speedtest', target: 'all' }, diag: { action: 'diag' }, gemusers: { action: 'gemusers', n: 10 }, logs: { action: 'logs', n: 150 } };
    $$('#igtab [data-a]').forEach(b => b.onclick = () => igAct(igS(P[b.dataset.a]), null, nr));
    $('#igrec').onclick = () => igAct(igS({ action: 'recent', word: $('#igtw').value.trim() }), null, nr);
    $('#igwatch').onclick = () => igAct(igS({ action: 'watch', word: $('#igtw').value.trim() }), null, { refresh: false, title: 'Live traffic (60 s) — open the app on a phone now' });
    $('#igpc').onclick = () => igAct(igS({ action: 'panel_check' }), null, nr);
    $('#igpf').onclick = () => igAct(igS({ action: 'panel_fix' }), 'Add one rule at the top of the panel\'s routing? Its Xray restarts for 2-3 seconds.');
    $('#igpu2').onclick = () => igAct(igS({ action: 'panel_undo' }), 'Remove the igproxy rule from the panel?');
  },
  server() {
    const s = IG.cur, i = s.info || {};
    $('#igtab').innerHTML = `<div class="card pad sec"><h3>Agent</h3><table class="tbl igt">
      <tr><td>Server</td><td><b>${esc(s.name)}</b> <span class="mono faint">${esc(s.host)}</span></td></tr>
      <tr><td>Agent on this server</td><td class="mono">${esc(i.sum || '—')}</td></tr><tr><td>Agent on the panel</td><td class="mono">${esc(IG.data?.agent || '—')}</td></tr></table>
      <div class="actions" style="margin-top:12px"><button class="btn pri" id="igsd">Install / update agent</button>
      <button class="btn" id="igsa">${i.paused === 'YES' ? 'Turn back on' : 'Re-apply / restart'}</button>
      ${i.paused === 'YES' ? '' : '<button class="btn" id="igsp">Pause (everything direct)</button>'}</div>
      <p class="muted" style="font-size:13px;margin-bottom:0">Name, address and SSH login are the server's own, under <b>Servers</b>.</p></div>
     <div class="card pad sec"><h3>Remove</h3><div class="actions"><button class="btn danger" id="igsr">Take off this page</button><button class="btn danger" id="igsu">Uninstall igproxy from the server</button></div>
      <p class="muted" style="font-size:13px;margin-bottom:0">Taking it off the page leaves igproxy running on the server.</p></div>`;
    $('#igsd').onclick = () => igAct(igS({ action: 'deploy' }), `Install / update the agent on ${s.name}? A few seconds without routing; settings and WARPs are kept.`);
    $('#igsa').onclick = () => igAct(igS({ action: 'apply' }));
    $('#igsp') && ($('#igsp').onclick = () => igAct(igS({ action: 'pause' }), 'Pause igproxy? All traffic goes direct until you turn it back on.'));
    $('#igsr').onclick = () => igRemove(false);
    $('#igsu').onclick = () => igRemove(true);
  }
};
async function igRemove(uninstall) {
  const s = IG.cur;
  if (uninstall) {
    if (!confirm(`Remove igproxy from ${s.name} completely? Its settings and WARPs on that server are deleted.`)) return;
    try { const r = await api('/igproxy/action', igS({ action: 'uninstall' })); const res = await igRunJob(r.job, 'Uninstall igproxy'); if (!res.done) return; } catch (e) { return toast(e.message); }
  } else if (!confirm(`Take ${s.name} off the IG routing page? igproxy keeps running on it.`)) return;
  try { await api('/igproxy/enable', { ID: s.id, On: false }); IG.cur = null; toast('Removed'); igLoad(true); } catch (e) { toast(e.message); }
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
      return `<div class="ln${hl ? ' hl' : ''}"><span class="t mono" title="${esc(l.trim())}">${esc(l.trim())}</span>${m && gA && gw.includes(m[1]) ? `<button class="btn sm" data-gu="${m[1]}" title="only Google moves to this WARP">Google</button>` : ''}${m && useA ? `<button class="btn sm" data-u="${m[1]}">Use</button>` : ''}${m && delA ? `<button class="btn sm danger" data-d="${m[1]}">Delete</button>` : ''}</div>`;
    }).join('') : '<div class="faint">empty</div>';
    $$('[data-d]', box).forEach(b => b.onclick = () => igAct(igS({ action: delA, n: b.dataset.d }), 'Delete number ' + b.dataset.d + '?'));
    $$('[data-u]', box).forEach(b => b.onclick = () => igAct(igS({ action: useA, n: b.dataset.u })));
    $$('[data-gu]', box).forEach(b => b.onclick = () => igAct(igS({ action: gA, n: b.dataset.gu })));
  } catch (e) { toast(e.message); box.innerHTML = ''; }
}

// ---- route table: every server × service
function igMatrix(box) {
  if (!IG.data) { box.innerHTML = '<div class="skel" style="height:200px"></div>'; return; }
  const L = igList().filter(s => s.info.ig), maxp = Math.max(0, ...L.map(s => +s.info.proxies || 0));
  if (!L.length) { box.innerHTML = '<div class="card empty"><div class="big">🔀</div>No server with a running agent to route.</div>'; return; }
  box.innerHTML = `<div class="card pad mat"><div class="actions" style="justify-content:flex-end;margin-bottom:6px"><button class="btn pri" id="igmApply" disabled>Apply changes</button></div>
    <table class="tbl igt"><thead><tr><th>Server</th>${Object.keys(IGSV).map(g => `<th>${IGSV[g]}</th>`).join('')}</tr></thead><tbody>
    <tr><td><b>All servers →</b></td>${Object.keys(IGSV).map(g => `<td data-l="${IGSV[g]}"><select data-all="${g}"><option value="">—</option>${igViaOpts(g, '', maxp)}</select></td>`).join('')}</tr>
    ${L.map(s => `<tr><td><b>${esc(s.name)}</b> ${igOwner(s)} ${s.info.state === 'OK' ? '' : igPill(s.info.state)}</td>${Object.keys(IGSV).map(g => { const v = s.info[g.toLowerCase()]; return `<td data-l="${IGSV[g]}"><select data-s="${esc(s.id)}" data-g="${g}" data-cur="${esc(v)}">${igViaOpts(g, v, +s.info.proxies || 0)}</select></td>`; }).join('')}</tr>`).join('')}</tbody>
    </table><div class="mdesc">The "All servers" row sets one service on every row (not applied yet). Servers that are offline or without the agent aren't in the table.</div></div>`;
  const mark = () => { let n = 0; $$('select[data-s]', box).forEach(x => { const c = x.value !== x.dataset.cur; x.classList.toggle('chg', c); n += c; }); $('#igmApply').disabled = !n; $('#igmApply').textContent = n ? `Apply ${n} change${n > 1 ? 's' : ''}` : 'Apply changes'; };
  $$('select[data-s]', box).forEach(x => x.onchange = mark);
  // a choice a server doesn't have (Proxy 3 where it has two) leaves that row as it was
  $$('select[data-all]', box).forEach(x => x.onchange = () => { if (!x.value) return; $$(`select[data-g="${x.dataset.all}"][data-s]`, box).forEach(y => { if ([...y.options].some(o => o.value === x.value)) y.value = x.value; }); mark(); });
  $('#igmApply').onclick = async () => {
    const ch = $$('select[data-s]', box).filter(x => x.value !== x.dataset.cur).map(x => ({ srv: x.dataset.s, svc: x.dataset.g, via: x.value }));
    if (!ch.length || !confirm(`Apply ${ch.length} route change${ch.length > 1 ? 's' : ''}?`)) return;
    // one after the other: two changes on one server at once would race
    for (const c of ch) {
      let r; try { r = await api('/igproxy/action', { srv: c.srv, action: 'route', svc: c.svc, via: c.via }); } catch (e) { toast(e.message); continue; }
      const res = await igRunJob(r.job, 'Route — ' + ((IG.data.servers.find(s => s.id === c.srv) || {}).name || '') + ' · ' + IGSV[c.svc]);
      if (!res.done) break;
    }
    igLoad(true);
  };
}

// ---- every server at once
function igBulk(box) {
  const card = (i, t, d, id) => `<div class="card pad"><h3 style="margin:0 0 6px">${i} ${t}</h3><p class="muted" style="margin:0 0 12px;font-size:13px">${d}</p><button class="btn pri" data-b="${id}">Run</button></div>`;
  box.innerHTML = `<p class="muted" style="margin-top:0">On every server in view, one after the other.</p><div class="grid cards">
    ${card('🧪', 'Test all', 'Tests every proxy and WARP of every server.', 'test')}
    ${card('🔄', 'Fresh Google IP everywhere', 'When users complain about Gemini: Google moves to a fresh WARP IP on each server now.', 'rotate')}
    ${card('⬆️', 'Update old agents', 'Installs the current agent where an old one runs (a few seconds per server).', 'deploy')}
    ${card('🛠', 'Fix panels', 'Where the x-ui panel diverts Google, adds one rule at the top of its routing.', 'fix')}
    ${card('📜', 'Logs of all', 'The last 40 igproxy log lines of each server.', 'logs')}
    ${card('👥', 'Gemini users', 'Gemini connections of the last 10 minutes, per exit.', 'gem')}</div>`;
  const nr = { refresh: false };
  const B = {
    test: () => igAct({ srv: 'all', action: 'status_short' }, null, nr),
    rotate: () => igAct({ srv: 'all', action: 'google_rotate' }),
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
  const L = igList(), opts = L.map(s => `<option value="${esc(s.id)}">${esc(s.name)}${s.owner ? ' (' + esc(s.owner) + ')' : ''}</option>`).join('');
  box.innerHTML = `<p class="muted" style="margin-top:0">WARP accounts are never copied or backed up: each server keeps its own.</p>
   <div class="card pad sec"><h3>Copy settings from one server to others</h3><div class="ff">
    <label class="f">From<select id="igcf" class="inp">${opts}</select></label>
    <label class="f" style="grid-column:span 2">What<select id="igcp" class="inp"><option value="routes proxies ig tg opts">Everything: routes, sites, proxies, test account + Gemini key, Telegram, settings</option><option value="routes">Routes + sites only</option><option value="proxies">Proxies only</option><option value="routes proxies">Routes + sites + proxies</option><option value="opts">WARP settings only</option></select></label></div>
    <div style="margin:12px 0" id="igct">${L.map(s => `<label class="f row" style="display:inline-flex;margin-inline-end:14px"><input type="checkbox" value="${esc(s.id)}" checked> ${esc(s.name)}${s.owner ? ' (' + esc(s.owner) + ')' : ''}</label>`).join('')}</div>
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
    const nameOf = (x) => { const s = (IG.data?.servers || []).find(y => y.id === x.server); return (s ? s.name : x.file) + ' · ' + new Date(x.t * 1000).toLocaleString() + (x.owner ? ' (' + x.owner + ')' : ''); };
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
