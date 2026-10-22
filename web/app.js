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
    STATE.user = me.user; STATE.version = me.version || "";
    await loadAll();
    renderShell();
  } catch (e) { renderAuth('login'); }
}
async function loadAll() {
  const [methods, servers, tunnels, settings, helpers] = await Promise.all([
    api('/methods'), api('/servers'), api('/tunnels'), api('/settings'), api('/helpers').catch(() => [])]);
  STATE.helpers = (helpers || []).map(x => x.name); STATE.hostArch = (settings && settings.hostArch) || 'amd64';
  STATE.methods = methods || []; STATE.servers = servers || []; STATE.tunnels = tunnels || [];
  STATE.settings = (settings && settings.settings) || {}; STATE.agentPin = settings.agentPin || ''; STATE.agentPort = settings.agentPort || 7020;
}
const iranServers = () => STATE.servers.filter(s => (s.role || 'iran') === 'iran');
const foreignServers = () => STATE.servers.filter(s => s.role === 'foreign');
const methodsFor = (fam) => STATE.methods.filter(m => m.families.includes(fam));
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
  quantumBg.start();
  $('#af').onsubmit = async (ev) => {
    ev.preventDefault();
    try { await api(reg ? '/register' : '/login', { username: ev.target.u.value, password: ev.target.p.value }); location.reload(); }
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
  let cv, ctx, raf = 0, last = 0, W = 0, H = 0, dpr = 1, on = true, time = 0;
  try { on = localStorage.getItem('tp-bg') !== 'off'; } catch (e) {}
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
  const nav = [['servers', 'Servers', '🖥'], ['tunnels', 'Tunnels', '🛰'], ['routes', 'Routes', '🔀'], ['bench', 'Benchmark', '📊'], ['settings', 'Settings', '⚙']];
  const shell = h(`<div class="shell">
    <aside class="side" id="side">
      <div class="brand"><div class="dot"></div><div><b>${esc(STATE.settings.panelName || 'Tunnel Panel')}</b><small>server link manager</small></div></div>
      <nav class="nav">${nav.map(n => `<button data-v="${n[0]}"><span>${n[2]}</span>${n[1]}</button>`).join('')}</nav>
      <div class="foot">
        <button class="btn ghost sm" id="themeBtn">◐ Theme</button>
        <button class="btn ghost sm" id="bgBtn" title="Animated background on/off">✦ Live background</button>
        <div class="faint" style="font-size:11px;padding:0 8px">Signed in as <b>${esc(STATE.user)}</b>${STATE.version ? `<br>version <span class="mono">${esc(STATE.version)}</span>` : ''}</div>
        <button class="btn ghost sm" id="logout">Sign out</button>
      </div></aside>
    <main class="main" id="work"></main></div>`);
  document.body.appendChild(shell);
  $$('.nav button', shell).forEach(b => b.onclick = () => { STATE.view = b.dataset.v; paintNav(); renderView(); $('#side').classList.remove('open'); });
  $('#logout').onclick = async () => { await api('/logout', {}); location.reload(); };
  $('#themeBtn').onclick = toggleTheme;
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

function renderView() {
  const w = $('#work'); w.innerHTML = '';
  ({ tunnels: viewTunnels, servers: viewServers, routes: viewRoutes, bench: viewBench, settings: viewSettings }[STATE.view])(w);
  trafficWatch();
  healthWatch();
}

/* ---------------- routes ---------------- */
// One card per Iran ⇄ foreign pair: its tunnels and every path they run (hot standby: each
// path ✓/✕ and the one users are on), and the order the next Re-apply / hot standby /
// failover uses — the pair's latest benchmark ranking, per address family.
const ageTxt = (u) => { const s = Math.floor(Date.now() / 1000) - u; return s < 3600 ? `${Math.max(1, Math.floor(s / 60))} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`; };
async function viewRoutes(w) {
  w.innerHTML = topbar('Routes', 'Each Iran ⇄ foreign pair: which tunnels and paths are connected, which one carries the users, and the order a Re-apply, hot standby or failover picks paths in (the latest benchmark of that pair).');
  const box = h('<div class="grid" style="gap:16px"><div class="muted">loading…</div></div>');
  w.appendChild(box);
  let hist = [];
  try { hist = await api('/bench/history'); } catch (e) {}
  const pairs = new Map();
  const key = (i, f) => i + '|' + (f || '');
  STATE.tunnels.forEach(t => { const k = key(t.serverId, t.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: t.serverId, foreign: t.foreignId || '', tunnels: [] }); pairs.get(k).tunnels.push(t); });
  hist.forEach(r => { const k = key(r.iranId, r.foreignId); if (!pairs.has(k)) pairs.set(k, { iran: r.iranId, foreign: r.foreignId || '', tunnels: [] }); });
  box.innerHTML = '';
  if (!pairs.size) { box.appendChild(h('<div class="card empty"><div class="big">🔀</div>No tunnels or benchmarks yet.</div>')); return; }
  const srvLabel = (id, fb) => { const s = id ? serverById(id) : null; return s ? `${s.country ? flag(s.country) : ''} ${esc(s.name)}` : fb; };
  for (const p of pairs.values()) {
    const tunnels = p.tunnels.map(t => {
      let st, cls;
      if (!t.active) { st = 'stopped'; cls = 'off'; }
      else if (t.health === null || t.health === undefined) { st = 'running · not checked yet'; cls = 'unk'; }
      else if (t.health) { st = '✕ ' + t.health; cls = 'bad'; }
      else { st = '✓ connected'; cls = 'ok'; }
      const m = methodTitle(t.active || t.selected);
      let paths = '';
      if (t.hotStandby && t.hs && t.hs.paths) {
        paths = `<div class="hsl" style="margin:6px 0 0 14px">${t.hs.paths.map((x, i) => `<div class="${t.hs.ok[i] ? 'ok' : 'bad'}${i === t.hs.active ? ' cur' : ''}">${t.hs.ok[i] ? '✓' : '✕'} ${esc(x)}${i === t.hs.active ? ' <b>← users</b>' : ''}</div>`).join('')}</div>`;
      } else if (t.hotStandby) {
        paths = '<div class="faint" style="font-size:12px;margin:4px 0 0 14px">⚡ hot standby on — its paths start on the next Start/Re-apply</div>';
      }
      return `<div class="rt-t ${cls}"><div><b>${esc(t.name)}</b> <span class="faint mono">:${esc(t.ports)}</span></div><div class="faint" style="font-size:12.5px">${esc(m || '—')} · ${famName(t.family)} — <span class="st">${esc(st)}</span></div>${paths}</div>`;
    }).join('') || '<div class="faint">no tunnel on this pair</div>';
    const fams = ['v4', 'v6'].map(f => {
      const r = hist.find(x => x.iranId === p.iran && (x.foreignId || '') === p.foreign && x.family === f);
      if (!r) return `<div class="rt-b"><div class="lbl">${famName(f)}</div><div class="faint" style="font-size:12.5px">not benchmarked yet</div></div>`;
      const rows = r.results.filter(x => !x.skipped).map((x, i) => `<div class="${x.ok ? '' : 'bad'}">${x.ok ? (x.recommended ? '★' : (i + 1) + '.') : '✕'} ${esc(x.title)} ${x.ok ? `<span class="faint">↓${x.downMbps.toFixed(0)} ↑${x.upMbps.toFixed(0)} Mbps · ${x.rttMs.toFixed(0)} ms</span>` : `<span class="faint">${esc((x.error || 'failed').slice(0, 70))}</span>`}</div>`).join('');
      return `<div class="rt-b"><div class="lbl">${famName(f)} · benchmark ${ageTxt(r.at)}</div><div class="hsl">${rows}</div></div>`;
    }).join('');
    const card = h(`<div class="card" style="padding:14px 16px">
      <div class="tc-h"><h3>${srvLabel(p.iran, 'Iran')} ⇄ ${srvLabel(p.foreign, '🖥 this panel host')}</h3><button class="btn sm" data-rb>📊 Benchmark now</button></div>
      <div class="lbl" style="margin-top:8px">Tunnels &amp; paths</div><div class="rt-ts">${tunnels}</div>
      <div class="lbl" style="margin-top:10px">Order a Re-apply / hot standby / failover uses (best first)</div><div class="rt-bs">${fams}</div></div>`);
    $('[data-rb]', card).onclick = async (e) => {
      const fam = (p.tunnels[0] && p.tunnels[0].family) || 'v4';
      try { const r = await api('/bench/start', { iranId: p.iran, foreignId: p.foreign, family: fam, seconds: 3 }); toast('Benchmark started'); openLog({ id: 'bench', name: 'Benchmark' }, r.job); } catch (er) { alertModal('Benchmark', er.message); }
    };
    box.appendChild(card);
  }
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
  const sum = Object.values(tun).reduce((a, x) => (x.error ? a : [a[0] + x.down, a[1] + x.up]), [0, 0]);
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
    <button class="btn ghost sm menu-toggle" onclick="document.getElementById('side').classList.toggle('open')">☰</button>
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
function viewSettings(w) {
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
        <label class="f">Automatic benchmark every … hours <span class="faint">(every route with a running tunnel, on the spare slot — live tunnels aren't touched; blank = 12, 0 = off)</span><input name="autoBench" class="mono" inputmode="numeric" value="${esc(s.autoBench || '')}" placeholder="12"></label>
      </div>
      <h3 style="margin-top:6px">Telegram bot</h3>
      <div class="two">
        <label class="f">Bot token<input name="telegramTok" class="mono" value="${esc(s.telegramTok || '')}" placeholder="123456:ABC..."></label>
        <label class="f">Admin chat id(s)<input name="telegramAdmin" class="mono" value="${esc(s.telegramAdmin || '')}" placeholder="comma-separated"></label>
      </div>
      <div class="faint" style="font-size:12px">Message your bot <b>/start</b>; it replies with your chat id if you're not yet an admin. The bot can start, stop and switch every tunnel.</div>
      <label class="row f"><input type="checkbox" name="telegramBackup" value="on" ${s.telegramBackup === 'on' ? 'checked' : ''}> Send the daily backup to the admin chat too</label>
      <div><button class="btn pri">Save settings</button></div>
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

/* ---------------- servers ---------------- */
// Two clearly separate groups: Iran (entry) and foreign (exit, incl. this panel host).
function viewServers(w) {
  w.innerHTML = topbar('Servers', 'Iran servers are where users connect; foreign servers are where traffic exits. The panel reaches each one by agent, SSH, jump host or proxy — whichever works.');
  const ir = iranServers(), fg = foreignServers();
  const sec = (key, title, sub, n, add) => h(`<section class="group">
    <div class="ghd"><div><h2>${title} <span class="count">${n}</span></h2><p>${sub}</p></div><button class="btn pri sm" data-add="${key}">${add}</button></div>
    <div class="grid cards" data-list="${key}"></div></section>`);
  const irSec = sec('iran', '🇮🇷 Iran servers', 'Entry side — users connect here; the tunnel forwards their traffic abroad.', ir.length, '+ Add Iran server');
  const fgSec = sec('foreign', '🌍 Foreign servers', 'Exit side — your services (xray/v2ray…) run here. This panel host counts as one.', fg.length + 1, '+ Add foreign server');
  const irList = $('[data-list=iran]', irSec), fgList = $('[data-list=foreign]', fgSec);
  if (!ir.length) irList.appendChild(h(`<div class="card empty small"><div class="big">🇮🇷</div>No Iran server yet — add one to start building tunnels.</div>`));
  ir.forEach(x => irList.appendChild(serverCard(x)));
  fgList.appendChild(panelHostCard());
  fg.forEach(x => fgList.appendChild(serverCard(x)));
  w.appendChild(irSec); w.appendChild(fgSec);
  w.appendChild(outageSection());
  $$('[data-add]', w).forEach(b => b.onclick = () => serverModal({ role: b.dataset.add }));
  $$('[data-edit]', w).forEach(b => b.onclick = () => serverModal(STATE.servers.find(x => x.id === b.dataset.edit)));
  $$('[data-del]', w).forEach(b => b.onclick = async () => { if (!confirmInline(b, 'Click again to delete')) return; try { await api('/servers/delete', { ID: b.dataset.del }); await loadAll(); renderView(); } catch (e) { alertModal('Error', e.message); } });
  $$('[data-test]', w).forEach(b => b.onclick = () => testServer(b.dataset.test, b));
  $$('[data-agent]', w).forEach(b => b.onclick = () => agentModal(b.dataset.agent));
  $$('[data-bridge]', w).forEach(b => b.onclick = () => bridgeModal(b.dataset.bridge));
  $$('[data-optz]', w).forEach(b => b.onclick = () => optimizeModal(b.dataset.optz));
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
// keep an open ⋯ menu above the next card (browsers without :has()), and close it once an item is picked
document.addEventListener('toggle', (e) => { const d = e.target; if (!d.matches || !d.matches('details.more')) return; const c = d.closest('.card'); if (c) c.classList.toggle('raised', d.open); }, true);
document.addEventListener('click', (e) => { const mi = e.target.closest && e.target.closest('details.more .mi'); if (mi) setTimeout(() => { const d = mi.closest('details.more'); if (d && !mi.dataset.armed) d.removeAttribute('open'); }, 0); });
function serverCard(s) {
  const isIran = (s.role || 'iran') === 'iran';
  const status = s.agentOnline ? `<span class="pill on"><span class="led"></span>agent online</span>`
    : s.prepared ? `<span class="pill ok2"><span class="led"></span>reachable</span>`
    : `<span class="pill off"><span class="led"></span>not tested</span>`;
  const n = STATE.tunnels.filter(t => t.serverId === s.id || t.foreignId === s.id).length;
  const sub = [s.city, s.os && s.arch ? `${s.os} ${s.arch}` : ''].filter(Boolean).join(' · ');
  return h(`<div class="card scard ${isIran ? 'ir' : 'fg'}">
    <div class="sh"><div class="sname"><span class="sflag">${s.country ? flag(s.country) : (isIran ? '🇮🇷' : '🌍')}</span><div><h3>${esc(s.name || '(unnamed)')}</h3><small>${esc(sub || (isIran ? 'Iran · entry' : 'foreign · exit'))}</small></div></div>${status}</div>
    <dl class="kv">
      <dt>IPv4</dt><dd class="mono">${esc(s.ipv4 || '—')}</dd>
      <dt>IPv6</dt><dd class="mono">${esc(s.ipv6 || (s.prepared ? 'none' : 'read on test'))}</dd>
      <dt>SSH</dt><dd class="mono">${esc(s.sshUser || 'root')}@${esc(s.sshHost || s.ipv4 || s.ipv6 || '?')}:${s.sshPort || 22}</dd>
      ${s.lastPath ? `<dt>Reached via</dt><dd>${esc(s.lastPath)}</dd>` : ''}
      ${s.proxy ? `<dt>Proxy</dt><dd class="mono">${esc(s.proxy)}</dd>` : ''}
      <dt>Tunnels</dt><dd>${n}</dd>
      <dt>Packages</dt><dd>${s.provisioned ? '<span style="color:var(--good)">✓ installed</span>' : '<span class="faint">not yet</span>'}</dd>
    </dl>
    <div class="nic" data-nic="${s.id}"></div>
    <div class="sfoot">
      <button class="btn sm" data-test="${s.id}">Test connection</button>
      <button class="btn sm" data-prep="${s.id}" title="Pre-install every method's binaries and packages once, so switching methods is instant">${s.provisioned ? 'Update packages' : 'Install packages'}</button>
      <span class="grow"></span>
      ${moreMenu([
        { label: '⚡ Optimize kernel', attr: `data-optz="${s.id}"` },
        isIran ? { label: '📡 Agent install command', attr: `data-agent="${s.id}"` } : null,
        { label: '🔑 SSH bridge', attr: `data-bridge="${s.id}"` },
        { label: '✎ Edit', attr: `data-edit="${s.id}"` },
        { label: '🗑 Delete', attr: `data-del="${s.id}"`, danger: true },
      ])}
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
  const m = modal(`<h2>${s.id ? 'Edit server' : (s.role === 'foreign' ? 'Add foreign server' : 'Add Iran server')}</h2>
    <form class="ff" id="srvf">
      <div class="two">
        <label class="f">Name<input name="name" value="${esc(s.name || '')}" required></label>
        <label class="f">Role<select name="role"><option value="iran"${s.role === 'foreign' ? '' : ' selected'}>🇮🇷 Iran (entry)</option><option value="foreign"${s.role === 'foreign' ? ' selected' : ''}>🌍 Foreign (exit)</option></select></label>
      </div>
      <div class="two">
        <label class="f">Public IPv4<input name="ipv4" class="mono" value="${esc(s.ipv4 || '')}"></label>
        <label class="f">Public IPv6<input name="ipv6" class="mono" placeholder="blank = read from the server on Test" value="${esc(s.ipv6 || '')}"></label>
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
// Summary strip, then tunnels grouped by their Iran server.
function viewTunnels(w) {
  w.innerHTML = topbar('Tunnels', 'Each tunnel links one Iran server to one foreign server. Pick a connection method and switch any time.',
    `<button class="btn pri" id="addTun"${iranServers().length ? '' : ' disabled title="Add an Iran server first"'}>+ New tunnel</button>`);
  const run = STATE.tunnels.filter(t => t.active).length;
  w.appendChild(h(`<div class="summary">
    <div class="stat"><small>Running tunnels</small><b>${run}<span> / ${STATE.tunnels.length}</span> <span class="downtxt" data-sum-down></span></b></div>
    <div class="stat"><small>Live download ↓</small><b class="dn" data-sum-dn>—</b></div>
    <div class="stat"><small>Live upload ↑</small><b class="up" data-sum-up>—</b></div>
    <div class="stat"><small>Servers</small><b>${iranServers().length}<span> Iran · </span>${foreignServers().length + 1}<span> foreign</span></b></div>
  </div>`));
  if (!STATE.tunnels.length) {
    w.appendChild(h(`<div class="card empty"><div class="big">🛰</div>${iranServers().length ? 'No tunnels yet — press <b>+ New tunnel</b>.' : 'Start on the <b>Servers</b> page: add an Iran server, then create a tunnel here.'}</div>`));
  }
  // one dense grid; filter chips per Iran server instead of separate sections
  if (STATE.tunnels.length) {
    const counts = {};
    STATE.tunnels.forEach(t => counts[t.serverId] = (counts[t.serverId] || 0) + 1);
    const ids = Object.keys(counts).sort((x, y) => serverName(x).localeCompare(serverName(y)));
    if (STATE.tunFilter && !counts[STATE.tunFilter]) STATE.tunFilter = '';
    if (ids.length > 1) {
      const bar = h(`<div class="filters"><button class="fchip${!STATE.tunFilter ? ' on' : ''}" data-f="">All <b>${STATE.tunnels.length}</b></button>${ids.map(id => {
        const sv = serverById(id);
        return `<button class="fchip${STATE.tunFilter === id ? ' on' : ''}" data-f="${id}">${sv && sv.country ? flag(sv.country) : '🇮🇷'} ${esc(serverName(id))} <b>${counts[id]}</b></button>`;
      }).join('')}</div>`);
      $$('[data-f]', bar).forEach(b => b.onclick = () => { STATE.tunFilter = b.dataset.f; renderView(); });
      w.appendChild(bar);
    }
    const grid = h(`<div class="grid tgrid"></div>`);
    STATE.tunnels.filter(t => !STATE.tunFilter || t.serverId === STATE.tunFilter)
      .sort((x, y) => (!!y.active - !!x.active) || x.name.localeCompare(y.name))
      .forEach(t => grid.appendChild(tunnelCard(t)));
    w.appendChild(grid);
  }
  $('#addTun').onclick = () => { if (iranServers().length) tunnelModal(); };
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
  const card = h(`<div class="card tc${t.active ? ' live' : ''}" data-id="${t.id}">
    <div class="tc-h"><h3 title="${esc(t.name)}">${esc(t.name)}</h3>${active ? `<span class="pill on"><span class="led"></span>running</span>` : `<span class="pill off"><span class="led"></span>stopped</span>`}</div>
    <div class="tc-r" title="${esc(serverName(t.serverId))} → ${esc(fg ? fg.name : 'this panel host')}">
      <span class="sd" data-ir></span><span class="nm">${fl(ir, '🇮🇷')} ${esc(serverName(t.serverId))}</span>
      <span class="ln${t.active ? ' on' : ''}"></span>
      <span class="nm r">${fl(fg, fg ? '🌍' : '🖥')} ${esc(fg ? fg.name : 'panel host')}</span><span class="sd" data-fg></span>
    </div>
    <div class="tc-m"><span class="chip mth" title="${esc((active || selM)?.title || '')}">${esc((active || selM)?.title || '—')}</span><span class="chip mono">:${esc(t.ports)}</span><span class="chip">${famName(t.family)}</span>${miss ? `<span class="chip warn" title="needs ${esc(miss)}">⚠ needs upload</span>` : ''}${t.clash ? `<span class="chip bad" title="${esc(t.clash)}">⚠ port clash</span>` : ''}${t.failover ? `<span class="chip fo" title="original ${esc(methodTitle(t.failover.method))} (${t.failover.family}) failed: ${esc(t.failover.reason || '')} — re-checked every hour">🔁 backup path · original ${esc(methodTitle(t.failover.method))} ${t.failover.family}</span>` : ''}${t.hotStandby ? hsChip(t) : (t.noFailover ? '' : '<span class="chip" title="automatic failover is on">🔁 auto</span>')}</div>
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
  if (!v || !v.paths) return '<div class="faint" style="font-size:12px">⚡ Hot standby is on — every compatible path starts on the next Start/Re-apply.</div>';
  return `<div class="lbl">⚡ Hot standby paths <span class="faint">(switcher order; checked every 2 s on the Iran server)</span></div><div class="hsl">${v.paths.map((p, i) =>
    `<div class="${v.ok[i] ? 'ok' : 'bad'}${i === v.active ? ' cur' : ''}">${v.ok[i] ? '✓' : '✕'} ${esc(p)}${i === v.active ? ' <b>← users</b>' : ''}</div>`).join('')}</div>`;
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
    selEl.innerHTML = choices.filter(c => c.fam === fam).map(c => { const v = `${c.m.id}|${fam}`; return `<option value="${v}"${c.m.id === want ? ' selected' : ''}>${esc(c.m.title)} · ${esc(c.m.encrypt)}${methodMissing(c.m, t) ? ' ⚠ needs upload' : ''}${c.m.id === t.active && fam === t.family ? ' ✓ running' : ''}</option>`; }).join('');
    $$('[data-fams] button', m).forEach(b => b.classList.toggle('on', b.dataset.f === fam));
  };
  fill(sel.split('|')[1] || t.family, sel.split('|')[0]);
  $$('[data-fams] button', m).forEach(b => b.onclick = () => { fill(b.dataset.f, pick().mid); optBox.hidden = true; refresh(); });
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
    const n = STATE.tunnels.filter(x => x._down).length, el = $('[data-sum-down]');
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
  ports: t.ports, note: t.note, shape: t.shape || {}, noFailover: !!t.noFailover, hotStandby: !!t.hotStandby, selected: t.selected || '', ...patch });
async function saveTunnel(t, patch) {
  try { await api('/tunnels/save', tunnelBody(t, patch)); Object.assign(t, patch); } catch (e) {}
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
    try { await api('/tunnels/save', tunnelBody(t, { options: { [mid]: opts } })); await loadAll(); renderView(); toast('Options saved'); } catch (e) { alertModal('Error', e.message); }
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
      <label class="row f"><input type="checkbox" id="tFail"${t.noFailover ? '' : ' checked'}> 🔁 Automatic failover <span class="faint" style="font-weight:500">— if the tunnel is down for 5 min, switch to a working method / IPv4⇄IPv6 path; re-check the original every hour and switch back when it works</span></label>
      <label class="row f"><input type="checkbox" id="tHot"${t.hotStandby ? ' checked' : ''}> ⚡ Hot standby <span class="faint" style="font-weight:500">— keep every compatible method (IPv4 and IPv6) running; users go through the chosen one and a switcher on the Iran server moves them to the best working path within seconds (no SSH needed), and back after ${60}s of stability. Order: this route's benchmark. Applies on the next Start/Re-apply.</span></label>
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


boot();
