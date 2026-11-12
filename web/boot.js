// Runs in <head>, before the first paint (the CSP allows no inline script): the theme, the
// accent colour and the text direction are on <html> before anything is drawn, so neither
// the sign-in page nor the panel flashes the wrong colours or the wrong side.
// Three themes: black, graphite, white. No choice yet → the system's light / dark.
(function () {
  const de = document.documentElement;
  const get = (k) => { try { return localStorage.getItem(k) || ''; } catch (e) { return ''; } };
  const put = (k, v) => { try { if (v) localStorage.setItem(k, v); else localStorage.removeItem(k); } catch (e) {} };
  const THEMES = ['black', 'graphite', 'white'];
  // the old two-way setting carries over: dark → black, light → white
  let t = get('tp-theme');
  if (t === 'dark') { t = 'black'; put('tp-theme', t); }
  else if (t === 'light') { t = 'white'; put('tp-theme', t); }
  else if (t && !THEMES.includes(t)) { t = ''; put('tp-theme', ''); }
  // the old "violet" swatch was the default accent in all but name
  if (get('tp-accent').toLowerCase() === '#6d5dfc') put('tp-accent', '');
  const sys = () => (window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'black' : 'white');
  const theme = () => get('tp-theme') || sys();
  // the panel colour of each theme: an accent is fitted to read on it
  const PANEL = { black: '#0f0f11', graphite: '#26282c', white: '#ffffff' };
  const rgb = (c) => [1, 3, 5].map(i => parseInt(c.slice(i, i + 2), 16));
  const hex = (a) => '#' + a.map(v => Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, '0')).join('');
  const lum = (c) => { const [r, g, b] = rgb(c).map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  // the accent as text on the panel reads (contrast ≥ 4.5): darkened on white, lightened on the dark ones
  const fit = (c, th) => {
    const bg = PANEL[th] || PANEL.white, to = th === 'white' ? [0, 0, 0] : [255, 255, 255];
    let out = c;
    for (let i = 1; i <= 20 && ratio(out, bg) < 4.5; i++) out = hex(rgb(c).map((v, j) => v + (to[j] - v) * i * 0.05));
    return out;
  };
  // text on an accent-filled button: white where it reads, else near-black
  const onAcc = (c) => (ratio(c, '#ffffff') >= 4.5 ? '#ffffff' : '#0c0f1a');
  const paint = () => {
    const th = theme(), s = de.style, a = get('tp-accent');
    de.setAttribute('data-theme', th);
    if (/^#[0-9a-f]{6}$/i.test(a)) {
      const c = fit(a, th);
      s.setProperty('--accent', c); s.setProperty('--accent-fg', onAcc(c));
      s.setProperty('--accent-soft', `color-mix(in srgb, ${c} ${th === 'white' ? 13 : 20}%, var(--panel))`);
    } else { s.removeProperty('--accent'); s.removeProperty('--accent-fg'); s.removeProperty('--accent-soft'); }
  };
  window.tpLook = {
    THEMES,
    theme, chosen: () => get('tp-theme'),
    accent: () => get('tp-accent'),
    setTheme(v) { put('tp-theme', THEMES.includes(v) ? v : ''); paint(); },
    setAccent(v) { put('tp-accent', /^#[0-9a-f]{6}$/i.test(v || '') ? v : ''); paint(); },
  };
  paint();
  // following the system (nothing chosen): a change there shows at once
  try { matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (!get('tp-theme')) paint(); }); } catch (e) {}
  // the language's direction before the first paint too (i18n.js does the rest)
  if ((get('tp-lang') || 'fa') === 'fa') { de.lang = 'fa'; de.dir = 'rtl'; }
})();
