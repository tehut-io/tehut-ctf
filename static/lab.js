/* Tehut Security CTF harness: flag chips, submit dialog, toasts, confetti,
   hints and filters. This file is part of the game, not the target. */
(function () {
  'use strict';
  const FLAG_RE = /FLAG\{[A-Za-z0-9_]+\}/g;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

  // ------------------------------------------------------------ toasts
  function toast(html, kind = '', ms = 5000) {
    const box = $('#toasts');
    if (!box) return;
    const t = document.createElement('div');
    t.className = 'toast ' + kind;
    t.innerHTML = html;
    box.appendChild(t);
    setTimeout(() => { t.style.transition = 'opacity .4s'; t.style.opacity = '0'; }, ms);
    setTimeout(() => t.remove(), ms + 450);
  }
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

  // ------------------------------------------------------------ 8-bit "coin" blip
  function coin() {
    try {
      const ac = new (window.AudioContext || window.webkitAudioContext)();
      const o = ac.createOscillator(), g = ac.createGain();
      o.type = 'square';
      o.frequency.setValueAtTime(988, ac.currentTime);            // B5
      o.frequency.setValueAtTime(1319, ac.currentTime + 0.08);    // E6
      g.gain.setValueAtTime(0.05, ac.currentTime);
      g.gain.exponentialRampToValueAtTime(0.001, ac.currentTime + 0.35);
      o.connect(g).connect(ac.destination);
      o.start();
      o.stop(ac.currentTime + 0.35);
    } catch (e) { /* no audio, no problem */ }
  }

  // ------------------------------------------------------------ confetti
  function confetti() {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const c = document.createElement('canvas');
    c.id = 'confetti';
    document.body.appendChild(c);
    const ctx = c.getContext('2d');
    const W = c.width = innerWidth, H = c.height = innerHeight;
    const colors = ['#39ff88', '#b26bff', '#ffc400', '#4dd2ff', '#ff5a6a'];
    const parts = Array.from({length: 160}, () => ({
      x: W / 2 + (Math.random() - .5) * 200, y: H / 3,
      vx: (Math.random() - .5) * 14, vy: Math.random() * -12 - 4,
      s: Math.random() * 7 + 4, r: Math.random() * 6, vr: (Math.random() - .5) * .3,
      c: colors[Math.floor(Math.random() * colors.length)],
    }));
    const start = performance.now();
    (function frame(t) {
      ctx.clearRect(0, 0, W, H);
      parts.forEach(p => {
        p.vy += .35; p.vx *= .99; p.x += p.vx; p.y += p.vy; p.r += p.vr;
        ctx.save(); ctx.translate(p.x, p.y); ctx.rotate(p.r);
        ctx.fillStyle = p.c; ctx.fillRect(-p.s / 2, -p.s / 4, p.s, p.s / 2); ctx.restore();
      });
      if (t - start < 3000) requestAnimationFrame(frame); else c.remove();
    })(start);
  }

  // ------------------------------------------------------------ submitting
  function updateHud(p) {
    if (!p) return;
    $$('[data-hud="score"]').forEach(e => e.textContent = p.score);
    $$('[data-hud="solved"]').forEach(e => e.textContent = p.solved);
  }

  async function submitFlag(value, chip) {
    const flag = String(value || '').trim();
    if (!flag) return;
    let d;
    try {
      const r = await fetch('/hq/api/submit', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                               body: JSON.stringify({flag})});
      d = await r.json();
    } catch (e) {
      toast('Could not reach HQ. Is the lab running?', 'bad');
      return;
    }
    if (!d.ok) { toast('❌ ' + esc(d.msg), 'bad shake'); return; }
    if (chip) chip.classList.add('done');
    updateHud(d.progress);
    if (d.already) { toast('👍 Already captured: <b>' + esc(d.title) + '</b>'); return; }
    confetti();
    coin();
    toast('🕹️ <b>1UP!</b> <b>' + esc(d.title) + '</b> captured! +' + d.points + ' pts<br>' +
          '<small>Rank: ' + esc(d.progress.rank.icon + ' ' + d.progress.rank.name) +
          ' · ' + d.progress.solved + '/' + d.progress.total + '</small>', 'good', 6500);
    if (document.body.classList.contains('hq')) setTimeout(() => location.reload(), 2200);
  }

  // ------------------------------------------------------------ flag chips
  // Any FLAG{...} text on a page becomes a clickable "submit me" chip.
  function chipify(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        const p = n.parentElement;
        if (!p || p.closest('script,style,textarea,input,.flag-chip,#toasts,dialog')) return NodeFilter.FILTER_REJECT;
        FLAG_RE.lastIndex = 0;
        return FLAG_RE.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      },
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(n => {
      const frag = document.createDocumentFragment();
      let last = 0;
      n.nodeValue.replace(FLAG_RE, (m, idx) => {
        frag.appendChild(document.createTextNode(n.nodeValue.slice(last, idx)));
        frag.appendChild(makeChip(m));
        last = idx + m.length;
      });
      frag.appendChild(document.createTextNode(n.nodeValue.slice(last)));
      n.parentNode.replaceChild(frag, n);
    });
  }

  function makeChip(f) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'flag-chip';
    b.textContent = '🚩 ' + f;
    b.addEventListener('click', e => { e.preventDefault(); submitFlag(f, b); });
    return b;
  }

  // Flags found by the XSS detector / Konami code arrive via this queue.
  function drain() {
    const q = window.__labQueue || [];
    while (q.length) {
      const [, f] = q.shift();
      const wrap = document.createElement('div');
      wrap.innerHTML = '🎯 <b>JavaScript executed!</b> Your flag:<br>';
      wrap.appendChild(makeChip(f));
      const t = document.createElement('div');
      t.className = 'toast good';
      t.appendChild(wrap);
      ($('#toasts') || document.body).appendChild(t);
    }
  }

  // ------------------------------------------------------------ konami
  const KONAMI = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
                  'ArrowLeft', 'ArrowRight', 'b', 'a'];
  let kpos = 0;
  document.addEventListener('keydown', async e => {
    const k = e.key.length === 1 ? e.key.toLowerCase() : e.key;
    kpos = k === KONAMI[kpos] ? kpos + 1 : (k === KONAMI[0] ? 1 : 0);
    if (kpos === KONAMI.length) {
      kpos = 0;
      const d = await (await fetch('/hq/api/konami', {method: 'POST'})).json();
      const t = document.createElement('div');
      t.className = 'toast good';
      t.innerHTML = '🎮 <b>+30 lives!</b> Just kidding, here is a flag:<br>';
      t.appendChild(makeChip(d.flag));
      $('#toasts').appendChild(t);
      confetti();
      coin();
    }
  });

  // ------------------------------------------------------------ HQ page bits
  function initHq() {
    $$('[data-filter]').forEach(btn => btn.addEventListener('click', () => {
      $$('[data-filter]').forEach(b => b.classList.toggle('active', b === btn));
      const f = btn.dataset.filter;
      $$('.mission').forEach(m => {
        m.hidden = !(f === 'all' || m.dataset.state === f || m.dataset.diff === f);
      });
      $$('[data-cat]').forEach(c => { c.hidden = !$$('.mission', c).some(m => !m.hidden); });
    }));

    document.addEventListener('click', async e => {
      const btn = e.target.closest('[data-hint]');
      if (!btn) return;
      const cost = +btn.dataset.cost;
      if (cost && !confirm('Reveal this hint? It costs ' + cost + ' points if you solve the challenge.')) return;
      const r = await fetch('/hq/api/hint', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                             body: JSON.stringify({key: btn.dataset.hint, level: +btn.dataset.level})});
      const d = await r.json();
      if (!d.ok) { toast(esc(d.msg || 'Nope.'), 'bad'); return; }
      location.hash = 'm-' + btn.dataset.hint;
      location.reload();
    });
  }

  // ------------------------------------------------------------ dark / light toggle
  // Neon (dark) by default; the player's choice is remembered for every page.
  // The <head> applies it before paint.
  function theme() {
    return document.documentElement.dataset.theme || 'dark';
  }
  function initTheme() {
    const paint = () => $$('[data-theme-toggle]').forEach(b => {
      const dark = theme() === 'dark';
      b.textContent = dark ? '☀️' : '🌙';
      b.title = b.ariaLabel = dark ? 'Switch to light mode' : 'Switch to dark mode';
    });
    $$('[data-theme-toggle]').forEach(b => b.addEventListener('click', () => {
      const next = theme() === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem('tehut-theme', next); } catch (e) { /* private mode */ }
      paint();
    }));
    paint();
  }

  // ------------------------------------------------------------ boot
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    chipify(document.body);
    if (document.body.classList.contains('hq')) initHq();

    const dlg = $('#submit-dialog');
    $$('[data-open-submit]').forEach(b => b.addEventListener('click', () => {
      dlg.showModal(); $('input', dlg).focus();
    }));
    $$('[data-submit-form]').forEach(form => form.addEventListener('submit', e => {
      const submitter = e.submitter;
      if (submitter && submitter.value === 'cancel') return;
      e.preventDefault();
      const input = $('input[name="flag"]', form);
      submitFlag(input.value);
      input.value = '';
      if (dlg && dlg.open) dlg.close();
    }));

    window.Lab = {toast, confetti, submitFlag, drain};
    drain();
  });
})();
