// Portail web de Portunia Gate : sortie web dans un onglet. Le navigateur (Chromium) tourne
// sur la Gate ; cette page affiche l'image de la page et lui renvoie souris, clavier et adresse.
'use strict';

const FR = document.documentElement.lang === 'fr';
const T = (en, fr) => (FR ? fr : en);
const $ = (id) => document.getElementById(id);

const nom = decodeURIComponent(location.pathname.split('/').pop() || '');
$('nom').textContent = nom;
document.title = nom;

const scene = $('scene');
const canvas = $('page');
const ctx = canvas.getContext('2d');
const keys = $('clavier');
const address = $('adresse');
const notice = $('notice');

function showNotice(title, text, actions) {
  $('notice-titre').textContent = title;
  $('notice-texte').textContent = text;
  const box = $('notice-actions');
  box.replaceChildren();
  for (const [label, fn, primary] of actions) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = primary ? 'btn primary' : 'btn';
    b.textContent = label;
    b.addEventListener('click', fn);
    box.append(b);
  }
  notice.hidden = false;
}

let toastTimer = 0;
function toast(text) {
  const b = $('bulle');
  b.textContent = text;
  b.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { b.hidden = true; }, 4000);
}

let ws = null;
let closedByServer = false;
let warnTimer = 0;

function send(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

// ---------- Image de la page ----------

// Une seule image décodée à la fois : la plus récente remplace celle qui attendait.
let decoding = false;
let waiting = null;
async function draw(buffer) {
  if (decoding) { waiting = buffer; return; }
  decoding = true;
  try {
    const bmp = await createImageBitmap(new Blob([buffer], { type: 'image/jpeg' }));
    if (canvas.width !== bmp.width || canvas.height !== bmp.height) {
      canvas.width = bmp.width;
      canvas.height = bmp.height;
    }
    ctx.drawImage(bmp, 0, 0);
    bmp.close();
    $('attente').hidden = true;
  } catch { /* image abîmée : la suivante la remplace */ }
  decoding = false;
  if (waiting) { const next = waiting; waiting = null; draw(next); }
}

function viewSize() {
  return { l: Math.max(320, Math.floor(scene.clientWidth)), h: Math.max(240, Math.floor(scene.clientHeight)) };
}

let resizeTimer = 0;
new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => send({ t: 'taille', ...viewSize() }), 300);
}).observe(scene);

// ---------- Connexion ----------

function connect() {
  notice.hidden = true;
  closedByServer = false;
  $('attente').hidden = false;
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const s = viewSize();
  const start = new URLSearchParams(location.search).get('url');
  ws = new WebSocket(`${scheme}://${location.host}/ws-navigateur/${encodeURIComponent(nom)}?l=${s.l}&h=${s.h}${start ? `&url=${encodeURIComponent(start)}` : ''}`);
  ws.binaryType = 'arraybuffer';
  ws.addEventListener('message', (e) => {
    if (typeof e.data !== 'string') { draw(e.data); return; }
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.t === 'pret') {
      if (!start) address.focus();
    } else if (msg.t === 'page') {
      if (document.activeElement !== address) address.value = msg.url === 'about:blank' ? '' : msg.url;
      document.title = msg.titre && msg.url !== 'about:blank' ? `${msg.titre} — ${nom}` : nom;
    } else if (msg.t === 'copie') {
      if (msg.texte) navigator.clipboard.writeText(msg.texte).then(() => toast(T('Copied', 'Copié')), () => toast(T('The browser refused access to the clipboard.', 'Le navigateur a refusé l\'accès au presse-papiers.')));
    } else if (msg.t === 'message') {
      toast(msg.texte);
    } else if (msg.t === 'inactif') {
      let left = msg.s;
      clearInterval(warnTimer);
      const update = () => showNotice(T('Still there?', 'Toujours là ?'), T(`Without activity, the browser closes in ${left} s.`, `Sans activité, le navigateur se ferme dans ${left} s.`), [[T('Continue', 'Continuer'), () => { send({ t: 'actif' }); notice.hidden = true; clearInterval(warnTimer); keys.focus(); }, true]]);
      update();
      warnTimer = setInterval(() => { left -= 1; if (left <= 0) clearInterval(warnTimer); else update(); }, 1000);
    } else if (msg.t === 'ferme') {
      closedByServer = true;
      clearInterval(warnTimer);
      showNotice(T('Browser closed', 'Navigateur fermé'), msg.raison || '', [[T('Reopen', 'Rouvrir'), connect, true], [T('My servers', 'Mes serveurs'), () => { location.href = '/?accueil'; }]]);
    }
  });
  ws.addEventListener('close', (e) => {
    if (closedByServer) return;
    clearInterval(warnTimer);
    const text = e.code === 1006 ? T('Connection lost, or web session expired.', 'Connexion perdue, ou session web expirée.') : T('The connection to the Gate is closed.', 'La connexion à la Gate est fermée.');
    showNotice(T('Browser closed', 'Navigateur fermé'), text, [[T('Reopen', 'Rouvrir'), connect, true], [T('My servers', 'Mes serveurs'), () => { location.href = '/?accueil'; }]]);
  });
}

// ---------- Souris ----------

const mods = (e) => (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0);

function point(e) {
  const r = canvas.getBoundingClientRect();
  const sx = canvas.width / (r.width || 1);
  const sy = canvas.height / (r.height || 1);
  return { x: Math.round((e.clientX - r.left) * sx), y: Math.round((e.clientY - r.top) * sy) };
}

let moveQueued = null;
canvas.addEventListener('pointerdown', (e) => {
  if (e.pointerType === 'touch') { touchStart(e); return; }
  e.preventDefault();
  keys.focus({ preventScroll: true });
  canvas.setPointerCapture(e.pointerId);
  send({ t: 'souris', e: 'bas', ...point(e), b: e.button, bs: e.buttons, n: Math.max(1, e.detail || 1), m: mods(e) });
});
canvas.addEventListener('pointerup', (e) => {
  if (e.pointerType === 'touch') { touchEnd(e); return; }
  send({ t: 'souris', e: 'haut', ...point(e), b: e.button, bs: e.buttons, n: Math.max(1, e.detail || 1), m: mods(e) });
});
canvas.addEventListener('pointermove', (e) => {
  if (e.pointerType === 'touch') { touchMove(e); return; }
  const first = !moveQueued;
  moveQueued = { t: 'souris', e: 'bouge', ...point(e), b: -1, bs: e.buttons, m: mods(e) };
  if (first) requestAnimationFrame(() => { send(moveQueued); moveQueued = null; });
});
canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  const scale = e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? canvas.height : 1;
  send({ t: 'molette', ...point(e), dx: e.deltaX * scale, dy: e.deltaY * scale, m: mods(e) });
}, { passive: false });
canvas.addEventListener('contextmenu', (e) => e.preventDefault());

// Doigt : un appui bref clique, un glissement fait défiler.
let touch = null;
function touchStart(e) {
  touch = { x: e.clientX, y: e.clientY, moved: false, p: point(e) };
}
function touchMove(e) {
  if (!touch) return;
  const dx = touch.x - e.clientX;
  const dy = touch.y - e.clientY;
  if (Math.abs(dx) + Math.abs(dy) > 6) touch.moved = true;
  if (touch.moved) {
    send({ t: 'molette', ...touch.p, dx, dy, m: 0 });
    touch.x = e.clientX;
    touch.y = e.clientY;
  }
}
function touchEnd() {
  if (touch && !touch.moved) {
    keys.focus({ preventScroll: true });
    send({ t: 'souris', e: 'bas', ...touch.p, b: 0, bs: 1, n: 1, m: 0 });
    send({ t: 'souris', e: 'haut', ...touch.p, b: 0, bs: 0, n: 1, m: 0 });
  }
  touch = null;
}

// ---------- Clavier et presse-papiers ----------

// La saisie arrive dans un champ invisible : le collage du système y passe aussi.
keys.addEventListener('keydown', (e) => {
  const cmd = e.ctrlKey || e.metaKey;
  if (cmd && !e.altKey && (e.key === 'v' || e.key === 'V')) return; // évènement « paste » ci-dessous
  if (cmd && !e.altKey && (e.key === 'c' || e.key === 'C')) { e.preventDefault(); send({ t: 'copier' }); return; }
  if (e.key === 'F5' && !cmd) { e.preventDefault(); send({ t: 'recharger' }); return; }
  if (e.isComposing) return;
  e.preventDefault();
  send({ t: 'touche', e: 'bas', key: e.key, code: e.code, kc: e.keyCode, m: mods(e), rep: e.repeat });
});
keys.addEventListener('keyup', (e) => {
  const cmd = e.ctrlKey || e.metaKey;
  if (cmd && ['v', 'V', 'c', 'C'].includes(e.key)) return;
  e.preventDefault();
  send({ t: 'touche', e: 'haut', key: e.key, code: e.code, kc: e.keyCode, m: mods(e) });
});
keys.addEventListener('paste', (e) => {
  e.preventDefault();
  const text = e.clipboardData?.getData('text/plain') || '';
  if (text) send({ t: 'coller', texte: text });
});
// Saisie composée (accents sur mobile, méthodes de saisie) : le texte final.
keys.addEventListener('compositionend', (e) => {
  if (e.data) send({ t: 'coller', texte: e.data });
  keys.value = '';
});
keys.addEventListener('input', () => { if (!keys.value || keys.value.length > 1000) keys.value = ''; });

$('coller').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (text) send({ t: 'coller', texte: text });
    keys.focus({ preventScroll: true });
  } catch {
    toast(T('Press Ctrl+V in the page to paste.', 'Appuyez sur Ctrl+V dans la page pour coller.'));
  }
});

// ---------- Barre ----------

$('barre').addEventListener('submit', (e) => {
  e.preventDefault();
  const url = address.value.trim();
  if (!url) return;
  send({ t: 'aller', url });
  keys.focus({ preventScroll: true });
});
address.addEventListener('focus', () => address.select());
$('retour').addEventListener('click', () => send({ t: 'retour' }));
$('avancer').addEventListener('click', () => send({ t: 'avancer' }));
$('recharger').addEventListener('click', () => send({ t: 'recharger' }));
$('fermer').addEventListener('click', () => {
  send({ t: 'fermer' });
  setTimeout(() => { window.close(); location.href = '/?accueil'; }, 200);
});

connect();
