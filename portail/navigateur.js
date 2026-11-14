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

// ---------- Vidéo et son (Gate 0.54) ----------

// H.264 « constrained baseline », niveau 4.1 (ffmpeg sur la Gate), son Opus 48 kHz stéréo.
const CODEC = 'avc1.42E029';
const AUDIO = { codec: 'opus', sampleRate: 48000, numberOfChannels: 2 };
const stats = { mode: 'images', images: 0, sons: 0, octets: 0 };
window.__navigateur = stats;

async function videoSupported() {
  if (new URLSearchParams(location.search).has('images')) return false;
  if (!('VideoDecoder' in window) || !('AudioDecoder' in window)) return false;
  try {
    const v = await VideoDecoder.isConfigSupported({ codec: CODEC, optimizeForLatency: true });
    const a = await AudioDecoder.isConfigSupported(AUDIO);
    return !!(v.supported && a.supported);
  } catch { return false; }
}

let videoMode = false;
let video = null;
let waitKey = true;
function newVideoDecoder() {
  video = new VideoDecoder({
    output: (frame) => {
      if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
        canvas.width = frame.displayWidth;
        canvas.height = frame.displayHeight;
      }
      ctx.drawImage(frame, 0, 0);
      frame.close();
      stats.images += 1;
      $('attente').hidden = true;
    },
    error: () => { waitKey = true; setTimeout(newVideoDecoder, 0); },
  });
  video.configure({ codec: CODEC, optimizeForLatency: true });
  waitKey = true;
}

let audioCtx = null;
let audioGain = null;
let audio = null;
let playAt = 0;
let muted = false;
// Les navigateurs ne jouent le son qu'après un geste de l'utilisateur dans la page.
function startAudio() {
  if (audioCtx || !videoMode || $('son').hidden) return;
  try {
    audioCtx = new AudioContext({ sampleRate: 48000, latencyHint: 'interactive' });
    audioGain = audioCtx.createGain();
    audioGain.gain.value = muted ? 0 : 1;
    audioGain.connect(audioCtx.destination);
    audio = new AudioDecoder({ output: playAudio, error: () => { audio = null; } });
    audio.configure(AUDIO);
    $('son').title = T('Sound of the page: click to mute', 'Son de la page : cliquez pour le couper');
  } catch { audioCtx = null; }
}
function playAudio(data) {
  const buffer = audioCtx.createBuffer(data.numberOfChannels, data.numberOfFrames, data.sampleRate);
  for (let c = 0; c < data.numberOfChannels; c += 1) {
    const plane = new Float32Array(data.numberOfFrames);
    data.copyTo(plane, { planeIndex: c, format: 'f32-planar' });
    buffer.copyToChannel(plane, c);
  }
  data.close();
  const src = audioCtx.createBufferSource();
  src.buffer = buffer;
  src.connect(audioGain);
  const now = audioCtx.currentTime;
  // Un peu d'avance contre les à-coups du réseau, jamais plus de 0,4 s de retard.
  if (playAt < now + 0.03 || playAt > now + 0.4) playAt = now + 0.08;
  src.start(playAt);
  playAt += buffer.duration;
  stats.sons += 1;
}
$('son').addEventListener('click', () => {
  if (!audioCtx) { startAudio(); return; }
  muted = !muted;
  audioGain.gain.value = muted ? 0 : 1;
  $('son').textContent = muted ? T('Sound off', 'Son coupé') : T('Sound', 'Son');
  keys.focus({ preventScroll: true });
});
for (const ev of ['pointerdown', 'keydown']) document.addEventListener(ev, () => startAudio(), { capture: true });

function media(buffer) {
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 10) return;
  const kind = bytes[0];
  const key = bytes[1] === 1;
  const ts = Number(new DataView(buffer).getBigUint64(2));
  const data = bytes.subarray(10);
  if (kind === 1 && video) {
    // Retard du décodeur : on saute jusqu'à la prochaine image clé (une par seconde).
    if (!key && (waitKey || video.decodeQueueSize > 6)) { waitKey = true; return; }
    waitKey = false;
    try { video.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: ts, data })); } catch { waitKey = true; }
  } else if (kind === 2 && audio && audio.state === 'configured') {
    try { audio.decode(new EncodedAudioChunk({ type: 'key', timestamp: ts, data })); } catch { /* paquet perdu */ }
  }
}

// Vidéo regardée (son qui joue, onglet visible) : l'utilisateur est là, même sans toucher la
// souris ; la session ne se ferme pas pour inactivité.
let soundsSeen = 0;
setInterval(() => {
  const playing = stats.sons > soundsSeen && audioCtx && !muted && !document.hidden;
  soundsSeen = stats.sons;
  if (playing) send({ t: 'actif' });
}, 60000);

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
    stats.images += 1;
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

let canVideo = null;
async function connect() {
  notice.hidden = true;
  closedByServer = false;
  $('attente').hidden = false;
  if (canVideo === null) canVideo = await videoSupported();
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const s = viewSize();
  const start = new URLSearchParams(location.search).get('url');
  ws = new WebSocket(`${scheme}://${location.host}/ws-navigateur/${encodeURIComponent(nom)}?l=${s.l}&h=${s.h}${canVideo ? '&video=1' : ''}${start ? `&url=${encodeURIComponent(start)}` : ''}`);
  ws.binaryType = 'arraybuffer';
  ws.addEventListener('message', (e) => {
    if (typeof e.data !== 'string') { stats.octets += e.data.byteLength; if (videoMode) media(e.data); else draw(e.data); return; }
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.t === 'pret') {
      videoMode = !!msg.video;
      stats.mode = videoMode ? 'video' : 'images';
      if (videoMode && !video) newVideoDecoder();
      $('son').hidden = !msg.son;
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
