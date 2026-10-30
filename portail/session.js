// Portail web de Heimdia : un terminal relié au bastion par WebSocket.
'use strict';

const FR = document.documentElement.lang === 'fr';
const T = (en, fr) => (FR ? fr : en);

const nom = decodeURIComponent(location.pathname.split('/').pop() || '');
document.getElementById('nom').textContent = nom;
document.title = nom;

const term = new Terminal({
  cursorBlink: true,
  fontFamily: "'Cascadia Mono', Consolas, 'SF Mono', ui-monospace, monospace",
  fontSize: 14,
  scrollback: 5000,
  theme: { background: '#111215', foreground: '#d6d8dd' },
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(document.getElementById('term'));
fit.fit();

const notice = document.getElementById('notice');
function showNotice(title, text, actions) {
  document.getElementById('notice-titre').textContent = title;
  document.getElementById('notice-texte').textContent = text;
  const box = document.getElementById('notice-actions');
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

let ws = null;
let clipboard = true;
let closedByServer = false;
let warnTimer = 0;

function send(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function connect() {
  notice.hidden = true;
  closedByServer = false;
  term.reset();
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${scheme}://${location.host}/ws/${encodeURIComponent(nom)}?cols=${term.cols}&rows=${term.rows}`);
  ws.binaryType = 'arraybuffer';
  ws.addEventListener('message', (e) => {
    if (typeof e.data !== 'string') { term.write(new Uint8Array(e.data)); return; }
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.t === 'inactif') {
      let left = msg.s;
      clearInterval(warnTimer);
      const update = () => showNotice(T('Still there?', 'Toujours là ?'), T(`Without activity, the session closes in ${left} s.`, `Sans activité, la session se ferme dans ${left} s.`), [[T('Continue', 'Continuer'), () => { send({ t: 'actif' }); notice.hidden = true; clearInterval(warnTimer); term.focus(); }, true]]);
      update();
      warnTimer = setInterval(() => { left -= 1; if (left <= 0) clearInterval(warnTimer); else update(); }, 1000);
    } else if (msg.t === 'ferme') {
      closedByServer = true;
      clearInterval(warnTimer);
      showNotice(T('Session closed', 'Session fermée'), msg.raison || '', [[T('Reopen', 'Rouvrir'), connect, true], [T('My servers', 'Mes serveurs'), () => { location.href = '/'; }]]);
    }
  });
  ws.addEventListener('close', (e) => {
    if (closedByServer) return;
    clearInterval(warnTimer);
    const text = e.code === 1006 ? T('Connection lost, or web session expired.', 'Connexion perdue, ou session web expirée.') : T('The connection to the bastion is closed.', 'La connexion au bastion est fermée.');
    showNotice(T('Session closed', 'Session fermée'), text, [[T('Reopen', 'Rouvrir'), connect, true], [T('My servers', 'Mes serveurs'), () => { location.href = '/'; }]]);
  });
  term.focus();
}

term.onData((d) => send({ t: 'in', d }));
let resizeTimer = 0;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { fit.fit(); send({ t: 'taille', c: term.cols, r: term.rows }); }, 150);
});

// Copier-coller selon le réglage du bastion.
document.getElementById('copier').addEventListener('click', async () => {
  const text = term.getSelection();
  if (text) await navigator.clipboard.writeText(text).catch(() => {});
  term.focus();
});
document.getElementById('coller').addEventListener('click', async () => {
  const text = await navigator.clipboard.readText().catch(() => '');
  if (text) send({ t: 'in', d: text });
  term.focus();
});
document.getElementById('fermer').addEventListener('click', () => {
  closedByServer = true;
  if (ws) ws.close();
  window.close();
  showNotice(T('Session closed', 'Session fermée'), T('You can close this tab.', 'Vous pouvez fermer cet onglet.'), [[T('My servers', 'Mes serveurs'), () => { location.href = '/'; }, true]]);
});
// Sans copier-coller autorisé : pas de collage dans le terminal.
document.getElementById('term').addEventListener('paste', (e) => { if (!clipboard) { e.preventDefault(); e.stopPropagation(); } }, true);

(async () => {
  try {
    const [etat, list] = await Promise.all([
      fetch('/api/etat', { credentials: 'same-origin' }).then((r) => r.json()),
      fetch('/api/serveurs', { credentials: 'same-origin' }).then((r) => (r.ok ? r.json() : { serveurs: [] })),
    ]);
    clipboard = etat.presse_papiers !== false;
    document.getElementById('copier').hidden = !clipboard;
    document.getElementById('coller').hidden = !clipboard;
    const s = (list.serveurs || []).find((x) => x.nom === nom);
    // Serveur Bureau à distance (lien ancien ou page en cache) : la bonne page.
    if (s?.protocole === 'rdp') { location.replace(`/bureau/${encodeURIComponent(nom)}`); return; }
    if (s) {
      document.getElementById('mode').textContent = { coffre: T('Vault', 'Coffre'), enregistre: T('Recorded', 'Enregistré'), rebond: T('Jump', 'Rebond') }[s.mode] || s.mode;
      document.getElementById('rec').hidden = s.mode === 'rebond';
    }
    if (!etat.connecte) { location.href = '/'; return; }
  } catch { /* le terminal dira s'il ne peut pas se connecter */ }
  connect();
})();
