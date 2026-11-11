// Portail web de Portunia Gate : Bureau à distance dans le navigateur (client IronRDP), à travers
// le passage RDCleanPath de la Gate.
import '/static/iron-remote-desktop.js?v=__V__';
import { Backend, init, displayControl, performanceFlags, RdpFileTransferProvider } from '/static/iron-remote-desktop-rdp.js?v=__V__';

const FR = document.documentElement.lang === 'fr';
const T = (en, fr) => (FR ? fr : en);

const nom = decodeURIComponent(location.pathname.split('/').pop() || '');
document.getElementById('nom').textContent = nom;
document.title = `${nom} · ${T('Remote Desktop', 'Bureau à distance')}`;

const screen = document.getElementById('ecran');
const form = document.getElementById('identifiants');
const error = document.getElementById('erreur');
const notice = document.getElementById('notice');
let ui = null;
let element = null;
// Serveur en mode coffre : pas d'identifiants Windows à demander.
let vault = false;

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

/** Message compréhensible pour une erreur du client RDP. */
function explain(err) {
  const kind = typeof err?.kind === 'function' ? err.kind() : undefined;
  const http = typeof err?.rdcleanpathDetails === 'function' ? err.rdcleanpathDetails()?.httpStatusCode : undefined;
  switch (kind) {
    case 1: case 2: return T('Windows login or password refused.', 'Identifiant ou mot de passe Windows refusé.');
    case 3: return T('The Windows server denies access to this account.', 'Le serveur Windows refuse l\'accès à ce compte.');
    case 4: return http === 401 ? T('Authorisation expired: reopen the server from the list.', 'Autorisation expirée : rouvrez le serveur depuis la liste.') : http === 403 ? T('Access denied by the Gate (rule or server).', 'Accès refusé par la Gate (règle ou serveur).') : T('The Gate could not reach the Windows server.', 'La Gate n\'a pas pu joindre le serveur Windows.');
    case 5: return T('Gate unreachable.', 'Gate injoignable.');
    case 6: return T('The Windows server refuses the negotiation (NLA disabled or version too old?).', 'Le serveur Windows refuse la négociation (NLA désactivé ou version trop ancienne ?).');
    default: return (typeof err?.backtrace === 'function' ? err.backtrace() : String(err?.message || err || '')).split('\n')[0] || T('Cannot connect.', 'Connexion impossible.');
  }
}

const ready = init('WARN').catch(() => {});

// Qualité d'affichage : effets visuels demandés au serveur Windows (mêmes choix que Portunia).
// Rapide = sans fond d'écran, glisser de fenêtre, animations, thèmes ni ombre du curseur ;
// Maximale = lissage des polices et composition du bureau ; Équilibrée = réglage d'IronRDP.
const QUALITY_FLAGS = { fast: 0x2f, best: 0x180 };
const quality = document.getElementById('qualite');
try { quality.value = QUALITY_FLAGS[localStorage.getItem('qualite-rdp')] ? localStorage.getItem('qualite-rdp') : 'balanced'; } catch {}
quality.addEventListener('change', () => { try { localStorage.setItem('qualite-rdp', quality.value); } catch {} });

async function open(user, password, domain) {
  // Jeton à usage unique pour ce serveur, demandé avec la session du portail.
  const res = await fetch(`/api/rdp/${encodeURIComponent(nom)}`, { method: 'POST', credentials: 'same-origin', headers: { 'X-Portunia-Gate': 'portail' } });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { location.href = '/?accueil'; return; }
  if (!res.ok) throw new Error(data.erreur || T('Server unavailable', 'Serveur indisponible'));
  await ready;

  // Session ouverte : l'image occupe toute la zone, sans marge (la mise à l'échelle d'IronRDP
  // se calcule sur la fenêtre, une marge ferait déborder l'image).
  screen.classList.add('live');
  element = document.createElement('iron-remote-desktop');
  element.setAttribute('scale', 'fit');
  element.setAttribute('flexcenter', 'true');
  const loaded = new Promise((resolve) => element.addEventListener('ready', (e) => resolve(e.detail.irgUserInteraction), { once: true }));
  element.module = Backend;
  form.hidden = true;
  screen.append(element);
  ui = await loaded;

  const etat = await fetch('/api/etat', { credentials: 'same-origin' }).then((r) => r.json()).catch(() => ({}));
  ui.setEnableClipboard(etat.presse_papiers !== false);
  // Copie de fichiers : seulement si la règle l'autorise (sinon la Gate la bloque de toute façon)
  // et si le copier-coller du portail est permis, puisqu'elle passe par le presse-papiers.
  if (data.fichiers && etat.presse_papiers !== false) enableFiles();
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const start = desktopSize();
  lastSize = `${start.width}x${start.height}`;
  // Coffre : la Gate ouvre la session Windows ; la page s'authentifie auprès d'elle avec le jeton.
  const builder = ui.configBuilder()
    .withUsername(data.coffre ? 'portunia' : user)
    .withPassword(data.coffre ? data.jeton : password)
    .withServerDomain(data.coffre ? '' : domain)
    .withDestination(nom)
    .withProxyAddress(`${scheme}://${location.host}/ws-rdp`)
    .withAuthToken(data.jeton)
    .withDesktopSize(start)
    .withExtension(displayControl(true));
  const flags = QUALITY_FLAGS[quality.value];
  if (flags !== undefined) builder.withExtension(performanceFlags(flags));
  const config = builder.build();
  const session = await ui.connect(config);
  ui.setVisibility(true);
  document.getElementById('cad').disabled = false;
  document.getElementById('plein').disabled = false;
  followSize();
  if (window.PortuniaClavier?.tactile) touch();
  const end = await session.run();
  sizeWatch?.disconnect();
  showNotice(T('Session closed', 'Session fermée'), end?.reason?.() || T('The Remote Desktop session has ended.', 'La session Bureau à distance est terminée.'), [[T('Reopen', 'Rouvrir'), () => location.reload(), true], [T('My servers', 'Mes serveurs'), () => { location.href = '/?accueil'; }]]);
}

// Copie de fichiers par le presse-papiers. Envoyer : fichiers déposés sur le bureau ou choisis,
// puis collés dans Windows. Recevoir : fichiers copiés dans Windows, téléchargés d'ici. La Gate
// note chaque fichier au journal (nom, taille, empreinte).
let files = null;
const panel = document.getElementById('fichiers');
const fileList = document.getElementById('fichiers-liste');
const rows = new Map();

function fileRow(key, name) {
  let row = rows.get(key);
  if (!row) {
    row = document.createElement('li');
    const label = document.createElement('span');
    label.className = 'name';
    label.textContent = name;
    label.title = name;
    const state = document.createElement('span');
    state.className = 'state';
    row.append(label, state);
    fileList.prepend(row);
    rows.set(key, row);
  }
  panel.hidden = false;
  return row;
}

function setState(row, text) {
  row.querySelector('.state').textContent = text;
}

function sizeText(n) {
  if (n < 1024) return `${n} o`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} Ko`;
  return `${(n / 1024 / 1024).toFixed(1)} Mo`;
}

function saveBlob(blob, name) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 60000);
}

function upload(list) {
  if (!list.length) return;
  files.uploadFiles(list);
  for (const f of list) {
    if (f.isDirectory || (f.file === null)) continue;
    setState(fileRow(`up:${f.name}`, f.name), T('ready: paste in Windows (Ctrl+V)', 'prêt : collez dans Windows (Ctrl+V)'));
  }
}

function enableFiles() {
  files = new RdpFileTransferProvider();
  ui.enableFileTransfer(files);
  const send = document.getElementById('envoyer');
  send.hidden = false;
  send.addEventListener('click', async () => upload(await files.showFilePicker({ multiple: true }).catch(() => [])));
  screen.addEventListener('dragover', (e) => { files.handleDragOver(e); screen.classList.add('drop'); });
  screen.addEventListener('dragleave', () => screen.classList.remove('drop'));
  screen.addEventListener('drop', async (e) => {
    screen.classList.remove('drop');
    upload(await files.handleDrop(e).catch(() => []));
  });
  document.getElementById('fichiers-fermer').addEventListener('click', () => { panel.hidden = true; });
  files.on('upload-progress', (p) => setState(fileRow(`up:${p.fileName}`, p.fileName), `${T('sending', 'envoi')} ${Math.round(p.percentage)} %`));
  files.on('upload-complete', (file) => setState(fileRow(`up:${file.name}`, file.name), T('sent ✓', 'envoyé ✓')));
  // Fichiers copiés dans Windows : proposés au téléchargement.
  files.on('files-available', (list) => {
    list.forEach((info, index) => {
      if (info.isDirectory) return;
      const row = fileRow(`down:${info.path || ''}\\${info.name}`, info.path ? `${info.path}\\${info.name}` : info.name);
      setState(row, sizeText(info.size || 0));
      row.querySelector('button')?.remove();
      const get = document.createElement('button');
      get.type = 'button';
      get.className = 'btn';
      get.textContent = T('Download', 'Télécharger');
      get.addEventListener('click', async () => {
        get.disabled = true;
        try {
          const blob = await files.downloadFile(info, index).completion;
          saveBlob(blob, info.name);
          setState(row, T('received ✓', 'reçu ✓'));
          get.remove();
        } catch (err) {
          setState(row, T('failed', 'échec'));
          get.disabled = false;
        }
      });
      row.append(get);
    });
  });
  files.on('download-progress', (p) => {
    for (const row of rows.values()) {
      if (row.querySelector('.name').textContent.endsWith(p.fileName)) setState(row, `${Math.round(p.percentage)} %`);
    }
  });
  files.on('error', (err) => {
    if (err.fileName) setState(fileRow(`err:${err.fileName}`, err.fileName), T('failed', 'échec'));
    else showNotice(T('File copy', 'Copie de fichiers'), err.message || '', [[T('OK', 'OK'), () => { notice.hidden = true; }, true]]);
  });
}

// La résolution du bureau Windows suit la place disponible : plein écran, fenêtre agrandie
// ou réduite (canal d'affichage dynamique). Le serveur accepte des largeurs paires, 200 à 8192.
let sizeWatch = null;
let sizeTimer = 0;
let lastSize = '';
/** Place réellement disponible pour l'image (zone d'affichage, marges déduites). */
function area() {
  const cs = getComputedStyle(screen);
  return {
    width: screen.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight),
    height: screen.clientHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom),
  };
}
/** Taille du bureau Windows : la zone, en largeur paire, 200 à 8192. */
function desktopSize() {
  const box = area();
  return {
    width: Math.min(8192, Math.max(200, Math.round(box.width) & ~1)),
    height: Math.min(8192, Math.max(200, Math.round(box.height))),
  };
}
function applySize() {
  if (!ui || !element || typing) return;
  const { width, height } = desktopSize();
  const key = `${width}x${height}`;
  if (key === lastSize) return;
  lastSize = key;
  ui.resize(width, height);
  // Le bureau change de taille : l'image est recalée sur la zone.
  setTimeout(() => ui?.setScale?.(1), 400);
}
function followSize() {
  const later = () => { clearTimeout(sizeTimer); sizeTimer = setTimeout(applySize, 250); };
  sizeWatch = new ResizeObserver(later);
  sizeWatch.observe(screen);
  document.addEventListener('fullscreenchange', () => { fullLabel(); later(); });
  window.addEventListener('resize', later);
}

// ---------- Écran tactile ----------
// Un appui = clic gauche ; appui long = clic droit ; glisser = glisser (bouton gauche
// enfoncé) ; deux doigts qui glissent = molette ; appui à deux doigts = clic droit.
// « Clavier » ouvre le clavier du téléphone : le texte part en Unicode (il ne dépend pas de la
// disposition du clavier Windows), les touches spéciales et les raccourcis en codes de touches.
let typing = false;
const LONG_PRESS = 550;
const SLOP = 10;
function touch() {
  const rds = ui.remoteDesktopService;
  const canvas = element.shadowRoot?.querySelector('canvas');
  if (!rds || !canvas) return;
  element.style.touchAction = 'none';
  const point = (t) => {
    const r = canvas.getBoundingClientRect();
    return { x: Math.round((t.clientX - r.left) * canvas.width / r.width), y: Math.round((t.clientY - r.top) * canvas.height / r.height) };
  };
  const button = (b, down) => rds.mouseButtonState({ button: b, preventDefault() {} }, down, false);
  const click = (b) => { button(b, true); button(b, false); };
  let g = null;
  element.addEventListener('touchstart', (e) => {
    e.preventDefault();
    if (e.touches.length === 1) {
      const t = e.touches[0];
      g = { kind: 'one', x: t.clientX, y: t.clientY, dragging: false, done: false };
      rds.updateMousePosition(point(t));
      g.timer = setTimeout(() => {
        if (g?.kind === 'one' && !g.dragging) { click(2); g.done = true; navigator.vibrate?.(15); }
      }, LONG_PRESS);
    } else if (e.touches.length === 2) {
      clearTimeout(g?.timer);
      if (g?.dragging) button(0, false);
      g = { kind: 'two', y: (e.touches[0].clientY + e.touches[1].clientY) / 2, start: Date.now(), moved: 0, acc: 0, p: point(e.touches[0]) };
    }
  }, { passive: false });
  element.addEventListener('touchmove', (e) => {
    e.preventDefault();
    if (g?.kind === 'one' && e.touches.length === 1 && !g.done) {
      const t = e.touches[0];
      if (!g.dragging && Math.hypot(t.clientX - g.x, t.clientY - g.y) > SLOP) {
        clearTimeout(g.timer);
        g.dragging = true;
        button(0, true);
      }
      if (g.dragging) rds.updateMousePosition(point(t));
    } else if (g?.kind === 'two' && e.touches.length === 2) {
      const y = (e.touches[0].clientY + e.touches[1].clientY) / 2;
      g.moved += Math.abs(y - g.y);
      g.acc += y - g.y;
      g.y = y;
      // Un cran de molette tous les 24 pixels ; le contenu suit les doigts.
      while (Math.abs(g.acc) >= 24) {
        const s = Math.sign(g.acc);
        rds.mouseWheel({ deltaY: -s * 120, deltaX: 0, deltaMode: 0 });
        g.acc -= s * 24;
      }
    }
  }, { passive: false });
  element.addEventListener('touchend', (e) => {
    e.preventDefault();
    if (!g || e.touches.length) return;
    if (g.kind === 'one') {
      clearTimeout(g.timer);
      if (g.dragging) button(0, false);
      else if (!g.done) click(0);
    } else if (g.moved < SLOP && Date.now() - g.start < 400) {
      rds.updateMousePosition(g.p);
      click(2);
    }
    g = null;
  }, { passive: false });
  element.addEventListener('touchcancel', () => {
    clearTimeout(g?.timer);
    if (g?.dragging) button(0, false);
    g = null;
  });
  keyboard(rds);
}

// Raccourcis (Ctrl, Alt, Win + lettre) : code de la touche selon la disposition du clavier
// Windows, choisie dans la barre (AZERTY par défaut en français).
const AZERTY = { a: 'KeyQ', q: 'KeyA', z: 'KeyW', w: 'KeyZ', m: 'Semicolon' };
const SPECIAL = new Set(['Enter', 'Backspace', 'Tab', 'Escape', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Delete', 'Home', 'End', 'PageUp', 'PageDown']);
const MODS = { ctrl: ['ControlLeft', 'Control'], alt: ['AltLeft', 'Alt'], win: ['MetaLeft', 'Meta'] };
function keyboard(rds) {
  const send = (type, code, key) => rds.sendKeyboardEvent(new KeyboardEvent(type, { code, key }));
  const tap = (code, key) => { send('keydown', code, key); send('keyup', code, key); };
  const withMods = (mods, fn) => {
    const list = [...mods].filter((m) => MODS[m]);
    for (const m of list) send('keydown', ...MODS[m]);
    fn();
    for (const m of list.reverse()) send('keyup', ...MODS[m]);
  };
  let layout = FR ? 'azerty' : 'qwerty';
  try { layout = localStorage.getItem('clavier-windows') || layout; } catch {}
  const text = (ch, mods) => {
    if (ch === '\n') { withMods(mods, () => tap('Enter', 'Enter')); return; }
    if (mods.size) {
      const c = ch.toLowerCase();
      const code = /^[a-z]$/.test(c) ? (layout === 'azerty' && AZERTY[c]) || `Key${c.toUpperCase()}` : /^[0-9]$/.test(c) ? `Digit${c}` : c === ' ' ? 'Space' : null;
      if (code) { withMods(mods, () => tap(code, ch)); return; }
    }
    rds.setKeyboardUnicodeMode(true);
    tap('', ch);
    rds.setKeyboardUnicodeMode(false);
  };

  const input = document.createElement('textarea');
  input.className = 'saisie';
  for (const [k, v] of Object.entries({ autocapitalize: 'off', autocomplete: 'off', autocorrect: 'off', spellcheck: 'false', 'aria-label': T('Keyboard input', 'Saisie au clavier') })) input.setAttribute(k, v);
  document.body.append(input);

  const KEY = { esc: ['Escape', 'Escape'], tab: ['Tab', 'Tab'], left: ['ArrowLeft', 'ArrowLeft'], up: ['ArrowUp', 'ArrowUp'], down: ['ArrowDown', 'ArrowDown'], right: ['ArrowRight', 'ArrowRight'], del: ['Delete', 'Delete'], home: ['Home', 'Home'], end: ['End', 'End'], pgup: ['PageUp', 'PageUp'], pgdn: ['PageDown', 'PageDown'] };
  const layoutLabel = () => (layout === 'azerty' ? 'AZERTY' : 'QWERTY');
  const bar = PortuniaClavier.bar([
    { id: 'esc', label: 'Esc' }, { id: 'tab', label: 'Tab' },
    { id: 'ctrl', label: 'Ctrl', sticky: true }, { id: 'alt', label: 'Alt', sticky: true }, { id: 'win', label: 'Win', sticky: true },
    { id: 'left', label: '←' }, { id: 'up', label: '↑' }, { id: 'down', label: '↓' }, { id: 'right', label: '→' },
    { id: 'del', label: T('Del', 'Suppr') }, { id: 'home', label: T('Home', 'Début') }, { id: 'end', label: T('End', 'Fin') },
    { id: 'pgup', label: T('PgUp', 'Pg↑') }, { id: 'pgdn', label: T('PgDn', 'Pg↓') },
    { id: 'start', label: T('Start', 'Démarrer'), title: T('Windows key', 'Touche Windows') },
    { id: 'layout', label: layoutLabel(), title: T('Layout of the Windows keyboard, for shortcuts', 'Disposition du clavier Windows, pour les raccourcis') },
  ], (id, mods) => {
    if (id === 'layout') {
      layout = layout === 'azerty' ? 'qwerty' : 'azerty';
      try { localStorage.setItem('clavier-windows', layout); } catch {}
      bar.el.querySelector('[data-layout]').textContent = layoutLabel();
      return;
    }
    if (id === 'start') { withMods(mods, () => tap('MetaLeft', 'Meta')); return; }
    withMods(mods, () => tap(...KEY[id]));
  });
  bar.el.classList.add('floating');
  bar.el.lastChild.dataset.layout = '';
  bar.el.hidden = true;
  document.body.append(bar.el);

  // Barre juste au-dessus du clavier du téléphone.
  const place = () => {
    const vv = window.visualViewport;
    bar.el.style.bottom = vv ? `${Math.max(0, window.innerHeight - vv.height - vv.offsetTop)}px` : '0px';
  };
  window.visualViewport?.addEventListener('resize', place);
  window.visualViewport?.addEventListener('scroll', place);

  let composing = false;
  input.addEventListener('compositionstart', () => { composing = true; });
  input.addEventListener('compositionend', (e) => {
    composing = false;
    const mods = bar.take();
    for (const ch of e.data || '') text(ch, mods);
    input.value = '';
  });
  input.addEventListener('input', (e) => {
    if (composing || e.isComposing) return;
    if (e.inputType === 'insertText' || e.inputType === 'insertReplacementText' || e.inputType === 'insertFromPaste') {
      const mods = bar.take();
      for (const ch of e.data || '') text(ch, mods);
    } else if (e.inputType === 'insertLineBreak' || e.inputType === 'insertParagraph') {
      text('\n', bar.take());
    } else if (e.inputType === 'deleteContentBackward') {
      withMods(bar.take(), () => tap('Backspace', 'Backspace'));
    }
    input.value = '';
  });
  // Touches sans texte : Entrée, Retour arrière (champ vide), flèches d'un clavier branché…
  input.addEventListener('keydown', (e) => {
    if (e.keyCode === 229 || !SPECIAL.has(e.key)) return;
    e.preventDefault();
    withMods(bar.take(), () => tap(e.key, e.key));
  });

  const kb = document.getElementById('clavier');
  kb.hidden = false;
  kb.addEventListener('pointerdown', (e) => e.preventDefault());
  kb.addEventListener('mousedown', (e) => e.preventDefault());
  kb.addEventListener('click', () => {
    if (typing) input.blur();
    else input.focus({ preventScroll: true });
  });
  input.addEventListener('focus', () => { typing = true; bar.el.hidden = false; kb.classList.add('on'); place(); });
  input.addEventListener('blur', () => {
    typing = false;
    bar.take();
    bar.el.hidden = true;
    kb.classList.remove('on');
    setTimeout(applySize, 300);
  });
}

// Plein écran de toute la zone d'affichage (Échap ou le même bouton pour en sortir).
const fullButton = document.getElementById('plein');
function fullLabel() {
  fullButton.textContent = document.fullscreenElement ? T('Exit full screen', 'Quitter le plein écran') : T('Full screen', 'Plein écran');
}

// Ouvre la session ; en cas d'échec, le formulaire revient avec l'explication.
async function attempt(account, password, domain) {
  document.getElementById('ouvrir').disabled = true;
  try {
    await open(account, password, domain);
  } catch (err) {
    if (element) { element.remove(); element = null; }
    screen.classList.remove('live');
    form.hidden = false;
    error.textContent = explain(err);
  } finally {
    document.getElementById('mdp').value = '';
    document.getElementById('ouvrir').disabled = false;
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  error.textContent = '';
  const user = document.getElementById('utilisateur').value.trim();
  const password = document.getElementById('mdp').value;
  let domain = document.getElementById('domaine').value.trim();
  if (vault) { await attempt('', '', ''); return; }
  if (!user || !password) { error.textContent = T('Give the Windows user and password.', 'Indiquez l\'utilisateur et le mot de passe Windows.'); return; }
  // DOMAINE\utilisateur ou utilisateur@domaine : le domaine se déduit.
  let account = user;
  if (!domain && user.includes('\\')) [domain, account] = user.split('\\', 2);
  await attempt(account, password, domain);
});

document.getElementById('cad').addEventListener('click', () => ui?.ctrlAltDel());
fullButton.addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  else screen.requestFullscreen?.().catch(() => {});
  element?.focus?.();
});
document.getElementById('fermer').addEventListener('click', () => {
  ui?.shutdown();
  window.close();
  showNotice(T('Session closed', 'Session fermée'), T('You can close this tab.', 'Vous pouvez fermer cet onglet.'), [[T('My servers', 'Mes serveurs'), () => { location.href = '/?accueil'; }, true]]);
});

// Compte proposé par le serveur (s'il est déclaré), et vérification de la session du portail.
(async () => {
  const etat = await fetch('/api/etat', { credentials: 'same-origin' }).then((r) => r.json()).catch(() => ({}));
  if (!etat.connecte) { location.href = '/?accueil'; return; }
  const list = await fetch('/api/serveurs', { credentials: 'same-origin' }).then((r) => (r.ok ? r.json() : { serveurs: [] })).catch(() => ({ serveurs: [] }));
  const s = (list.serveurs || []).find((x) => x.nom === nom);
  // Coffre : rien à demander, la session s'ouvre tout de suite (le bouton sert à réessayer).
  if (s?.mode === 'coffre') {
    vault = true;
    for (const id of ['utilisateur', 'mdp', 'domaine']) {
      const input = document.getElementById(id);
      input.required = false;
      input.closest('label')?.setAttribute('hidden', '');
    }
    await attempt('', '', '');
    return;
  }
  if (s?.compte) document.getElementById('utilisateur').value = s.compte;
  document.getElementById(s?.compte ? 'mdp' : 'utilisateur').focus();
})();
