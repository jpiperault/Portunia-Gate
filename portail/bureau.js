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
  if (res.status === 401) { location.href = '/'; return; }
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
  const builder = ui.configBuilder()
    .withUsername(user)
    .withPassword(password)
    .withServerDomain(domain)
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
  const end = await session.run();
  sizeWatch?.disconnect();
  showNotice(T('Session closed', 'Session fermée'), end?.reason?.() || T('The Remote Desktop session has ended.', 'La session Bureau à distance est terminée.'), [[T('Reopen', 'Rouvrir'), () => location.reload(), true], [T('My servers', 'Mes serveurs'), () => { location.href = '/'; }]]);
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
  if (!ui || !element) return;
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

// Plein écran de toute la zone d'affichage (Échap ou le même bouton pour en sortir).
const fullButton = document.getElementById('plein');
function fullLabel() {
  fullButton.textContent = document.fullscreenElement ? T('Exit full screen', 'Quitter le plein écran') : T('Full screen', 'Plein écran');
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  error.textContent = '';
  const user = document.getElementById('utilisateur').value.trim();
  const password = document.getElementById('mdp').value;
  let domain = document.getElementById('domaine').value.trim();
  if (!user || !password) { error.textContent = T('Give the Windows user and password.', 'Indiquez l\'utilisateur et le mot de passe Windows.'); return; }
  // DOMAINE\utilisateur ou utilisateur@domaine : le domaine se déduit.
  let account = user;
  if (!domain && user.includes('\\')) [domain, account] = user.split('\\', 2);
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
  showNotice(T('Session closed', 'Session fermée'), T('You can close this tab.', 'Vous pouvez fermer cet onglet.'), [[T('My servers', 'Mes serveurs'), () => { location.href = '/'; }, true]]);
});

// Compte proposé par le serveur (s'il est déclaré), et vérification de la session du portail.
(async () => {
  const etat = await fetch('/api/etat', { credentials: 'same-origin' }).then((r) => r.json()).catch(() => ({}));
  if (!etat.connecte) { location.href = '/'; return; }
  const list = await fetch('/api/serveurs', { credentials: 'same-origin' }).then((r) => (r.ok ? r.json() : { serveurs: [] })).catch(() => ({ serveurs: [] }));
  const s = (list.serveurs || []).find((x) => x.nom === nom);
  if (s?.compte) document.getElementById('utilisateur').value = s.compte;
  document.getElementById(s?.compte ? 'mdp' : 'utilisateur').focus();
})();
