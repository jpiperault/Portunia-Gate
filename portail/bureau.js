// Portail web de Heimdia : Bureau à distance dans le navigateur (client IronRDP), à travers
// le passage RDCleanPath du bastion.
import '/static/iron-remote-desktop.js';
import { Backend, init, displayControl } from '/static/iron-remote-desktop-rdp.js';

const nom = decodeURIComponent(location.pathname.split('/').pop() || '');
document.getElementById('nom').textContent = nom;
document.title = `${nom} · Bureau à distance`;

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
    case 1: case 2: return 'Identifiant ou mot de passe Windows refusé.';
    case 3: return 'Le serveur Windows refuse l\'accès à ce compte.';
    case 4: return http === 401 ? 'Autorisation expirée : rouvrez le serveur depuis la liste.' : http === 403 ? 'Accès refusé par le bastion (règle ou serveur).' : 'Le bastion n\'a pas pu joindre le serveur Windows.';
    case 5: return 'Bastion injoignable.';
    case 6: return 'Le serveur Windows refuse la négociation (NLA désactivé ou version trop ancienne ?).';
    default: return (typeof err?.backtrace === 'function' ? err.backtrace() : String(err?.message || err || '')).split('\n')[0] || 'Connexion impossible.';
  }
}

const ready = init('WARN').catch(() => {});

async function open(user, password, domain) {
  // Jeton à usage unique pour ce serveur, demandé avec la session du portail.
  const res = await fetch(`/api/rdp/${encodeURIComponent(nom)}`, { method: 'POST', credentials: 'same-origin', headers: { 'X-Heimdia': 'portail' } });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { location.href = '/'; return; }
  if (!res.ok) throw new Error(data.erreur || 'Serveur indisponible');
  await ready;

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
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const box = screen.getBoundingClientRect();
  const config = ui.configBuilder()
    .withUsername(user)
    .withPassword(password)
    .withServerDomain(domain)
    .withDestination(nom)
    .withProxyAddress(`${scheme}://${location.host}/ws-rdp`)
    .withAuthToken(data.jeton)
    .withDesktopSize({ width: Math.max(800, Math.round(box.width)), height: Math.max(600, Math.round(box.height)) })
    .withExtension(displayControl(true))
    .build();
  const session = await ui.connect(config);
  ui.setVisibility(true);
  document.getElementById('cad').disabled = false;
  document.getElementById('plein').disabled = false;
  const end = await session.run();
  showNotice('Session fermée', end?.reason?.() || 'La session Bureau à distance est terminée.', [['Rouvrir', () => location.reload(), true], ['Mes serveurs', () => { location.href = '/'; }]]);
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  error.textContent = '';
  const user = document.getElementById('utilisateur').value.trim();
  const password = document.getElementById('mdp').value;
  let domain = document.getElementById('domaine').value.trim();
  if (!user || !password) { error.textContent = 'Indiquez l\'utilisateur et le mot de passe Windows.'; return; }
  // DOMAINE\utilisateur ou utilisateur@domaine : le domaine se déduit.
  let account = user;
  if (!domain && user.includes('\\')) [domain, account] = user.split('\\', 2);
  document.getElementById('ouvrir').disabled = true;
  try {
    await open(account, password, domain);
  } catch (err) {
    if (element) { element.remove(); element = null; }
    form.hidden = false;
    error.textContent = explain(err);
  } finally {
    document.getElementById('mdp').value = '';
    document.getElementById('ouvrir').disabled = false;
  }
});

document.getElementById('cad').addEventListener('click', () => ui?.ctrlAltDel());
document.getElementById('plein').addEventListener('click', () => element?.requestFullscreen?.().catch(() => {}));
document.getElementById('fermer').addEventListener('click', () => {
  ui?.shutdown();
  window.close();
  showNotice('Session fermée', 'Vous pouvez fermer cet onglet.', [['Mes serveurs', () => { location.href = '/'; }, true]]);
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
