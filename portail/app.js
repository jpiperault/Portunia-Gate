// Portail web de Portunia Gate : connexion, puis serveurs autorisés. Aucune administration ici.
'use strict';

const app = document.getElementById('app');

// Accueil du portail : toujours « /?accueil ». « / » seul, demandé depuis une page du site
// alors qu'une interface web est ouverte, revient à cette interface (voir portal.rs).
if (location.pathname === '/' && !location.search) history.replaceState(null, '', '/?accueil');

// Langue de la page, choisie par la Gate (cookie du sélecteur, sinon langue du navigateur).
const FR = document.documentElement.lang === 'fr';
const T = (en, fr) => (FR ? fr : en);

// Sélecteur de langue : retenu un an dans un cookie lu par la Gate.
function langSwitch() {
  return h('button', {
    class: 'btn lang', type: 'button', lang: FR ? 'en' : 'fr',
    onclick: () => {
      document.cookie = `portunia_gate_langue=${FR ? 'en' : 'fr'}; Path=/; Max-Age=31536000; SameSite=Strict; Secure`;
      location.reload();
    },
  }, FR ? 'English' : 'Français');
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children) if (c != null && c !== false) el.append(c);
  return el;
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json', 'X-Portunia-Gate': 'portail' } : { 'X-Portunia-Gate': 'portail' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.erreur || T('Gate error', 'Erreur de la Gate')), { status: res.status });
  return data;
}

function brand(nom) {
  return h('div', { class: 'brand' }, h('span', { class: 'mark' }, (nom || 'H').slice(0, 1).toUpperCase()), nom);
}

// ---------- Portail fermé ----------

function closed(nom) {
  document.title = `${nom} · ${T('portal closed', 'portail fermé')}`;
  app.replaceChildren(h('div', { class: 'center' }, h('div', { class: 'card', style: 'text-align:center' },
    brand(nom),
    h('h1', {}, T('Portal closed', 'Portail fermé')),
    h('p', { class: 'foot', style: 'font-size:13px' }, T('Browser access is disabled at the moment. Use Portunia, or contact your administrator.', 'L\'accès par le navigateur est désactivé en ce moment. Utilisez Portunia, ou adressez-vous à votre administrateur.')),
    h('p', { class: 'foot' }, langSwitch()))));
}

/** Serveurs web (interface d'administration) relayés par la Gate. */
const WEB = ['http', 'https'];

// ---------- Connexion ----------

let turnstileToken = '';

function loadTurnstile(siteKey, slot) {
  window.onTurnstileReady = () => {
    window.turnstile.render(slot, {
      sitekey: siteKey,
      callback: (t) => { turnstileToken = t; },
      'expired-callback': () => { turnstileToken = ''; },
    });
  };
  document.head.append(h('script', { src: 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileReady&render=explicit', async: true, defer: true }));
}

function loginForm(state) {
  document.title = `${state.nom} · ${T('sign in', 'connexion')}`;
  const login = h('input', { id: 'login', autocomplete: 'username', required: true, spellcheck: 'false', autocapitalize: 'off' });
  const pass = h('input', { id: 'pass', type: 'password', autocomplete: 'current-password', required: true });
  // Pas obligatoire ici : un compte peut en être dispensé, la Gate décide.
  const code = h('input', { id: 'code', class: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '8', pattern: '[0-9 ]*' });
  const error = h('p', { class: 'error', role: 'alert' });
  const submit = h('button', { class: 'btn primary', type: 'submit' }, T('Sign in', 'Se connecter'));
  const slot = h('div');
  const form = h('form', { class: 'card', novalidate: true },
    brand(state.nom),
    h('h1', {}, T('Sign in', 'Se connecter')),
    state.banniere ? h('p', { class: 'legal' }, state.banniere.trim()) : null,
    h('label', {}, T('Login', 'Identifiant'), login),
    h('label', {}, T('Password', 'Mot de passe'), pass),
    h('label', {}, state.code_facultatif ? T('Authenticator app code (if your account requires one)', 'Code de l\'application d\'authentification (si votre compte en demande un)') : T('Authenticator app code', 'Code de l\'application d\'authentification'), code),
    slot, error, submit,
    h('p', { class: 'foot' }, T('First sign-in or lost code: contact your administrator.', 'Première connexion ou code perdu : adressez-vous à votre administrateur.')),
    h('p', { class: 'foot' }, langSwitch()));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    error.textContent = '';
    if (!login.value.trim() || !pass.value) { error.textContent = T('Fill in your login and password.', 'Remplissez l\'identifiant et le mot de passe.'); return; }
    if (state.turnstile && !turnstileToken) { error.textContent = T('Wait for the anti-bot check.', 'Patientez pendant la vérification anti-robots.'); return; }
    submit.disabled = true;
    try {
      await api('POST', '/api/connexion', { login: login.value.trim(), mot_de_passe: pass.value, code: code.value.replace(/\s/g, ''), turnstile: turnstileToken });
      // Application Android Portunia Gate : elle peut proposer d'enrôler ce téléphone.
      try { window.PortuniaGateApp?.connecte(); } catch { /* application ancienne */ }
      start();
    } catch (err) {
      error.textContent = err.message;
      code.value = '';
      if (window.turnstile) { window.turnstile.reset(); turnstileToken = ''; }
    } finally {
      submit.disabled = false;
    }
  });
  app.replaceChildren(h('div', { class: 'center' }, form));
  if (state.turnstile) loadTurnstile(state.turnstile, slot);
  login.focus();
}

// ---------- Serveurs ----------

const MODES = { coffre: T('Vault', 'Coffre'), enregistre: T('Recorded', 'Enregistré'), rebond: T('Jump', 'Rebond') };
let countdown = 0;

function remaining(iso) {
  const ms = Date.parse(iso) - Date.now();
  if (ms <= 0) return T('expired', 'expirée');
  const min = Math.max(1, Math.floor(ms / 60000));
  return min >= 60 ? `${Math.floor(min / 60)} h ${String(min % 60).padStart(2, '0')}` : `${min} min`;
}

// Client RDP ordinaire (mstsc, Windows App, Remmina) sans Portunia : quoi taper, mot de passe RDP.
function nativePanel(info) {
  const when = (iso) => new Date(iso).toLocaleString(document.documentElement.lang);
  const state = h('p', { class: 'native-hint' });
  const shown = h('div', { class: 'native-pw', hidden: true });
  const remove = h('button', { class: 'btn', type: 'button' }, T('Remove', 'Retirer'));
  const create = h('button', { class: 'btn primary', type: 'button' });
  const paint = () => {
    state.textContent = info.mot_de_passe
      ? T(`RDP password created on ${when(info.mot_de_passe)}.`, `Mot de passe RDP créé le ${when(info.mot_de_passe)}.`)
      : T('You have no RDP password yet.', 'Vous n\'avez pas encore de mot de passe RDP.');
    create.textContent = info.mot_de_passe ? T('New password', 'Nouveau mot de passe') : T('Create my RDP password', 'Créer mon mot de passe RDP');
    remove.hidden = !info.mot_de_passe;
  };
  create.onclick = async () => {
    if (info.mot_de_passe && !confirm(T('The current RDP password will stop working. Continue?', 'Le mot de passe RDP actuel ne marchera plus. Continuer ?'))) return;
    create.disabled = true;
    try {
      const r = await api('POST', '/api/rdp-natif/mot-de-passe');
      info.mot_de_passe = new Date().toISOString();
      const code = h('code', {}, r.mot_de_passe);
      const copy = h('button', { class: 'btn', type: 'button', onclick: () => navigator.clipboard?.writeText(r.mot_de_passe).then(() => { copy.textContent = T('Copied', 'Copié'); }, () => {}) }, T('Copy', 'Copier'));
      shown.replaceChildren(code, copy, h('span', { class: 'native-hint' }, T('Shown only once: save it in the RDP client or a password manager.', 'Affiché une seule fois : enregistrez-le dans le client RDP ou un gestionnaire de mots de passe.')));
      shown.hidden = false;
    } catch (err) {
      alert(err.message);
    }
    create.disabled = false;
    paint();
  };
  remove.onclick = async () => {
    if (!confirm(T('Remove your RDP password? You will no longer be able to connect with an RDP client this way.', 'Retirer votre mot de passe RDP ? Vous ne pourrez plus vous connecter ainsi avec un client RDP.'))) return;
    try {
      await api('DELETE', '/api/rdp-natif/mot-de-passe');
      info.mot_de_passe = null;
      shown.hidden = true;
    } catch (err) {
      alert(err.message);
    }
    paint();
  };
  paint();
  const user = (srv) => `${info.login}%${srv}${info.code ? T('%code', '%code') : ''}`;
  // Raccourci .rdp : adresse et utilisateur déjà remplis ; le mot de passe reste demandé.
  const shortcut = (srv) => {
    const text = [`full address:s:${info.adresse}`, `username:s:${info.login}%${srv}`, 'prompt for credentials:i:1', 'enablecredsspsupport:i:1', 'authentication level:i:2', ''].join('\r\n');
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'application/x-rdp' })), download: `${srv}.rdp` });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  return h('details', { class: 'native' },
    h('summary', {}, T('Connect with mstsc or Windows App (without Portunia)', 'Se connecter avec mstsc ou Windows App (sans Portunia)')),
    h('div', { class: 'native-body' },
      h('p', {}, T('In the Remote Desktop client, type:', 'Dans le client Bureau à distance, tapez :')),
      h('ul', {},
        h('li', {}, T('Computer: ', 'Ordinateur : '), h('code', {}, info.adresse)),
        h('li', {}, T('User: ', 'Utilisateur : '), h('code', {}, user(T('server', 'serveur')))),
        h('li', {}, T('Password: your RDP password (below)', 'Mot de passe : votre mot de passe RDP (ci-dessous)'))),
      info.code ? h('p', { class: 'native-hint' }, T('Add the 6-digit code of your authentication app after a second %: julien%srv-ad-01%123456.', 'Ajoutez le code à 6 chiffres de votre application d\'authentification après un second % : julien%srv-ad-01%123456.')) : null,
      h('div', { class: 'native-list' }, ...info.serveurs.map((srv) => h('div', { class: 'native-row' },
        h('b', {}, srv), h('code', {}, user(srv)),
        h('button', { class: 'btn', type: 'button', title: T('Shortcut for mstsc with the address and user filled in', 'Raccourci pour mstsc, adresse et utilisateur remplis'), onclick: () => shortcut(srv) }, '.rdp')))),
      h('div', { class: 'native-actions' }, create, remove),
      state, shown));
}

// Serveurs sur approbation (Gate 0.38) : demande avec motif, état de la demande.
function approvalPanel(info, reload) {
  const when = (iso) => new Date(iso).toLocaleString(document.documentElement.lang, { dateStyle: 'short', timeStyle: 'short' });
  const status = { attente: T('waiting for an approver', 'en attente d\'un approbateur'), accordee: T('granted', 'accordé'), refusee: T('refused', 'refusé'), annulee: T('cancelled', 'annulé'), expiree: T('expired', 'expiré') };
  const rows = info.a_demander.map((s) => {
    if (s.demande) {
      const cancel = h('button', { class: 'btn', type: 'button', onclick: async () => {
        try { await api('POST', `/api/approbations/${s.demande.id}/annuler`); reload(); } catch (e) { alert(e.message); }
      } }, T('Cancel', 'Annuler'));
      return h('div', { class: 'appr-row' }, h('b', {}, s.serveur), h('span', { class: 'appr-state' }, T(`Asked ${when(s.demande.demande)}: `, `Demandé le ${when(s.demande.demande)} : `), status.attente), cancel);
    }
    const reason = h('input', { class: 'input', placeholder: T('Reason (required)', 'Motif (obligatoire)'), maxlength: '500' });
    const ticket = h('input', { class: 'input appr-ticket', placeholder: T('Ticket (optional)', 'Ticket (facultatif)'), maxlength: '100' });
    const send = h('button', { class: 'btn primary', type: 'button', onclick: async () => {
      if (!reason.value.trim()) { reason.focus(); return; }
      send.disabled = true;
      try { await api('POST', '/api/approbations', { serveur: s.serveur, motif: reason.value, ticket: ticket.value }); reload(); }
      catch (e) { alert(e.message); send.disabled = false; }
    } }, T('Ask for access', 'Demander l\'accès'));
    return h('div', { class: 'appr-row' }, h('b', {}, s.serveur), s.description ? h('span', { class: 'native-hint' }, s.description) : null, reason, ticket, send);
  });
  const recent = info.mes_demandes.filter((r) => r.etat !== 'attente').slice(0, 5).map((r) =>
    h('div', { class: 'native-hint' }, `${r.serveur} · ${status[r.etat] ?? r.etat}${r.decide_par ? T(` by ${r.decide_par}`, ` par ${r.decide_par}`) : ''}${r.jusqua && r.etat === 'accordee' ? T(` until ${when(r.jusqua)}`, ` jusqu'au ${when(r.jusqua)}`) : ''}${r.commentaire ? ` — ${r.commentaire}` : ''}`));
  return h('details', { class: 'native', open: true },
    h('summary', {}, T('Servers on approval', 'Serveurs sur approbation')),
    h('div', { class: 'native-body' },
      h('p', { class: 'native-hint' }, T('An approver must grant access, for a duration, before you can open these servers.', 'Un approbateur doit accorder l\'accès, pour une durée, avant que vous puissiez ouvrir ces serveurs.')),
      ...rows, ...recent));
}

async function home(state) {
  let data;
  try {
    data = await api('GET', '/api/serveurs');
  } catch (err) {
    if (err.status === 401) return start();
    app.replaceChildren(h('p', { class: 'loading' }, err.message));
    return;
  }
  document.title = `${state.nom} · ${T('my servers', 'mes serveurs')}`;
  const sessionText = () => `${T('Session: ', 'Session : ')}${remaining(data.expire)}`;
  const timer = h('span', { class: 'timer', title: T('Automatic sign-out', 'Déconnexion automatique') }, sessionText());
  clearInterval(countdown);
  countdown = setInterval(() => {
    timer.textContent = sessionText();
    if (Date.parse(data.expire) <= Date.now()) start();
  }, 30000);
  const logout = h('button', { class: 'btn', type: 'button', onclick: async () => { await api('POST', '/api/deconnexion').catch(() => {}); start(); } }, T('Sign out', 'Se déconnecter'));
  const search = h('input', { type: 'search', placeholder: T('Search for a server', 'Rechercher un serveur'), 'aria-label': T('Search for a server', 'Rechercher un serveur') });
  const grid = h('div', { class: 'grid' });
  const count = h('span', { class: 'who' });
  const render = () => {
    const q = search.value.trim().toLowerCase();
    const list = data.serveurs.filter((s) => !q || s.nom.toLowerCase().includes(q) || s.dossier.toLowerCase().includes(q) || (s.description || '').toLowerCase().includes(q));
    grid.replaceChildren();
    const folders = [...new Set(list.map((s) => s.dossier))].sort((a, b) => a.localeCompare(b));
    for (const f of folders) {
      if (f) grid.append(h('div', { class: 'fold' }, f));
      for (const s of list.filter((x) => x.dossier === f)) {
        const ready = !s.indisponible;
        grid.append(h('button', {
          class: 'srv', type: 'button', disabled: !ready, title: s.indisponible || T(`Open ${s.nom} in a new tab`, `Ouvrir ${s.nom} dans un nouvel onglet`),
          onclick: () => window.open(`/${s.protocole === 'rdp' ? 'bureau' : WEB.includes(s.protocole) ? 'web' : 'session'}/${encodeURIComponent(s.nom)}`, '_blank', 'noopener'),
        },
          h('b', {}, s.nom),
          h('span', { class: 'tags' }, h('span', { class: `tag ${s.protocole}` }, s.protocole.toUpperCase()), h('span', { class: `tag${s.mode === 'rebond' ? ' plain' : ''}` }, MODES[s.mode] || s.mode)),
          h('small', {}, !ready ? s.indisponible
            : s.description ? s.description
            : WEB.includes(s.protocole) ? T('Web interface in a tab, through the Gate; pages visited are logged', 'Interface web dans un onglet, par la Gate ; pages visitées journalisées')
            : s.protocole === 'rdp' && s.mode === 'coffre' ? T('Remote Desktop in a tab; signed in by the Gate', 'Bureau à distance dans un onglet ; session ouverte par la Gate')
            : s.protocole === 'rdp' && s.mode === 'rebond' ? T('Remote Desktop in a tab, not recorded; Windows credentials asked', 'Bureau à distance dans un onglet, non enregistré ; identifiants Windows demandés')
            : s.protocole === 'rdp' ? T('Remote Desktop in a tab; Windows credentials asked', 'Bureau à distance dans un onglet ; identifiants Windows demandés')
            : s.mode === 'enregistre' ? T('Your credentials will be asked in the terminal', 'Vos identifiants seront demandés dans le terminal') : T('Open in a tab of this browser', 'Ouvrir dans un onglet de ce navigateur'))));
      }
    }
    if (!list.length) grid.append(h('p', { class: 'empty' }, q ? T('No matching server.', 'Aucun serveur ne correspond.') : T('No server is allowed for you at the moment.', 'Aucun serveur ne vous est autorisé en ce moment.')));
    count.textContent = T(`${data.serveurs.length} server(s) allowed at the moment`, `${data.serveurs.length} serveur(s) autorisé(s) en ce moment`);
  };
  search.addEventListener('input', render);
  render();
  // Entrée RDP native ouverte et serveurs accessibles ainsi : panneau d'aide (Gate 0.34).
  const native = await api('GET', '/api/rdp-natif').catch(() => null);
  const approvals = await api('GET', '/api/approbations').catch(() => null);
  app.replaceChildren(
    h('header', { class: 'top' }, brand(state.nom), h('span', { class: 'grow' }), timer, h('span', { class: 'who' }, data.login), langSwitch(), logout),
    h('section', { class: 'home' }, h('div', { style: 'display:flex;gap:12px;flex-wrap:wrap;align-items:center' }, search, count), grid,
      approvals?.a_demander?.length ? approvalPanel(approvals, () => home(state)) : null,
      native?.actif && native.serveurs.length ? nativePanel(native) : null));
}

// ---------- Démarrage ----------

async function start() {
  clearInterval(countdown);
  let state;
  try {
    state = await api('GET', '/api/etat');
  } catch (err) {
    app.replaceChildren(h('p', { class: 'loading' }, T(`Gate unreachable: ${err.message}`, `Gate injoignable : ${err.message}`)));
    return;
  }
  if (!state.actif) return closed(state.nom);
  if (!state.connecte) return loginForm(state);
  return home(state);
}

start();
