// Portail web de Heimdia : connexion, puis serveurs autorisés. Aucune administration ici.
'use strict';

const app = document.getElementById('app');

// Langue de la page, choisie par le bastion (cookie du sélecteur, sinon langue du navigateur).
const FR = document.documentElement.lang === 'fr';
const T = (en, fr) => (FR ? fr : en);

// Sélecteur de langue : retenu un an dans un cookie lu par le bastion.
function langSwitch() {
  return h('button', {
    class: 'btn lang', type: 'button', lang: FR ? 'en' : 'fr',
    onclick: () => {
      document.cookie = `heimdia_langue=${FR ? 'en' : 'fr'}; Path=/; Max-Age=31536000; SameSite=Strict; Secure`;
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
    headers: body ? { 'Content-Type': 'application/json', 'X-Heimdia': 'portail' } : { 'X-Heimdia': 'portail' },
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
  const code = h('input', { id: 'code', class: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, maxlength: '8', pattern: '[0-9 ]*' });
  const error = h('p', { class: 'error', role: 'alert' });
  const submit = h('button', { class: 'btn primary', type: 'submit' }, T('Sign in', 'Se connecter'));
  const slot = h('div');
  const form = h('form', { class: 'card', novalidate: true },
    brand(state.nom),
    h('h1', {}, T('Sign in', 'Se connecter')),
    state.banniere ? h('p', { class: 'legal' }, state.banniere.trim()) : null,
    h('label', {}, T('Login', 'Identifiant'), login),
    h('label', {}, T('Password', 'Mot de passe'), pass),
    h('label', {}, T('Authenticator app code', 'Code de l\'application d\'authentification'), code),
    slot, error, submit,
    h('p', { class: 'foot' }, T('First sign-in or lost code: contact your administrator.', 'Première connexion ou code perdu : adressez-vous à votre administrateur.')),
    h('p', { class: 'foot' }, langSwitch()));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    error.textContent = '';
    if (!login.value.trim() || !pass.value || !code.value.trim()) { error.textContent = T('Fill in the three fields.', 'Remplissez les trois champs.'); return; }
    if (state.turnstile && !turnstileToken) { error.textContent = T('Wait for the anti-bot check.', 'Patientez pendant la vérification anti-robots.'); return; }
    submit.disabled = true;
    try {
      await api('POST', '/api/connexion', { login: login.value.trim(), mot_de_passe: pass.value, code: code.value.replace(/\s/g, ''), turnstile: turnstileToken });
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
    const list = data.serveurs.filter((s) => !q || s.nom.toLowerCase().includes(q) || s.dossier.toLowerCase().includes(q));
    grid.replaceChildren();
    const folders = [...new Set(list.map((s) => s.dossier))].sort((a, b) => a.localeCompare(b));
    for (const f of folders) {
      if (f) grid.append(h('div', { class: 'fold' }, f));
      for (const s of list.filter((x) => x.dossier === f)) {
        const ready = !s.indisponible;
        grid.append(h('button', {
          class: 'srv', type: 'button', disabled: !ready, title: s.indisponible || T(`Open ${s.nom} in a new tab`, `Ouvrir ${s.nom} dans un nouvel onglet`),
          onclick: () => window.open(`/${s.protocole === 'rdp' ? 'bureau' : 'session'}/${encodeURIComponent(s.nom)}`, '_blank', 'noopener'),
        },
          h('b', {}, s.nom),
          h('span', { class: 'tags' }, h('span', { class: `tag ${s.protocole}` }, s.protocole.toUpperCase()), h('span', { class: `tag${s.mode === 'rebond' ? ' plain' : ''}` }, MODES[s.mode] || s.mode)),
          h('small', {}, !ready ? s.indisponible
            : s.protocole === 'rdp' ? T('Remote Desktop in a tab; Windows credentials asked', 'Bureau à distance dans un onglet ; identifiants Windows demandés')
            : s.mode === 'enregistre' ? T('Your credentials will be asked in the terminal', 'Vos identifiants seront demandés dans le terminal') : T('Open in a tab of this browser', 'Ouvrir dans un onglet de ce navigateur'))));
      }
    }
    if (!list.length) grid.append(h('p', { class: 'empty' }, q ? T('No matching server.', 'Aucun serveur ne correspond.') : T('No server is allowed for you at the moment.', 'Aucun serveur ne vous est autorisé en ce moment.')));
    count.textContent = T(`${data.serveurs.length} server(s) allowed at the moment`, `${data.serveurs.length} serveur(s) autorisé(s) en ce moment`);
  };
  search.addEventListener('input', render);
  render();
  app.replaceChildren(
    h('header', { class: 'top' }, brand(state.nom), h('span', { class: 'grow' }), timer, h('span', { class: 'who' }, data.login), langSwitch(), logout),
    h('section', { class: 'home' }, h('div', { style: 'display:flex;gap:12px;flex-wrap:wrap;align-items:center' }, search, count), grid));
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
