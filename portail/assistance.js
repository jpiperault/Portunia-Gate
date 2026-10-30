// Page de téléchargement de Portunia Assist. Avec un lien d'invitation (/assistance/j/123#456789),
// le code est mis dans le nom du fichier téléchargé : le programme le lit et se relie tout seul.
// Le secret (après #) ne quitte jamais le navigateur.
'use strict';

const dl = document.getElementById('dl');
const place = (location.pathname.match(/\/assistance\/j\/(\d{3})$/) || [])[1];
const secret = (location.hash.match(/^#(\d{6})$/) || [])[1];
if (place && secret) dl.setAttribute('download', `Portunia Assist ${place}${secret}.exe`);

// Programme absent du serveur : on le dit plutôt que de télécharger une page d'erreur.
fetch('/assistance/portunia-assist.exe', { method: 'HEAD' }).then((r) => {
  if (!r.ok) { dl.hidden = true; document.getElementById('absent').hidden = false; }
}).catch(() => {});
