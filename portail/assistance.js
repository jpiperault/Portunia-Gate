// Page de téléchargement de Portunia Assist. Le nom du fichier porte l'adresse de ce bastion :
// le programme y lit où se connecter (« Portunia Assist (acces.exemple.fr).exe »).
'use strict';

const dl = document.getElementById('dl');
dl.setAttribute('download', `Portunia Assistance (${location.host}).exe`);

// Programme absent du serveur : on le dit plutôt que de télécharger une page d'erreur.
fetch('/assistance/portunia-assist.exe', { method: 'HEAD' }).then((r) => {
  if (!r.ok) { dl.hidden = true; document.getElementById('absent').hidden = false; }
}).catch(() => {});
