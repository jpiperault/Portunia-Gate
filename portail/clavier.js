// Portail web de Portunia Gate : barre de touches pour écran tactile (terminal et Bureau à
// distance). Les touches ne prennent pas le focus : le clavier du téléphone reste ouvert.
// Ctrl, Alt et Win sont « collantes » : elles s'appliquent à la touche suivante.
'use strict';

(() => {
  const tactile = navigator.maxTouchPoints > 0 || matchMedia('(pointer: coarse)').matches;

  /**
   * keys : [{ id, label, title?, sticky? }] ; onKey(id, mods) pour une touche ordinaire, avec
   * les touches collantes armées (Set d'id), qui sont alors relâchées.
   */
  function bar(keys, onKey) {
    const el = document.createElement('div');
    el.className = 'keys';
    el.setAttribute('role', 'toolbar');
    const armed = new Set();
    const buttons = new Map();
    function take() {
      const mods = new Set(armed);
      armed.clear();
      for (const b of buttons.values()) b.classList.remove('on');
      return mods;
    }
    for (const k of keys) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = k.sticky ? 'key mod' : 'key';
      b.textContent = k.label;
      if (k.title) b.title = k.title;
      // Pas de focus sur la touche (le champ de saisie le garde, le clavier reste ouvert).
      b.addEventListener('pointerdown', (e) => e.preventDefault());
      b.addEventListener('mousedown', (e) => e.preventDefault());
      b.addEventListener('click', () => {
        if (k.sticky) {
          if (armed.has(k.id)) armed.delete(k.id);
          else armed.add(k.id);
          b.classList.toggle('on', armed.has(k.id));
          return;
        }
        onKey(k.id, take());
      });
      buttons.set(k.id, b);
      el.append(b);
    }
    return { el, take, armed: () => armed.size > 0 };
  }

  window.PortuniaClavier = {
    tactile,
    bar,
    // Application Android Portunia Gate (son agent utilisateur).
    app: /PortuniaGate\//.test(navigator.userAgent),
  };
})();
