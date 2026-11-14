-- Navigation depuis le portail web (Gate 0.53) : une sortie web peut aussi s'ouvrir dans un onglet
-- du portail. Le navigateur tourne alors sur la Gate (service portunia-gate-navigateur, Chromium
-- sans accès réseau hors de la sortie web) et la page en reçoit l'image. Désactivé par défaut.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS sortie_portail BOOLEAN NOT NULL DEFAULT false;
