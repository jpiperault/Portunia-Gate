-- Description d'un serveur, affichée sur sa vignette dans le portail web et dans Portunia
-- (à la place du texte automatique). Vide : texte automatique.

ALTER TABLE targets ADD COLUMN description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 200);
