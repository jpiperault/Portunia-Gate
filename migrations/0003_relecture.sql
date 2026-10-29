-- Étape 3 : relecture des sessions (mode du serveur, frappe enregistrée, texte pour la recherche).

ALTER TABLE sessions ADD COLUMN mode TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN frappe BOOLEAN NOT NULL DEFAULT false;
-- Texte affiché et lignes tapées (sans les saisies masquées), rempli à la fin de la session.
ALTER TABLE sessions ADD COLUMN texte TEXT;
UPDATE sessions s SET mode = t.mode FROM targets t WHERE t.id = s.target_id;
CREATE INDEX sessions_login ON sessions (user_login, started_at DESC);
