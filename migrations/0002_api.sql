-- Étape 2 : API pour Portunia (sessions d'API, jetons SSH à usage unique, première connexion).

ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT false;
-- Secret TOTP proposé à l'enrôlement, en attente du premier code juste.
ALTER TABLE users ADD COLUMN totp_pending BYTEA;

CREATE TABLE api_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    client     TEXT NOT NULL DEFAULT '',
    address    TEXT NOT NULL DEFAULT ''
);

-- Jeton remis à Portunia pour ouvrir une session SSH sans redemander le code.
CREATE TABLE ssh_tickets (
    ticket_hash TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    target_id   UUID NOT NULL REFERENCES targets ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL
);

-- L'historique des sessions survit à la suppression d'un compte ou d'un serveur.
ALTER TABLE sessions ADD COLUMN user_login TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN target_name TEXT NOT NULL DEFAULT '';
UPDATE sessions s SET user_login = u.login FROM users u WHERE u.id = s.user_id;
UPDATE sessions s SET target_name = t.name FROM targets t WHERE t.id = s.target_id;
ALTER TABLE sessions ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE sessions ALTER COLUMN target_id DROP NOT NULL;
ALTER TABLE sessions DROP CONSTRAINT sessions_user_id_fkey;
ALTER TABLE sessions DROP CONSTRAINT sessions_target_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users ON DELETE SET NULL;
ALTER TABLE sessions ADD CONSTRAINT sessions_target_id_fkey FOREIGN KEY (target_id) REFERENCES targets ON DELETE SET NULL;
