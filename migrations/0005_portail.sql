-- Portail web : sessions du navigateur, et adresse réelle de l'utilisateur portée par le jeton SSH.

CREATE TABLE web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    address    TEXT NOT NULL DEFAULT ''
);

-- Jeton remis par le portail : la session SSH garde l'adresse du navigateur, pas celle du portail.
ALTER TABLE ssh_tickets ADD COLUMN client_addr TEXT;
