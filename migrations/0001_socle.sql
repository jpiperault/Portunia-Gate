-- Socle de Heimdia : comptes, cibles, droits, sessions et journal d'audit.

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    login         TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL CHECK (role IN ('user', 'auditor', 'admin')),
    password_hash TEXT,
    -- Secret TOTP chiffré par le coffre ; NULL = pas encore enrôlé.
    totp_secret   BYTEA,
    -- Dernier pas TOTP accepté : un code ne sert qu'une fois.
    totp_last_step BIGINT NOT NULL DEFAULT 0,
    -- Combinaisons acceptées (« password+totp,key ») ; NULL = réglage général.
    auth_policy   TEXT,
    disabled      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_keys (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    public_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    label       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE groups (
    id   UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE group_members (
    group_id UUID NOT NULL REFERENCES groups ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE targets (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    folder      TEXT NOT NULL DEFAULT '',
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    mode        TEXT NOT NULL CHECK (mode IN ('rebond', 'enregistre', 'coffre')),
    -- Compte sur la cible : imposé en mode coffre, proposé sinon.
    account     TEXT,
    secret_kind TEXT NOT NULL DEFAULT 'none' CHECK (secret_kind IN ('none', 'password', 'key')),
    secret      BYTEA,
    -- Empreinte SHA256 de la clé du serveur, mémorisée à la première connexion.
    host_key    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rules (
    id            UUID PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    group_id      UUID NOT NULL REFERENCES groups ON DELETE CASCADE,
    allow_sftp    BOOLEAN NOT NULL DEFAULT false,
    allow_tunnels BOOLEAN NOT NULL DEFAULT false,
    record_input  BOOLEAN NOT NULL DEFAULT false,
    -- Jours autorisés : bit 0 = lundi … bit 6 = dimanche.
    days          SMALLINT NOT NULL DEFAULT 127,
    -- Heures autorisées [from, to[ ; NULL = toute la journée.
    hour_from     SMALLINT CHECK (hour_from BETWEEN 0 AND 23),
    hour_to       SMALLINT CHECK (hour_to BETWEEN 1 AND 24),
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rule_targets (
    rule_id   UUID NOT NULL REFERENCES rules ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets ON DELETE CASCADE,
    PRIMARY KEY (rule_id, target_id)
);

CREATE TABLE sessions (
    id               UUID PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users,
    target_id        UUID NOT NULL REFERENCES targets,
    kind             TEXT NOT NULL CHECK (kind IN ('shell', 'exec', 'sftp', 'rebond', 'tunnel')),
    detail           TEXT NOT NULL DEFAULT '',
    client_addr      TEXT NOT NULL DEFAULT '',
    started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at         TIMESTAMPTZ,
    recording        TEXT,
    recording_sha256 TEXT,
    signature        TEXT,
    bytes            BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX sessions_started ON sessions (started_at DESC);

-- Journal chaîné : chaque ligne contient l'empreinte de la précédente.
CREATE TABLE audit (
    seq       BIGINT PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL,
    actor     TEXT NOT NULL,
    event     TEXT NOT NULL,
    detail    JSONB NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
