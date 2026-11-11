-- Téléphones enrôlés (Gate 0.47) : l'application Android Portunia Gate garde une clé P-256 dans
-- le Keystore du téléphone, utilisable seulement après l'empreinte ; la Gate garde la clé
-- publique. Connexion au portail par un défi signé, sans mot de passe ni code.
CREATE TABLE IF NOT EXISTS appareils (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    nom        TEXT NOT NULL,
    cle        BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used  TIMESTAMPTZ,
    address    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS appareils_user ON appareils (user_id);

-- Session du portail ouverte par un téléphone : fermée avec lui s'il est retiré.
ALTER TABLE web_sessions ADD COLUMN IF NOT EXISTS appareil UUID REFERENCES appareils ON DELETE CASCADE;
