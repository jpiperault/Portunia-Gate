-- Purge du journal (Gate 0.42) : avant de supprimer les événements anciens, la Gate note le
-- premier événement gardé et l'empreinte de celui qui le précédait, signés par sa clé.
-- La vérification de la chaîne repart de la dernière ancre.
CREATE TABLE IF NOT EXISTS audit_ancres (
    seq       BIGINT PRIMARY KEY,
    prev_hash TEXT NOT NULL,
    supprimes BIGINT NOT NULL,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    signature TEXT NOT NULL
);
