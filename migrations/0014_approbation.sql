-- Approbation des accès (0.38) : une règle peut exiger qu'un approbateur accorde l'accès,
-- pour une durée, sur demande motivée.

ALTER TABLE rules ADD COLUMN IF NOT EXISTS approval BOOLEAN NOT NULL DEFAULT false;
-- Groupe des approbateurs ; NULL : les administrateurs.
ALTER TABLE rules ADD COLUMN IF NOT EXISTS approver_group UUID REFERENCES groups ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS approvals (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    target_id    UUID NOT NULL REFERENCES targets ON DELETE CASCADE,
    reason       TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    ticket       TEXT NOT NULL DEFAULT '' CHECK (length(ticket) <= 100),
    status       TEXT NOT NULL DEFAULT 'attente' CHECK (status IN ('attente', 'accordee', 'refusee', 'annulee', 'expiree')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by   TEXT NOT NULL DEFAULT '',
    decided_at   TIMESTAMPTZ,
    -- Fin de l'accès accordé.
    until        TIMESTAMPTZ,
    comment      TEXT NOT NULL DEFAULT '' CHECK (length(comment) <= 500),
    -- Utilisateur prévenu de la fin proche (10 minutes avant).
    warned       BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS approvals_user_target ON approvals (user_id, target_id, status);
