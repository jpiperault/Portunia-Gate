-- Adresse e-mail des comptes (notifications : approbation des accès, alertes).

ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '' CHECK (length(email) <= 254);
