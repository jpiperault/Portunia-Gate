-- Bureau à distance : copie de fichiers par le presse-papiers, autorisée par règle et tracée
-- (nombre de fichiers transférés pendant la session).

ALTER TABLE rules ADD COLUMN allow_files BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN fichiers INTEGER NOT NULL DEFAULT 0;
