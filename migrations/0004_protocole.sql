-- Bureau à distance (RDP) : chaque serveur a son protocole. Les serveurs existants sont en SSH.

ALTER TABLE targets ADD COLUMN protocole TEXT NOT NULL DEFAULT 'ssh' CHECK (protocole IN ('ssh', 'rdp'));
