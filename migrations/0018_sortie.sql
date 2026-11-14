-- Sortie web (Gate 0.48) : une cible « sortie » laisse Portunia naviguer sur Internet par la Gate
-- (proxy SOCKS5 local relié au SSH de la Gate). La cible porte son filtre : domaines autorisés
-- (vide : tous), domaines bloqués et ports permis. Les réseaux internes restent toujours refusés.
ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_protocole_check;
ALTER TABLE targets ADD CONSTRAINT targets_protocole_check CHECK (protocole IN ('ssh', 'rdp', 'http', 'https', 'sortie'));
ALTER TABLE targets ADD COLUMN IF NOT EXISTS sortie_domaines TEXT NOT NULL DEFAULT '';
ALTER TABLE targets ADD COLUMN IF NOT EXISTS sortie_bloques TEXT NOT NULL DEFAULT '';
ALTER TABLE targets ADD COLUMN IF NOT EXISTS sortie_ports TEXT NOT NULL DEFAULT '80,443';

-- Une session « navigation » par connexion de Portunia : sites visités résumés à la fermeture.
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_kind_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_kind_check CHECK (kind IN ('shell', 'exec', 'sftp', 'rebond', 'tunnel', 'rdp', 'web', 'navigation'));
