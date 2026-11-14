-- Jetons à usage unique (Gate 0.49, B5 de l'audit du 11 novembre) : chacun a un usage, vérifié
-- quand il est présenté. Un jeton de fichier .rdp ne sert plus de mot de passe SSH, ni un jeton
-- du portail d'entrée d'interface web. Les jetons en cours (60 s au plus) gardent « ssh ».
ALTER TABLE ssh_tickets ADD COLUMN IF NOT EXISTS usage TEXT NOT NULL DEFAULT 'ssh';
ALTER TABLE ssh_tickets DROP CONSTRAINT IF EXISTS ssh_tickets_usage_check;
ALTER TABLE ssh_tickets ADD CONSTRAINT ssh_tickets_usage_check CHECK (usage IN ('ssh', 'rdp', 'rdp-natif', 'web'));
