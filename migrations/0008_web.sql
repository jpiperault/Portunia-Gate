-- Interfaces web derrière la Gate (vCenter, iDRAC, pare-feu, applications internes) :
-- nouveaux protocoles de serveur « http » et « https », en mode enregistré.

ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_protocole_check;
ALTER TABLE targets ADD CONSTRAINT targets_protocole_check CHECK (protocole IN ('ssh', 'rdp', 'http', 'https'));
