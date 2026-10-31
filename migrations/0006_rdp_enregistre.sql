-- Bureau à distance en mode enregistré : la Gate relaie la session (passage RDCleanPath)
-- et l'enregistre ; nouveau type de session « rdp ».

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_kind_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_kind_check CHECK (kind IN ('shell', 'exec', 'sftp', 'rebond', 'tunnel', 'rdp'));
