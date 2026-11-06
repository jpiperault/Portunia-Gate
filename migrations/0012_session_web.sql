-- Sessions web (interfaces web relayées par la Gate, 0.35) : nouveau type de session « web ».

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_kind_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_kind_check CHECK (kind IN ('shell', 'exec', 'sftp', 'rebond', 'tunnel', 'rdp', 'web'));
