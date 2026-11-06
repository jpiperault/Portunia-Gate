-- Mot de passe RDP d'un compte : pour un client RDP ordinaire sans Portunia (mstsc avec
-- « compte%serveur »). Scellé par la Gate (l'authentification Windows, NTLM, exige de le
-- relire) ; distinct du mot de passe du compte, qui reste haché.

ALTER TABLE users ADD COLUMN rdp_password BYTEA;
ALTER TABLE users ADD COLUMN rdp_password_at TIMESTAMPTZ;
