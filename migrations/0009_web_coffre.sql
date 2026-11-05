-- Interfaces web en mode coffre : la Gate connecte l'utilisateur avec le compte du coffre.
-- auto : remplit le formulaire de connexion et le valide (et authentification HTTP si le
-- serveur la demande) ; remplir : remplit seulement ; basic : authentification HTTP toujours.

ALTER TABLE targets ADD COLUMN web_connexion TEXT NOT NULL DEFAULT 'auto' CHECK (web_connexion IN ('auto', 'remplir', 'basic'));
