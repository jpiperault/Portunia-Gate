-- État de la Gate (0.39) : refus des dernières 24 heures et activité du jour, sans parcourir tout le journal.
CREATE INDEX IF NOT EXISTS audit_at ON audit (at);
