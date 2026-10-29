//! Réglages de démarrage, lus dans l'environnement (Docker Compose les fournit).

use std::path::PathBuf;

pub struct Config {
    /// Base PostgreSQL : HEIMDIA_DATABASE_URL.
    pub database_url: String,
    /// Clés, enregistrements : HEIMDIA_DATA_DIR (par défaut /var/lib/heimdia).
    pub data_dir: PathBuf,
    /// Écoute SSH : HEIMDIA_SSH_LISTEN (par défaut 0.0.0.0:2222).
    pub ssh_listen: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("HEIMDIA_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("HEIMDIA_DATABASE_URL manquant (ex. postgres://heimdia:…@postgres/heimdia)"))?;
        Ok(Self {
            database_url,
            data_dir: std::env::var_os("HEIMDIA_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| "/var/lib/heimdia".into()),
            ssh_listen: std::env::var("HEIMDIA_SSH_LISTEN").unwrap_or_else(|_| "0.0.0.0:2222".into()),
        })
    }

    pub fn recordings_dir(&self) -> PathBuf {
        self.data_dir.join("enregistrements")
    }
}
