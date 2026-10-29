//! Réglages de démarrage, lus dans l'environnement (Docker Compose les fournit).

use std::path::PathBuf;

pub struct Config {
    /// Base PostgreSQL : HEIMDIA_DATABASE_URL.
    pub database_url: String,
    /// Clés, enregistrements : HEIMDIA_DATA_DIR (par défaut /var/lib/heimdia).
    pub data_dir: PathBuf,
    /// Écoute SSH : HEIMDIA_SSH_LISTEN (par défaut 0.0.0.0:2222).
    pub ssh_listen: String,
    /// Écoute de l'API HTTPS pour Portunia : HEIMDIA_API_LISTEN (par défaut 0.0.0.0:8443).
    pub api_listen: String,
    /// Port SSH vu des utilisateurs (redirection Docker) : HEIMDIA_SSH_PUBLIC_PORT.
    pub ssh_public_port: u16,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("HEIMDIA_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("HEIMDIA_DATABASE_URL manquant (ex. postgres://heimdia:…@postgres/heimdia)"))?;
        // Paquet Debian : HEIMDIA_SSH_PORT et HEIMDIA_API_PORT de /etc/heimdia/heimdia.env.
        // Docker : le conteneur écoute 2222 et 8443, Compose publie les ports choisis.
        let port = |name: &str| std::env::var(name).ok().and_then(|p| p.trim().parse::<u16>().ok());
        let ssh_port = port("HEIMDIA_SSH_PORT").unwrap_or(2222);
        let api_port = port("HEIMDIA_API_PORT").unwrap_or(8443);
        Ok(Self {
            database_url,
            data_dir: std::env::var_os("HEIMDIA_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/var/lib/heimdia".into()),
            ssh_listen: std::env::var("HEIMDIA_SSH_LISTEN").unwrap_or_else(|_| format!("0.0.0.0:{ssh_port}")),
            api_listen: std::env::var("HEIMDIA_API_LISTEN").unwrap_or_else(|_| format!("0.0.0.0:{api_port}")),
            ssh_public_port: port("HEIMDIA_SSH_PUBLIC_PORT").unwrap_or(ssh_port),
        })
    }

    pub fn recordings_dir(&self) -> PathBuf {
        self.data_dir.join("enregistrements")
    }
}
