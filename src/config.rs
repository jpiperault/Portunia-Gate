//! Réglages de démarrage, lus dans l'environnement (Docker Compose les fournit).

use std::path::PathBuf;

pub struct Config {
    /// Base PostgreSQL : PORTUNIA_GATE_DATABASE_URL.
    pub database_url: String,
    /// Clés, enregistrements : PORTUNIA_GATE_DATA_DIR (par défaut /var/lib/portunia-gate).
    pub data_dir: PathBuf,
    /// Écoute SSH : PORTUNIA_GATE_SSH_LISTEN (par défaut 0.0.0.0:2222).
    pub ssh_listen: String,
    /// Écoute de l'API HTTPS pour Portunia : PORTUNIA_GATE_API_LISTEN (par défaut 0.0.0.0:8443).
    pub api_listen: String,
    /// Port SSH vu des utilisateurs (redirection Docker) : PORTUNIA_GATE_SSH_PUBLIC_PORT.
    pub ssh_public_port: u16,
    /// Portail web en HTTP, pour Cloudflare Tunnel : PORTUNIA_GATE_PORTAL_LISTEN (par défaut
    /// 127.0.0.1:8445, jamais à publier directement sur Internet).
    pub portal_listen: String,
    /// Portail web en HTTPS derrière le proxy Cloudflare (adresses de Cloudflare seulement) :
    /// PORTUNIA_GATE_PORTAL_TLS_LISTEN, ex. 0.0.0.0:8446 ; absent = pas d'écoute HTTPS.
    pub portal_tls_listen: Option<String>,
    /// État du tunnel Cloudflare (cloudflared) : PORTUNIA_GATE_TUNNEL_METRICS (par défaut 127.0.0.1:20241).
    pub tunnel_metrics: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("PORTUNIA_GATE_DATABASE_URL")
            .map_err(|_| anyhow::anyhow!(crate::t!("PORTUNIA_GATE_DATABASE_URL missing (e.g. postgres://portunia_gate:…@postgres/portunia_gate)", "PORTUNIA_GATE_DATABASE_URL manquant (ex. postgres://portunia_gate:…@postgres/portunia_gate)")))?;
        // Paquet Debian : PORTUNIA_GATE_SSH_PORT et PORTUNIA_GATE_API_PORT de /etc/portunia-gate/portunia-gate.env.
        // Docker : le conteneur écoute 2222 et 8443, Compose publie les ports choisis.
        let port = |name: &str| std::env::var(name).ok().and_then(|p| p.trim().parse::<u16>().ok());
        let text = |name: &str| std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let ssh_port = port("PORTUNIA_GATE_SSH_PORT").unwrap_or(2222);
        let api_port = port("PORTUNIA_GATE_API_PORT").unwrap_or(8443);
        Ok(Self {
            database_url,
            data_dir: std::env::var_os("PORTUNIA_GATE_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/var/lib/portunia-gate".into()),
            ssh_listen: std::env::var("PORTUNIA_GATE_SSH_LISTEN").unwrap_or_else(|_| format!("0.0.0.0:{ssh_port}")),
            api_listen: std::env::var("PORTUNIA_GATE_API_LISTEN").unwrap_or_else(|_| format!("0.0.0.0:{api_port}")),
            ssh_public_port: port("PORTUNIA_GATE_SSH_PUBLIC_PORT").unwrap_or(ssh_port),
            portal_listen: text("PORTUNIA_GATE_PORTAL_LISTEN").unwrap_or_else(|| "127.0.0.1:8445".into()),
            portal_tls_listen: text("PORTUNIA_GATE_PORTAL_TLS_LISTEN"),
            tunnel_metrics: text("PORTUNIA_GATE_TUNNEL_METRICS").unwrap_or_else(|| "127.0.0.1:20241".into()),
        })
    }

    /// Port local du serveur SSH, auquel le portail se connecte pour l'utilisateur.
    pub fn ssh_local_port(&self) -> u16 {
        self.ssh_listen.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(2222)
    }

    pub fn recordings_dir(&self) -> PathBuf {
        self.data_dir.join("enregistrements")
    }
}
