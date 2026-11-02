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
    /// Mode Cloudflare : réseaux d'où cloudflared peut venir s'il n'est pas sur la machine
    /// (conteneur) : PORTUNIA_GATE_PORTAL_TUNNEL_PEERS, séparés par des virgules.
    pub portal_tunnel_peers: Vec<String>,
    /// État du tunnel Cloudflare (cloudflared) : PORTUNIA_GATE_TUNNEL_METRICS (par défaut 127.0.0.1:20241).
    pub tunnel_metrics: String,
    /// Tunnel géré : cloudflared déjà présent (machine sans accès à GitHub) au lieu de celui que
    /// la Gate télécharge : PORTUNIA_GATE_CLOUDFLARED.
    pub cloudflared: Option<PathBuf>,
    /// Espace libre minimal pour ouvrir une session enregistrée : PORTUNIA_GATE_MIN_FREE_MB
    /// (par défaut 512). Sous la moitié, les sessions enregistrées en cours se ferment.
    pub min_free_mb: u64,
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
            portal_tunnel_peers: crate::portal::parse_networks(&[text("PORTUNIA_GATE_PORTAL_TUNNEL_PEERS").unwrap_or_default()])
                .map_err(|bad| anyhow::anyhow!("PORTUNIA_GATE_PORTAL_TUNNEL_PEERS : {bad}"))?,
            tunnel_metrics: text("PORTUNIA_GATE_TUNNEL_METRICS").unwrap_or_else(|| "127.0.0.1:20241".into()),
            cloudflared: text("PORTUNIA_GATE_CLOUDFLARED").map(PathBuf::from),
            min_free_mb: text("PORTUNIA_GATE_MIN_FREE_MB").and_then(|v| v.parse().ok()).unwrap_or(512),
        })
    }

    /// Port local du serveur SSH, auquel le portail se connecte pour l'utilisateur.
    pub fn ssh_local_port(&self) -> u16 {
        self.ssh_listen.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(2222)
    }

    pub fn min_free_bytes(&self) -> u64 {
        self.min_free_mb.saturating_mul(1024 * 1024)
    }

    pub fn recordings_dir(&self) -> PathBuf {
        self.data_dir.join("enregistrements")
    }
}
