//! Surveillance interne : si le bastion ne répond plus, il le dit dans son journal et
//! s'arrête, pour être redémarré par systemd (Restart=on-failure) ou Docker
//! (restart: unless-stopped), au lieu de rester bloqué jusqu'à une intervention.
//!
//! - Toutes les 20 s : la base répond (SELECT 1) et le serveur SSH accepte une connexion
//!   et envoie sa bannière. Trois échecs de suite : arrêt, avec ce qui a échoué.
//! - Un fil système indépendant vérifie que le planificateur des tâches avance : s'il est
//!   figé plus de 90 s (tâche qui bloque tous les fils), arrêt aussi.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::io::AsyncReadExt;

use crate::State;

const PERIOD: Duration = Duration::from_secs(20);
const FAILURES_BEFORE_EXIT: u32 = 3;
const FROZEN_AFTER: u64 = 90;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Un contrôle : la base, puis le serveur SSH. Renvoie ce qui a échoué.
async fn check(state: &State) -> Result<(), String> {
    match tokio::time::timeout(Duration::from_secs(10), sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.db)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(t!(format!("database: {e}"), format!("base de données : {e}"))),
        Err(_) => return Err(t!("database: no answer within 10 s", "base de données : pas de réponse en 10 s").into()),
    }
    let ssh = async {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", state.config.ssh_local_port())).await?;
        let mut banner = [0u8; 4];
        tcp.read_exact(&mut banner).await?;
        Ok::<_, std::io::Error>(&banner == b"SSH-")
    };
    match tokio::time::timeout(Duration::from_secs(10), ssh).await {
        Ok(Ok(true)) => Ok(()),
        Ok(Ok(false)) => Err(t!("SSH server: unexpected answer", "serveur SSH : réponse inattendue").into()),
        Ok(Err(e)) => Err(t!(format!("SSH server: {e}"), format!("serveur SSH : {e}"))),
        Err(_) => Err(t!("SSH server: no banner within 10 s", "serveur SSH : pas de bannière en 10 s").into()),
    }
}

pub async fn run(state: Arc<State>) -> anyhow::Result<()> {
    let beat = Arc::new(AtomicU64::new(now_secs()));
    let watched = beat.clone();
    std::thread::Builder::new().name("surveillance".into()).spawn(move || loop {
        std::thread::sleep(Duration::from_secs(15));
        let quiet = now_secs().saturating_sub(watched.load(Ordering::Relaxed));
        if quiet > FROZEN_AFTER {
            eprintln!("{}", t!(format!("Heimdia frozen for {quiet} s (tasks blocked): stopping for automatic restart."), format!("Heimdia figé depuis {quiet} s (tâches bloquées) : arrêt pour redémarrage automatique.")));
            std::process::exit(70);
        }
    })?;

    // Laisse le service démarrer avant le premier contrôle.
    tokio::time::sleep(PERIOD).await;
    let mut failures = 0;
    let mut since = Instant::now();
    loop {
        beat.store(now_secs(), Ordering::Relaxed);
        match check(&state).await {
            Ok(()) => {
                if failures > 0 {
                    tracing::info!("{}", t!("watchdog: the bastion is answering again", "surveillance : le bastion répond de nouveau"));
                }
                failures = 0;
            }
            Err(why) => {
                if failures == 0 {
                    since = Instant::now();
                }
                failures += 1;
                let (size, idle, web) = (state.db.size(), state.db.num_idle(), state.web.active());
                tracing::warn!(
                    "{}",
                    t!(
                        format!("watchdog: {why} (attempt {failures}/{FAILURES_BEFORE_EXIT}, database: {size} connection(s) of which {idle} idle, web terminals: {web})"),
                        format!("surveillance : {why} (essai {failures}/{FAILURES_BEFORE_EXIT}, base : {size} connexion(s) dont {idle} libre(s), terminaux web : {web})")
                    )
                );
                if failures >= FAILURES_BEFORE_EXIT {
                    let secs = since.elapsed().as_secs();
                    tracing::error!(
                        "{}",
                        t!(
                            format!("watchdog: the bastion has not answered for {secs} s ({why}); stopping for automatic restart"),
                            format!("surveillance : le bastion ne répond plus depuis {secs} s ({why}) ; arrêt pour redémarrage automatique")
                        )
                    );
                    std::process::exit(70);
                }
            }
        }
        beat.store(now_secs(), Ordering::Relaxed);
        tokio::time::sleep(PERIOD).await;
    }
}
