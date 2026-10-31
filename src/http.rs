//! Limites communes aux serveurs HTTP (API et portail) : une requête lente ne garde pas
//! une connexion ouverte. Le temps d'une WebSocket n'est pas concerné : elle sort d'ici dès
//! son ouverture.

use std::time::Duration;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper_util::rt::TokioTimer;

/// Temps pour recevoir les en-têtes d'une requête.
const HEADERS: Duration = Duration::from_secs(10);
/// Temps pour lire le corps d'une requête et y répondre.
const REQUEST: Duration = Duration::from_secs(120);

pub fn limit<A>(server: &mut axum_server::Server<A>) {
    server.http_builder().http1().timer(TokioTimer::new()).header_read_timeout(HEADERS);
}

async fn within(limit: Duration, request: Request, next: Next) -> Response {
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

/// Couche axum : une requête ne dure pas plus de `REQUEST`.
pub async fn deadline(request: Request, next: Next) -> Response {
    within(REQUEST, request, next).await
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        time::{Duration, Instant},
    };

    use axum::{middleware::from_fn, routing::post, Router};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Serveur réglé comme l'API et le portail, avec une seconde pour une requête.
    fn server() -> SocketAddr {
        let app = Router::new()
            .route("/", post(|_: String| async { "ok" }))
            .layer(from_fn(|r, n| within(Duration::from_secs(1), r, n)));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mut server = axum_server::from_tcp(listener);
        limit(&mut server);
        tokio::spawn(server.serve(app.into_make_service()));
        address
    }

    /// Temps avant que le serveur réponde ou ferme.
    async fn seconds_to_end(address: SocketAddr, partial: &[u8]) -> f32 {
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(partial).await.unwrap();
        let start = Instant::now();
        let mut buf = [0u8; 1024];
        let end = async {
            loop {
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(20), end).await.expect("connexion restée ouverte");
        start.elapsed().as_secs_f32()
    }

    #[tokio::test]
    async fn en_tetes_trop_lents() {
        let t = seconds_to_end(server(), b"POST / HTTP/1.1\r\nHost: x\r\n").await;
        assert!((9.0..12.0).contains(&t), "{t} s");
    }

    #[tokio::test]
    async fn corps_trop_lent() {
        let t = seconds_to_end(server(), b"POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 100\r\n\r\n").await;
        assert!(t < 4.0, "{t} s");
    }
}
