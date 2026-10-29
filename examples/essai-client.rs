//! Client d'essai : se connecte au bastion (mot de passe puis code TOTP), envoie des lignes
//! dans le terminal et affiche ce qui revient. Sert aux essais de bout en bout.
//!
//!   HEIMDIA_HOTE=192.168.91.51:2222 HEIMDIA_NOM=essai%srv-coffre HEIMDIA_MDP=… \
//!   HEIMDIA_TOTP=<clé base32> cargo run --example essai-client -- "hostname" "exit"

use std::{sync::Arc, time::Duration};

use russh::{
    client::{self, KeyboardInteractiveAuthResponse},
    keys::PublicKeyOrCertificate,
    ChannelMsg,
};

struct Accept;
impl client::Handler for Accept {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, _key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn base32_decode(text: &str) -> Vec<u8> {
    let (mut out, mut buffer, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.chars().filter(|c| c.is_ascii_alphanumeric()) {
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c.to_ascii_uppercase()).unwrap() as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    out
}

fn totp(secret: &[u8]) -> String {
    let step = chrono::Utc::now().timestamp() / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let h = ring::hmac::sign(&key, &step.to_be_bytes());
    let h = h.as_ref();
    let o = (h[h.len() - 1] & 0x0f) as usize;
    let v = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]) % 1_000_000;
    format!("{v:06}")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let (host, name, password, secret) = (env("HEIMDIA_HOTE"), env("HEIMDIA_NOM"), env("HEIMDIA_MDP"), env("HEIMDIA_TOTP"));
    let lines: Vec<String> = std::env::args().skip(1).collect();
    let mut handle = client::connect(Arc::new(client::Config::default()), host.as_str(), Accept).await?;

    let mut result = handle.authenticate_password(&name, &password).await?;
    println!("[mot de passe] {result:?}");
    if !result.success() && !secret.is_empty() {
        let mut reply = handle.authenticate_keyboard_interactive_start(&name, None).await?;
        loop {
            match reply {
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let answers: Vec<String> = prompts
                        .iter()
                        .map(|p| {
                            println!("[question] {}", p.prompt);
                            if p.prompt.contains("Code") {
                                totp(&base32_decode(&secret))
                            } else {
                                password.clone()
                            }
                        })
                        .collect();
                    reply = handle.authenticate_keyboard_interactive_respond(answers).await?;
                }
                KeyboardInteractiveAuthResponse::Success => {
                    println!("[code] accepté");
                    result = russh::client::AuthResult::Success;
                    break;
                }
                other => {
                    println!("[code] refusé : {other:?}");
                    break;
                }
            }
        }
    }
    if !result.success() {
        anyhow::bail!("authentification refusée");
    }

    // Rebond (comme « ssh -J ») : on lit la bannière SSH de la cible, à travers le bastion.
    if let Ok(address) = std::env::var("HEIMDIA_REBOND") {
        let (h, p) = address.rsplit_once(':').unwrap();
        let mut stream = handle.channel_open_direct_tcpip(h, p.parse()?, "127.0.0.1", 0).await?.into_stream();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), tokio::io::AsyncReadExt::read(&mut stream, &mut buf)).await??;
        println!("[rebond] bannière de la cible : {}", String::from_utf8_lossy(&buf[..n]).trim());
        return Ok(());
    }

    let mut channel = handle.channel_open_session().await?;
    channel.request_pty(true, "xterm-256color", 100, 30, 0, 0, &[]).await?;
    channel.request_shell(true).await?;
    let mut output = Vec::new();
    let mut pending = lines.into_iter();
    loop {
        match tokio::time::timeout(Duration::from_millis(2500), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => output.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => println!("[code de sortie] {exit_status}"),
            Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
            Ok(Some(_)) => {}
            // Silence : on envoie la ligne suivante, ou on s'arrête.
            Err(_) => match pending.next() {
                Some(line) => channel.data_bytes(format!("{line}\r").into_bytes()).await?,
                None => break,
            },
        }
    }
    println!(
        "----- écran -----\n{}\n-----------------",
        String::from_utf8_lossy(&output).replace('\r', "")
    );
    Ok(())
}
