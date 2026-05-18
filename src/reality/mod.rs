mod hello_parser;
mod server_rustls;

use anyhow::{Result, anyhow};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub use server_rustls::PrefixedStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub short_ids: Vec<String>,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct RealityServer {
    inner: server_rustls::RealityServerRustls,
}

impl RealityServer {
    pub fn new(config: RealityConfig) -> Result<Self> {
        if config.dest.is_empty() {
            return Err(anyhow!("Reality dest cannot be empty"));
        }
        if config.private_key.is_empty() {
            return Err(anyhow!("Reality privateKey cannot be empty"));
        }

        let private_key = decode_private_key(&config.private_key)?;

        info!(dest = %config.dest, "initialized Reality server transport");
        debug!(fingerprint = %config.fingerprint, server_names = ?config.server_names, "Reality transport settings");

        let inner = server_rustls::RealityServerRustls::new(
            private_key.to_vec(),
            Some(config.dest.clone()),
            config.short_ids.clone(),
            config.server_names.clone(),
        )?;

        Ok(Self { inner })
    }

    pub async fn accept<S>(
        &self,
        stream: S,
    ) -> Result<tokio_rustls::server::TlsStream<server_rustls::PrefixedStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.inner.accept(stream).await
    }
}

pub fn generate_keypair() -> (String, String) {
    let mut private_key_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut private_key_bytes);
    let private_key = StaticSecret::from(private_key_bytes);
    let public_key = X25519PublicKey::from(&private_key);
    (
        URL_SAFE_NO_PAD.encode(private_key.to_bytes()),
        URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
    )
}

pub fn public_key_from_private_key(private_key: &str) -> Result<String> {
    let private_key_bytes = decode_private_key(private_key)?;
    let public_key = X25519PublicKey::from(&StaticSecret::from(private_key_bytes));
    Ok(URL_SAFE_NO_PAD.encode(public_key.as_bytes()))
}

fn decode_private_key(private_key: &str) -> Result<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(private_key)
        .or_else(|_| STANDARD.decode(private_key))
        .map_err(|err| anyhow!("failed to decode Reality private key: {err}"))?;
    if decoded.len() != 32 {
        return Err(anyhow!(
            "Reality privateKey must be 32 bytes, got {}",
            decoded.len()
        ));
    }
    let mut private_key_bytes = [0_u8; 32];
    private_key_bytes.copy_from_slice(&decoded);
    Ok(private_key_bytes)
}

fn default_fingerprint() -> String {
    "chrome".to_string()
}

#[cfg(test)]
mod tests {
    use super::{RealityConfig, RealityServer, generate_keypair, public_key_from_private_key};

    #[test]
    fn reality_server_accepts_valid_config() {
        let config = RealityConfig {
            dest: "www.apple.com:443".to_string(),
            server_names: vec!["www.apple.com".to_string()],
            private_key: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=".to_string(),
            public_key: None,
            short_ids: vec!["0123456789abcdef".to_string()],
            fingerprint: "chrome".to_string(),
        };

        assert!(RealityServer::new(config).is_ok());
    }

    #[test]
    fn generated_keypair_round_trips_public_key_derivation() {
        let (private_key, public_key) = generate_keypair();
        assert_eq!(
            public_key_from_private_key(&private_key).unwrap(),
            public_key
        );
    }
}
