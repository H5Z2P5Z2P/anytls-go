use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use anyhow::{Result, anyhow, bail};
use bytes::Buf;
use hkdf::Hkdf;
use lru::LruCache;
use once_cell::sync::Lazy;
use ring::hmac;
use rustls::ServerConfig;
use rustls::reality::RealityConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::hello_parser::{self, ClientHelloInfo};

#[derive(Hash, PartialEq, Eq, Clone)]
struct CertKey {
    host: String,
}

static CERT_CACHE: Lazy<Mutex<LruCache<CertKey, (Vec<u8>, Vec<u8>, Vec<u8>)>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(
        std::num::NonZeroUsize::new(100).expect("nonzero"),
    ))
});

pub struct RealityServerRustls {
    reality_config: Arc<RealityConfig>,
    server_names: Vec<String>,
}

impl Clone for RealityServerRustls {
    fn clone(&self) -> Self {
        Self {
            reality_config: Arc::clone(&self.reality_config),
            server_names: self.server_names.clone(),
        }
    }
}

impl RealityServerRustls {
    pub fn new(
        private_key: Vec<u8>,
        dest: Option<String>,
        short_ids: Vec<String>,
        server_names: Vec<String>,
    ) -> Result<Self> {
        let mut short_ids_bytes = Vec::new();
        for short_id in short_ids {
            short_ids_bytes
                .push(hex::decode(&short_id).map_err(|err| anyhow!("invalid shortId hex: {err}"))?);
        }

        let reality_config = RealityConfig::new(private_key)
            .with_verify_client(true)
            .with_short_ids(short_ids_bytes)
            .with_dest(dest.unwrap_or_else(|| "www.microsoft.com:443".to_string()));
        reality_config
            .validate()
            .map_err(|err| anyhow!("Reality config validation failed: {err:?}"))?;

        Ok(Self {
            reality_config: Arc::new(reality_config),
            server_names,
        })
    }

    pub async fn accept<S>(
        &self,
        mut stream: S,
    ) -> Result<tokio_rustls::server::TlsStream<PrefixedStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut buffer = Vec::with_capacity(2048);
        let handshake_timeout = std::time::Duration::from_secs(5);

        let read_task = async {
            while buffer.len() < 5 {
                let mut chunk = [0_u8; 1024];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    bail!("connection closed early");
                }
                buffer.extend_from_slice(&chunk[..n]);
            }

            let needed = if buffer[0] == 0x16 {
                5 + u16::from_be_bytes([buffer[3], buffer[4]]) as usize
            } else {
                buffer.len()
            };
            while buffer.len() < needed && buffer.len() < 16384 {
                let mut chunk = [0_u8; 1024];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..n]);
            }
            Ok::<(), anyhow::Error>(())
        };

        match tokio::time::timeout(handshake_timeout, read_task).await {
            Ok(result) => result?,
            Err(_) => bail!("handshake timeout: client sent incomplete or no data"),
        }

        if let Ok(Some(info)) = hello_parser::parse_client_hello(&buffer) {
            let sni_valid = if self.server_names.is_empty() {
                true
            } else if let Some(sni) = &info.server_name {
                self.server_names.iter().any(|name| name == sni)
            } else {
                false
            };

            if !sni_valid {
                warn!(server_name = ?info.server_name, allowed = ?self.server_names, "Reality SNI mismatch");
            } else if let Some((_offset, auth_key)) = self.verify_client_reality(&info, &buffer) {
                let dest_str = self
                    .reality_config
                    .dest
                    .as_deref()
                    .unwrap_or("www.microsoft.com:443");
                let dest_host = dest_str.split(':').next().unwrap_or("www.microsoft.com");
                info!("Reality verified client, generating dynamic certificate");

                let (cert, key) = self.generate_reality_cert(&auth_key, dest_host)?;
                let mut conn_reality_config = (*self.reality_config).clone();
                conn_reality_config.private_key = auth_key.to_vec();
                conn_reality_config.verify_client = false;

                let mut config = ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .map_err(|err| anyhow!("config build failed: {err}"))?;
                config.reality_config = Some(Arc::new(conn_reality_config));

                let acceptor = TlsAcceptor::from(Arc::new(config));
                let prefixed = PrefixedStream::new(buffer, stream);

                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    acceptor.accept(prefixed),
                )
                .await
                {
                    Ok(Ok(tls)) => {
                        info!("Reality handshake successful");
                        return Ok(tls);
                    }
                    Ok(Err(err)) => {
                        error!(error = %err, "Reality TLS handshake failed");
                        bail!("handshake failure");
                    }
                    Err(_) => {
                        error!("Reality TLS handshake timeout");
                        bail!("handshake timeout");
                    }
                }
            }
        }

        let dest = self
            .reality_config
            .dest
            .as_deref()
            .unwrap_or("www.microsoft.com:443");
        debug!(dest, "Non-Reality client or SNI mismatch, falling back");
        self.fallback(stream, &buffer, dest).await?;
        bail!("fallback completed")
    }

    fn verify_client_reality(
        &self,
        info: &ClientHelloInfo,
        full_hello: &[u8],
    ) -> Option<(usize, [u8; 32])> {
        if info.session_id.len() != 32 || info.public_key.is_none() {
            return None;
        }

        let mut server_priv = [0_u8; 32];
        server_priv.copy_from_slice(&self.reality_config.private_key);
        let client_pub: [u8; 32] = info.public_key.as_ref()?.as_slice().try_into().ok()?;
        let shared =
            StaticSecret::from(server_priv).diffie_hellman(&X25519PublicKey::from(client_pub));

        let hk = Hkdf::<Sha256>::new(Some(&info.client_random[0..20]), shared.as_bytes());
        let mut auth_key = [0_u8; 32];
        if hk.expand(b"REALITY", &mut auth_key).is_err() {
            return None;
        }

        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&auth_key));
        let nonce = Nonce::from_slice(&info.client_random[20..32]);
        let handshake_msg = if full_hello[0] == 0x16 {
            &full_hello[5..]
        } else {
            full_hello
        };
        let mut aad = handshake_msg.to_vec();
        if let Some(pos) = hex::encode(&aad)
            .find(&hex::encode(&info.session_id))
            .map(|pos| pos / 2)
        {
            for idx in 0..32 {
                if pos + idx < aad.len() {
                    aad[pos + idx] = 0;
                }
            }
        }

        let mut buf = info.session_id.clone();
        if cipher.decrypt_in_place(nonce, &aad, &mut buf).is_err() || buf.len() < 16 {
            return None;
        }

        if short_id_matches(&buf, &self.reality_config.short_ids) {
            return Some((0, auth_key));
        }
        None
    }

    fn generate_reality_cert(
        &self,
        auth_key: &[u8; 32],
        host: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let cache_key = CertKey {
            host: host.to_string(),
        };
        let template = {
            let mut cache = CERT_CACHE.lock().expect("cert cache mutex poisoned");
            if let Some(cached) = cache.get(&cache_key) {
                cached.clone()
            } else {
                use rcgen12::{Certificate, CertificateParams, KeyPair, PKCS_ED25519};

                let key_pair = KeyPair::generate(&PKCS_ED25519)
                    .map_err(|err| anyhow!("key generation failed: {err}"))?;
                let public_key_raw = key_pair.public_key_raw().to_vec();
                let mut params = CertificateParams::new(vec![host.to_string()]);
                params.alg = &PKCS_ED25519;
                params.key_pair = Some(key_pair);
                let cert = Certificate::from_params(params)
                    .map_err(|err| anyhow!("certificate generation failed: {err}"))?;
                let cert_der = cert
                    .serialize_der()
                    .map_err(|err| anyhow!("certificate serialization failed: {err}"))?;
                let private_key_der = cert.serialize_private_key_der();

                let tuple: (Vec<u8>, Vec<u8>, Vec<u8>) =
                    (cert_der, private_key_der, public_key_raw);
                cache.put(cache_key.clone(), tuple.clone());
                tuple
            }
        };

        let (mut cert_der, private_key_der, public_key_raw) = template;
        if cert_der.len() < 64 {
            bail!("certificate DER too short");
        }

        let signature_offset = cert_der.len() - 64;
        let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
        let signature = hmac::sign(&key, &public_key_raw);
        cert_der[signature_offset..].copy_from_slice(signature.as_ref());

        Ok((
            CertificateDer::from(cert_der),
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der)),
        ))
    }

    async fn fallback<S>(&self, mut stream: S, prefix: &[u8], dest: &str) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut dest_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(dest),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => bail!("fallback connection timeout"),
        };
        dest_stream.write_all(prefix).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await?;
        Ok(())
    }
}

fn short_id_matches(buf: &[u8], short_ids: &[Vec<u8>]) -> bool {
    if short_ids.is_empty() || short_ids.iter().any(|short_id| short_id.is_empty()) {
        return true;
    }

    short_ids
        .iter()
        .any(|short_id| short_id == &buf[4..12] || short_id == &buf[8..16])
}

pub struct PrefixedStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix.has_remaining() {
            let n = std::cmp::min(buf.remaining(), self.prefix.remaining());
            let pos = self.prefix.position() as usize;
            buf.put_slice(&self.prefix.get_ref()[pos..pos + n]);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::short_id_matches;

    #[test]
    fn empty_short_id_matches_empty_sid_clients() {
        assert!(short_id_matches(&[0_u8; 16], &[Vec::new()]));
        assert!(short_id_matches(&[0_u8; 16], &[]));
    }

    #[test]
    fn configured_short_id_matches_supported_offsets() {
        let mut buf = [0_u8; 16];
        buf[8..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(short_id_matches(&buf, &[vec![1, 2, 3, 4, 5, 6, 7, 8]]));
    }
}
