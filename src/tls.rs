use std::fs;
use std::io;
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

use crate::error::{AnyTlsError, Result};

pub fn client_config_insecure() -> Arc<ClientConfig> {
    let verifier = Arc::new(NoCertificateVerification);
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    )
}

pub fn server_name(name: &str) -> Result<ServerName<'static>> {
    let name = if name.trim().is_empty() {
        "127.0.0.1".to_owned()
    } else {
        name.to_owned()
    };
    ServerName::try_from(name.clone()).map_err(|_| AnyTlsError::InvalidDnsName(name))
}

pub fn self_signed_server_config() -> Result<Arc<ServerConfig>> {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|err| AnyTlsError::protocol(err.to_string()))?;
    let cert_der = certified.cert.der().clone();
    let key_der = certified.key_pair.serialize_der();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));

    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)?,
    ))
}

pub fn server_config_from_paths(certificate_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    let cert_pem = fs::read(certificate_path)?;
    let key_pem = fs::read(key_path)?;

    let certificates = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| AnyTlsError::protocol(format!("failed to parse certificate PEM: {err}")))?;
    if certificates.is_empty() {
        return Err(AnyTlsError::protocol("no certificates found in certificate_path"));
    }

    let key = private_key_from_pem(&key_pem)?;

    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)?,
    ))
}

fn private_key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = io::BufReader::new(pem);
    loop {
        let item = rustls_pemfile::read_one(&mut reader)
            .map_err(|err| AnyTlsError::protocol(format!("failed to parse private key PEM: {err}")))?;
        match item {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            Some(_) => continue,
            None => {
                return Err(AnyTlsError::protocol(
                    "no supported private key found in key_path; expected PKCS#8, PKCS#1, or SEC1 PEM",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::private_key_from_pem;

    #[test]
    fn tls_loader_accepts_pkcs8_private_key_pem() {
        let pem = std::fs::read(
            "/home/huaihuai/work/anytls-go/vendor/rustls-reality/test-ca/rsa/end.rsa",
        )
        .unwrap();
        assert!(private_key_from_pem(&pem).is_ok());
    }

    #[test]
    fn tls_loader_rejects_missing_private_key() {
        let err = private_key_from_pem(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            .unwrap_err();
        assert!(err.to_string().contains("no supported private key found"));
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
