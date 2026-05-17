use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnyTlsError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("session is closed")]
    SessionClosed,
}

pub type Result<T> = std::result::Result<T, AnyTlsError>;

impl AnyTlsError {
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}
