use std::fs;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::reality::RealityConfig;
use crate::tcp_brutal::TcpBrutalConfig;
use crate::AnyTlsError;

pub const DEFAULT_SERVER_LISTEN: &str = "0.0.0.0:8443";
pub const DEFAULT_SERVER_SECURITY: &str = "tls";
pub const DEFAULT_TCP_BRUTAL_CWND_GAIN: u32 = 15;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFileConfig {
    #[serde(default = "default_server_listen")]
    pub listen: String,
    pub password: String,
    #[serde(default)]
    pub padding_scheme: Option<String>,
    #[serde(default = "default_server_security")]
    pub security: String,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub reality: Option<RealityConfig>,
    #[serde(default)]
    pub tcp_brutal: ServerTcpBrutalConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsConfig {
    pub server_name: String,
    pub certificate_path: String,
    pub key_path: String,
}

impl ServerFileConfig {
    pub fn load(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        serde_yaml::from_str(&raw)
            .map_err(|err| AnyTlsError::protocol(format!("invalid yaml config {path}: {err}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTcpBrutalConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up_mbps: Option<u64>,
    #[serde(default)]
    pub down_mbps: Option<u64>,
    #[serde(default = "default_tcp_brutal_cwnd_gain")]
    pub cwnd_gain: u32,
}

impl Default for ServerTcpBrutalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            up_mbps: None,
            down_mbps: None,
            cwnd_gain: DEFAULT_TCP_BRUTAL_CWND_GAIN,
        }
    }
}

impl ServerTcpBrutalConfig {
    pub fn enabled(up_mbps: u64, down_mbps: u64, cwnd_gain: u32) -> Self {
        Self {
            enabled: true,
            up_mbps: Some(up_mbps),
            down_mbps: Some(down_mbps),
            cwnd_gain,
        }
    }

    pub fn to_server_tcp_brutal(&self) -> Result<Option<TcpBrutalConfig>> {
        if !self.enabled {
            return Ok(None);
        }

        let down_mbps = self.down_mbps.ok_or_else(|| {
            AnyTlsError::protocol(
                "tcp_brutal.enabled requires tcp_brutal.down_mbps in server yaml config",
            )
        })?;

        Ok(Some(TcpBrutalConfig::new(
            mbps_to_bytes_per_second(down_mbps)?,
            self.cwnd_gain,
        )?))
    }
}

pub fn mbps_to_bytes_per_second(mbps: u64) -> Result<u64> {
    if mbps == 0 {
        return Err(AnyTlsError::protocol(
            "tcp brutal mbps must be greater than 0",
        ));
    }
    mbps.checked_mul(125_000).ok_or_else(|| {
        AnyTlsError::protocol("tcp brutal rate overflowed while converting Mbps to bytes/s")
    })
}

fn default_server_listen() -> String {
    DEFAULT_SERVER_LISTEN.to_string()
}

fn default_server_security() -> String {
    DEFAULT_SERVER_SECURITY.to_string()
}

fn default_tcp_brutal_cwnd_gain() -> u32 {
    DEFAULT_TCP_BRUTAL_CWND_GAIN
}

#[cfg(test)]
mod tests {
    use super::{ServerFileConfig, ServerTcpBrutalConfig, mbps_to_bytes_per_second};

    #[test]
    fn server_yaml_parses_reality_and_brutal_sections() {
        let config: ServerFileConfig = serde_yaml::from_str(
            r#"
listen: 0.0.0.0:28088
password: secret
security: reality
reality:
  dest: pypi.org:443
  server_names:
    - pypi.org
  private_key: QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=
tcp_brutal:
  enabled: true
  up_mbps: 500
  down_mbps: 50
"#,
        )
        .unwrap();

        assert_eq!(config.listen, "0.0.0.0:28088");
        assert_eq!(config.security, "reality");
        assert_eq!(config.reality.unwrap().server_names, vec!["pypi.org"]);
        assert_eq!(config.tcp_brutal.down_mbps, Some(50));
    }

    #[test]
    fn server_yaml_parses_tls_section() {
        let config: ServerFileConfig = serde_yaml::from_str(
            r#"
listen: 0.0.0.0:10443
password: secret
security: tls
tls:
  server_name: green.hhdaisy.com
  certificate_path: /etc/ssl/certimate/cert.crt
  key_path: /etc/ssl/certimate/cert.key
"#,
        )
        .unwrap();

        let tls = config.tls.unwrap();
        assert_eq!(tls.server_name, "green.hhdaisy.com");
        assert_eq!(tls.certificate_path, "/etc/ssl/certimate/cert.crt");
        assert_eq!(tls.key_path, "/etc/ssl/certimate/cert.key");
    }

    #[test]
    fn tcp_brutal_server_rate_uses_down_mbps() {
        let config = ServerTcpBrutalConfig::enabled(500, 50, 15);
        let brutal = config.to_server_tcp_brutal().unwrap().unwrap();
        assert_eq!(brutal.rate, 6_250_000);
        assert_eq!(brutal.cwnd_gain, 15);
    }

    #[test]
    fn mbps_conversion_matches_decimal_network_units() {
        assert_eq!(mbps_to_bytes_per_second(1).unwrap(), 125_000);
    }
}
