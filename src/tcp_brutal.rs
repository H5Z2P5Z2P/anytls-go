use tokio::net::TcpStream;

use crate::AnyTlsError;
use crate::error::Result;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBrutalConfig {
    pub rate: u64,
    pub cwnd_gain: u32,
}

impl TcpBrutalConfig {
    pub fn new(rate: u64, cwnd_gain: u32) -> Result<Self> {
        if rate == 0 {
            return Err(AnyTlsError::protocol(
                "tcp brutal rate must be greater than 0",
            ));
        }
        if cwnd_gain == 0 {
            return Err(AnyTlsError::protocol(
                "tcp brutal cwnd gain must be greater than 0",
            ));
        }
        Ok(Self { rate, cwnd_gain })
    }
}

pub fn apply_to_stream(stream: &TcpStream, config: TcpBrutalConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::apply_to_stream(stream, config)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, config);
        Err(AnyTlsError::protocol(
            "tcp brutal is only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::AsRawFd;

    use tokio::net::TcpStream;

    use crate::AnyTlsError;
    use crate::error::Result;
    use crate::tcp_brutal::TcpBrutalConfig;

    const TCP_BRUTAL_PARAMS: libc::c_int = 23301;

    pub(super) fn apply_to_stream(stream: &TcpStream, config: TcpBrutalConfig) -> Result<()> {
        let fd = stream.as_raw_fd();
        set_sockopt(fd, libc::IPPROTO_TCP, libc::TCP_CONGESTION, b"brutal").map_err(|err| {
            AnyTlsError::protocol(format!(
                "failed to enable tcp brutal congestion control: {err}"
            ))
        })?;

        let params = brutal_params_bytes(config);
        set_sockopt(fd, libc::IPPROTO_TCP, TCP_BRUTAL_PARAMS, &params).map_err(|err| {
            AnyTlsError::protocol(format!("failed to set tcp brutal parameters: {err}"))
        })?;

        Ok(())
    }

    fn brutal_params_bytes(config: TcpBrutalConfig) -> [u8; 12] {
        let mut bytes = [0_u8; 12];
        bytes[..8].copy_from_slice(&config.rate.to_ne_bytes());
        bytes[8..].copy_from_slice(&config.cwnd_gain.to_ne_bytes());
        bytes
    }

    fn set_sockopt(
        fd: libc::c_int,
        level: libc::c_int,
        optname: libc::c_int,
        value: &[u8],
    ) -> io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                level,
                optname,
                value.as_ptr().cast(),
                value.len() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::brutal_params_bytes;
        use crate::tcp_brutal::TcpBrutalConfig;

        #[test]
        fn brutal_params_match_expected_layout() {
            let config = TcpBrutalConfig {
                rate: 0x0102_0304_0506_0708,
                cwnd_gain: 0x1112_1314,
            };
            let bytes = brutal_params_bytes(config);
            assert_eq!(&bytes[..8], &config.rate.to_ne_bytes());
            assert_eq!(&bytes[8..], &config.cwnd_gain.to_ne_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tcp_brutal::TcpBrutalConfig;

    #[test]
    fn config_rejects_zero_rate() {
        assert!(TcpBrutalConfig::new(0, 15).is_err());
    }

    #[test]
    fn config_rejects_zero_cwnd_gain() {
        assert!(TcpBrutalConfig::new(1, 0).is_err());
    }
}
