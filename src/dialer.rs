use std::cmp::Reverse;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use once_cell::sync::Lazy;
use tokio::net::TcpStream;
use tokio::task;
use tokio::time::timeout;

use crate::socks_addr::SocksAddr;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

static GAI_CONFIG: Lazy<GaiConfig> = Lazy::new(|| GaiConfig::from_path("/etc/gai.conf"));

pub async fn connect_tcp(destination: &SocksAddr) -> io::Result<TcpStream> {
    let addrs = resolve_destination(destination).await?;
    connect_addrs(destination, addrs).await
}

async fn resolve_destination(destination: &SocksAddr) -> io::Result<Vec<SocketAddr>> {
    match destination {
        SocksAddr::Ip(addr) => Ok(vec![*addr]),
        SocksAddr::Domain { host, port } => {
            let host = host.clone();
            let port = *port;
            let addrs = task::spawn_blocking(move || {
                (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|iter| iter.collect::<Vec<_>>())
            })
            .await
            .map_err(|err| io::Error::other(format!("resolver task failed: {err}")))??;
            if addrs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no addresses resolved for {destination}"),
                ));
            }
            let addrs = GAI_CONFIG.sort_socket_addrs(addrs);
            Ok(addrs)
        }
    }
}

async fn connect_addrs(destination: &SocksAddr, addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => {
                last_err = Some(err);
            }
            Err(_) => {
                let err = io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("outbound tcp connect to {addr} timed out"),
                );
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses resolved for {destination}"),
        )
    }))
}

#[derive(Clone, Debug, Default)]
struct GaiConfig {
    precedence: Vec<GaiPrecedence>,
}

impl GaiConfig {
    fn from_path(path: &str) -> Self {
        std::fs::read_to_string(path)
            .map(|content| Self::parse(&content))
            .unwrap_or_default()
    }

    fn parse(content: &str) -> Self {
        let mut precedence = Vec::new();
        for line in content.lines() {
            let line = line.split_once('#').map_or(line, |(line, _)| line).trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(keyword) = parts.next() else {
                continue;
            };
            if keyword != "precedence" {
                continue;
            }
            let (Some(prefix), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            let (Some(prefix), Ok(value)) = (IpPrefix::parse(prefix), value.parse::<i32>()) else {
                continue;
            };
            precedence.push(GaiPrecedence { prefix, value });
        }
        Self { precedence }
    }

    fn sort_socket_addrs(&self, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        if self.precedence.is_empty() {
            return addrs;
        }
        addrs.sort_by_key(|addr| Reverse(self.precedence_value(addr.ip())));
        addrs
    }

    fn precedence_value(&self, ip: IpAddr) -> i32 {
        let mut matched = None;
        for entry in &self.precedence {
            if entry.prefix.matches(ip)
                && matched
                    .as_ref()
                    .is_none_or(|best: &&GaiPrecedence| entry.prefix.len > best.prefix.len)
            {
                matched = Some(entry);
            }
        }
        matched.map_or(0, |entry| entry.value)
    }
}

#[derive(Clone, Debug)]
struct GaiPrecedence {
    prefix: IpPrefix,
    value: i32,
}

#[derive(Clone, Debug)]
struct IpPrefix {
    addr: Ipv6Addr,
    len: u8,
}

impl IpPrefix {
    fn parse(value: &str) -> Option<Self> {
        let (addr, len) = value.split_once('/').unwrap_or((value, "128"));
        let addr = addr.parse::<IpAddr>().ok()?;
        let len = len.parse::<u8>().ok()?;
        match addr {
            IpAddr::V4(addr) => {
                let len = 96_u8.checked_add(len)?;
                if len > 128 {
                    return None;
                }
                Some(Self {
                    addr: addr.to_ipv6_mapped(),
                    len,
                })
            }
            IpAddr::V6(addr) => {
                if len > 128 {
                    return None;
                }
                Some(Self { addr, len })
            }
        }
    }

    fn matches(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V4(addr) => addr.to_ipv6_mapped(),
            IpAddr::V6(addr) => addr,
        };
        if self.len == 0 {
            return true;
        }
        let shift = 128 - self.len;
        let mask = u128::MAX << shift;
        (ipv6_to_u128(self.addr) & mask) == (ipv6_to_u128(ip) & mask)
    }
}

fn ipv6_to_u128(addr: Ipv6Addr) -> u128 {
    u128::from_be_bytes(addr.octets())
}

#[cfg(test)]
mod tests {
    use super::GaiConfig;

    #[test]
    fn gai_precedence_prefers_ipv4_mapped_addresses_when_configured() {
        let config = GaiConfig::parse("precedence ::/0 40\nprecedence ::ffff:0:0/96 100\n");
        let addrs = vec![
            "[2606:4700:7::da]:443".parse().unwrap(),
            "162.159.140.220:443".parse().unwrap(),
        ];

        let addrs = config.sort_socket_addrs(addrs);

        assert!(addrs[0].is_ipv4());
    }

    #[test]
    fn gai_precedence_uses_longest_matching_prefix() {
        let config = GaiConfig::parse("precedence ::/0 100\nprecedence ::ffff:0:0/96 10\n");
        let addrs = vec![
            "162.159.140.220:443".parse().unwrap(),
            "[2606:4700:7::da]:443".parse().unwrap(),
        ];

        let addrs = config.sort_socket_addrs(addrs);

        assert!(addrs[0].is_ipv6());
    }

    #[test]
    fn empty_gai_config_preserves_resolver_order() {
        let config = GaiConfig::parse("# no active rules\n");
        let addrs = vec![
            "[2606:4700:7::da]:443".parse().unwrap(),
            "162.159.140.220:443".parse().unwrap(),
        ];

        let sorted = config.sort_socket_addrs(addrs.clone());

        assert_eq!(sorted, addrs);
    }
}
