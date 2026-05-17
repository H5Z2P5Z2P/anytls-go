use std::collections::BTreeMap;

use md5::{Digest, Md5};
use rand::Rng;

use crate::settings::StringMap;

pub const CHECK_MARK: i32 = -1;

pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\
\n0=30-30\
\n1=100-400\
\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\
\n3=9-9,500-1000\
\n4=500-1000\
\n5=500-1000\
\n6=500-1000\
\n7=500-1000";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddingFactory {
    raw_scheme: Vec<u8>,
    scheme: BTreeMap<String, String>,
    stop: u32,
    md5: String,
}

impl PaddingFactory {
    pub fn default_scheme() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME).expect("default padding scheme is valid")
    }

    pub fn new(raw_scheme: &[u8]) -> Option<Self> {
        let parsed = StringMap::from_bytes(raw_scheme);
        let stop = parsed.get("stop")?.parse::<u32>().ok()?;
        let mut scheme = BTreeMap::new();
        for line in String::from_utf8_lossy(raw_scheme).split('\n') {
            if let Some((key, value)) = line.split_once('=') {
                scheme.insert(key.to_owned(), value.to_owned());
            }
        }
        Some(Self {
            raw_scheme: raw_scheme.to_vec(),
            scheme,
            stop,
            md5: hex_md5(raw_scheme),
        })
    }

    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    pub fn stop(&self) -> u32 {
        self.stop
    }

    pub fn md5(&self) -> &str {
        &self.md5
    }

    pub fn generate_record_payload_sizes(&self, packet: u32) -> Vec<i32> {
        let Some(spec) = self.scheme.get(&packet.to_string()) else {
            return Vec::new();
        };

        let mut sizes = Vec::new();
        for item in spec.split(',') {
            if item == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }
            let Some((min, max)) = item.split_once('-') else {
                continue;
            };
            let Ok(mut min) = min.parse::<i64>() else {
                continue;
            };
            let Ok(mut max) = max.parse::<i64>() else {
                continue;
            };
            if min > max {
                std::mem::swap(&mut min, &mut max);
            }
            if min <= 0 || max <= 0 {
                continue;
            }
            if min == max {
                sizes.push(min as i32);
            } else {
                // Keep compatibility with the Go implementation: upper bound is exclusive.
                sizes.push(rand::thread_rng().gen_range(min..max) as i32);
            }
        }
        sizes
    }
}

fn hex_md5(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{CHECK_MARK, PaddingFactory};

    #[test]
    fn padding_factory_rejects_missing_stop() {
        assert!(PaddingFactory::new(b"0=30-30").is_none());
    }

    #[test]
    fn padding_factory_parses_fixed_sizes_and_check_marks() {
        let padding = PaddingFactory::new(b"stop=3\n0=30-30\n1=9-9,c,10-10").unwrap();

        assert_eq!(padding.stop(), 3);
        assert_eq!(padding.generate_record_payload_sizes(0), vec![30]);
        assert_eq!(
            padding.generate_record_payload_sizes(1),
            vec![9, CHECK_MARK, 10]
        );
    }

    #[test]
    fn default_padding_scheme_matches_protocol_stop() {
        let padding = PaddingFactory::default_scheme();

        assert_eq!(padding.stop(), 8);
        assert_eq!(padding.generate_record_payload_sizes(0), vec![30]);
    }
}
