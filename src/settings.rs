use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StringMap(BTreeMap<String, String>);

impl StringMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut map = Self::new();
        for line in String::from_utf8_lossy(bytes).split('\n') {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key, value);
            }
        }
        map
    }
}

impl FromIterator<(String, String)> for StringMap {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::StringMap;

    #[test]
    fn string_map_round_trips_key_value_lines() {
        let parsed = StringMap::from_bytes(b"v=2\nclient=anytls/0.0.12\nignored\npadding-md5=abc");

        assert_eq!(parsed.get("v"), Some("2"));
        assert_eq!(parsed.get("client"), Some("anytls/0.0.12"));
        assert_eq!(parsed.get("padding-md5"), Some("abc"));
        assert_eq!(parsed.get("ignored"), None);
    }

    #[test]
    fn string_map_serializes_deterministically() {
        let mut map = StringMap::new();
        map.insert("v", "2");
        map.insert("client", "anytls-rust/0.1.0");

        assert_eq!(map.to_bytes(), b"client=anytls-rust/0.1.0\nv=2");
    }
}
