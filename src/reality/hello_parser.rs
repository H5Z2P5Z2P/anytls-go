use anyhow::{Result, anyhow};
use bytes::Buf;

pub struct ClientHelloInfo {
    pub session_id: Vec<u8>,
    pub client_random: [u8; 32],
    pub public_key: Option<Vec<u8>>,
    pub server_name: Option<String>,
}

pub fn parse_client_hello(buf: &[u8]) -> Result<Option<ClientHelloInfo>> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return Ok(None);
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return Ok(None);
    }

    let mut cursor = &buf[5..];
    if cursor.remaining() < 4 {
        return Err(anyhow!("short handshake buffer"));
    }
    if cursor.get_u8() != 0x01 {
        return Ok(None);
    }
    cursor.advance(3);

    if cursor.remaining() < 2 + 32 {
        return Err(anyhow!("short client hello body"));
    }
    cursor.advance(2);

    let mut client_random = [0_u8; 32];
    cursor.copy_to_slice(&mut client_random);

    if cursor.remaining() < 1 {
        return Err(anyhow!("missing session id length"));
    }
    let session_id_len = cursor.get_u8() as usize;
    if cursor.remaining() < session_id_len {
        return Err(anyhow!("short session id"));
    }
    let mut session_id = vec![0_u8; session_id_len];
    cursor.copy_to_slice(&mut session_id);

    if cursor.remaining() < 2 {
        return Err(anyhow!("missing cipher suites length"));
    }
    let cipher_suites_len = cursor.get_u16() as usize;
    if cursor.remaining() < cipher_suites_len {
        return Err(anyhow!("short cipher suites"));
    }
    cursor.advance(cipher_suites_len);

    if cursor.remaining() < 1 {
        return Err(anyhow!("missing compression methods length"));
    }
    let compression_methods_len = cursor.get_u8() as usize;
    if cursor.remaining() < compression_methods_len {
        return Err(anyhow!("short compression methods"));
    }
    cursor.advance(compression_methods_len);

    if cursor.remaining() < 2 {
        return Ok(Some(ClientHelloInfo {
            session_id,
            client_random,
            public_key: None,
            server_name: None,
        }));
    }

    let extensions_len = cursor.get_u16() as usize;
    if cursor.remaining() < extensions_len {
        return Err(anyhow!("short extensions"));
    }
    let mut extensions = &cursor[..extensions_len];
    let mut public_key = None;
    let mut server_name = None;

    while extensions.has_remaining() {
        if extensions.remaining() < 4 {
            break;
        }
        let ext_type = extensions.get_u16();
        let ext_len = extensions.get_u16() as usize;
        if extensions.remaining() < ext_len {
            break;
        }
        let mut ext_data = &extensions[..ext_len];
        extensions.advance(ext_len);

        if ext_type == 0x0000 && ext_data.remaining() >= 2 {
            let list_len = ext_data.get_u16() as usize;
            if ext_data.remaining() >= list_len {
                let mut list = &ext_data[..list_len];
                while list.has_remaining() {
                    if list.remaining() < 3 {
                        break;
                    }
                    let name_type = list.get_u8();
                    let name_len = list.get_u16() as usize;
                    if list.remaining() < name_len {
                        break;
                    }
                    if name_type == 0x00 {
                        let mut name_bytes = vec![0_u8; name_len];
                        list.copy_to_slice(&mut name_bytes);
                        if let Ok(name) = String::from_utf8(name_bytes) {
                            server_name = Some(name);
                        }
                        break;
                    }
                    list.advance(name_len);
                }
            }
        }

        if ext_type == 0x0033 {
            if ext_data.remaining() < 2 {
                continue;
            }
            let shares_len = ext_data.get_u16() as usize;
            if ext_data.remaining() < shares_len {
                continue;
            }
            let mut shares = &ext_data[..shares_len];
            while shares.has_remaining() {
                if shares.remaining() < 4 {
                    break;
                }
                let group = shares.get_u16();
                let key_len = shares.get_u16() as usize;
                if shares.remaining() < key_len {
                    break;
                }
                if group == 0x001d && key_len == 32 {
                    let mut key = vec![0_u8; 32];
                    shares.copy_to_slice(&mut key);
                    public_key = Some(key);
                    break;
                }
                shares.advance(key_len);
            }
        }

        if public_key.is_some() && server_name.is_some() {
            break;
        }
    }

    Ok(Some(ClientHelloInfo {
        session_id,
        client_random,
        public_key,
        server_name,
    }))
}
