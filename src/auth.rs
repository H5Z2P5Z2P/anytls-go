use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AnyTlsError, Result};
use crate::padding::PaddingFactory;

pub const PASSWORD_HASH_LEN: usize = 32;

pub fn password_hash(password: &str) -> [u8; PASSWORD_HASH_LEN] {
    Sha256::digest(password.as_bytes()).into()
}

pub fn build_auth_request(password_hash: &[u8; PASSWORD_HASH_LEN], padding: &PaddingFactory) -> Vec<u8> {
    let padding_len = padding
        .generate_record_payload_sizes(0)
        .first()
        .copied()
        .unwrap_or_default()
        .max(0) as usize;
    let mut request = Vec::with_capacity(PASSWORD_HASH_LEN + 2 + padding_len);
    request.extend_from_slice(password_hash);
    request.extend_from_slice(&(padding_len as u16).to_be_bytes());
    request.resize(PASSWORD_HASH_LEN + 2 + padding_len, 0);
    request
}

pub async fn write_auth_request<W>(
    writer: &mut W,
    password_hash: &[u8; PASSWORD_HASH_LEN],
    padding: &PaddingFactory,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&build_auth_request(password_hash, padding)).await?;
    Ok(())
}

pub async fn read_and_verify_auth<R>(
    reader: &mut R,
    expected_hash: &[u8; PASSWORD_HASH_LEN],
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut actual_hash = [0_u8; PASSWORD_HASH_LEN];
    reader.read_exact(&mut actual_hash).await?;
    if &actual_hash != expected_hash {
        return Err(AnyTlsError::AuthenticationFailed);
    }

    let mut len = [0_u8; 2];
    reader.read_exact(&mut len).await?;
    let padding_len = u16::from_be_bytes(len) as usize;
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        reader.read_exact(&mut padding).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PASSWORD_HASH_LEN, build_auth_request, password_hash, read_and_verify_auth};
    use crate::error::AnyTlsError;
    use crate::padding::PaddingFactory;

    #[test]
    fn auth_request_is_hash_padding_length_and_padding() {
        let hash = password_hash("secret");
        let padding = PaddingFactory::new(b"stop=1\n0=3-3").unwrap();

        let request = build_auth_request(&hash, &padding);

        assert_eq!(request.len(), PASSWORD_HASH_LEN + 2 + 3);
        assert_eq!(&request[..PASSWORD_HASH_LEN], hash.as_slice());
        assert_eq!(&request[PASSWORD_HASH_LEN..PASSWORD_HASH_LEN + 2], &[0, 3]);
        assert_eq!(&request[PASSWORD_HASH_LEN + 2..], &[0, 0, 0]);
    }

    #[tokio::test]
    async fn auth_verification_rejects_wrong_password_hash() {
        let expected = password_hash("expected");
        let actual = password_hash("actual");
        let padding = PaddingFactory::new(b"stop=1\n0=0-0").unwrap();
        let request = build_auth_request(&actual, &padding);
        let mut reader = tokio::io::BufReader::new(request.as_slice());

        let err = read_and_verify_auth(&mut reader, &expected).await.unwrap_err();

        assert!(matches!(err, AnyTlsError::AuthenticationFailed));
    }
}
