use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{AnyTlsError, Result};

pub const HEADER_SIZE: usize = 1 + 4 + 2;
pub const MAX_FRAME_DATA_LEN: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Waste = 0,
    Syn = 1,
    Psh = 2,
    Fin = 3,
    Settings = 4,
    Alert = 5,
    UpdatePaddingScheme = 6,
    SynAck = 7,
    HeartRequest = 8,
    HeartResponse = 9,
    ServerSettings = 10,
}

impl Command {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Waste),
            1 => Some(Self::Syn),
            2 => Some(Self::Psh),
            3 => Some(Self::Fin),
            4 => Some(Self::Settings),
            5 => Some(Self::Alert),
            6 => Some(Self::UpdatePaddingScheme),
            7 => Some(Self::SynAck),
            8 => Some(Self::HeartRequest),
            9 => Some(Self::HeartResponse),
            10 => Some(Self::ServerSettings),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub command: Command,
    pub stream_id: u32,
    pub data: Bytes,
}

impl Frame {
    pub fn new(command: Command, stream_id: u32, data: impl Into<Bytes>) -> Result<Self> {
        let data = data.into();
        if data.len() > MAX_FRAME_DATA_LEN {
            return Err(AnyTlsError::protocol(format!(
                "frame data too large: {} bytes",
                data.len()
            )));
        }
        Ok(Self {
            command,
            stream_id,
            data,
        })
    }

    pub fn empty(command: Command, stream_id: u32) -> Self {
        Self {
            command,
            stream_id,
            data: Bytes::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.data.len());
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.reserve(HEADER_SIZE + self.data.len());
        self.encode_header_into(out);
        out.extend_from_slice(&self.data);
    }

    pub fn encode_header(&self) -> [u8; HEADER_SIZE] {
        let mut header = [0_u8; HEADER_SIZE];
        header[0] = self.command as u8;
        header[1..5].copy_from_slice(&self.stream_id.to_be_bytes());
        header[5..7].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        header
    }

    pub fn encode_header_into(&self, out: &mut Vec<u8>) {
        out.push(self.command as u8);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
    }

    pub fn decode(buffer: &mut BytesMut) -> Result<Option<Self>> {
        if buffer.len() < HEADER_SIZE {
            return Ok(None);
        }
        let command = Command::from_u8(buffer[0])
            .ok_or_else(|| AnyTlsError::protocol(format!("unknown command: {}", buffer[0])))?;
        let stream_id = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]);
        let data_len = u16::from_be_bytes([buffer[5], buffer[6]]) as usize;
        let total_len = HEADER_SIZE + data_len;
        if buffer.len() < total_len {
            return Ok(None);
        }
        buffer.advance(HEADER_SIZE);
        let data = if data_len > 0 {
            buffer.split_to(data_len).freeze()
        } else {
            Bytes::new()
        };
        Ok(Some(Self {
            command,
            stream_id,
            data,
        }))
    }

    pub async fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut header = [0_u8; HEADER_SIZE];
        reader.read_exact(&mut header).await?;
        let command = Command::from_u8(header[0])
            .ok_or_else(|| AnyTlsError::protocol(format!("unknown command: {}", header[0])))?;
        let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let data_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = vec![0_u8; data_len];
        if data_len > 0 {
            reader.read_exact(&mut data).await?;
        }
        Ok(Self {
            command,
            stream_id,
            data: Bytes::from(data),
        })
    }
}

pub fn waste_frame(padding_len: usize) -> Result<Vec<u8>> {
    Frame::new(Command::Waste, 0, vec![0_u8; padding_len]).map(|frame| frame.encode())
}

pub fn waste_frame_into(out: &mut Vec<u8>, padding_len: usize) -> Result<()> {
    if padding_len > MAX_FRAME_DATA_LEN {
        return Err(AnyTlsError::protocol(format!(
            "frame data too large: {padding_len} bytes"
        )));
    }
    out.push(Command::Waste as u8);
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.resize(out.len() + padding_len, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::{Command, Frame, HEADER_SIZE};
    use bytes::BytesMut;

    #[test]
    fn frame_encodes_big_endian_header() {
        let frame = Frame::new(Command::Psh, 0x0102_0304, b"abc".to_vec()).unwrap();

        assert_eq!(frame.encode(), vec![2, 1, 2, 3, 4, 0, 3, b'a', b'b', b'c']);
    }

    #[tokio::test]
    async fn frame_reads_big_endian_header() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[7, 0, 0, 0, 9, 0, 2, b'o', b'k'])
            .await
            .unwrap();
        drop(writer);

        let frame = Frame::read_from(&mut reader).await.unwrap();

        assert_eq!(frame.command, Command::SynAck);
        assert_eq!(frame.stream_id, 9);
        assert_eq!(&frame.data[..], b"ok");
    }

    #[test]
    fn frame_decodes_from_bytesmut_without_copying_payload() {
        let mut buffer = BytesMut::from(&[2, 0, 0, 0, 7, 0, 3, b'f', b'o', b'o'][..]);

        let frame = Frame::decode(&mut buffer).unwrap().unwrap();

        assert_eq!(frame.command, Command::Psh);
        assert_eq!(frame.stream_id, 7);
        assert_eq!(&frame.data[..], b"foo");
        assert!(buffer.is_empty());
    }

    #[test]
    fn header_size_matches_protocol() {
        assert_eq!(HEADER_SIZE, 7);
    }
}
