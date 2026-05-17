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
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(command: Command, stream_id: u32, data: impl Into<Vec<u8>>) -> Result<Self> {
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
            data: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.data.len());
        out.push(self.command as u8);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
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
            data,
        })
    }
}

pub fn waste_frame(padding_len: usize) -> Result<Vec<u8>> {
    Frame::new(Command::Waste, 0, vec![0_u8; padding_len]).map(|frame| frame.encode())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::{Command, Frame, HEADER_SIZE};

    #[test]
    fn frame_encodes_big_endian_header() {
        let frame = Frame::new(Command::Psh, 0x0102_0304, b"abc".to_vec()).unwrap();

        assert_eq!(
            frame.encode(),
            vec![2, 1, 2, 3, 4, 0, 3, b'a', b'b', b'c']
        );
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
        assert_eq!(frame.data, b"ok");
    }

    #[test]
    fn header_size_matches_protocol() {
        assert_eq!(HEADER_SIZE, 7);
    }
}
