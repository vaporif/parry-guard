//! Wire protocol for daemon IPC.
//!
//! Wire format:
//! - Request: `[1B scan_type][4B threshold_le][4B text_len_le][text...]`
//! - Response: `[1B response_code]`

use std::io::{self, Read, Write};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum text payload: 16 MB.
const MAX_TEXT_LEN: u32 = 16 * 1024 * 1024;

/// Header size: 1 byte type + 4 bytes threshold + 4 bytes text length.
const HEADER_LEN: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    /// Full scan including ML.
    Full = 0x00,
    /// Ping to check if daemon is alive.
    Ping = 0x02,
}

impl ScanType {
    fn from_byte(b: u8) -> io::Result<Self> {
        match b {
            0x00 => Ok(Self::Full),
            0x02 => Ok(Self::Ping),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown scan type",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanRequest {
    pub scan_type: ScanType,
    pub threshold: f32,
    pub text: String,
}

impl ScanRequest {
    /// Encode to wire format into any `BufMut`.
    fn encode(&self, buf: &mut impl BufMut) -> io::Result<()> {
        buf.put_u8(self.scan_type as u8);
        buf.put_f32_le(self.threshold);
        let text = self.text.as_bytes();
        let len = u32::try_from(text.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "text too large"))?;
        buf.put_u32_le(len);
        buf.put_slice(text);
        Ok(())
    }

    /// Decode from a `BytesMut` buffer. Returns `Ok(None)` if not enough data yet.
    fn decode(src: &mut BytesMut) -> io::Result<Option<Self>> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        let scan_type = ScanType::from_byte(src[0])?;
        let threshold = f32::from_le_bytes([src[1], src[2], src[3], src[4]]);
        let text_len = u32::from_le_bytes([src[5], src[6], src[7], src[8]]);

        if text_len > MAX_TEXT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "text exceeds 16MB limit",
            ));
        }

        let text_len_usize = text_len as usize;
        let total = HEADER_LEN + text_len_usize;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }

        src.advance(HEADER_LEN);
        let text_bytes = src.split_to(text_len_usize);
        let text = String::from_utf8(text_bytes.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(Self {
            scan_type,
            threshold,
            text,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanResponse {
    Clean = 0x00,
    Injection = 0x01,
    Secret = 0x02,
    Pong = 0x03,
    /// Daemon could not complete the scan.
    Error = 0x04,
}

impl ScanResponse {
    fn from_byte(b: u8) -> io::Result<Self> {
        match b {
            0x00 => Ok(Self::Clean),
            0x01 => Ok(Self::Injection),
            0x02 => Ok(Self::Secret),
            0x03 => Ok(Self::Pong),
            0x04 => Ok(Self::Error),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown response",
            )),
        }
    }
}

// ─── Tokio codec (async server) ─────────────────────────────────────────────

/// Codec for the daemon wire protocol. Delegates to `ScanRequest`/`ScanResponse` methods.
pub struct DaemonCodec;

impl Decoder for DaemonCodec {
    type Item = ScanRequest;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<ScanRequest>> {
        ScanRequest::decode(src)
    }
}

impl Encoder<ScanResponse> for DaemonCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ScanResponse, dst: &mut BytesMut) -> io::Result<()> {
        dst.put_u8(item as u8);
        Ok(())
    }
}

// ─── Sync helpers (client) ──────────────────────────────────────────────────

/// Write a scan request to a sync writer.
///
/// # Errors
///
/// Returns an error if writing to the stream fails or text exceeds size limit.
pub fn write_request<W: Write>(w: &mut W, req: &ScanRequest) -> io::Result<()> {
    let mut buf = Vec::with_capacity(HEADER_LEN + req.text.len());
    req.encode(&mut buf)?;
    w.write_all(&buf)?;
    w.flush()
}

/// Read a scan response from a sync reader.
///
/// # Errors
///
/// Returns an error if reading fails or the response byte is unknown.
pub fn read_response<R: Read>(r: &mut R) -> io::Result<ScanResponse> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    ScanResponse::from_byte(buf[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_request(req: &ScanRequest) -> BytesMut {
        let mut buf = BytesMut::new();
        req.encode(&mut buf).unwrap();
        buf
    }

    // ─── Codec tests ─────────────────────────────────────────────────────────

    #[test]
    fn codec_decode_full_request() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.75,
            text: "hello world".to_string(),
        };
        let mut buf = encode_request(&req);
        let decoded = DaemonCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, req);
        assert!(buf.is_empty());
    }

    #[test]
    fn codec_decode_partial_header() {
        let mut buf = BytesMut::from(&[0x00, 0x01][..]);
        assert!(DaemonCodec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 2); // not consumed
    }

    #[test]
    fn codec_decode_partial_body() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.5,
            text: "hello".to_string(),
        };
        let full = encode_request(&req);
        // Only provide header + partial text
        let mut buf = BytesMut::from(&full[..HEADER_LEN + 2]);
        assert!(DaemonCodec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn codec_encode_response() {
        let mut buf = BytesMut::new();
        DaemonCodec
            .encode(ScanResponse::Injection, &mut buf)
            .unwrap();
        assert_eq!(buf.as_ref(), &[0x01]);
    }

    #[test]
    fn codec_roundtrip_all_responses() {
        for resp in [
            ScanResponse::Clean,
            ScanResponse::Injection,
            ScanResponse::Secret,
            ScanResponse::Pong,
            ScanResponse::Error,
        ] {
            let mut buf = BytesMut::new();
            DaemonCodec.encode(resp, &mut buf).unwrap();
            assert_eq!(buf.len(), 1);
            assert_eq!(ScanResponse::from_byte(buf[0]).unwrap(), resp);
        }
    }

    #[test]
    fn codec_rejects_oversized_text() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00);
        buf.put_f32_le(0.5);
        buf.put_u32_le(MAX_TEXT_LEN + 1);
        assert!(DaemonCodec.decode(&mut buf).is_err());
    }

    #[test]
    fn codec_rejects_unknown_scan_type() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xFF);
        buf.put_f32_le(0.5);
        buf.put_u32_le(0);
        assert!(DaemonCodec.decode(&mut buf).is_err());
    }

    // ─── Sync client helpers tests ───────────────────────────────────────────

    #[test]
    fn sync_roundtrip_request_response() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.75,
            text: "hello".to_string(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req).unwrap();

        // Verify response round-trip
        let resp_buf = [ScanResponse::Injection as u8];
        let resp = read_response(&mut &resp_buf[..]).unwrap();
        assert_eq!(resp, ScanResponse::Injection);
    }

    #[test]
    fn sync_rejects_unknown_response() {
        let buf = [0xFF];
        assert!(read_response(&mut &buf[..]).is_err());
    }

    #[test]
    fn codec_decode_utf8_text() {
        let req = ScanRequest {
            scan_type: ScanType::Full,
            threshold: 0.5,
            text: "hello \u{1F600} \u{00E9}".to_string(),
        };
        let mut buf = encode_request(&req);
        let decoded = DaemonCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn codec_decode_ping() {
        let req = ScanRequest {
            scan_type: ScanType::Ping,
            threshold: 0.0,
            text: String::new(),
        };
        let mut buf = encode_request(&req);
        let decoded = DaemonCodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, req);
    }
}
