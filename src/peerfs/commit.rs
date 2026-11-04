//! The bounded, canonical PeerFS commit3 signing boundary. No object-store IO.
use super::{forbidden, invalid, too_large};
use crate::{model::Error, peer_store::valid_id};
use base64::{Engine, engine::general_purpose::STANDARD};

const CONTEXT: &[u8] = b"peerfs 2026-10-27 commit signature\0";
const MAX_MESSAGE: usize = 65_536;

/// Decode the exact complete signing message; return only canonical bytes.
pub(super) fn message(encoded: &str, host: &str) -> Result<Vec<u8>, Error> {
    let bytes = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if bytes.len() > MAX_MESSAGE {
        return Err(too_large());
    }
    if STANDARD.encode(&bytes) != encoded {
        return Err(invalid());
    }
    let unsigned = bytes.strip_prefix(CONTEXT).ok_or_else(invalid)?;
    let mut input = Decoder {
        bytes: unsigned,
        offset: 0,
        canonical: Vec::with_capacity(unsigned.len()),
    };
    if input.byte()? != 3 {
        return Err(invalid());
    }
    input.object()?;
    let count = input.integer()?;
    if count > 64 || count > (input.remaining() / 33) as u64 {
        return Err(invalid());
    }
    for _ in 0..count {
        input.object()?;
    }
    if input.data(16)?.len() != 16 {
        return Err(invalid());
    }
    let author = input.string(69)?;
    if !valid_id(author, "host", 32) {
        return Err(invalid());
    }
    let local_author = author == host;
    input.optional_string()?;
    input.optional_string()?;
    input.integer()?; // Milliseconds, not a trusted clock or freshness assertion.
    input.string(16_384)?;
    match input.byte()? {
        0 => {}
        1 => input.object()?,
        _ => return Err(invalid()),
    }
    if input.byte()? != 0 || input.remaining() != 0 || input.canonical.as_slice() != unsigned {
        return Err(invalid());
    }
    // Check the entire encoding before considering any key use.
    if !local_author {
        return Err(forbidden());
    }
    Ok(bytes)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    canonical: Vec<u8>,
}
impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(count).ok_or_else(invalid)?;
        let part = self.bytes.get(self.offset..end).ok_or_else(invalid)?;
        self.offset = end;
        self.canonical.extend_from_slice(part);
        Ok(part)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn integer(&mut self) -> Result<u64, Error> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.bytes.get(self.offset).ok_or_else(invalid)?;
            self.offset += 1;
            let low = u64::from(byte & 127);
            if shift == 63 && low > 1 {
                return Err(invalid());
            }
            value |= low << shift;
            if byte & 128 == 0 {
                if shift != 0 && low == 0 {
                    return Err(invalid());
                }
                let mut remaining = value;
                loop {
                    let low = (remaining & 127) as u8;
                    remaining >>= 7;
                    self.canonical
                        .push(if remaining == 0 { low } else { low | 128 });
                    if remaining == 0 {
                        break;
                    }
                }
                return Ok(value);
            }
        }
        Err(invalid())
    }
    fn data(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let size = self.integer()?;
        if size > limit as u64 || size > self.remaining() as u64 {
            return Err(invalid());
        }
        self.take(size as usize)
    }
    fn string(&mut self, limit: usize) -> Result<&'a str, Error> {
        std::str::from_utf8(self.data(limit)?).map_err(|_| invalid())
    }
    fn optional_string(&mut self) -> Result<(), Error> {
        match self.byte()? {
            0 => Ok(()),
            1 => self.string(256).map(|_| ()),
            _ => Err(invalid()),
        }
    }
    fn object(&mut self) -> Result<(), Error> {
        if self.byte()? != 1 {
            return Err(invalid());
        }
        self.take(32).map(|_| ())
    }
}
