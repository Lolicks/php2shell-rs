use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("unexpected end of input at offset {offset} (needed {needed} more bytes)")]
    UnexpectedEof { offset: usize, needed: usize },
    #[error("integer overflow while computing an offset or size")]
    Overflow,
    #[error("invalid {what}: {detail}")]
    Invalid { what: &'static str, detail: String },
    #[error("requested offset {offset} is outside the buffer of {len} bytes")]
    OutOfBounds { offset: usize, len: usize },
}

pub type Result<T> = std::result::Result<T, ParseError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    endian: Endian,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], endian: Endian) -> Self {
        Self {
            data,
            pos: 0,
            endian,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn seek(&mut self, offset: usize) -> Result<()> {
        if offset > self.data.len() {
            return Err(ParseError::OutOfBounds {
                offset,
                len: self.data.len(),
            });
        }
        self.pos = offset;
        Ok(())
    }

    pub fn skip(&mut self, count: usize) -> Result<()> {
        let next = self.pos.checked_add(count).ok_or(ParseError::Overflow)?;
        if next > self.data.len() {
            return Err(ParseError::UnexpectedEof {
                offset: self.pos,
                needed: count,
            });
        }
        self.pos = next;
        Ok(())
    }

    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(count).ok_or(ParseError::Overflow)?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(ParseError::UnexpectedEof {
                offset: self.pos,
                needed: count,
            })?;
        self.pos = end;
        Ok(slice)
    }

    pub fn slice_at(&self, offset: usize, count: usize) -> Result<&'a [u8]> {
        let end = offset.checked_add(count).ok_or(ParseError::Overflow)?;
        self.data.get(offset..end).ok_or(ParseError::UnexpectedEof {
            offset,
            needed: count,
        })
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self
            .bytes(2)?
            .try_into()
            .map_err(|_| ParseError::Overflow)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    pub fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .map_err(|_| ParseError::Overflow)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    pub fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self
            .bytes(8)?
            .try_into()
            .map_err(|_| ParseError::Overflow)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }

    pub fn u16_at(&self, offset: usize) -> Result<u16> {
        let bytes: [u8; 2] = self
            .slice_at(offset, 2)?
            .try_into()
            .map_err(|_| ParseError::Overflow)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    pub fn u32_at(&self, offset: usize) -> Result<u32> {
        let bytes: [u8; 4] = self
            .slice_at(offset, 4)?
            .try_into()
            .map_err(|_| ParseError::Overflow)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    pub fn u64_at(&self, offset: usize) -> Result<u64> {
        let bytes: [u8; 8] = self
            .slice_at(offset, 8)?
            .try_into()
            .map_err(|_| ParseError::Overflow)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }

    /// Reads a NUL-terminated string starting at `offset`, with an explicit
    /// upper bound so malformed tables cannot cause unbounded scans.
    pub fn cstring_at(&self, offset: usize, max_len: usize) -> Result<&'a [u8]> {
        if offset > self.data.len() {
            return Err(ParseError::OutOfBounds {
                offset,
                len: self.data.len(),
            });
        }
        let limit = offset.saturating_add(max_len).min(self.data.len());
        let window = &self.data[offset..limit];
        let end = window
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| ParseError::Invalid {
                what: "cstring",
                detail: "missing NUL terminator".into(),
            })?;
        Ok(&window[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_and_big_endian() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = Reader::new(&data, Endian::Little);
        assert_eq!(reader.u16().unwrap(), 0x0201);
        assert_eq!(reader.u32().unwrap(), 0x06050403);
        assert_eq!(reader.remaining(), 2);

        let mut reader = Reader::new(&data, Endian::Big);
        assert_eq!(reader.u32().unwrap(), 0x01020304);
        assert_eq!(reader.u64_at(0).unwrap(), 0x0102030405060708);
    }

    #[test]
    fn rejects_truncated_and_overflowing_reads() {
        let mut reader = Reader::new(&[1, 2, 3], Endian::Little);
        assert!(matches!(
            reader.u64(),
            Err(ParseError::UnexpectedEof { .. })
        ));
        assert!(matches!(
            reader.skip(usize::MAX),
            Err(ParseError::UnexpectedEof { .. })
        ));
        reader.skip(3).unwrap();
        assert!(matches!(reader.skip(usize::MAX), Err(ParseError::Overflow)));
        assert!(matches!(
            reader.seek(4),
            Err(ParseError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn cstring_is_bounded() {
        let reader = Reader::new(b"abcdef\x00tail", Endian::Little);
        assert_eq!(reader.cstring_at(0, 16).unwrap(), b"abcdef");
        assert!(reader.cstring_at(0, 3).is_err());
    }
}
