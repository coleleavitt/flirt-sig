use crate::Error;

/// Cursor over the bytes of a signature file.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let bytes = self
            .data
            .get(self.pos..)
            .and_then(|rest| rest.get(..n))
            .ok_or(Error::Truncated { offset: self.pos })?;
        self.pos += n;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn le16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_le_bytes)
    }

    pub(crate) fn le32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_le_bytes)
    }

    pub(crate) fn be16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn be32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_be_bytes)
    }

    /// A 15-bit number in 1 or 2 bytes: bit 7 of the first byte selects the long form.
    pub(crate) fn var15(&mut self) -> Result<u16, Error> {
        let first = self.u8()?;
        if first & 0x80 == 0 {
            return Ok(first.into());
        }
        Ok(u16::from(first & 0x7f) << 8 | u16::from(self.u8()?))
    }

    /// A 32-bit number in 1, 2, 4 or 5 bytes, selected by the top bits of the first byte.
    pub(crate) fn var32(&mut self) -> Result<u32, Error> {
        let first = self.u8()?;
        if first & 0x80 == 0 {
            Ok(first.into())
        } else if first & 0xc0 != 0xc0 {
            Ok(u32::from(first & 0x7f) << 8 | u32::from(self.u8()?))
        } else if first & 0xe0 != 0xe0 {
            let mid = u32::from(self.u8()?);
            let low = u32::from(self.be16()?);
            Ok(u32::from(first & 0x3f) << 24 | mid << 16 | low)
        } else {
            self.be32()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;

    #[test]
    fn variable_length_numbers() {
        let mut r = Reader::new(&[0x7f, 0x81, 0x02, 0xc1, 0x02, 0x03, 0x04, 0xe0, 1, 2, 3, 4]);
        assert_eq!(r.var15().unwrap(), 0x7f);
        assert_eq!(r.var15().unwrap(), 0x0102);
        assert_eq!(r.var32().unwrap(), 0x0102_0304);
        assert_eq!(r.var32().unwrap(), 0x0102_0304);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn truncated_read_reports_offset() {
        let mut r = Reader::new(&[0x80]);
        assert!(matches!(
            r.var15(),
            Err(crate::Error::Truncated { offset: 1 })
        ));
    }
}
