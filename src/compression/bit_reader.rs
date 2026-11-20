use std::io::{self, Read};

/// Bytes read from the source per refill.
const BUF_SIZE: usize = 0x1_0000;
/// Zeroed bytes behind the valid data, so peeking never reads stale bytes.
const PADDING: usize = 16;

/// MSB-first bit reader over any `Read` source.
///
/// Bits past the end of the input read as zero. The block headers tell the
/// decoder where the data ends; reading clearly beyond it is an error.
pub(super) struct BitReader<R: Read> {
    reader: R,
    buf: Vec<u8>,
    /// Valid bytes in `buf`.
    len: usize,
    /// Current byte in `buf`.
    pos: usize,
    /// Current bit in that byte (0..8).
    bit: u32,
    /// Stream offset of `buf[0]`.
    base: u64,
    eof: bool,
}

impl<R: Read> BitReader<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader,
            buf: vec![0; BUF_SIZE + PADDING],
            len: 0,
            pos: 0,
            bit: 0,
            base: 0,
            eof: false,
        }
    }

    /// Make sure at least 8 bytes can be peeked.
    fn ensure(&mut self) -> io::Result<()> {
        if self.len >= self.pos + 8 {
            return Ok(());
        }
        if self.eof {
            if self.pos > self.len + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "compressed data is truncated",
                ));
            }
            return Ok(());
        }

        // Move the unread bytes to the front and refill.
        self.buf.copy_within(self.pos..self.len, 0);
        self.base += self.pos as u64;
        self.len -= self.pos;
        self.pos = 0;
        while self.len < BUF_SIZE && !self.eof {
            match self.reader.read(&mut self.buf[self.len..BUF_SIZE]) {
                Ok(0) => self.eof = true,
                Ok(n) => self.len += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.buf[self.len..self.len + PADDING].fill(0);
        Ok(())
    }

    /// The next 32 bits without consuming them.
    #[inline]
    pub(super) fn peek32(&mut self) -> io::Result<u32> {
        self.ensure()?;
        let b = &self.buf[self.pos..self.pos + 5];
        let v = u64::from(b[0]) << 32
            | u64::from(b[1]) << 24
            | u64::from(b[2]) << 16
            | u64::from(b[3]) << 8
            | u64::from(b[4]);
        // Drop the bits already consumed in b[0]; the cast keeps the next 32.
        Ok((v >> (8 - self.bit)) as u32)
    }

    /// The next 16 bits without consuming them.
    #[inline]
    pub(super) fn peek16(&mut self) -> io::Result<u32> {
        Ok(self.peek32()? >> 16)
    }

    /// Consume `n` (at most 32) bits.
    #[inline]
    pub(super) fn skip(&mut self, n: u32) {
        let total = self.bit + n;
        self.pos += (total / 8) as usize;
        self.bit = total % 8;
    }

    /// Read `n` (1..=16) bits.
    pub(super) fn read_bits(&mut self, n: u32) -> io::Result<u32> {
        debug_assert!((1..=16).contains(&n));
        let v = self.peek16()? >> (16 - n);
        self.skip(n);
        Ok(v)
    }

    /// Skip to the next byte boundary.
    pub(super) fn align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }

    /// Absolute position in bits.
    pub(super) fn position(&self) -> u64 {
        (self.base + self.pos as u64) * 8 + u64::from(self.bit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bits_msb_first() {
        let mut bits = BitReader::new(&[0b1010_1100u8, 0b0101_0011][..]);
        assert_eq!(bits.read_bits(3).unwrap(), 0b101);
        assert_eq!(bits.read_bits(7).unwrap(), 0b011_0001);
        assert_eq!(bits.position(), 10);
        bits.align();
        assert_eq!(bits.position(), 16);
    }

    #[test]
    fn test_refill_across_buffer_boundary() {
        let data: Vec<u8> = (0..BUF_SIZE * 2 + 3).map(|i| i as u8).collect();
        let mut bits = BitReader::new(&data[..]);
        for &expected in &data {
            assert_eq!(bits.read_bits(8).unwrap(), u32::from(expected));
        }
    }

    #[test]
    fn test_reads_zeros_then_fails_past_eof() {
        let mut bits = BitReader::new(&[0xffu8][..]);
        assert_eq!(bits.read_bits(8).unwrap(), 0xff);
        assert_eq!(bits.read_bits(16).unwrap(), 0);
        bits.skip(32);
        assert!(bits.peek32().is_err());
    }
}
