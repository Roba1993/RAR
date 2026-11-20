use super::bit_reader::BitReader;
use std::io::{self, Read};

/// Codes up to this length are resolved with a single table lookup.
const QUICK_BITS: u32 = 10;
/// RAR code lengths are 1..=15 bits (0 means unused symbol).
const MAX_CODE_LENGTH: usize = 15;

/// Canonical Huffman decoder built from code lengths.
///
/// Layout follows unrar's `DecodeTable`: for each code length the upper code
/// limit (left aligned to 16 bits) and the index of its first symbol in the
/// symbol list sorted by code length.
#[derive(Clone)]
pub(super) struct HuffmanTable {
    /// Exclusive upper limit of the left aligned codes per length.
    limit: [u32; MAX_CODE_LENGTH + 1],
    /// Index into `symbols` of the first code of each length.
    first: [u32; MAX_CODE_LENGTH + 1],
    /// Symbols ordered by code length, then by value.
    symbols: Vec<u16>,
    quick_len: Vec<u8>,
    quick_symbol: Vec<u16>,
}

impl HuffmanTable {
    pub(super) fn new(lengths: &[u8]) -> Self {
        let mut count = [0u32; MAX_CODE_LENGTH + 1];
        for &l in lengths {
            count[usize::from(l & 0xf)] += 1;
        }
        count[0] = 0;

        let mut limit = [0u32; MAX_CODE_LENGTH + 1];
        let mut first = [0u32; MAX_CODE_LENGTH + 1];
        let mut upper = 0u32;
        for len in 1..=MAX_CODE_LENGTH {
            upper += count[len];
            limit[len] = upper << (16 - len);
            upper *= 2;
            first[len] = first[len - 1] + count[len - 1];
        }

        let mut next = first;
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &l) in lengths.iter().enumerate() {
            let l = usize::from(l & 0xf);
            if l != 0 {
                symbols[next[l] as usize] = symbol as u16;
                next[l] += 1;
            }
        }

        let mut table = Self {
            limit,
            first,
            symbols,
            quick_len: vec![0; 1 << QUICK_BITS],
            quick_symbol: vec![0; 1 << QUICK_BITS],
        };
        let mut len = 1;
        for code in 0..1u32 << QUICK_BITS {
            let field = code << (16 - QUICK_BITS);
            while len <= MAX_CODE_LENGTH && field >= table.limit[len] {
                len += 1;
            }
            table.quick_len[code as usize] = len as u8;
            if len <= MAX_CODE_LENGTH {
                table.quick_symbol[code as usize] = table.symbol(field, len);
            }
        }
        table
    }

    /// Symbol for the left aligned code `field` of length `len`. Incomplete
    /// code sets can produce invalid indexes; they fall back to the first
    /// symbol like unrar does.
    fn symbol(&self, field: u32, len: usize) -> u16 {
        let offset = field.wrapping_sub(self.limit[len - 1]) >> (16 - len);
        let index = self.first[len].wrapping_add(offset) as usize;
        self.symbols.get(index).copied().unwrap_or(self.symbols[0])
    }

    pub(super) fn decode<R: Read>(&self, bits: &mut BitReader<R>) -> io::Result<usize> {
        let field = bits.peek16()? & 0xfffe;
        if field < self.limit[QUICK_BITS as usize] {
            let code = (field >> (16 - QUICK_BITS)) as usize;
            bits.skip(u32::from(self.quick_len[code]));
            return Ok(usize::from(self.quick_symbol[code]));
        }
        let len = (QUICK_BITS as usize + 1..MAX_CODE_LENGTH)
            .find(|&len| field < self.limit[len])
            .unwrap_or(MAX_CODE_LENGTH);
        bits.skip(len as u32);
        Ok(usize::from(self.symbol(field, len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_codes() {
        // lengths A=1, B=2, C=3, D=3 give the codes 0, 10, 110, 111
        let table = HuffmanTable::new(&[1, 2, 3, 3]);
        // 0 10 110 111 0
        let mut bits = BitReader::new(&[0b0101_1011u8, 0b1000_0000][..]);
        let decoded: Vec<usize> = (0..5).map(|_| table.decode(&mut bits).unwrap()).collect();
        assert_eq!(decoded, [0, 1, 2, 3, 0]);
    }

    #[test]
    fn test_long_codes_bypass_quick_table() {
        // one 1-bit code and fourteen codes growing to 15 bits
        let mut lengths = vec![1u8];
        lengths.extend(2..=15);
        lengths.push(15);
        let table = HuffmanTable::new(&lengths);
        // all ones: the last 15 bit code
        let mut bits = BitReader::new(&[0xffu8, 0xfe][..]);
        assert_eq!(table.decode(&mut bits).unwrap(), 15);
        assert_eq!(bits.position(), 15);
    }

    #[test]
    fn test_empty_table_does_not_panic() {
        let table = HuffmanTable::new(&[0; 20]);
        let mut bits = BitReader::new(&[0xffu8; 4][..]);
        assert_eq!(table.decode(&mut bits).unwrap(), 0);
    }
}
