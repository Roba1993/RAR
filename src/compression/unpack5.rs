//! The LZ + Huffman stage of the RAR 5.0 algorithm.
//!
//! The compressed data of a file is a sequence of blocks. Each block starts
//! byte aligned with a small header and may carry new Huffman tables. Its
//! symbols decode to literals, matches and filter definitions.

use super::bit_reader::BitReader;
use super::filter::{Filter, FilterKind};
use super::huffman::HuffmanTable;
use std::collections::VecDeque;
use std::io::{self, Read};

/// Symbols of the bit length table, which encodes the other tables.
const BIT_LENGTH_SYMBOLS: usize = 20;
/// Main table: 256 literals, filter, repeat, 4 old distances, 44 length slots.
const MAIN_SYMBOLS: usize = 306;
/// Distance slots of the RAR 5.0 format (dictionary up to 4 GB).
const DISTANCE_SYMBOLS: usize = 64;
const LOW_DISTANCE_SYMBOLS: usize = 16;
const REPEAT_LENGTH_SYMBOLS: usize = 44;
const TABLES_SIZE: usize =
    MAIN_SYMBOLS + DISTANCE_SYMBOLS + LOW_DISTANCE_SYMBOLS + REPEAT_LENGTH_SYMBOLS;

/// Main table symbols above the literals.
const SLOT_FILTER: usize = 256;
const SLOT_REPEAT_LAST: usize = 257;
const SLOT_OLD_DISTANCE: usize = 258;
const SLOT_OLD_DISTANCE_LAST: usize = 261;
const SLOT_MATCH: usize = 262; // ..=305

/// Longest possible match (length slot 43 plus distance bonus) with headroom.
const MAX_MATCH: u64 = 0x1100;
/// Filters covering more data than this are invalid and ignored.
const MAX_FILTER_LEN: u32 = 0x40_0000;
/// Limit of queued filters, protects against corrupt data.
const MAX_FILTERS: usize = 8192;
/// Amount of data decoded per refill of the output buffer.
const CHUNK: u64 = 0x1_0000;
/// The window always fits the largest filter block plus decoding headroom.
const MIN_WINDOW: u64 = 0x80_0000;
/// The window starts this small and grows with the output up to its full size.
const INITIAL_WINDOW: u64 = 0x10_0000;

fn corrupt(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Huffman tables of a block.
struct BlockTables {
    main: HuffmanTable,
    distance: HuffmanTable,
    low_distance: HuffmanTable,
    repeat_length: HuffmanTable,
}

/// A decoded main table symbol.
enum Symbol {
    Literal(u8),
    Match {
        length: u32,
        distance: u64,
    },
    /// Repeat the last match.
    RepeatLast,
    /// New length with one of the four previous distances.
    OldDistance {
        index: usize,
        length: u32,
    },
    /// A filter definition, `None` if it's invalid and to be ignored.
    Filter(Option<Filter>),
}

/// Decoder state of the RAR 5.0 algorithm.
///
/// All positions are absolute byte counts of decoded data. In solid archives
/// they keep counting over file boundaries.
pub(super) struct Unpack5 {
    /// Sliding window (power of two in size), indexed by `pos & mask`.
    window: Vec<u8>,
    mask: u64,
    /// Full window size. Until the window has grown to it, the window holds
    /// all output from position 0 without wrapping.
    window_target: u64,
    /// Bytes decoded into the window.
    pos: u64,
    /// Bytes handed out through `out`.
    flushed: u64,
    /// Start of the current file; filter offsets are relative to it.
    file_start: u64,
    file_end: u64,
    tables: Option<BlockTables>,
    /// Bit position where the current block ends.
    block_end: u64,
    last_block: bool,
    /// The first block header of the current file is still to be read.
    need_header: bool,
    /// The last four match distances. Before the first match they're never
    /// referenced by valid data; the masked window access keeps invalid
    /// references harmless.
    old_dist: [u64; 4],
    last_length: u32,
    filters: VecDeque<Filter>,
    /// The current file is completely decoded.
    finished: bool,
    out: Vec<u8>,
    out_pos: usize,
}

/// Window size: the dictionary size, at least large enough for the largest
/// filter, but not much larger than `needed` bytes of output.
fn window_size(dict_size: u64, needed: u64) -> u64 {
    let wanted = dict_size.max(MIN_WINDOW);
    let cap = needed
        .saturating_add(CHUNK + 2 * MAX_MATCH)
        .checked_next_power_of_two()
        .unwrap_or(u64::MAX);
    // both are powers of two, apart from u64::MAX which is never the minimum
    wanted.min(cap)
}

/// Resize `window` to `size` zeroed bytes, reporting failure instead of aborting.
fn resize_window(window: &mut Vec<u8>, size: u64) -> io::Result<()> {
    let size = usize::try_from(size).map_err(|_| corrupt("dictionary too large"))?;
    window
        .try_reserve_exact(size.saturating_sub(window.len()))
        .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "can't allocate dictionary"))?;
    window.resize(size, 0);
    Ok(())
}

impl Unpack5 {
    pub(super) fn new(dict_size: u64, unpacked_size: u64) -> io::Result<Self> {
        let window_target = window_size(dict_size, unpacked_size);
        let mut window = Vec::new();
        resize_window(&mut window, window_target.min(INITIAL_WINDOW))?;
        Ok(Self {
            mask: window.len() as u64 - 1,
            window,
            window_target,
            pos: 0,
            flushed: 0,
            file_start: 0,
            file_end: unpacked_size,
            tables: None,
            block_end: 0,
            last_block: false,
            need_header: true,
            old_dist: [u64::MAX; 4],
            last_length: 0,
            filters: VecDeque::new(),
            finished: false,
            out: Vec::new(),
            out_pos: 0,
        })
    }

    /// Continue the solid stream with the next file.
    pub(super) fn start_file(&mut self, unpacked_size: u64, dict_size: u64) -> io::Result<()> {
        // The window of the first file may be capped to that file's size.
        // Allow it to grow further if the solid stream needs more.
        let wanted = window_size(dict_size, self.pos.saturating_add(unpacked_size));
        if wanted > self.window_target {
            let len = self.window.len() as u64;
            if self.pos > len {
                // The window wrapped already, so move the history to the
                // positions of the larger window.
                let mut window = Vec::new();
                resize_window(&mut window, wanted)?;
                let mask = wanted - 1;
                for p in self.pos - len..self.pos {
                    window[(p & mask) as usize] = self.window[(p & self.mask) as usize];
                }
                self.window = window;
                self.mask = mask;
            }
            self.window_target = wanted;
        }
        self.flushed = self.pos;
        self.file_start = self.pos;
        self.file_end = self.pos.saturating_add(unpacked_size);
        self.block_end = 0;
        self.last_block = false;
        self.need_header = true;
        self.filters.clear();
        self.finished = false;
        self.out.clear();
        self.out_pos = 0;
        Ok(())
    }

    pub(super) fn read<R: Read>(
        &mut self,
        bits: &mut BitReader<R>,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
            self.fill(bits)?;
        }
        let n = buf.len().min(self.out.len() - self.out_pos);
        buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
        self.out_pos += n;
        Ok(n)
    }

    /// Decode until output is available or the file is complete.
    fn fill<R: Read>(&mut self, bits: &mut BitReader<R>) -> io::Result<()> {
        loop {
            self.flush_ready();
            if !self.out.is_empty() || self.flushed >= self.file_end {
                return Ok(());
            }
            if self.finished {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "compressed data ended before the file was complete",
                ));
            }
            let before = self.pos;
            self.decode(bits)?;
            if self.pos == before && !self.finished {
                return Err(corrupt("decoder made no progress"));
            }
        }
    }

    /// Move all output which no longer waits for a filter to `out`.
    fn flush_ready(&mut self) {
        let target = self.pos.min(self.file_end);
        while self.flushed < target {
            let Some(&filter) = self.filters.front() else {
                self.emit(target);
                return;
            };
            if filter.start < self.flushed {
                // overlaps output which is already written, invalid
                self.filters.pop_front();
                continue;
            }
            if filter.start >= target {
                self.emit(target);
                return;
            }
            self.emit(filter.start);
            let filter_end = filter.start + u64::from(filter.len);
            if filter_end > target && !self.finished {
                return; // wait for the rest of the filtered block
            }
            self.filters.pop_front();
            let out_start = self.out.len();
            self.emit(filter_end.min(target));
            // Offsets are 32 bit, like unrar's.
            let file_offset = (filter.start - self.file_start) as u32;
            filter.kind.apply(&mut self.out[out_start..], file_offset);
        }
    }

    /// Copy the window up to `end` into `out`.
    fn emit(&mut self, end: u64) {
        let size = self.window.len() as u64;
        while self.flushed < end {
            let index = self.flushed & self.mask;
            let n = (size - index).min(end - self.flushed);
            self.out
                .extend_from_slice(&self.window[index as usize..(index + n) as usize]);
            self.flushed += n;
        }
    }

    /// Grow the window while it's smaller than its target and the next match
    /// could reach its end. Growing before the first wrap keeps all
    /// positions valid, they're simply extended with zeros.
    fn grow_window(&mut self) -> io::Result<()> {
        let mut len = self.window.len() as u64;
        if len < self.window_target && self.pos + MAX_MATCH > len {
            while len < self.window_target && self.pos + MAX_MATCH > len {
                len = (len * 2).min(self.window_target);
            }
            resize_window(&mut self.window, len)?;
            self.mask = len - 1;
        }
        Ok(())
    }

    fn put(&mut self, byte: u8) {
        self.window[(self.pos & self.mask) as usize] = byte;
        self.pos += 1;
    }

    fn copy_match(&mut self, length: u32, distance: u64) {
        let mut src = self.pos.wrapping_sub(distance);
        for _ in 0..length {
            self.window[(self.pos & self.mask) as usize] = self.window[(src & self.mask) as usize];
            self.pos += 1;
            src = src.wrapping_add(1);
        }
    }

    /// Decode up to one chunk of output.
    fn decode<R: Read>(&mut self, bits: &mut BitReader<R>) -> io::Result<()> {
        let limit = self.pos + CHUNK;
        while self.pos < limit {
            self.grow_window()?;
            // Never overwrite window data which hasn't been flushed yet.
            if self.pos - self.flushed + MAX_MATCH > self.window.len() as u64 {
                break;
            }
            if self.pos >= self.file_end {
                self.finished = true;
                return Ok(());
            }
            // Blocks may be empty, so this can take several headers.
            while self.need_header || bits.position() >= self.block_end {
                if !self.need_header && self.last_block {
                    self.finished = true;
                    return Ok(());
                }
                self.read_block_header(bits)?;
            }

            let tables = self
                .tables
                .as_ref()
                .ok_or_else(|| corrupt("missing tables"))?;
            match read_symbol(tables, bits, self.pos)? {
                Symbol::Literal(byte) => self.put(byte),
                Symbol::Match { length, distance } => {
                    self.old_dist = [
                        distance,
                        self.old_dist[0],
                        self.old_dist[1],
                        self.old_dist[2],
                    ];
                    self.last_length = length;
                    self.copy_match(length, distance);
                }
                Symbol::RepeatLast => {
                    if self.last_length != 0 {
                        self.copy_match(self.last_length, self.old_dist[0]);
                    }
                }
                Symbol::OldDistance { index, length } => {
                    // move the used distance to the front
                    self.old_dist[..=index].rotate_right(1);
                    self.last_length = length;
                    self.copy_match(length, self.old_dist[0]);
                }
                Symbol::Filter(None) => {}
                Symbol::Filter(Some(filter)) => {
                    if self.filters.len() >= MAX_FILTERS {
                        return Err(corrupt("too many filters"));
                    }
                    self.filters.push_back(filter);
                }
            }
        }
        Ok(())
    }

    fn read_block_header<R: Read>(&mut self, bits: &mut BitReader<R>) -> io::Result<()> {
        bits.align();
        let flags = bits.read_bits(8)?;
        let checksum = bits.read_bits(8)?;
        let size_bytes = ((flags >> 3) & 3) + 1;
        if size_bytes == 4 {
            return Err(corrupt("invalid block header"));
        }
        let mut size = 0u32;
        for i in 0..size_bytes {
            size |= bits.read_bits(8)? << (i * 8);
        }
        if (0x5a ^ flags ^ size ^ (size >> 8) ^ (size >> 16)) & 0xff != checksum {
            return Err(corrupt("block header checksum mismatch"));
        }

        // `size` bytes of data, of which the last byte has 1..=8 valid bits
        let last_byte_bits = u64::from(flags & 7) + 1;
        self.block_end = (bits.position() + u64::from(size) * 8 + last_byte_bits).saturating_sub(8);
        self.last_block = flags & 0x40 != 0;
        self.need_header = false;
        if flags & 0x80 != 0 {
            self.tables = Some(read_tables(bits)?);
        } else if self.tables.is_none() {
            return Err(corrupt("first block has no tables"));
        }
        Ok(())
    }
}

/// Read the Huffman tables at the start of a block.
fn read_tables<R: Read>(bits: &mut BitReader<R>) -> io::Result<BlockTables> {
    // 4 bit lengths of the bit length table; 15 introduces a run of zeros
    let mut bit_lengths = [0u8; BIT_LENGTH_SYMBOLS];
    let mut i = 0;
    while i < BIT_LENGTH_SYMBOLS {
        let length = bits.read_bits(4)? as u8;
        let zeros = if length == 15 { bits.read_bits(4)? } else { 0 };
        if zeros == 0 {
            bit_lengths[i] = length;
            i += 1;
        } else {
            let end = (i + zeros as usize + 2).min(BIT_LENGTH_SYMBOLS);
            bit_lengths[i..end].fill(0);
            i = end;
        }
    }
    let bit_length_table = HuffmanTable::new(&bit_lengths);

    // Code lengths of all tables: 0..=15 literally, 16/17 repeat the previous
    // length, 18/19 write zeros.
    let mut lengths = [0u8; TABLES_SIZE];
    let mut i = 0;
    while i < TABLES_SIZE {
        let number = bit_length_table.decode(bits)?;
        if number < 16 {
            lengths[i] = number as u8;
            i += 1;
            continue;
        }
        let count = if number % 2 == 0 {
            bits.read_bits(3)? as usize + 3
        } else {
            bits.read_bits(7)? as usize + 11
        };
        let end = (i + count).min(TABLES_SIZE);
        let value = if number < 18 {
            *lengths[..i]
                .last()
                .ok_or_else(|| corrupt("table starts with a repeat"))?
        } else {
            0
        };
        lengths[i..end].fill(value);
        i = end;
    }

    let (main, rest) = lengths.split_at(MAIN_SYMBOLS);
    let (distance, rest) = rest.split_at(DISTANCE_SYMBOLS);
    let (low_distance, repeat_length) = rest.split_at(LOW_DISTANCE_SYMBOLS);
    Ok(BlockTables {
        main: HuffmanTable::new(main),
        distance: HuffmanTable::new(distance),
        low_distance: HuffmanTable::new(low_distance),
        repeat_length: HuffmanTable::new(repeat_length),
    })
}

/// Read the next main symbol including its length, distance or filter data.
/// `pos` is the current output position, which filters are relative to.
fn read_symbol<R: Read>(
    tables: &BlockTables,
    bits: &mut BitReader<R>,
    pos: u64,
) -> io::Result<Symbol> {
    let slot = tables.main.decode(bits)?;
    Ok(match slot {
        0..=255 => Symbol::Literal(slot as u8),
        SLOT_FILTER => Symbol::Filter(read_filter(bits, pos)?),
        SLOT_REPEAT_LAST => Symbol::RepeatLast,
        SLOT_OLD_DISTANCE..=SLOT_OLD_DISTANCE_LAST => {
            let length_slot = tables.repeat_length.decode(bits)?;
            Symbol::OldDistance {
                index: slot - SLOT_OLD_DISTANCE,
                length: slot_to_length(bits, length_slot as u32)?,
            }
        }
        _ => {
            let length = slot_to_length(bits, (slot - SLOT_MATCH) as u32)?;
            let distance = read_distance(tables, bits)?;
            Symbol::Match {
                length: length + length_bonus(distance),
                distance,
            }
        }
    })
}

/// Match length from a length slot: 2..=9 directly, then base plus extra bits.
fn slot_to_length<R: Read>(bits: &mut BitReader<R>, slot: u32) -> io::Result<u32> {
    if slot < 8 {
        return Ok(2 + slot);
    }
    let extra_bits = slot / 4 - 1;
    let base = 2 + ((4 | (slot & 3)) << extra_bits);
    Ok(base + bits.read_bits(extra_bits)?)
}

/// Distance from a distance slot: 1..=4 directly, then base plus extra bits.
/// The lowest 4 extra bits of longer distances are Huffman coded.
fn read_distance<R: Read>(tables: &BlockTables, bits: &mut BitReader<R>) -> io::Result<u64> {
    let slot = tables.distance.decode(bits)? as u32;
    if slot < 4 {
        return Ok(1 + u64::from(slot));
    }
    let extra_bits = slot / 2 - 1;
    let mut distance = 1 + (u64::from(2 | (slot & 1)) << extra_bits);
    if extra_bits < 4 {
        distance += u64::from(bits.peek32()? >> (32 - extra_bits));
        bits.skip(extra_bits);
    } else {
        if extra_bits > 4 {
            distance += u64::from(bits.peek32()? >> (36 - extra_bits)) << 4;
            bits.skip(extra_bits - 4);
        }
        distance += tables.low_distance.decode(bits)? as u64;
    }
    Ok(distance)
}

/// Long distances imply longer minimum match lengths.
fn length_bonus(distance: u64) -> u32 {
    match distance {
        0..=0x100 => 0,
        0x101..=0x2000 => 1,
        0x2001..=0x40000 => 2,
        _ => 3,
    }
}

/// Read a filter definition. Returns `None` for filters to be ignored.
fn read_filter<R: Read>(bits: &mut BitReader<R>, pos: u64) -> io::Result<Option<Filter>> {
    let start = read_filter_number(bits)?;
    let len = read_filter_number(bits)?;
    let kind = match bits.read_bits(3)? {
        0 => FilterKind::Delta {
            channels: bits.read_bits(5)? as usize + 1,
        },
        1 => FilterKind::E8,
        2 => FilterKind::E8E9,
        3 => FilterKind::Arm,
        _ => return Ok(None), // unknown filter type, unrar skips it too
    };
    if len == 0 || len > MAX_FILTER_LEN {
        return Ok(None);
    }
    Ok(Some(Filter {
        start: pos + u64::from(start),
        len,
        kind,
    }))
}

/// A 1 to 4 byte little endian number, preceded by its byte count - 1.
fn read_filter_number<R: Read>(bits: &mut BitReader<R>) -> io::Result<u32> {
    let byte_count = bits.read_bits(2)? + 1;
    let mut value = 0;
    for i in 0..byte_count {
        value |= bits.read_bits(8)? << (i * 8);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_bonus() {
        assert_eq!(length_bonus(0x100), 0);
        assert_eq!(length_bonus(0x101), 1);
        assert_eq!(length_bonus(0x2001), 2);
        assert_eq!(length_bonus(0x40001), 3);
    }

    #[test]
    fn test_window_size() {
        // small files get a small window, large dictionaries are honoured
        assert_eq!(window_size(0x2_0000, 100), 0x2_0000);
        assert_eq!(window_size(1 << 30, 100), 0x2_0000);
        assert_eq!(window_size(1 << 30, 1 << 40), 1 << 30);
        assert_eq!(window_size(0x2_0000, 1 << 40), MIN_WINDOW);
        assert_eq!(window_size(1 << 32, u64::MAX), 1 << 32);
    }
}
