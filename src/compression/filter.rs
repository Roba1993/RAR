/// Transformations RAR applies to blocks of data before compressing them.
/// The decoder reverts them on the decompressed output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FilterKind {
    /// Byte-wise delta coding interleaved over the given number of channels.
    Delta { channels: usize },
    /// x86 CALL (0xE8) targets converted to absolute addresses.
    E8,
    /// x86 CALL (0xE8) and JMP (0xE9) targets converted to absolute addresses.
    E8E9,
    /// ARM BL instruction targets converted to absolute addresses.
    Arm,
}

/// A filter covering `len` bytes of output from the absolute position `start`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Filter {
    pub(super) start: u64,
    pub(super) len: u32,
    pub(super) kind: FilterKind,
}

impl FilterKind {
    /// Revert the filter on `data`, which starts at `file_offset` within the file.
    pub(super) fn apply(self, data: &mut [u8], file_offset: u32) {
        match self {
            Self::E8 => x86(data, file_offset, false),
            Self::E8E9 => x86(data, file_offset, true),
            Self::Arm => arm(data, file_offset),
            Self::Delta { channels } => delta(data, channels),
        }
    }
}

fn x86(data: &mut [u8], file_offset: u32, include_e9: bool) {
    // Addresses are taken modulo this virtual file size.
    const FILE_SIZE: u32 = 0x100_0000;

    let mut cur = 0;
    while cur + 4 < data.len() {
        let opcode = data[cur];
        cur += 1;
        if opcode != 0xe8 && !(include_e9 && opcode == 0xe9) {
            continue;
        }

        let offset = (cur as u32).wrapping_add(file_offset) % FILE_SIZE;
        let field = &mut data[cur..cur + 4];
        // The address is a signed 32 bit value, compared as in unrar.
        let addr = i32::from_le_bytes(field.try_into().unwrap());
        let new = if addr < 0 {
            (addr.wrapping_add(offset as i32) >= 0).then(|| addr.wrapping_add(FILE_SIZE as i32))
        } else {
            (addr < FILE_SIZE as i32).then(|| addr.wrapping_sub(offset as i32))
        };
        if let Some(new) = new {
            field.copy_from_slice(&new.to_le_bytes());
        }
        cur += 4;
    }
}

fn arm(data: &mut [u8], file_offset: u32) {
    let (instructions, _) = data.as_chunks_mut::<4>();
    for (i, instr) in instructions.iter_mut().enumerate() {
        // BL with a 24 bit word offset
        if instr[3] == 0xeb {
            let pos = file_offset.wrapping_add(i as u32 * 4);
            let target = u32::from_le_bytes([instr[0], instr[1], instr[2], 0]);
            let offset = target.wrapping_sub(pos / 4);
            instr[..3].copy_from_slice(&offset.to_le_bytes()[..3]);
        }
    }
}

fn delta(data: &mut [u8], channels: usize) {
    // The input holds all bytes of channel 0, then channel 1, ...; the output
    // interleaves them again.
    let src = data.to_vec();
    let mut src = src.iter();
    for channel in 0..channels {
        let mut prev = 0u8;
        for byte in data.iter_mut().skip(channel).step_by(channels) {
            prev = prev.wrapping_sub(*src.next().unwrap_or(&0));
            *byte = prev;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta() {
        let original = [10u8, 100, 12, 101, 15, 99];
        let mut encoded = vec![];
        for channel in 0..2 {
            let mut prev = 0u8;
            for &b in original.iter().skip(channel).step_by(2) {
                encoded.push(prev.wrapping_sub(b));
                prev = b;
            }
        }
        FilterKind::Delta { channels: 2 }.apply(&mut encoded, 0);
        assert_eq!(encoded, original);
    }

    #[test]
    fn test_e8() {
        // absolute target 0x100 of the call at offset 0 becomes relative 0x100 - 1
        let mut data = [0xe8, 0x00, 0x01, 0x00, 0x00, 0x90];
        FilterKind::E8.apply(&mut data, 0);
        assert_eq!(data, [0xe8, 0xff, 0x00, 0x00, 0x00, 0x90]);
    }

    #[test]
    fn test_e8e9() {
        let mut data = [
            0xe9, 0x00, 0x01, 0x00, 0x00, 0xe9, 0x10, 0x00, 0x00, 0x00, 0x90,
        ];
        let mut e8_only = data;
        FilterKind::E8E9.apply(&mut data, 0x10);
        // offsets 0x11 and 0x16 are subtracted
        assert_eq!(&data[1..5], &(0x100u32 - 0x11).to_le_bytes());
        assert_eq!(&data[6..10], &(0x10u32.wrapping_sub(0x16)).to_le_bytes());
        // without E9 support the jumps stay untouched
        let unchanged = e8_only;
        FilterKind::E8.apply(&mut e8_only, 0x10);
        assert_eq!(e8_only, unchanged);
    }

    #[test]
    fn test_e8_negative_address() {
        // a negative address becomes positive when the call position makes it so
        let mut data = [0xe8, 0xff, 0xff, 0xff, 0xff, 0x90];
        FilterKind::E8.apply(&mut data, 0);
        assert_eq!(&data[1..5], &0x00ff_ffffu32.to_le_bytes());
    }

    #[test]
    fn test_arm() {
        // BL at file offset 8 with absolute word target 0x10 becomes 0x10 - 8/4
        let mut data = [0x10, 0x00, 0x00, 0xeb, 0x01, 0x02, 0x03, 0x04];
        FilterKind::Arm.apply(&mut data, 8);
        assert_eq!(data, [0x0e, 0x00, 0x00, 0xeb, 0x01, 0x02, 0x03, 0x04]);
    }
}
