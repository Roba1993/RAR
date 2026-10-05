#[cfg(test)]
use crate::head_block::Flags;
use crate::head_block::{HeadBlock, Typ};
use crate::util::get_bit_at;
use crate::vint::vint;

use nom::bytes::complete::take;
use nom::error::ErrorKind;

/// Archive header which can exist once for each
/// .rar archive file.
#[derive(PartialEq, Debug, Default)]
pub struct ArchiveBlock {
    pub head: HeadBlock,
    pub flags: ArchiveFlags,
    pub volume_number: u64,
}

impl ArchiveBlock {
    /// Parse a byte slice and returns an ArchiveBlock and the not consumed byte slice.
    /// When an error occours this function returns a nom error.
    pub fn parse(inp: &[u8]) -> nom::IResult<&[u8], ArchiveBlock> {
        // get the base header
        let (input, head) = HeadBlock::parse(inp)?;

        // check if the defined type is archive header
        if head.typ != Typ::MainArchive {
            return Err(nom::Err::Error(nom::error::Error::new(
                inp,
                ErrorKind::Verify,
            )));
        }

        // get the archive flags
        let (mut input, flags) = vint(input)?;
        let flags = ArchiveFlags::from(flags);

        // create the archive struct
        let mut archive = ArchiveBlock {
            head,
            flags,
            volume_number: 0,
        };

        // check for volumne number
        if archive.flags.volume_number {
            let (i, n) = vint(input)?;
            input = i;
            archive.volume_number = n;
        }

        // check for a data area
        if archive.head.flags.extra_area {
            // _ holds locator data - no processed right now
            let (i, _) = take(archive.head.extra_area_size as usize)(input)?;
            input = i;
        }

        Ok((input, archive))
    }
}

#[test]
fn test_archive() {
    // test a success case
    let data = [
        0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x01, 0x05, 0x07, 0x00, 0x06, 0x01, 0x01, 0x80, 0x80, 0x80,
        0x00, 0x8C, 0x0D, 0x88, 0xE2,
    ];

    let flags = Flags {
        extra_area: true,
        skip: true,
        ..Default::default()
    };
    let mut arc = ArchiveBlock {
        head: HeadBlock::new(4091642603, 11, Typ::MainArchive, flags),
        flags: ArchiveFlags::default(),
        volume_number: 0,
    };
    arc.head.extra_area_size = 7;
    assert_eq!(
        ArchiveBlock::parse(&data),
        Ok((&[0x8C, 0x0D, 0x88, 0xE2][..], arc))
    );

    // test a wrong header type
    let data = [
        0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x02, 0x05, 0x07, 0x00, 0x06, 0x01, 0x01, 0x80, 0x80, 0x80,
        0x00, 0x8C, 0x0D, 0x88, 0xE2,
    ];
    assert_eq!(
        ArchiveBlock::parse(&data),
        Err(nom::Err::Error(nom::error::Error::new(
            &data[..],
            ErrorKind::Verify
        )))
    );
}

/// Archive header flags which define main
/// flags for the archive header
#[derive(PartialEq, Debug, Default)]
pub struct ArchiveFlags {
    pub multivolume: bool,   // Volume. Archive is a part of multivolume set.
    pub volume_number: bool, // Volume number field is present. This flag is present in all volumes except first.
    pub solid: bool,         // Solid archive.
    pub recovery: bool,      // 0x0008   Recovery record is present.
    pub locked: bool,        // Locked archive.
}

impl From<u64> for ArchiveFlags {
    fn from(i: u64) -> Self {
        let mut f = ArchiveFlags::default();

        if get_bit_at(i, 0) {
            f.multivolume = true;
        }
        if get_bit_at(i, 1) {
            f.volume_number = true;
        }
        if get_bit_at(i, 2) {
            f.solid = true;
        }
        if get_bit_at(i, 3) {
            f.recovery = true;
        }
        if get_bit_at(i, 4) {
            f.locked = true;
        }

        f
    }
}
