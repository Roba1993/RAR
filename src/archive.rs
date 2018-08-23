use header::Header;
use nom;
use header::header;
use util::get_bit_at;
use vint::vint;

/// Archive header
#[derive(PartialEq, Debug)]
pub struct ArchiveBlock {
    pub head: Header,
    pub flags: ArchiveFlags,
    pub volume_number: u64,
}

/// Archive header flags
#[derive(PartialEq, Debug)]
pub struct ArchiveFlags {
    pub multivolume: bool,      // Volume. Archive is a part of multivolume set.
    pub volume_number: bool,    // Volume number field is present. This flag is present in all volumes except first.
    pub solid: bool,            // Solid archive.
    pub recovery: bool,         // 0x0008   Recovery record is present.
    pub locked: bool,           // Locked archive.
}

impl ArchiveFlags {
    pub fn new() -> ArchiveFlags {
        ArchiveFlags {
            multivolume: false,
            volume_number: false,
            solid: false,
            recovery: false,
            locked: false,
        }
    }
}

impl From<u64> for ArchiveFlags {
    fn from(i: u64) -> Self {
        let mut f = ArchiveFlags::new();

        if get_bit_at(i, 0) { f.multivolume = true; }
        if get_bit_at(i, 1) { f.volume_number = true; }
        if get_bit_at(i, 2) { f.solid = true; }
        if get_bit_at(i, 3) { f.recovery = true; }
        if get_bit_at(i, 4) { f.locked = true; }

        f
    }
}

/// Returns an archive
pub fn archive(inp: &[u8]) -> nom::IResult<&[u8], ArchiveBlock> {
    // get the base header
    let (input, head) = header(inp)?;

    // check if the defined type is archive header
    if head.typ != ::header::Typ::MainArchive {
        return Err(nom::Err::Error(error_position!(inp, nom::ErrorKind::IsNot)));
    }

    // get the flags
    let (mut input, flags) = vint(input)?;
    let flags = ArchiveFlags::from(flags);

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
        let (i, _) = take!(input, archive.head.extra_area_size)?;
        input = i;
    }

    Ok((input, archive))
}
#[test]
fn test_archive() {
    // test a success case
    let data = [
        0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x01, 0x05, 0x07,
        0x00, 0x06, 0x01, 0x01, 0x80, 0x80, 0x80, 0x00, 0x8C, 
        0x0D, 0x88, 0xE2, 
    ];

    let mut flags = ::header::Flags::new();
    flags.extra_area = true;
    flags.skip = true;
    let mut arc = ArchiveBlock {
        head: Header::new(4091642603, 11, ::header::Typ::MainArchive, flags),
        flags: ArchiveFlags::new(),
        volume_number: 0,
    };
    arc.head.extra_area_size = 7;
    assert_eq!(archive(&data), Ok((&[0x8C, 0x0D, 0x88, 0xE2][..], arc)));

    // test a wrong header type
    let data = [
        0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x02, 0x05, 0x07,
        0x00, 0x06, 0x01, 0x01, 0x80, 0x80, 0x80, 0x00, 0x8C, 
        0x0D, 0x88, 0xE2, 
    ];
    assert_eq!(archive(&data), Err(nom::Err::Error(error_position!(&data[..], nom::ErrorKind::IsNot))));
}
