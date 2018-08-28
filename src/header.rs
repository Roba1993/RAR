use nom;
use nom::be_u32;
use vint::vint;
use std::convert::From;
use util::get_bit_at;

/// general Header valid for all rar blocks
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Header {
    pub crc: u32,
    pub size: u64,
    pub typ: Typ,
    pub flags: Flags,
    pub extra_area_size: u64,
    pub data_area_size: u64,
}

impl Header {
    pub fn new(crc: u32, size: u64, typ: Typ, flags: Flags,) -> Self {
        Header {
            crc,
            size,
            typ,
            flags,
            extra_area_size: 0,
            data_area_size: 0,
        }
    }
}

/// Definition of the header block typ
#[derive(PartialEq, Debug, Clone)]
pub enum Typ {
    MainArchive,
    File,
    Service,
    Encryption,
    EndArchive,
    Unknown,
}

impl From<u64> for Typ {
    fn from(i: u64) -> Self {
        match i {
            1 => Typ::MainArchive,
            2 => Typ::File,
            3 => Typ::Service,
            4 => Typ::Encryption,
            5 => Typ::EndArchive,
            _ => Typ::Unknown
        }
    }
}

impl Default for Typ {
    fn default() -> Typ {
        Typ::Unknown
    }
}


/// Flags for a header block
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Flags {
    pub extra_area: bool,   // Extra are is present in the end of header. 
    pub data_area: bool,    // Data area is present in the end of header. 
    pub skip: bool,         // Blocks with unknown type and this flag must be skipped when updating an archive. 
    pub data_prev: bool,    // Data area is continuing from previous volume. 
    pub data_next: bool,    // Data area is continuing in next volume. 
    pub preceding: bool,    // Block depends on preceding file block. 
    pub preserve: bool,     // Preserve a child block if host block is modified.
}

impl Flags {
    pub fn new() -> Flags {
        Flags {
            extra_area: false,
            data_area: false,
            skip: false, 
            data_prev: false,
            data_next: false,
            preceding: false,
            preserve: false,
        }
    }
}

impl From<u64> for Flags {
    fn from(i: u64) -> Self {
        let mut f = Flags::new();

        if get_bit_at(i, 0) { f.extra_area = true; }
        if get_bit_at(i, 1) { f.data_area = true; }
        if get_bit_at(i, 2) { f.skip = true; }
        if get_bit_at(i, 3) { f.data_prev = true; }
        if get_bit_at(i, 4) { f.data_next = true; }
        if get_bit_at(i, 5) { f.preceding = true; }
        if get_bit_at(i, 6) { f.preserve = true; }

        f
    }
}


/// Returns the next complete vint number as u64.
pub fn header(input: &[u8]) -> nom::IResult<&[u8], Header> {
    // get the base header
    let (mut input, mut bh) = base_header(input)?;

    // check for a extra area
    if bh.flags.extra_area {
        let (i, s) = vint(input)?;
        input = i;
        bh.extra_area_size = s;
    }

    // check for a data area
    if bh.flags.data_area {
        let (i, s) = vint(input)?;
        input = i;
        bh.data_area_size = s;
    }

    Ok((input, bh))
}
#[test]
fn test_header() {
    let data = [0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x01, 0x05, 0x07, 0x00];

    let mut flags = Flags::new();
    flags.extra_area = true;
    flags.skip = true;
    let mut h = Header::new(4091642603, 11, Typ::MainArchive, flags);
    h.extra_area_size = 7;
    assert_eq!(header(&data), Ok((&[0x00][..], h)));
}


/// get a base header
named!(base_header(&[u8]) -> (Header), 
    do_parse!(
        crc: be_u32 >>
        size: vint >>
        typ: vint >>
        flags: vint >>
        (Header::new(crc, size, typ.into(), flags.into()))
    )
);
#[test]
fn test_base_header() {
    let data = [0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x01, 0x05, 0x07];

    let mut flags = Flags::new();
    flags.extra_area = true;
    flags.skip = true;
    let header = Header::new(4091642603, 11, Typ::MainArchive, flags);
    assert_eq!(base_header(&data), Ok((&[0x07][..], header)));
}

