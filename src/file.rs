use header::Header;
use nom;
use nom::be_u32;
use header::header;
use util::{get_bit_at, split_u64};
use vint::{vint, vint_t};


/// file header
#[derive(PartialEq, Debug)]
pub struct File {
    pub head: Header,
    pub flags: FileFlags,
    pub unpacked_size: u64,
    pub attributes: u64,
    pub mtime: u32,
    pub data_crc: u32,
    pub compression: Compression,
    pub creation_os: OsFlags,
    pub name_len: u64,
    pub name: String
}



/// file flags
#[derive(PartialEq, Debug)]
pub struct FileFlags {
    pub directory: bool,    // Directory file system object (file header only).
    pub time: bool,         // Time field in Unix format is present.
    pub crc: bool,          // CRC32 field is present
    pub unknown_size: bool, // Unpacked size is unknown.  
}

impl FileFlags {
    pub fn new() -> FileFlags {
        FileFlags {
            directory: false,
            time: false,
            crc: false,
            unknown_size: false,
        }
    }
}

impl From<u64> for FileFlags {
    fn from(i: u64) -> Self {
        let mut f = FileFlags::new();

        if get_bit_at(i, 0) { f.directory = true; }
        if get_bit_at(i, 1) { f.time = true; }
        if get_bit_at(i, 2) { f.crc = true; }
        if get_bit_at(i, 3) { f.unknown_size = true; }

        f
    }
}


/// OS flags
#[derive(PartialEq, Debug)]
pub enum OsFlags {
    WINDOWS,
    UNIX,
    UNKNOWN
}

impl From<u64> for OsFlags {
    fn from(i: u64) -> Self {
        if i == 0 { return OsFlags::WINDOWS }
        if i == 0 { return OsFlags::UNIX }
        OsFlags::UNKNOWN
    }
}


/// Compression dataset
#[derive(PartialEq, Debug, Clone)]
pub struct Compression {
    pub version: u8,
    pub solid: bool,
    pub flag: CompressionFlags,
    pub dictonary: u8
}

impl Compression {
    pub fn get_directonary(&self) -> u32 {
        128 * (self.dictonary as f32).exp2() as u32
    }
}
#[test]
fn test_get_directonary() {
    let mut data = Compression {
        version: 0,
        solid: false,
        flag: CompressionFlags::Save,
        dictonary: 0
    };

    assert_eq!(data.get_directonary(), 128);
    data.dictonary = 1;
    assert_eq!(data.get_directonary(), 256);
    data.dictonary = 10;
    assert_eq!(data.get_directonary(), 131072);
    data.dictonary = 15;
    assert_eq!(data.get_directonary(), 4194304);
}

/// Compression Flags
#[derive(PartialEq, Debug, Clone)]
pub enum CompressionFlags {
    Save,
    Fastest,
    Fast,
    Normal,
    Good,
    Best,
    Unknown
}

impl From<u8> for CompressionFlags {
    fn from(i: u8) -> Self {
        if i == 0 { return CompressionFlags::Save }
        if i == 1 { return CompressionFlags::Fastest }
        if i == 2 { return CompressionFlags::Fast }
        if i == 3 { return CompressionFlags::Normal }
        if i == 4 { return CompressionFlags::Good }
        if i == 5 { return CompressionFlags::Best }
        CompressionFlags::Unknown
    }
}


/// Returns an file
pub fn file(inp: &[u8]) -> nom::IResult<&[u8], File> {
    // get the base header
    let (input, head) = header(inp)?;

    // check if the defined type is archive header
    if head.typ != ::header::Typ::File && head.typ != ::header::Typ::Service {
        return Err(nom::Err::Error(error_position!(inp, nom::ErrorKind::IsNot)));
    }

    // get the flags
    let (input, flags) = vint(input)?;
    let flags = FileFlags::from(flags);

    let (input, unpacked_size) = vint(input)?;
    let (mut input, attributes) = vint(input)?;

    // empty compression
    let compression = Compression {
        version: 0,
        solid: false,
        flag: CompressionFlags::Unknown,
        dictonary: 0
    };
    

    let mut file = File {
        head,
        flags,
        unpacked_size,
        attributes,
        mtime: 0,
        data_crc: 0,
        compression: compression,
        creation_os: OsFlags::UNKNOWN,
        name_len: 0,
        name: "".into()
    };

    // check for time
    if file.flags.time {
        let (i , mtime) = be_u32(input)?;
        input = i;
        file.mtime = mtime;
    }

    // check for file crc data
    if file.flags.crc {
        let (i , crc) = be_u32(input)?;
        input = i;
        file.data_crc = crc;
    }

    let (input, compr) = get_compression(input)?;
    file.compression = compr;

    let (input, os) = vint(input)?;
    file.creation_os = os.into();

    let (input, nlen) = vint(input)?;
    file.name_len = nlen;

    let (mut input, n) = take_str!(input, file.name_len)?;
    file.name = n.into();

    // check for a data area
    if file.head.flags.extra_area {
        // _ holds locator data - no processed right now
        let (i, _) = take!(input, file.head.extra_area_size)?;
        input = i;
    }

    Ok((input, file))
}
#[test]
fn test_archive() {
    // test a success case
    let data = [
        0x8C, 
        0x0D, 0x88, 0xE2, 0x24, 0x02, 0x03, 0x0B, 0xC6, 0x10, 
        0x04, 0xC6, 0x10, 0x20, 0x93, 0xF2, 0x9A, 0xCB, 0x80, 
        0x00, 0x00, 0x08, 0x74, 0x65, 0x78, 0x74, 0x2E, 0x74, 
        0x78, 0x74, 0x0A, 0x03, 0x02, 0x78, 0x27, 0x3C, 0x1E, 
        0x7D, 0xF2, 0xD3, 0x01, 0x46, 0x61, 0x72, 0x20, 0x66 
    ];

    let mut flags = ::header::Flags::new();
    flags.extra_area = true;
    flags.data_area = true;

    let compression = Compression {
        version: 0,
        solid: false,
        flag: CompressionFlags::Save,
        dictonary: 0
    };

    let mut fileFlag = FileFlags::new();
    fileFlag.crc = true;

    let mut arc = File {
        head: Header::new(2349697250, 36, ::header::Typ::File, flags),
        flags: fileFlag,
        unpacked_size: 2118,
        attributes: 32,
        mtime: 0,
        data_crc: 2482150091,
        compression,
        creation_os: OsFlags::WINDOWS,
        name_len: 8,
        name: "text.txt".into()
    };
    arc.head.extra_area_size = 11;
    arc.head.data_area_size = 2118;
    assert_eq!(file(&data), Ok((&data[41..][..], arc)));
}
#[test]
fn test_archive_png() {
    // test a success case
    let data = [0x3B, 0xC1, 0x34, 0x5E, 0x2B, 0x02, 0x03,   
        0x0B, 0xDB, 0x95, 0x83, 0x81, 0x00, 0x04, 0xDB, 0x95, 0x83, 0x81, 0x00, 0x20, 0x94, 0xB1, 0xA4,
        0x7A, 0x80, 0x00, 0x00, 0x09, 0x70, 0x68, 0x6F, 0x74, 0x6F, 0x2E, 0x6A, 0x70, 0x67, 0x0A, 0x03, 
        0x02, 0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x01, 0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x18, 0x45,
    ];

    let mut flags = ::header::Flags::new();
    flags.extra_area = true;
    flags.data_area = true;

    let compression = Compression {
        version: 0,
        solid: false,
        flag: CompressionFlags::Save,
        dictonary: 0
    };

    let mut fileFlag = FileFlags::new();
    fileFlag.crc = true;

    let mut arc = File {
        head: Header::new(1002517598, 43, ::header::Typ::File, flags),
        flags: fileFlag,
        unpacked_size: 2149083,
        attributes: 32,
        mtime: 0,
        data_crc: 2494669946,
        compression,
        creation_os: OsFlags::WINDOWS,
        name_len: 9,
        name: "photo.jpg".into()
    };
    arc.head.extra_area_size = 11;
    arc.head.data_area_size = 2149083;

    assert_eq!(file(&data), Ok((&data[48..][..], arc)));
}

/// get the compression info
fn get_compression(inp: &[u8]) -> nom::IResult<&[u8], Compression> {
    // get the vint
    let (inp, raw) = vint(inp)?;

    // split it back to an u8 array
    let clean = &split_u64(raw)[..];

    //println!("\nRAW: {:X?}\nCLEAN: {:X?}", raw, clean);

    // get the data from the compression
    // !!!!!! THIS IS PROBABLY WRONG !!!!!!
    let c = bits!(clean, do_parse!(
        dictonary: take_bits!(u8, 4) >>
        flag: take_bits!(u8, 4) >>
        solid: take_bits!(u8, 1) >>
        version: take_bits!(u8, 6) >>
        (Compression {version, solid: to_bool(solid), flag: flag.into(), dictonary})
    ));

    // change the error to an inp error and not and bit matchign error
    let c = c.map_err(|_| nom::Err::Error(nom::Context::Code(inp, nom::ErrorKind::Custom(0))) )?;

    // return the compression
    Ok((inp, c.1))
}
#[test]
fn test_get_compression() {
    let c = Compression {
        version: 0, 
        solid: false, 
        flag: CompressionFlags::Save, 
        dictonary: 0
    };
    assert_eq!(get_compression(&[0x80, 0x00]), Ok((&[][..], c.clone())));
    assert_eq!(get_compression(&[0x80, 0x00, 0x00]), Ok((&[0x00][..], c)));
    assert!(get_compression(&[0x80]).is_err());
}

fn to_bool(i: u8) -> bool {
    if i > 0 {
        return true;
    }
    false
}
#[test]
fn test_to_bool() {
    assert_eq!(to_bool(0), false);
    assert_eq!(to_bool(1), true);
    assert_eq!(to_bool(10), true);
}