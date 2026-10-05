use crate::util;
use crate::vint;
use chrono::{naive::NaiveDateTime, DateTime};

use nom::bytes::complete::take;
use nom::number::complete::{le_u32, le_u64};

/// The Extra Area Block which provides optional
/// information about the file.
/// This can be about the time, encryption, hash,
/// version, owner, etc.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct ExtraAreaBlock {
    pub file_time: Option<FileTimeBlock>,
    pub file_encryption: Option<FileEncryptionBlock>,
}

impl ExtraAreaBlock {
    /// Parse the Extra Area Block from a byte slice
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], ExtraAreaBlock> {
        let mut inp = input;

        let mut eab = ExtraAreaBlock {
            file_time: None,
            file_encryption: None,
        };

        // parse all the different extra blocks after each other
        while !inp.is_empty() {
            let (i, size) = vint::vint(inp)?;
            let (i, typ) = vint::vint(i)?;
            let (i, data) = take(size - 1)(i)?;
            inp = i;

            // based upon the block type use the right parser
            match typ {
                0x01 => eab.file_encryption = FileEncryptionBlock::parse(data).ok().map(|i| i.1),
                0x03 => eab.file_time = FileTimeBlock::parse(data).ok().map(|i| i.1),
                _ => {}
            }
        }

        Ok((inp, eab))
    }
}

#[test]
fn test_parse_extra_area_time() {
    let data = [
        0x0A, 0x03, 0x02, 0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x01,
    ];

    let ftb = FileTimeBlock {
        modification_time: Some(
            NaiveDateTime::parse_from_str("2016-11-22 11:42:49", "%Y-%m-%d %H:%M:%S").unwrap(),
        ),
        creation_time: None,
        access_time: None,
    };

    let eab = ExtraAreaBlock {
        file_time: Some(ftb),
        file_encryption: None,
    };

    assert_eq!(ExtraAreaBlock::parse(&data), Ok((&[][..], eab)));
}
#[test]
fn test_parse_extra_area_multi() {
    let data = [
        0x30, 0x1, 0x0, 0x3, 0xF, 0x91, 0x36, 0x5C, 0xDE, 0x8E, 0x8E, 0xD, 0x13, 0xFF, 0xBA, 0x80,
        0xE9, 0x2B, 0x5F, 0x8, 0x4A, 0x8D, 0x50, 0x37, 0xE8, 0xCD, 0xBE, 0x56, 0x7B, 0xCA, 0xC3,
        0xFC, 0x77, 0x85, 0x27, 0x7B, 0xBA, 0x8, 0xF2, 0xD8, 0xB3, 0x20, 0x71, 0x84, 0x52, 0x92,
        0x19, 0x56, 0x11, 0xA, 0x3, 0x2, 0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x1,
    ];

    let ftb = FileTimeBlock {
        modification_time: Some(
            NaiveDateTime::parse_from_str("2016-11-22 11:42:49", "%Y-%m-%d %H:%M:%S").unwrap(),
        ),
        creation_time: None,
        access_time: None,
    };

    let febf = FileEncryptionBlockFlags {
        pw_check_data: true,
        tweaked_crc: true,
    };

    let feb = FileEncryptionBlock {
        flags: febf,
        kdf_count: 15,
        salt: [
            145, 54, 92, 222, 142, 142, 13, 19, 255, 186, 128, 233, 43, 95, 8, 74,
        ],
        init: [
            141, 80, 55, 232, 205, 190, 86, 123, 202, 195, 252, 119, 133, 39, 123, 186,
        ],
        pw_check: [8, 242, 216, 179, 32, 113, 132, 82, 146, 25, 86, 17],
        ..Default::default()
    };

    let eab = ExtraAreaBlock {
        file_time: Some(ftb),
        file_encryption: Some(feb),
    };

    assert_eq!(ExtraAreaBlock::parse(&data), Ok((&[][..], eab)));
}

/// The File Time Block provides optional information
/// about the time
#[derive(PartialEq, Debug, Clone, Default)]
pub struct FileTimeBlock {
    pub modification_time: Option<NaiveDateTime>,
    pub creation_time: Option<NaiveDateTime>,
    pub access_time: Option<NaiveDateTime>,
}

impl FileTimeBlock {
    /// Create the file time block from a byte slice
    fn parse(input: &[u8]) -> nom::IResult<&[u8], FileTimeBlock> {
        let mut ftb = FileTimeBlock {
            modification_time: None,
            creation_time: None,
            access_time: None,
        };

        let (mut inp, flags) = vint::vint(input)?;

        // unix or windows time format?
        let unix_time = util::get_bit_at(flags, 0);

        // modification time available?
        if util::get_bit_at(flags, 1) {
            let (i, t) = FileTimeBlock::parse_timestamp(inp, unix_time)?;
            inp = i;
            ftb.modification_time = t;
        }

        // creation time available?
        if util::get_bit_at(flags, 2) {
            let (i, t) = FileTimeBlock::parse_timestamp(inp, unix_time)?;
            inp = i;
            ftb.creation_time = t;
        }

        // access time available?
        if util::get_bit_at(flags, 3) {
            let (i, t) = FileTimeBlock::parse_timestamp(inp, unix_time)?;
            inp = i;
            ftb.access_time = t;
        }

        Ok((inp, ftb))
    }

    /// Parses a timestamp from the byte slice from a unix or windows format
    fn parse_timestamp(
        input: &[u8],
        unix_time: bool,
    ) -> nom::IResult<&[u8], Option<NaiveDateTime>> {
        if unix_time {
            let (input, data) = take(4usize)(input)?;
            let (_, t) = le_u32(data)?;
            let t = DateTime::from_timestamp(t as i64, 0).map(|dt| dt.naive_utc());
            Ok((input, t))
        } else {
            let (input, data) = take(8usize)(input)?;
            let (_, t) = le_u64(data)?;
            let t = (t / 10000000) - 11644473600;
            let t = DateTime::from_timestamp(t as i64, 0).map(|dt| dt.naive_utc());
            Ok((input, t))
        }
    }
}

#[test]
fn test_parse_time() {
    let data = [0x02, 0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x01];
    let ftb = FileTimeBlock {
        modification_time: Some(
            NaiveDateTime::parse_from_str("2016-11-22 11:42:49", "%Y-%m-%d %H:%M:%S").unwrap(),
        ),
        creation_time: None,
        access_time: None,
    };

    assert_eq!(FileTimeBlock::parse(&data), Ok((&[][..], ftb)));
}

#[test]
fn test_convert_time() {
    let data = [0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x01];
    let t =
        Some(NaiveDateTime::parse_from_str("2016-11-22 11:42:49", "%Y-%m-%d %H:%M:%S").unwrap());

    assert_eq!(
        FileTimeBlock::parse_timestamp(&data, false),
        Ok((&[][..], t))
    );
}

/// File Encryption Block which gives the necessary
/// Information about the encrypted file.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct FileEncryptionBlock {
    pub version: FileEncryptionVersion,
    pub flags: FileEncryptionBlockFlags,
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub init: [u8; 16],
    pub pw_check: [u8; 12],
}

impl FileEncryptionBlock {
    fn parse(input: &[u8]) -> nom::IResult<&[u8], FileEncryptionBlock> {
        // parse version
        let (inp, version) = FileEncryptionVersion::parse(input)?;
        // Parse flags
        let (inp, flags) = FileEncryptionBlockFlags::parse(inp)?;
        // parse kdf count
        let (inp, kdf_count) = take(1usize)(inp)?;
        // parse salt value
        let (inp, salt) = take(16usize)(inp)?;
        // parse init value
        let (mut inp, init) = take(16usize)(inp)?;
        // parse pw check value
        let mut pw_check = [0; 12];
        if flags.pw_check_data {
            let (i, p) = take(12usize)(inp)?;
            pw_check.copy_from_slice(p);
            inp = i;
        }

        let mut feb = FileEncryptionBlock {
            version,
            flags,
            kdf_count: kdf_count[0],
            salt: [0; 16],
            init: [0; 16],
            pw_check,
        };

        feb.salt.copy_from_slice(salt);
        feb.init.copy_from_slice(init);

        Ok((inp, feb))
    }
}

#[test]
fn test_file_encryption_parse() {
    let data = [
        0x0, 0x3, 0xF, 0x91, 0x36, 0x5C, 0xDE, 0x8E, 0x8E, 0xD, 0x13, 0xFF, 0xBA, 0x80, 0xE9, 0x2B,
        0x5F, 0x8, 0x4A, 0x8D, 0x50, 0x37, 0xE8, 0xCD, 0xBE, 0x56, 0x7B, 0xCA, 0xC3, 0xFC, 0x77,
        0x85, 0x27, 0x7B, 0xBA, 0x8, 0xF2, 0xD8, 0xB3, 0x20, 0x71, 0x84, 0x52, 0x92, 0x19, 0x56,
        0x11,
    ];

    let febf = FileEncryptionBlockFlags {
        pw_check_data: true,
        tweaked_crc: true,
    };

    let feb = FileEncryptionBlock {
        flags: febf,
        kdf_count: 15,
        salt: [
            145, 54, 92, 222, 142, 142, 13, 19, 255, 186, 128, 233, 43, 95, 8, 74,
        ],
        init: [
            141, 80, 55, 232, 205, 190, 86, 123, 202, 195, 252, 119, 133, 39, 123, 186,
        ],
        pw_check: [8, 242, 216, 179, 32, 113, 132, 82, 146, 25, 86, 17],
        ..Default::default()
    };

    assert_eq!(FileEncryptionBlock::parse(&data), Ok((&[][..], feb)));
}

/// File Encryption Block which gives the necessary
/// Information about the encrypted file.
#[derive(PartialEq, Debug, Clone, Default)]
pub enum FileEncryptionVersion {
    #[default]
    Aes256,
    Unknown,
}

impl FileEncryptionVersion {
    fn parse(input: &[u8]) -> nom::IResult<&[u8], FileEncryptionVersion> {
        let (inp, version) = vint::vint(input)?;

        match version {
            0x00 => Ok((inp, FileEncryptionVersion::Aes256)),
            _ => Ok((inp, FileEncryptionVersion::Unknown)),
        }
    }
}

/// File Encryption Block Flags which gives informaton
/// about how the decrypt the file
#[derive(PartialEq, Debug, Clone, Default)]
pub struct FileEncryptionBlockFlags {
    pw_check_data: bool,
    tweaked_crc: bool,
}

impl FileEncryptionBlockFlags {
    fn parse(input: &[u8]) -> nom::IResult<&[u8], FileEncryptionBlockFlags> {
        // Parse flags
        let (inp, flags) = vint::vint(input)?;

        let febf = FileEncryptionBlockFlags {
            pw_check_data: util::get_bit_at(flags, 0),
            tweaked_crc: util::get_bit_at(flags, 1),
        };

        Ok((inp, febf))
    }
}
