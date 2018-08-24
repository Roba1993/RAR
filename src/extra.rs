use nom;
use vint;
use util;
use chrono::naive::NaiveDateTime;

#[derive(PartialEq, Debug, Clone, Default)]
pub struct ExtraAreaBlock {
    pub file_time: Option<FileTimeBlock>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct FileTimeBlock {
    pub modification_time: Option<NaiveDateTime>,
    pub creation_time: Option<NaiveDateTime>,
    pub access_time: Option<NaiveDateTime>,
}

pub fn parse_extra_area(input: &[u8]) -> nom::IResult<&[u8], ExtraAreaBlock> {
    let mut inp = input;

    let mut eab = ExtraAreaBlock {
        file_time: None,
    };

    while inp.len() > 0 {
        let (i, size) = vint::vint(inp)?;
        let (i, typ) = vint::vint(i)?;
        let (i, data) = take!(i, size-1)?;
        inp = i;

        match typ {
            0x03 => eab.file_time = parse_time(data).ok().map(|i| i.1),
            _ => {},
        }
    }

    Ok((inp, eab))
}
#[test]
fn test_parse_extra_area_time() {
    let data = [0x0A, 0x03, 0x02, 0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x01];

    let ftb = FileTimeBlock {
        modification_time: Some(NaiveDateTime::parse_from_str("2016-11-22 11:42:49", "%Y-%m-%d %H:%M:%S").unwrap()),
        creation_time: None,
        access_time: None,
    };

    let eab = ExtraAreaBlock {
        file_time: Some(ftb),
    };

    assert_eq!(parse_extra_area(&data), Ok((&[][..], eab)));
}

fn parse_time(input: &[u8]) -> nom::IResult<&[u8], FileTimeBlock> {
    let mut ftb = FileTimeBlock {
        modification_time: None,
        creation_time: None,
        access_time: None,
    };

    let (mut inp, flags) = vint::vint(input)?;

    // unix or windows time format?
    let unix_time =  util::get_bit_at(flags, 0);

    // modification time available?
    if util::get_bit_at(flags, 1) {
        let (i, t) = convert_time(inp, unix_time)?;
        inp = i;
        ftb.modification_time = t;
    }

    // creation time available?
    if util::get_bit_at(flags, 2) {
        let (i, t) = convert_time(inp, unix_time)?;
        inp = i;
        ftb.creation_time = t;
    }

    // access time available?
    if util::get_bit_at(flags, 3) {
        let (i, t) = convert_time(inp, unix_time)?;
        inp = i;
        ftb.access_time = t;
    }

    Ok((inp, ftb))
}
#[test]
fn test_parse_time() {
    let data = [0x02, 0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x01];
    let ftb = FileTimeBlock {
        modification_time: Some(NaiveDateTime::parse_from_str("2016-11-22 11:42:49", "%Y-%m-%d %H:%M:%S").unwrap()),
        creation_time: None,
        access_time: None,
    };

    assert_eq!(parse_time(&data), Ok((&[][..], ftb)));
}

fn convert_time(input: &[u8], unix_time: bool) -> nom::IResult<&[u8], Option<NaiveDateTime>> {
    if unix_time {
        let (i, t) = nom::le_u32(take!(input, 4)?.1)?;
        let t = NaiveDateTime::from_timestamp_opt(t as i64, 0);
        Ok((i, t))
    }
    else {
        let (i, t) = nom::le_u64(take!(input, 8)?.1)?;
        let t = (t / 10000000) - 11644473600;
        let t = NaiveDateTime::from_timestamp_opt(t as i64, 0);
        Ok((i, t))
    }
}
#[test]
fn test_convert_time() {
    let data = [0x9D, 0xA1, 0xE3, 0x8C, 0xB5, 0x44, 0xD2, 0x01];
    let t = Some(NaiveDateTime::parse_from_str("2016-11-22 11:42:49", "%Y-%m-%d %H:%M:%S").unwrap());

    assert_eq!(convert_time(&data, false), Ok((&[][..], t)));
}