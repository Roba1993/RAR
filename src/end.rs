use header::Header;
use nom;
use header::header;
use util::to_bool;
use vint::vint;

/// Archive header
#[derive(PartialEq, Debug, Default)]
pub struct EndBlock {
    pub head: Header,
    pub last_volume: bool,
}

/// Returns an archive
pub fn end_block(inp: &[u8]) -> nom::IResult<&[u8], EndBlock> {
    // get the base header
    let (input, head) = header(inp)?;

    // check if the defined type is archive header
    if head.typ != ::header::Typ::EndArchive {
        return Err(nom::Err::Error(error_position!(inp, nom::ErrorKind::IsNot)));
    }

    let (input, lv) = vint(input)?;
    let last_volume = !to_bool(lv as u8);

    let end = EndBlock {
        head,
        last_volume,
    };

    Ok((input, end))
}
#[test]
fn test_archive() {
    // test a success case
    let data = [
        0x1D, 0x77 , 0x56 , 0x51 , 0x03 , 0x05 , 0x04 , 0x00
    ];

    let mut flags = ::header::Flags::new();
    flags.skip = true;
    let arc = EndBlock {
        head: Header::new(494360145, 3, ::header::Typ::EndArchive, flags),
        last_volume: true
    };
    assert_eq!(end_block(&data), Ok((&[][..], arc)));

    // test a wrong header type
    let data = [
        0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x02, 0x05, 0x07,
        0x00, 0x06, 0x01, 0x01, 0x80, 0x80, 0x80, 0x00, 0x8C, 
        0x0D, 0x88, 0xE2, 
    ];
    assert_eq!(end_block(&data), Err(nom::Err::Error(error_position!(&data[..], nom::ErrorKind::IsNot))));
}
