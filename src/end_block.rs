use head_block::HeadBlock;
use nom;
use util::to_bool;
use vint::vint;

/// EndBlock which determines the end of an .rar file
#[derive(PartialEq, Debug, Default)]
pub struct EndBlock {
    pub head: HeadBlock,
    pub last_volume: bool,
}

impl EndBlock {
    /// Parse the end block information from a byte slice
    pub fn parse(inp: &[u8]) -> nom::IResult<&[u8], EndBlock> {
        // get the base header
        let (input, head) = HeadBlock::parse(inp)?;

        // check if the defined type is end archive header
        if head.typ != ::head_block::Typ::EndArchive {
            return Err(nom::Err::Error(error_position!(inp, nom::ErrorKind::IsNot)));
        }

        // check for the last volume flag
        let (input, lv) = vint(input)?;
        let last_volume = !to_bool(lv as u8);

        // create the end block
        let end = EndBlock { head, last_volume };

        Ok((input, end))
    }
}

#[test]
fn test_archive() {
    // test a success case
    let data = [0x1D, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00];

    let mut flags = ::head_block::Flags::new();
    flags.skip = true;
    let arc = EndBlock {
        head: HeadBlock::new(494360145, 3, ::head_block::Typ::EndArchive, flags),
        last_volume: true,
    };
    assert_eq!(EndBlock::parse(&data), Ok((&[][..], arc)));

    // test a wrong header type
    let data = [
        0xF3, 0xE1, 0x82, 0xEB, 0x0B, 0x02, 0x05, 0x07, 0x00, 0x06, 0x01, 0x01, 0x80, 0x80, 0x80,
        0x00, 0x8C, 0x0D, 0x88, 0xE2,
    ];
    assert_eq!(
        EndBlock::parse(&data),
        Err(nom::Err::Error(error_position!(
            &data[..],
            nom::ErrorKind::IsNot
        )))
    );
}
