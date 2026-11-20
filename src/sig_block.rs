use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::value;
use nom::Parser;

/// Signature of the .rar File. It can be either RAR5 or RAR4
#[derive(PartialEq, Debug, Clone)]
pub enum SignatureBlock {
    RAR5,
    RAR4,
}

impl SignatureBlock {
    /// Parse the .rar SignatureBlock
    pub fn parse(inp: &[u8]) -> nom::IResult<&[u8], SignatureBlock> {
        rar_signature(inp)
    }
}

fn rar_signature(input: &[u8]) -> nom::IResult<&[u8], SignatureBlock> {
    alt((
        value(SignatureBlock::RAR5, rar5_signature),
        value(SignatureBlock::RAR4, rar4_signature),
    ))
    .parse(input)
}

fn rar5_signature(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let (input, _) = rar_pre_signature(input)?;
    tag(b"\x1A\x07\x01\x00".as_slice())(input)
}

fn rar4_signature(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let (input, _) = rar_pre_signature(input)?;
    tag(b"\x1A\x07\x00".as_slice())(input)
}

fn rar_pre_signature(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    tag("Rar!")(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rar_signature() {
        // rar 5 header test
        assert_eq!(
            rar_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
            Ok((&b""[..], SignatureBlock::RAR5))
        );
        // rar 4 header test
        assert_eq!(
            rar_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
            Ok((&b""[..], SignatureBlock::RAR4))
        );
    }

    #[test]
    fn test_rar_pre_signature() {
        assert_eq!(
            rar_pre_signature(&[0x52, 0x61, 0x72, 0x21]),
            Ok((&b""[..], &b"Rar!"[..]))
        );
    }

    #[test]
    fn test_rar5_signature() {
        assert_eq!(
            rar5_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
            Ok((&b""[..], &[0x1A, 0x07, 0x01, 0x00][..]))
        );
    }

    #[test]
    fn test_rar4_signature() {
        assert_eq!(
            rar4_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
            Ok((&b""[..], &[0x1A, 0x07, 0x00][..]))
        );
    }
}
