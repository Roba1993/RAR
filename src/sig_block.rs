use nom;

/// Signature of the .rar File. It can be either RAR5 or RAR4
#[derive(PartialEq, Debug, Clone)]
pub enum SignatureBlock {
    RAR5,
    RAR4
}

impl SignatureBlock {
    /// Parse the .rar SignatureBlock
    pub fn parse(inp: &[u8]) -> nom::IResult<&[u8], SignatureBlock> {
        rar_signature(inp)
    }
}

// get a rar file signature
named!(rar_signature(&[u8]) -> (SignatureBlock), 
    alt!(value!(SignatureBlock::RAR5, rar5_signature) | value!(SignatureBlock::RAR4, rar4_signature))
);
#[test]
fn test_rar_signature() {
    // rar 5 header test
    assert_eq!(rar_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]), Ok((&b""[..], SignatureBlock::RAR5)));
    // rar 4 header test
    assert_eq!(rar_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]), Ok((&b""[..], SignatureBlock::RAR4)));
}

// get a rar 5 file signature
named!(rar5_signature(&[u8]) -> (&[u8], &[u8]), 
    pair!(rar_pre_signature, tag!([0x1A, 0x07, 0x01, 0x00]))
);
#[test]
fn test_rar5_signature() {
    // rar 5 header test
    assert!(rar5_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]).is_ok());
    // rar 5 header test
    assert!(rar5_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]).is_err());
}

// get a rar 4 file signature
named!(rar4_signature(&[u8]) -> (&[u8], &[u8]), 
    pair!(rar_pre_signature, tag!([0x1A, 0x07, 0x00]))
);
#[test]
fn test_rar4_signature() {
    // rar 4 header test
    assert!(rar4_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]).is_err());
    // rar 4 header test
    assert!(rar4_signature(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]).is_ok());
}

// get the general rar file signature
named!(rar_pre_signature, tag!("Rar!"));
#[test]
fn test_rar_pre_signature() {
    assert_eq!(rar_pre_signature(b"Rar!"), Ok((&b""[..], &b"Rar!"[..])));
    assert_eq!(rar_pre_signature(b"Rar!asdad"), Ok((&b"asdad"[..], &b"Rar!"[..])));
    assert!(rar_pre_signature(b"wrog").is_err());
}