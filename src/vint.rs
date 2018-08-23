use nom;

/// Returns the next complete vint number as u64.
pub fn vint(input: &[u8]) -> nom::IResult<&[u8], u64> {
    let mut out: u64;

    // collect all u8 with a high bit
    // if no high bit is available fail
    match collect_vint(input) {
        Ok(v) => {
            // get just the data bit's from the collection
            let coll = v.1.iter().map(|x| split_vint(x.clone()).1 as u64).collect::<Vec<u64>>();
            let mut len = coll.len();

            // we starting from the back, so we take the last byte with is not part of
            // the collection, because it has no high bit
            if let Ok(f) = take_one(&input[len..]) {
                out = split_vint(f.1[0]).1 as u64;
            }
            else {
                return Err(nom::Err::Incomplete(nom::Needed::Size(1)));
            }

            
            
            // afterwards we are looping in a reversed order over the collection
            // to push all the remaining bits to our vint
            for i in coll.iter().rev() {
                out = out << 7;
                out += i;        
            }
            
            // define the right the length to push the input foreward
            len += 1;
            return Ok((&input[len..], out));
        },
        // we only end the function early when there is not enough data
        Err(e) => {
            if e.is_incomplete() {
                return Err(e);
            }
        }
    }

    // when no high bit is available, just
    // take one u8 and give it back as u8
    out = take_one(input)?.1[0] as u64;
    Ok((&input[1..], out))
}
#[test]
fn test_vint() {
    assert_eq!(vint(&[0x01, 0xFF, 0x00]), Ok((&[0xFF, 0x00][..], 0x01)));
    assert_eq!(vint(&[0xFF, 0x01, 0x00]), Ok((&[0x00][..], 0xFF)));
    assert_eq!(vint(&[0xFF, 0xFF, 0x00]), Ok((&[][..], 0x3fff)));
    assert_eq!(vint(&[0x80, 0xFF, 0x80, 0x00]), Ok((&[][..], 0x3f80)));
    assert!(vint(&[]).is_err());
    assert!(vint(&[0xFF, 0xFF]).is_err());
}

/// Collect all vint which have a hight bit
/// Failes if no bit is available or the array end's with a high bit
named!(collect_vint(&[u8]) -> (&[u8]),
    take_while1!(is_vint_bit)
);
#[test]
fn test_collect_vint() {
    assert_eq!(collect_vint(&[0xFF, 0xFF, 0x00]), Ok((&[0x00][..],  &[0xFF, 0xFF][..])));
    assert_eq!(collect_vint(&[0xFF, 0xFF, 0x00, 0xFF]), Ok((&[0x00, 0xFF][..],  &[0xFF, 0xFF][..])));
    assert!(collect_vint(&[0xFF, 0xFF]).is_err());
    assert!(collect_vint(&[0x01]).is_err());
    assert!(collect_vint(&[0x01, 0x01]).is_err());
    assert!(collect_vint(&[]).is_err());
}

/// Take one byte
named!(take_one(&[u8]) -> (&[u8]),
    take!(1)
);
#[test]
fn test_take_one() {
    assert_eq!(take_one(&[0xFF, 0xFF, 0x00]), Ok((&[0xFF, 0x00][..],  &[0xFF][..])));
    assert_eq!(take_one(&[0xFF, 0xFF, 0x00, 0xFF]), Ok((&[0xFF, 0x00, 0xFF][..],  &[0xFF][..])));
    assert!(take_one(&[]).is_err());
}

/// split vint into data and extension bit
fn split_vint(i: u8) -> (u8, u8) {
    (i >> 7, (i << 1) >> 1)
}
#[test]
fn test_split_vint() {
    assert_eq!(split_vint(0xFF), (0x01, 0x7F));
    assert_eq!(split_vint(0x80), (0x01, 0x00));
    assert_eq!(split_vint(0x7F), (0x00, 0x7F));
    assert_eq!(split_vint(0x00), (0x00, 0x00));
    assert_eq!(split_vint(0x01), (0x00, 0x01));
}

/// check if the extension bit is set
fn is_vint_bit(a: u8) -> bool {
    a >> 7 == 1
}
#[test]
fn test_is_vint_bit() {
    assert_eq!(is_vint_bit(0xFF), true);
    assert_eq!(is_vint_bit(0x7F), false);
    assert_eq!(is_vint_bit(0x00), false);
    assert_eq!(is_vint_bit(0x01), false);
}