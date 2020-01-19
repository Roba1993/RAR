/// Returns true or fals if the bit is set at the given position
pub fn get_bit_at(input: u64, n: u64) -> bool {
    if n < 64 {
        input & (1 << n) != 0
    } else {
        false
    }
}
#[test]
fn test_get_bit_at() {
    assert_eq!(get_bit_at(0xFF, 1), true);
    assert_eq!(get_bit_at(0x7F, 7), false);
    assert_eq!(get_bit_at(0x7F, 6), true);
    assert_eq!(get_bit_at(0x00, 0), false);
    assert_eq!(get_bit_at(0x01, 0), true);
    assert_eq!(get_bit_at(0x02, 0), false);
    assert_eq!(get_bit_at(0x02, 1), true);
}

/// Split an u64 back to an array of u8
///
/// This is usefull if you need to have bytes again out of an
/// vint
pub fn split_u64(x: u64) -> [u8; 8] {
    let x = x.clone();
    let b1: u8 = ((x >> 56) & 0xff) as u8;
    let b2: u8 = ((x >> 48) & 0xff) as u8;
    let b3: u8 = ((x >> 40) & 0xff) as u8;
    let b4: u8 = ((x >> 32) & 0xff) as u8;
    let b5: u8 = ((x >> 24) & 0xff) as u8;
    let b6: u8 = ((x >> 16) & 0xff) as u8;
    let b7: u8 = ((x >> 8) & 0xff) as u8;
    let b8: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4, b5, b6, b7, b8];
}
#[test]
fn test_split_u64() {
    assert_eq!(
        split_u64(0x00000000),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        split_u64(0x000000FF),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]
    );
    assert_eq!(
        split_u64(0x0000FF00),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00]
    );
    assert_eq!(
        split_u64(0x00FF0000),
        [0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00]
    );
    assert_eq!(
        split_u64(0xFF000000),
        [0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        split_u64(0x0F0F0F0F),
        [0x00, 0x00, 0x00, 0x00, 0x0F, 0x0F, 0x0F, 0x0F]
    );
}

/// This function returns true when the value is greater than zero.
/// If the value is zero, return false
pub fn to_bool(i: u8) -> bool {
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
