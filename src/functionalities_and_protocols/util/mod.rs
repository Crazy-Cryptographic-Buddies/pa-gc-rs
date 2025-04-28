pub(crate) mod verifier;

pub(crate) fn parse_two_bits(value: u8) -> (u8, u8) {
    (value & 1u8, (value >> 1) & 1u8)
}

#[test]
fn try_recover() {
    let k = 1;
    let (k0, k1) = parse_two_bits(k);
    println!("{:?}", k0 + 2 * k1);
}