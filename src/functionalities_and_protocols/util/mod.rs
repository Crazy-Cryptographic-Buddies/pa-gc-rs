pub(crate) mod verifier;

pub(crate) fn parse_two_bits(value: u8) -> (u8, u8) {
    (value & 1u8, (value >> 1) & 1u8)
}