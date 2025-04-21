pub const SEED_BYTE_LEN: usize = 16;
pub const NUM_BITS_PER_HEX: usize = 4;

#[derive(Debug)]
pub enum GateType {
    AND,
    XOR,
    NOT,
}
