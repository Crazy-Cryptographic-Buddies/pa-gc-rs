use galois_2p8::{Field, GeneralField};

pub type Message = Vec<u8>;
pub type VOLEitHMACTag = Vec<u8>;
pub type VOLEitHMACKey = Vec<u8>;

pub const SEED_BYTE_LEN: usize = 16;
pub const NUM_BITS_PER_HEX: usize = 4;

pub type SeedU8x16 = [u8; SEED_BYTE_LEN];

#[derive(Debug)]
pub enum GateType {
    AND,
    XOR,
    NOT,
}

pub trait Zero {
    fn zero() -> Self;
}

impl Zero for SeedU8x16 {
    fn zero() -> Self {
        [0; SEED_BYTE_LEN]
    }
}