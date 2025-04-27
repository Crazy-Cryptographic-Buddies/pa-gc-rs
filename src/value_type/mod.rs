use blake3::Hash;

pub(crate) mod gf2p256;
pub mod gf2p8;
pub mod seed_u8x16;

pub trait InsecureRandom {
    fn insecurely_random() -> Self;
}

pub trait Zero {
    fn zero() -> Self;
}

impl Zero for u8 {
    fn zero() -> Self {
        0
    }   
}

pub trait U8ForGF {
    fn from_u8(u8_value: u8) -> Self;
    fn get_u8(&self) -> u8;
}

pub trait GFMultiplyingBit {
    fn gf_multiply_bit(&self, bit: u8) -> Self;
}

pub trait GFAddition {
    fn gf_add(&self, rhs: &Self) -> Self;
}

pub trait HashDigestToGF {
    fn from_hash_digest(hash_digest: &Hash) -> Self;
}

pub trait ByteCount {
    fn num_bytes() -> usize;
}