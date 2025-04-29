use blake3::Hash;

pub mod gf2p256;
pub mod gf2p8;
pub mod seed_u8x16;
pub(crate) mod garbled_row;

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

pub trait ByteManipulation {
    fn from_bytes(bytes: &[u8], cursor: &mut usize) -> Self;
    fn to_bytes(&self) -> Vec<u8>;

    fn num_bytes() -> usize;
}

impl ByteManipulation for u8 {
    fn from_bytes(bytes: &[u8], cursor: &mut usize) -> Self {
        let val = bytes[*cursor];
        *cursor += 1;
        val
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![*self]
    }

    fn num_bytes() -> usize {
        1
    }
}

pub trait CustomMultiplyingBit {
    fn custom_multiply_bit(&self, bit: u8) -> Self;
}

pub trait CustomAddition {
    fn custom_add(&self, rhs: &Self) -> Self;
}

pub trait HashDigestToGF {
    fn from_hash_digest(hash_digest: &Hash) -> Self;
}