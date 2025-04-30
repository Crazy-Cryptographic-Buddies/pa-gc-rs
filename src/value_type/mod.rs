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
        *cursor += Self::num_bytes();
        val
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![*self]
    }

    fn num_bytes() -> usize {
        1
    }
}

impl ByteManipulation for u32 {
    fn from_bytes(bytes: &[u8], cursor: &mut usize) -> Self {
        let val: u32 = (bytes[*cursor] as u32)
            | ((bytes[*cursor + 1] as u32) << 8)
            | ((bytes[*cursor + 2] as u32) << 16)
            | ((bytes[*cursor + 3] as u32) << 24);
        *cursor += Self::num_bytes();
        val
    }

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn num_bytes() -> usize {
        4
    }
}

impl ByteManipulation for u64 {
    fn from_bytes(bytes: &[u8], cursor: &mut usize) -> Self {
        let val: u64 = (bytes[*cursor] as u64)
            | ((bytes[*cursor + 1] as u64) << 8)
            | ((bytes[*cursor + 2] as u64) << 16)
            | ((bytes[*cursor + 3] as u64) << 24)
            | ((bytes[*cursor + 4] as u64) << 32)
            | ((bytes[*cursor + 5] as u64) << 40)
            | ((bytes[*cursor + 6] as u64) << 48)
            | ((bytes[*cursor + 7] as u64) << 56);
        *cursor += Self::num_bytes();
        val
    }

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }

    fn num_bytes() -> usize {
        8
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