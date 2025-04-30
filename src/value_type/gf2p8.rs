use bincode::Encode;
use blake3::Hash;
use rand::Rng;
use crate::value_type::{ByteManipulation, CustomAddition, CustomMultiplyingBit, HashDigestToGF, InsecureRandom, U8ForGF, Zero};

#[derive(Debug, Clone, PartialEq, Eq, Copy, Encode)]
pub struct GF2p8 {
    val: u8
}

impl U8ForGF for GF2p8 {
    fn from_u8(u8_value: u8) -> Self {
        Self {
            val: u8_value
        }
    }

    fn get_u8(&self) -> u8 {
        self.val
    }
}

impl CustomAddition for GF2p8 {
    fn custom_add(&self, rhs: &Self) -> Self {
        Self {
            val: self.val ^ rhs.val
        }
    }
}

impl CustomMultiplyingBit for GF2p8 {
    fn custom_multiply_bit(&self, bit: u8) -> Self {
        if bit == 0 {
            Self {
                val: 0
            }
        } else if bit == 1 {
            self.clone()
        } else {
            panic!("{:?} is not binary!", bit);
        }
    }
}

impl InsecureRandom for GF2p8 {
    fn insecurely_random() -> Self {
        let mut rng = rand::rng();
        let v = rng.random::<u8>();
        Self { val: v }
    }
}

impl Zero for GF2p8 {
    fn zero() -> Self {
        Self {
            val: 0u8
        }
    }
}

impl HashDigestToGF for GF2p8 {
    fn from_hash_digest(hash_digest: &Hash) -> Self {
        Self {
            val: hash_digest.as_bytes()[0]
        }
    }
}

impl ByteManipulation for GF2p8 {

    fn from_bytes(bytes: &[u8], cursor: &mut usize) -> Self {
        let val = bytes[*cursor];
        *cursor += 1;
        Self {
            val
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        vec![self.val]
    }

    fn num_bytes() -> usize {
        1
    }
}