use blake3::Hash;
use rand::Rng;
use crate::value_type::{GFAdd, GFMultiplyingBit, HashDigestToGF, InsecureRandom, U8ForGF, Zero};

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl GFAdd for GF2p8 {
    fn gf_add(&self, rhs: &Self) -> Self {
        Self {
            val: self.val ^ rhs.val
        }
    }
}

impl GFMultiplyingBit for GF2p8 {
    fn multiply_bit(&self, bit: u8) -> Self {
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
