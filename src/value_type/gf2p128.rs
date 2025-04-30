use bincode::Encode;
use rand::Rng;
use crate::value_type::{ByteManipulation, CustomAddition, CustomMultiplyingBit, InsecureRandom, Zero};

#[derive(Debug, Clone, PartialEq, Eq, Copy, Encode)]
pub struct GF2p128 {
    val: (u64, u64)
}

impl GF2p128 {
    // pub fn new(val: &(u64, u64, u64, u64)) -> Self {
    //     Self { val: *val }
    // }
}

impl Zero for GF2p128 {
    fn zero() -> Self {
        Self { val: (0, 0) }
    }
}

impl CustomAddition for GF2p128 {
    fn custom_add(&self, rhs: &Self) -> Self {
        Self {
            val: (
                self.val.0 ^ rhs.val.0,
                self.val.1 ^ rhs.val.1,
            )
        }
    }
}

impl CustomMultiplyingBit for GF2p128 {
    fn custom_multiply_bit(&self, bit: u8) -> Self {
        if bit == 0 {
            Self {
                val: (0, 0)
            }
        } else if bit == 1 {
            self.clone()
        } else {
            panic!("{:?} is not binary!", bit);
        }
    }
}

impl InsecureRandom for GF2p128 {
    fn insecurely_random() -> Self {
        let mut rng = rand::rng();
        let v0 = rng.random::<u64>();
        let v1 = rng.random::<u64>();
        Self { val: (v0, v1) }
    }
}

impl ByteManipulation for GF2p128 {
    fn from_bytes(bytes: &[u8], cursor: &mut usize) -> Self {
        let v0 = u64::from_bytes(&bytes, cursor);
        let v1 = u64::from_bytes(&bytes, cursor);
        Self {
            val: (v0, v1)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut res = vec![0; Self::num_bytes()];
        let mut cursor = 0;
        res[cursor..cursor+8].copy_from_slice(&(self.val.0).to_le_bytes());
        cursor += 8;
        res[cursor..cursor+8].copy_from_slice(&(self.val.1).to_le_bytes());
        res
    }

    fn num_bytes() -> usize {
        16
    }
}