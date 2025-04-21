use std::ops::BitXor;
use rand::Rng;
use crate::gf::{GFAdd, GFMultiplyingBit, Random};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GF256 {
    val: (u64, u64, u64, u64)
}

impl GF256 {
    pub fn new(val: &(u64, u64, u64, u64)) -> Self {
        Self { val: *val }
    }
}

impl GFAdd for GF256 {
    fn add(&self, rhs: &Self) -> Self {
        Self {
            val: (
                self.val.0 ^ rhs.val.0,
                self.val.1 ^ rhs.val.1,
                self.val.2 ^ rhs.val.2,
                self.val.3 ^ rhs.val.3
            )
        }
    }
}

impl GFMultiplyingBit for GF256 {
    fn multiply_bit(&self, bit: &u8) -> Self {
        if *bit == 0 {
            Self {
                val: (0, 0, 0, 0)
            }
        } else if *bit == 1 {
            self.clone()
        } else {
            panic!("{:?} is not binary!", bit);
        }
    }
}

impl Random for GF256 {
    fn random() -> Self {
        let mut rng = rand::rng();
        let v0 = rng.random::<u64>();
        let v1 = rng.random::<u64>();
        let v2 = rng.random::<u64>();
        let v3 = rng.random::<u64>();
        Self { val: (v0, v1, v2, v3) }
    }
}