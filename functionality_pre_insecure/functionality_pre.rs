use std::ops::BitXor;
use crate::gf::{Random, gf256::GF256};

struct FunctionalityPre<GF: BitXor + Random> {
    delta_a: GF,
    delta_b: GF,
}

impl<GF: BitXor + Random> FunctionalityPre<GF> {
    fn new() -> Self {
        Self {
            delta_a: GF::random(),
            delta_b: GF::random(),
        }
    }

    pub fn get_delta_a(&self) -> &GF {
        &self.delta_a
    }
    pub fn get_delta_b(&self) -> &GF {
        &self.delta_b
    }
}

#[test]
fn test_functionality_pre_generation() {
    let f_pre = FunctionalityPre::<GF256>::new();
    println!("delta_a: {:?}", f_pre.get_delta_a());
    println!("delta_b: {:?}", f_pre.get_delta_b());
}