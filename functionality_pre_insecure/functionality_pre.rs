use std::ops::BitXor;
use rand::Rng;
use crate::gf::{Random, gf256::GF256};

struct FunctionalityPre<GF: BitXor + Random> {
    delta_a: GF,
    delta_b: GF,
    s_vec: Vec<u8>,
    vole_mac_s_vec: Vec<GF>,
    vole_key_s_vec: Vec<GF>,
    r_vec: Vec<u8>,
    vole_mac_r_vec: Vec<GF>,
    vole_key_r_vec: Vec<GF>,
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

    pub fn generate(&mut self, num_tuples: usize) {
        let mut rng = rand::rng();
        self.s_vec = Vec::new();
        self.r_vec = Vec::new();
        self.vole_mac_s_vec = Vec::new();
        self.vole_key_s_vec = Vec::new();
        self.vole_mac_r_vec = Vec::new();
        self.vole_key_r_vec = Vec::new();
        for _ in 0..num_tuples {
            let s = rng.random::<u8>() & 1;
            let r = rng.random::<u8>() & 1;
            // TODO: continue here
        }
    }
}

#[test]
fn test_functionality_pre_generation() {
    let f_pre = FunctionalityPre::<GF256>::new();
    println!("delta_a: {:?}", f_pre.get_delta_a());
    println!("delta_b: {:?}", f_pre.get_delta_b());
}