use std::ops::BitXor;
use rand::Rng;
use itertools::izip;
use crate::value_type::{GFAdd, GFMultiplyingBit, InsecureRandom, Zero};
use crate::value_type::gf2p256::GF2p256;
use crate::vec_type::{
    bit_vec::BitVec,
    gf_vec::GFVec,
};

struct InsecureFunctionalityPre<GF: GFAdd + GFMultiplyingBit + Clone + Zero> {
    delta_a: GF,
    delta_b: GF,
    rand_r_vec: Option<BitVec>,
    vole_mac_rand_r_vec: Option<GFVec<GF>>,
    vole_key_rand_r_vec: Option<GFVec<GF>>,
    rand_s_vec: Option<BitVec>,
    vole_mac_rand_s_vec: Option<GFVec<GF>>,
    vole_key_rand_s_vec: Option<GFVec<GF>>,
}

impl<GF: InsecureRandom + GFAdd + GFMultiplyingBit + Clone + Zero> InsecureFunctionalityPre<GF> {
    fn new() -> Self {
        Self {
            delta_a: GF::insecurely_random(),
            delta_b: GF::insecurely_random(),
            rand_r_vec: None,
            vole_mac_rand_r_vec: None,
            vole_key_rand_r_vec: None,
            rand_s_vec: None,
            vole_mac_rand_s_vec: None,
            vole_key_rand_s_vec: None,
        }
    }

    // pub fn get_delta_a(&self) -> &GF {
    //     &self.delta_a
    // }
    // pub fn get_delta_b(&self) -> &GF {
    //     &self.delta_b
    // }

    pub fn generate_random(&mut self, num_random_voles: usize) {
        let mut rng = rand::rng();
        let mut rand_r_vec= BitVec::new();
        let mut vole_mac_rand_r_vec = GFVec::<GF>::new();
        let mut vole_key_rand_r_vec = GFVec::<GF>::new();
        let mut rand_s_vec = BitVec::new();
        let mut vole_mac_rand_s_vec = GFVec::<GF>::new();
        let mut vole_key_rand_s_vec = GFVec::<GF>::new();
        for _ in 0..num_random_voles {
            let rand_r = rng.random::<u8>() & 1;
            let rand_s = rng.random::<u8>() & 1;

            // sample M[r] and K[s]
            let mac_rand_r = GF::insecurely_random();
            let key_rand_s = GF::insecurely_random();

            // now compute M[s] and K[r]
            let mac_rand_s = key_rand_s.add(&self.delta_a.multiply_bit(&rand_s));
            let key_rand_r = mac_rand_r.add(&self.delta_b.multiply_bit(&rand_r));

            // push to vectors
            rand_r_vec.push(rand_r);
            vole_mac_rand_r_vec.push(mac_rand_r);
            vole_key_rand_r_vec.push(key_rand_r);
            rand_s_vec.push(rand_s);
            vole_mac_rand_s_vec.push(mac_rand_s);
            vole_key_rand_s_vec.push(key_rand_s);
        }
        self.rand_r_vec = Some(rand_r_vec);
        self.vole_mac_rand_r_vec = Some(vole_mac_rand_r_vec);
        self.vole_key_rand_r_vec = Some(vole_key_rand_r_vec);
        self.rand_s_vec = Some(rand_s_vec);
        self.vole_mac_rand_s_vec = Some(vole_mac_rand_s_vec);
        self.vole_key_rand_s_vec = Some(vole_key_rand_s_vec);
    }

    pub fn get_random_for_pa(&self) -> (&BitVec, &GFVec<GF>, &GFVec<GF>) {
        (
            self.rand_r_vec.as_ref().unwrap(),
            self.vole_mac_rand_r_vec.as_ref().unwrap(),
            self.vole_key_rand_s_vec.as_ref().unwrap(),
        )
    }

    pub fn get_random_for_pb(&self) -> (&BitVec, &GFVec<GF>, &GFVec<GF>) {
        (
            self.rand_s_vec.as_ref().unwrap(),
            self.vole_mac_rand_s_vec.as_ref().unwrap(),
            self.vole_key_rand_r_vec.as_ref().unwrap(),
        )
    }
}

#[test]
fn test_functionality_pre_generation() {
    let mut f_pre = InsecureFunctionalityPre::<GF2p256>::new();
    println!("delta_a: {:?}", f_pre.delta_a);
    println!("delta_b: {:?}", f_pre.delta_b);

    let num_random_voles = 100;
    f_pre.generate_random(num_random_voles);

    let (rand_r_vec, vole_mac_rand_r_vec, vole_key_rand_s_vec) = f_pre.get_random_for_pa();
    let (rand_s_vec, vole_mac_rand_s_vec, vole_key_rand_r_vec) = f_pre.get_random_for_pb();

    // check the lengths
    assert_eq!(rand_r_vec.len(), num_random_voles);
    assert_eq!(vole_mac_rand_r_vec.len(), num_random_voles);
    assert_eq!(vole_key_rand_r_vec.len(), num_random_voles);
    assert_eq!(rand_s_vec.len(), num_random_voles);
    assert_eq!(vole_mac_rand_s_vec.len(), num_random_voles);
    assert_eq!(vole_key_rand_s_vec.len(), num_random_voles);

    for (rand_r, vole_mac_rand_r, vole_key_rand_r) in izip!(
        rand_r_vec.iter(), vole_mac_rand_r_vec.into_iter(), vole_key_rand_r_vec.into_iter()
    ) {
        println!("rand_r, vole_mac_rand_r, vole_key_rand_r: {:?} {:?} {:?}", rand_r, vole_mac_rand_r, vole_key_rand_r);
        assert_eq!(vole_key_rand_r, &vole_mac_rand_r.add(&f_pre.delta_b.multiply_bit(rand_r)));
    }

    for (rand_s, vole_mac_rand_s, vole_key_rand_s) in izip!(
        rand_s_vec.iter(), vole_mac_rand_s_vec.into_iter(), vole_key_rand_s_vec.into_iter()
    ) {
        println!("rand_s, vole_mac_rand_s, vole_key_rand_s: {:?} {:?} {:?}", rand_s, vole_mac_rand_s, vole_key_rand_s);
        assert_eq!(vole_key_rand_s, &vole_mac_rand_s.add(&f_pre.delta_a.multiply_bit(rand_s)));
    }
    println!("test_functionality_pre_generation passed");
}