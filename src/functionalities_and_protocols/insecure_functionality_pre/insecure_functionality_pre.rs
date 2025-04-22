use rand::Rng;
use itertools::izip;
use crate::value_type::{GFAdd, GFMultiplyingBit, InsecureRandom, Zero};
use crate::value_type::gf2p256::GF2p256;
use crate::vec_type::{
    bit_vec::BitVec,
    gf_vec::GFVec,
};

pub struct InsecureFunctionalityPre<GF: GFAdd + GFMultiplyingBit + Clone + Zero> {
    delta_a: GF,
    delta_b: GF,

    // for randome tuples
    rand_r_vec: Option<BitVec>,
    vole_mac_rand_r_vec: Option<GFVec<GF>>,
    vole_key_rand_r_vec: Option<GFVec<GF>>,
    rand_s_vec: Option<BitVec>,
    vole_mac_rand_s_vec: Option<GFVec<GF>>,
    vole_key_rand_s_vec: Option<GFVec<GF>>,

    // for random AND tuples
    rand_aa_vec: Option<BitVec>,
    rand_ab_vec: Option<BitVec>,
    rand_ba_vec: Option<BitVec>,
    rand_bb_vec: Option<BitVec>,
    rand_ca_vec: Option<BitVec>,
    rand_cb_vec: Option<BitVec>,
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
            rand_aa_vec: None,
            rand_ab_vec: None,
            rand_ba_vec: None,
            rand_bb_vec: None,
            rand_ca_vec: None,
            rand_cb_vec: None,       
        }
    }

    // pub fn get_delta_a(&self) -> &GF {
    //     &self.delta_a
    // }
    // pub fn get_delta_b(&self) -> &GF {
    //     &self.delta_b
    // }

    fn generate_random_vole_macs_and_keys(
        rand_bit_vec: &BitVec, delta: &GF
    ) -> (GFVec<GF>, GFVec<GF>) {
        let mut vole_mac_vec = GFVec::<GF>::new();
        let mut vole_key_vec = GFVec::<GF>::new();
        for bit in rand_bit_vec.iter() {
            let mac = GF::insecurely_random();
            let key = mac.gf_add(&delta.multiply_bit(&bit));
            vole_mac_vec.push(mac);
            vole_key_vec.push(key);
        }
        (vole_mac_vec, vole_key_vec)
    }

    pub fn generate_random_tuples(&mut self, num_tuples: usize) {
        let mut rng = rand::rng();
        let mut rand_r_vec= BitVec::new();
        let mut rand_s_vec = BitVec::new();
        for _ in 0..num_tuples {
            let rand_r = rng.random::<u8>() & 1;
            let rand_s = rng.random::<u8>() & 1;

            // push to vectors
            rand_r_vec.push(rand_r);
            rand_s_vec.push(rand_s);
        }

        let (
            vole_mac_rand_r_vec, vole_key_rand_r_vec
        ) = Self::generate_random_vole_macs_and_keys(
            &rand_r_vec, &self.delta_b
        );

        let (
            vole_mac_rand_s_vec, vole_key_rand_s_vec
        ) = Self::generate_random_vole_macs_and_keys(
            &rand_s_vec, &self.delta_a
        );

        self.rand_r_vec = Some(rand_r_vec);
        self.vole_mac_rand_r_vec = Some(vole_mac_rand_r_vec);
        self.vole_key_rand_r_vec = Some(vole_key_rand_r_vec);
        self.rand_s_vec = Some(rand_s_vec);
        self.vole_mac_rand_s_vec = Some(vole_mac_rand_s_vec);
        self.vole_key_rand_s_vec = Some(vole_key_rand_s_vec);
    }
    
    pub fn generate_random_and_tuples(&mut self, num_tuples: usize) {
        let mut rng = rand::rng();
        let mut rand_aa_vec= BitVec::new();
        let mut rand_ab_vec = BitVec::new();
        let mut rand_ba_vec = BitVec::new();
        let mut rand_bb_vec = BitVec::new();
        let mut rand_ca_vec = BitVec::new();
        let mut rand_cb_vec = BitVec::new();
        for _ in 0..num_tuples {
            let rand_aa = rng.random::<u8>() & 1;
            let rand_ab = rng.random::<u8>() & 1;
            let rand_ba = rng.random::<u8>() & 1;
            let rand_bb = rng.random::<u8>() & 1;
            let rand_ca = rng.random::<u8>() & 1;
            let rand_cb = ((rand_aa ^ rand_ab) & (rand_ba ^ rand_bb)) ^ rand_ca;
            rand_aa_vec.push(rand_aa);
            rand_ab_vec.push(rand_ab);
            rand_ba_vec.push(rand_ba);
            rand_bb_vec.push(rand_bb);
            rand_ca_vec.push(rand_ca);
            rand_cb_vec.push(rand_cb);
        }
        self.rand_aa_vec = Some(rand_aa_vec);
        self.rand_ab_vec = Some(rand_ab_vec);
        self.rand_ba_vec = Some(rand_ba_vec);
        self.rand_bb_vec = Some(rand_bb_vec);
        self.rand_ca_vec = Some(rand_ca_vec);
        self.rand_cb_vec = Some(rand_cb_vec);   
    }

    pub fn get_random_tuples_for_pa(&self) -> (&BitVec, &GFVec<GF>, &GFVec<GF>) {
        (
            self.rand_r_vec.as_ref().unwrap(),
            self.vole_mac_rand_r_vec.as_ref().unwrap(),
            self.vole_key_rand_s_vec.as_ref().unwrap(),
        )
    }

    pub fn get_random_tuples_for_pb(&self) -> (&BitVec, &GFVec<GF>, &GFVec<GF>) {
        (
            self.rand_s_vec.as_ref().unwrap(),
            self.vole_mac_rand_s_vec.as_ref().unwrap(),
            self.vole_key_rand_r_vec.as_ref().unwrap(),
        )
    }
    
    pub fn get_random_and_tuples_for_pa(&self) -> (&BitVec, &BitVec, &BitVec) {
        (
            self.rand_aa_vec.as_ref().unwrap(), 
            self.rand_ba_vec.as_ref().unwrap(), 
            self.rand_ca_vec.as_ref().unwrap()
        )
    }
    
    pub fn get_random_and_tuples_for_pb(&self) -> (&BitVec, &BitVec, &BitVec) {
        (
            self.rand_ab_vec.as_ref().unwrap(), 
            self.rand_bb_vec.as_ref().unwrap(), 
            self.rand_cb_vec.as_ref().unwrap()
        )
    }
}

#[test]
fn test_functionality_pre_generating_random_tuples() {
    let mut f_pre = InsecureFunctionalityPre::<GF2p256>::new();
    println!("delta_a: {:?}", f_pre.delta_a);
    println!("delta_b: {:?}", f_pre.delta_b);

    let num_random_tuples = 100;
    f_pre.generate_random_tuples(num_random_tuples);

    let (rand_r_vec, vole_mac_rand_r_vec, vole_key_rand_s_vec) = f_pre.get_random_tuples_for_pa();
    let (rand_s_vec, vole_mac_rand_s_vec, vole_key_rand_r_vec) = f_pre.get_random_tuples_for_pb();

    // check the lengths
    assert_eq!(rand_r_vec.len(), num_random_tuples);
    assert_eq!(vole_mac_rand_r_vec.len(), num_random_tuples);
    assert_eq!(vole_key_rand_r_vec.len(), num_random_tuples);
    assert_eq!(rand_s_vec.len(), num_random_tuples);
    assert_eq!(vole_mac_rand_s_vec.len(), num_random_tuples);
    assert_eq!(vole_key_rand_s_vec.len(), num_random_tuples);

    for (rand_r, vole_mac_rand_r, vole_key_rand_r) in izip!(
        rand_r_vec.iter(), vole_mac_rand_r_vec.into_iter(), vole_key_rand_r_vec.into_iter()
    ) {
        println!("rand_r, vole_mac_rand_r, vole_key_rand_r: {:?} {:?} {:?}", rand_r, vole_mac_rand_r, vole_key_rand_r);
        assert_eq!(vole_key_rand_r, &vole_mac_rand_r.gf_add(&f_pre.delta_b.multiply_bit(rand_r)));
    }

    for (rand_s, vole_mac_rand_s, vole_key_rand_s) in izip!(
        rand_s_vec.iter(), vole_mac_rand_s_vec.into_iter(), vole_key_rand_s_vec.into_iter()
    ) {
        println!("rand_s, vole_mac_rand_s, vole_key_rand_s: {:?} {:?} {:?}", rand_s, vole_mac_rand_s, vole_key_rand_s);
        assert_eq!(vole_key_rand_s, &vole_mac_rand_s.gf_add(&f_pre.delta_a.multiply_bit(rand_s)));
    }
    println!("test_functionality_pre_generating_random_tuples passed");
}

#[test]
fn test_functionality_pre_generating_random_and_tuples () {
    let mut f_pre = InsecureFunctionalityPre::<GF2p256>::new();
    
    let num_random_and_tuples = 100;
    f_pre.generate_random_and_tuples(num_random_and_tuples);
    
    let (rand_aa, rand_ba, rand_ca) = f_pre.get_random_and_tuples_for_pa();
    let (rand_ab, rand_bb, rand_cb) = f_pre.get_random_and_tuples_for_pb();
    
    for (rand_aa, rand_ba, rand_ca, rand_ab, rand_bb, rand_cb) in izip!(
        rand_aa.iter(), rand_ba.iter(), rand_ca.iter(), rand_ab.iter(), rand_bb.iter(), rand_cb.iter()
    ) {
        println!("rand_aa, rand_ba, rand_ca, rand_ab, rand_bb, rand_cb: {:?} {:?} {:?} {:?} {:?} {:?}", rand_aa, rand_ba, rand_ca, rand_ab, rand_bb, rand_cb);
        assert_eq!(rand_ca ^ rand_cb, (rand_aa ^ rand_ab) & (rand_ba ^ rand_bb));
    }
    println!("test_functionality_pre_generating_random_and_tuples passed!");
}