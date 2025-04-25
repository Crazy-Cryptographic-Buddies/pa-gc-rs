use rand::Rng;
use itertools::izip;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{GFAddition, GFMultiplyingBit, InsecureRandom, Zero};
use crate::value_type::gf2p256::GF2p256;
use crate::vec_type::{
    bit_vec::BitVec,
    gf_vec::GFVec,
};

pub struct InsecureFunctionalityPre;

impl InsecureFunctionalityPre {

    fn generate_random_vole_macs_and_keys<GFVOLE: InsecureRandom + GFAddition + GFMultiplyingBit+ Clone + Zero>(
        delta: &GFVOLE,
        rand_bit_vec: &BitVec,
    ) -> (GFVec<GFVOLE>, GFVec<GFVOLE>) {
        let mut vole_mac_vec = GFVec::<GFVOLE>::new();
        let mut vole_key_vec = GFVec::<GFVOLE>::new();
        for bit in rand_bit_vec.iter() {
            let mac = GFVOLE::insecurely_random();
            let key = mac.gf_add(&delta.multiply_bit(*bit));
            vole_mac_vec.push(mac);
            vole_key_vec.push(key);
        }
        (vole_mac_vec, vole_key_vec)
    }

    pub fn generate_random_tuples<GFVOLE, GFVOLEitH>(
        public_parameter: &PublicParameter,
        delta: &GFVOLE,
        rand_r_bit_vec: &mut Option<BitVec>,
        vole_mac_rand_r_vec: &mut Option<GFVec<GFVOLE>>,
        vole_key_rand_r_vec: &mut Option<GFVec<GFVOLE>>,
    ) 
    where GFVOLE: InsecureRandom + GFAddition + Clone + GFMultiplyingBit + Zero {
        let mut rng = rand::rng();
        *rand_r_bit_vec = Some(
            BitVec::from_vec(
                (0..public_parameter.sum_big_ia_ib_iw).into_iter().map(
                    |_| rng.random::<u8>() & 1u8
                ).collect()
            )
        );

        let (
            vole_mac_vec, vole_key_vec
        ) = Self::generate_random_vole_macs_and_keys(
            delta, rand_r_bit_vec.as_ref().unwrap(),
        );
        *vole_mac_rand_r_vec = Some(vole_mac_vec);
        *vole_key_rand_r_vec = Some(vole_key_vec);
    }
    
    pub fn generate_random_and_tuples(len: usize) -> (
        (BitVec, BitVec, BitVec),
        (BitVec, BitVec, BitVec)
    ) {
        let mut rng = rand::rng();
        let mut pa_rand_a_bit_vec= BitVec::new();
        let mut pa_rand_b_bit_vec = BitVec::new();
        let mut pa_rand_c_bit_vec = BitVec::new();
        let mut pb_rand_a_bit_vec = BitVec::new();
        let mut pb_rand_b_bit_vec = BitVec::new();
        let mut pb_rand_c_bit_vec = BitVec::new();
        for _ in 0..len {
            let pa_rand_a_bit = rng.random::<u8>() & 1;
            let pa_rand_b_bit = rng.random::<u8>() & 1;
            let pa_rand_c_bit = rng.random::<u8>() & 1;
            let pb_rand_a_bit = rng.random::<u8>() & 1;
            let pb_rand_b_bit = rng.random::<u8>() & 1;
            let pb_rand_c_bit = (
                (pa_rand_a_bit ^ pb_rand_a_bit) & (pa_rand_b_bit ^ pb_rand_b_bit)
            ) ^ pa_rand_c_bit;
            pa_rand_a_bit_vec.push(pa_rand_a_bit);
            pa_rand_b_bit_vec.push(pa_rand_b_bit);
            pa_rand_c_bit_vec.push(pa_rand_c_bit);
            pb_rand_a_bit_vec.push(pb_rand_a_bit);
            pb_rand_b_bit_vec.push(pb_rand_b_bit);
            pb_rand_c_bit_vec.push(pb_rand_c_bit);
        }
        (
            (pa_rand_a_bit_vec, pa_rand_b_bit_vec, pa_rand_c_bit_vec),
            (pb_rand_a_bit_vec, pb_rand_b_bit_vec, pb_rand_c_bit_vec),
        )
    }

    // pub fn get_random_tuples_for_pa(&self) -> (&BitVec, &GFVec<GF>, &GFVec<GF>) {
    //     (
    //         self.rand_r_vec.as_ref().unwrap(),
    //         self.vole_mac_rand_r_vec.as_ref().unwrap(),
    //         self.vole_key_rand_s_vec.as_ref().unwrap(),
    //     )
    // }
    // 
    // pub fn get_random_tuples_for_pb(&self) -> (&BitVec, &GFVec<GF>, &GFVec<GF>) {
    //     (
    //         self.rand_s_vec.as_ref().unwrap(),
    //         self.vole_mac_rand_s_vec.as_ref().unwrap(),
    //         self.vole_key_rand_r_vec.as_ref().unwrap(),
    //     )
    // }
    // 
    // pub fn get_random_and_tuples_for_pa(&self) -> (&BitVec, &BitVec, &BitVec) {
    //     (
    //         self.rand_aa_vec.as_ref().unwrap(), 
    //         self.rand_ba_vec.as_ref().unwrap(), 
    //         self.rand_ca_vec.as_ref().unwrap()
    //     )
    // }
    // 
    // pub fn get_random_and_tuples_for_pb(&self) -> (&BitVec, &BitVec, &BitVec) {
    //     (
    //         self.rand_ab_vec.as_ref().unwrap(), 
    //         self.rand_bb_vec.as_ref().unwrap(), 
    //         self.rand_cb_vec.as_ref().unwrap()
    //     )
    // }
}

#[test]
fn test_functionality_pre_generating_random_tuples() {
    let delta_a = GF2p256::insecurely_random();
    let delta_b = GF2p256::insecurely_random();
    println!("delta_a: {:?}", delta_a);
    println!("delta_b: {:?}", delta_b);

    let num_random_tuples = 100;
    let (
        (pa_rand_a_bit_vec, pa_rand_b_bit_vec, pa_rand_c_bit_vec),
        (pb_rand_a_bit_vec, pb_rand_b_bit_vec, pb_rand_c_bit_vec)
    ) = InsecureFunctionalityPre::generate_random_tuples(num_random_tuples);

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
        assert_eq!(vole_key_rand_r, &vole_mac_rand_r.gf_add(&f_pre.delta_b.multiply_bit(*rand_r)));
    }

    for (rand_s, vole_mac_rand_s, vole_key_rand_s) in izip!(
        rand_s_vec.iter(), vole_mac_rand_s_vec.into_iter(), vole_key_rand_s_vec.into_iter()
    ) {
        println!("rand_s, vole_mac_rand_s, vole_key_rand_s: {:?} {:?} {:?}", rand_s, vole_mac_rand_s, vole_key_rand_s);
        assert_eq!(vole_key_rand_s, &vole_mac_rand_s.gf_add(&f_pre.delta_a.multiply_bit(*rand_s)));
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