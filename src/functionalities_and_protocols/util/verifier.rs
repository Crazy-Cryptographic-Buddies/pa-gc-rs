use std::fmt::Debug;
use crate::value_type::{GFAddition, GFMultiplyingBit, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::VecAddition;

pub struct Verifier;

impl Verifier {
    pub fn verify_vole_correlations<GFVOLE: GFAddition + GFMultiplyingBit + Clone + Zero + Debug + PartialEq>(
        bit_vec: &BitVec,
        voleith_mac_vec: &GFVec<GFVOLE>,
        delta: &GFVOLE,
        voleith_key_vec: &GFVec<GFVOLE>,
    ) {
        println!("Verifying Voleith Correlations");
        println!("bit_vec:           {:?}", bit_vec.iter());
        println!("voleith_key_vec:   {:?}", voleith_key_vec.iter());
        println!("voleith_mac_vec:   {:?}", voleith_mac_vec.iter());
        println!("bit * nabla + key: {:?}", voleith_key_vec.vec_add(
            &GFVec::<GFVOLE>::from_vec(
                bit_vec.iter().map(
                    |bit| delta.gf_multiply_bit(*bit)
                ).collect::<Vec<GFVOLE>>()
            )
        ).iter());
        assert_eq!(
            *voleith_mac_vec,
            voleith_key_vec.vec_add(
                &GFVec::<GFVOLE>::from_vec(
                    bit_vec.iter().map(
                        |bit| delta.gf_multiply_bit(*bit)
                    ).collect::<Vec<GFVOLE>>()
                )
            )
        );
    }
}