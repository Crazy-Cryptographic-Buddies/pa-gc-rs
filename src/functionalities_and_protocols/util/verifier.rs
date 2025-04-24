use std::fmt::Debug;
use crate::value_type::{GFAddition, GFMultiplyingBit, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::VecAddition;

pub struct Verifier;

impl Verifier {
    pub fn verify_voleith_correlations<GFVOLEitH: GFAddition + GFMultiplyingBit + Clone + Zero + Debug + PartialEq>(
        bit_vec: &BitVec,
        voleith_mac_vec: &GFVec<GFVOLEitH>,
        nabla: &GFVOLEitH,
        voleith_key_vec: &GFVec<GFVOLEitH>,
    ) {
        println!("Verifying Voleith Correlations");
        println!("bit_vec:           {:?}", bit_vec.iter());
        println!("voleith_key_vec:   {:?}", voleith_key_vec.iter());
        println!("voleith_mac_vec:   {:?}", voleith_mac_vec.iter());
        println!("bit * nabla + key: {:?}", voleith_key_vec.vec_add(
            &GFVec::<GFVOLEitH>::from_vec(
                bit_vec.iter().map(
                    |bit| nabla.multiply_bit(*bit)
                ).collect::<Vec<GFVOLEitH>>()
            )
        ).iter());
        assert_eq!(
            *voleith_mac_vec,
            voleith_key_vec.vec_add(
                &GFVec::<GFVOLEitH>::from_vec(
                    bit_vec.iter().map(
                        |bit| nabla.multiply_bit(*bit)
                    ).collect::<Vec<GFVOLEitH>>()
                )
            )
        );
    }
}