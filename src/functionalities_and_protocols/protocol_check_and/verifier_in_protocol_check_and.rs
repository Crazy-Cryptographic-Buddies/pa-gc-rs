use std::fmt::Debug;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::util::verifier::Verifier;
use crate::value_type::{GFAddition, GFMultiplyingBit, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::VecAddition;

pub struct VerifierInProtocolCheckAND;

impl VerifierInProtocolCheckAND {

    pub fn verify<GFVOLEitH: PartialEq + Clone + GFAddition + GFMultiplyingBit + Debug + Zero>(
        public_parameter: &PublicParameter,
        pa_published_bit_and_voleith_mac_tuple_rep: &(
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>)
        ),
        pb_published_bit_and_voleith_mac_tuple_rep: &(
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>)
        ),
        public_d_sum_bit_vec_rep: &Vec<BitVec>, public_e_sum_bit_vec_rep: &Vec<BitVec>,
        nabla_a_rep: &Vec<GFVOLEitH>, nabla_b_rep: &Vec<GFVOLEitH>,
        pa_voleith_key_tuple_rep: &(
            (Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>),
            (Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>)
        ),
        pb_voleith_key_tuple_rep: &(
            (Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>),
            (Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>, Vec<GFVec<GFVOLEitH>>)
        ),
    ) {
        let (
            (pa_d_bit_vec_rep, pa_voleith_mac_d_vec_rep),
            (pa_e_bit_vec_rep, pa_voleith_mac_e_vec_rep),
            (pa_tilde_z_bit_vec_rep, pa_voleith_mac_tilde_z_vec_rep)
        ) = pa_published_bit_and_voleith_mac_tuple_rep;
        let (
            (pb_d_bit_vec_rep, pb_voleith_mac_d_vec_rep),
            (pb_e_bit_vec_rep, pb_voleith_mac_e_vec_rep), 
            (pb_tilde_z_bit_vec_rep, pb_voleith_mac_tilde_z_vec_rep)
        ) = pb_published_bit_and_voleith_mac_tuple_rep;
        let (
            (pa_voleith_key_x_vec_rep, pa_voleith_key_y_vec_rep, pa_voleith_key_z_vec_rep),
            (pa_voleith_key_a_vec_rep, pa_voleith_key_b_vec_rep, pa_voleith_key_c_vec_rep)
        ) = pa_voleith_key_tuple_rep;
        let (
            (pb_voleith_key_x_vec_rep, pb_voleith_key_y_vec_rep, pb_voleith_key_z_vec_rep),
            (pb_voleith_key_a_vec_rep, pb_voleith_key_b_vec_rep, pb_voleith_key_c_vec_rep)
        ) = pb_voleith_key_tuple_rep;
        for repetition_id in 0..public_parameter.kappa {
            {
                let pa_voleith_key_d_vec = pa_voleith_key_x_vec_rep[repetition_id].vec_add(&pa_voleith_key_a_vec_rep[repetition_id]);
                Verifier::verify_voleith_correlations(
                    &pa_d_bit_vec_rep[repetition_id],
                    &pa_voleith_mac_d_vec_rep[repetition_id],
                    &nabla_b_rep[repetition_id],
                    &pa_voleith_key_d_vec
                );
            }
            {
                let pa_voleith_key_e_vec = pa_voleith_key_y_vec_rep[repetition_id].vec_add(&pa_voleith_key_b_vec_rep[repetition_id]);
                Verifier::verify_voleith_correlations(
                    &pa_e_bit_vec_rep[repetition_id],
                    &pa_voleith_mac_e_vec_rep[repetition_id],
                    &nabla_b_rep[repetition_id],
                    &pa_voleith_key_e_vec
                )
            }
            {
                let pb_voleith_key_d_vec = pb_voleith_key_x_vec_rep[repetition_id].vec_add(&pb_voleith_key_a_vec_rep[repetition_id]);
                Verifier::verify_voleith_correlations(
                    &pb_d_bit_vec_rep[repetition_id],
                    &pb_voleith_mac_d_vec_rep[repetition_id],
                    &nabla_a_rep[repetition_id],
                    &pb_voleith_key_d_vec
                );
            }
            {
                let pb_voleith_key_e_vec = pb_voleith_key_y_vec_rep[repetition_id].vec_add(&pb_voleith_key_b_vec_rep[repetition_id]);
                Verifier::verify_voleith_correlations(
                    &pb_e_bit_vec_rep[repetition_id],
                    &pb_voleith_mac_e_vec_rep[repetition_id],
                    &nabla_a_rep[repetition_id],
                    &pb_voleith_key_e_vec
                );
            }
            {
                let pa_voleith_key_tilde_z_vec = pa_voleith_key_z_vec_rep[repetition_id].vec_add(
                    &pa_voleith_key_c_vec_rep[repetition_id]
                ).vec_add(
                    &pa_voleith_key_b_vec_rep[repetition_id].entry_wise_multiply_bit_vec(
                        &public_d_sum_bit_vec_rep[repetition_id]
                    )
                ).vec_add(
                    &pa_voleith_key_a_vec_rep[repetition_id].entry_wise_multiply_bit_vec(
                        &public_e_sum_bit_vec_rep[repetition_id]
                    )
                );
                Verifier::verify_voleith_correlations(
                    &pa_tilde_z_bit_vec_rep[repetition_id],
                    &pa_voleith_mac_tilde_z_vec_rep[repetition_id],
                    &nabla_b_rep[repetition_id],
                    &pa_voleith_key_tilde_z_vec
                );
            }
            {
                let pb_voleith_key_tilde_z_vec = pb_voleith_key_z_vec_rep[repetition_id].vec_add(
                    &pb_voleith_key_c_vec_rep[repetition_id]
                ).vec_add(
                    &pb_voleith_key_b_vec_rep[repetition_id].entry_wise_multiply_bit_vec(
                        &public_d_sum_bit_vec_rep[repetition_id]
                    )
                ).vec_add(
                    &pb_voleith_key_a_vec_rep[repetition_id].entry_wise_multiply_bit_vec(
                        &public_e_sum_bit_vec_rep[repetition_id]
                    )
                );
                Verifier::verify_voleith_correlations(
                    &pb_tilde_z_bit_vec_rep[repetition_id],
                    &pb_voleith_mac_tilde_z_vec_rep[repetition_id],
                    &nabla_a_rep[repetition_id],
                    &pb_voleith_key_tilde_z_vec
                );
            }
        }
    }
}