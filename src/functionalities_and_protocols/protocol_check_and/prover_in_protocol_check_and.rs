use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{GFAddition, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::VecAddition;

pub struct ProverInProtocolCheckAND {
}

impl ProverInProtocolCheckAND {
    pub fn compute_masked_bits_and_voleith_macs<GFVOLEitH: Clone + GFAddition + Zero>(
        public_parameter: &PublicParameter,
        x_bit_vec: &BitVec, voleith_mac_x_vec_rep: &Vec<GFVec<GFVOLEitH>>,
        y_bit_vec: &BitVec, voleith_mac_y_vec_rep: &Vec<GFVec<GFVOLEitH>>,
        a_bit_vec_rep: &Vec<BitVec>, voleith_mac_a_vec_rep: &Vec<GFVec<GFVOLEitH>>,
        b_bit_vec_rep: &Vec<BitVec>, voleith_mac_b_vec_rep: &Vec<GFVec<GFVOLEitH>>,
    ) -> ((Vec<BitVec>, Vec<GFVec<GFVOLEitH>>), (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>)) {
        let mut d_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut e_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut voleith_mac_d_vec_rep: Vec<GFVec<GFVOLEitH>> = Vec::new();
        let mut voleith_mac_e_vec_rep: Vec<GFVec<GFVOLEitH>> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            d_bit_vec_rep.push(x_bit_vec.vec_add(&a_bit_vec_rep[repetition_id]));
            e_bit_vec_rep.push(y_bit_vec.vec_add(&b_bit_vec_rep[repetition_id]));
            voleith_mac_d_vec_rep.push(voleith_mac_x_vec_rep[repetition_id].vec_add(&voleith_mac_a_vec_rep[repetition_id]));
            voleith_mac_e_vec_rep.push(voleith_mac_y_vec_rep[repetition_id].vec_add(&voleith_mac_b_vec_rep[repetition_id]));
        }
        ((d_bit_vec_rep, voleith_mac_d_vec_rep), (e_bit_vec_rep, voleith_mac_e_vec_rep))
    }

    pub fn compute_masked_cross_bits_and_voleith_macs<GFVOLEitH: Clone + Zero + GFAddition> (
        public_parameter: &PublicParameter,
        public_d_sum_bit_vec_rep: &Vec<BitVec>, public_e_sum_bit_vec_rep: &Vec<BitVec>,
        z_bit_vec: &BitVec, voleith_mac_z_vec_rep: &Vec<GFVec<GFVOLEitH>>,
        a_bit_vec_rep: &Vec<BitVec>, voleith_mac_a_vec_rep: &Vec<GFVec<GFVOLEitH>>,
        b_bit_vec_rep: &Vec<BitVec>, voleith_mac_b_vec_rep: &Vec<GFVec<GFVOLEitH>>,
        c_bit_vec_rep: &Vec<BitVec>, voleith_mac_c_vec_rep: &Vec<GFVec<GFVOLEitH>>,
    ) -> (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>) {
        let mut tilde_z_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut voleith_mac_tilde_z_vec_rep: Vec<GFVec<GFVOLEitH>> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            tilde_z_bit_vec_rep.push(
                z_bit_vec.vec_add(
                    &c_bit_vec_rep[repetition_id]
                ).vec_add(
                    &b_bit_vec_rep[repetition_id].entry_wise_multiply(
                        &public_d_sum_bit_vec_rep[repetition_id]
                    )
                ).vec_add(
                    &a_bit_vec_rep[repetition_id].entry_wise_multiply(
                        &public_e_sum_bit_vec_rep[repetition_id]
                    )
                )
            );
            voleith_mac_tilde_z_vec_rep.push(
                voleith_mac_z_vec_rep[repetition_id].vec_add(
                    &voleith_mac_c_vec_rep[repetition_id]
                ).vec_add(
                    &voleith_mac_b_vec_rep[repetition_id].entry_wise_multiply_bit_vec(
                        &public_d_sum_bit_vec_rep[repetition_id]
                    )
                ).vec_add(
                    &voleith_mac_a_vec_rep[repetition_id].entry_wise_multiply_bit_vec(
                        &public_e_sum_bit_vec_rep[repetition_id]   
                    )
                )
            );
        }
        (tilde_z_bit_vec_rep, voleith_mac_tilde_z_vec_rep)
    }
}