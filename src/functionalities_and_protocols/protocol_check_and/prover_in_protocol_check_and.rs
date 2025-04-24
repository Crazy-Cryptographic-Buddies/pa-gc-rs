use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{GFAdd, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::VecAdd;

struct ProverInProtocolCheckAND {
}

impl ProverInProtocolCheckAND {
    pub fn compute_masked_bits_and_voleith_macs<GF: Clone + GFAdd + Zero>(
        public_parameter: &PublicParameter,
        x_bit_vec_rep: &Vec<BitVec>, voleith_mac_x_vec_rep: &Vec<GFVec<GF>>,
        y_bit_vec_rep: &Vec<BitVec>, voleith_mac_y_vec_rep: &Vec<GFVec<GF>>,
        a_bit_vec_rep: &Vec<BitVec>, voleith_mac_a_vec_rep: &Vec<GFVec<GF>>,
        b_bit_vec_rep: &Vec<BitVec>, voleith_mac_b_vec_rep: &Vec<GFVec<GF>>,
    ) -> (
        (Vec<BitVec>, Vec<GFVec<GF>>), (Vec<BitVec>, Vec<GFVec<GF>>)
    ) {
        let mut d_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut e_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut voleith_mac_d_vec_rep: Vec<GFVec<GF>> = Vec::new();
        let mut voleith_mac_e_vec_rep: Vec<GFVec<GF>> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            d_bit_vec_rep.push(x_bit_vec_rep[repetition_id].vec_add(&a_bit_vec_rep[repetition_id]));
            e_bit_vec_rep.push(y_bit_vec_rep[repetition_id].vec_add(&b_bit_vec_rep[repetition_id]));
            voleith_mac_d_vec_rep.push(voleith_mac_x_vec_rep[repetition_id].vec_add(&voleith_mac_a_vec_rep[repetition_id]));
            voleith_mac_e_vec_rep.push(voleith_mac_y_vec_rep[repetition_id].vec_add(&voleith_mac_b_vec_rep[repetition_id]));       
        }
        ((d_bit_vec_rep, voleith_mac_d_vec_rep), (e_bit_vec_rep, voleith_mac_e_vec_rep))
    }
}