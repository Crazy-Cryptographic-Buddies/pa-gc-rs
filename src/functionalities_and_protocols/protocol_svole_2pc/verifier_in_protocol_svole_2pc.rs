use blake3::Hash;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::protocol_svole::verifier_in_protocol_svole::VerifierInProtocolSVOLE;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, GFMultiplyingBit, U8ForGF, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::Split;
use crate::vec_type::VecAdd;

pub struct VerifierInProtocolSvole2PC;

impl VerifierInProtocolSvole2PC {
    
    fn distribute_bits_and_voleith_macs_to_state<GF: Clone + Zero + GFMultiplyingBit + GFAdd>(
        public_parameter: &PublicParameter,
        repetition_id: usize,
        nabla_rep: &Vec<GF>,
        public_voleith_key_vec: &mut GFVec<GF>,
        prover_masked_bit_tuple: &(BitVec, BitVec, BitVec, BitVec, BitVec)
    ) -> (GFVec<GF>, GFVec<GF>, GFVec<GF>, GFVec<GF>, GFVec<GF>) {
        let (
            hat_r_bit_vec, 
            hat_r_prime_bit_vec, 
            hat_a_bit_vec, 
            hat_b_bit_vec, 
            hat_c_bit_vec
        ) = prover_masked_bit_tuple;
        
        // then distribute the voleith macs
        let voleith_key_r_vec: GFVec<GF> = {
            let mut hat_r_bit_multiplying_nabla: GFVec<GF> = GFVec::new();
            for i in 0..public_parameter.sum_big_ia_ib_iw {
                hat_r_bit_multiplying_nabla.push(nabla_rep[repetition_id].multiply_bit(hat_r_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.sum_big_ia_ib_iw
            ).vec_add(&hat_r_bit_multiplying_nabla)
        };

        let voleith_key_r_prime_vec: GFVec<GF> = {
            let mut hat_r_prime_bit_multiplying_nabla: GFVec<GF> = GFVec::new();
            for i in 0..public_parameter.big_w {
                hat_r_prime_bit_multiplying_nabla.push(nabla_rep[repetition_id].multiply_bit(hat_r_prime_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_w
            ).vec_add(&hat_r_prime_bit_multiplying_nabla)
        };

        let voleith_key_tilde_a_vec: GFVec<GF> = {
            let mut hat_a_bit_multiplying_nabla: GFVec<GF> = GFVec::new();
            for i in 0..public_parameter.big_l {
                hat_a_bit_multiplying_nabla.push(nabla_rep[repetition_id].multiply_bit(hat_a_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_l
            ).vec_add(&hat_a_bit_multiplying_nabla)
        };

        let voleith_key_tilde_b_vec: GFVec<GF> = {
            let mut hat_b_bit_multiplying_nabla: GFVec<GF> = GFVec::new();
            for i in 0..public_parameter.big_l {
                hat_b_bit_multiplying_nabla.push(nabla_rep[repetition_id].multiply_bit(hat_b_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_l
            ).vec_add(&hat_b_bit_multiplying_nabla)
        };

        let voleith_key_tilde_c_vec: GFVec<GF> = {
            let mut hat_c_bit_multiplying_nabla: GFVec<GF> = GFVec::new();
            for i in 0..public_parameter.big_l {
                hat_c_bit_multiplying_nabla.push(nabla_rep[repetition_id].multiply_bit(hat_c_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_l
            ).vec_add(&hat_c_bit_multiplying_nabla)
        };
        
        assert_eq!(public_voleith_key_vec.len(), 0);

        (voleith_key_r_vec, voleith_key_r_prime_vec, voleith_key_tilde_a_vec, voleith_key_tilde_b_vec, voleith_key_tilde_c_vec)
    }
    pub fn reconstruct_and_fix_voleith_key_vec<GF: Clone + Zero + GFAdd + U8ForGF + GFMultiplyingBit>(
        public_parameter: &PublicParameter, 
        prover_com_hash_rep: &Vec<Hash>,
        prover_masked_bit_tuple_rep: &Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>,
        nabla_rep: &Vec<GF>, 
        decom_rep: &Vec<(SeedU8x16, Vec<SeedU8x16>)>
    ) -> Vec<(GFVec<GF>, GFVec<GF>, GFVec<GF>, GFVec<GF>, GFVec<GF>)> {
        let mut voleith_key_tuple_rep: Vec<(GFVec<GF>, GFVec<GF>, GFVec<GF>, GFVec<GF>, GFVec<GF>)> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            let mut public_voleith_key_vec = VerifierInProtocolSVOLE::reconstruct(
                public_parameter, 
                &prover_com_hash_rep[repetition_id], 
                &nabla_rep[repetition_id], 
                &decom_rep[repetition_id]
            );
            voleith_key_tuple_rep.push(
                Self::distribute_bits_and_voleith_macs_to_state(
                    public_parameter, 
                    repetition_id, 
                    &nabla_rep, 
                    &mut public_voleith_key_vec, 
                    &prover_masked_bit_tuple_rep[repetition_id])
            );
        }
        voleith_key_tuple_rep
    }
}