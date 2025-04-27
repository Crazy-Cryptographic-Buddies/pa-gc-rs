use blake3::Hash;
use crate::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::protocol_svole::prover_in_protocol_svole::ProverInProtocolSVOLE;
use crate::value_type::{GFAddition, U8ForGF, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::{Split, VecAddition};

pub struct ProverInProtocolSVOLE2PC {

}

impl ProverInProtocolSVOLE2PC {
    fn distribute_bits_and_voleith_macs_to_state<GFVOLE, GFVOLEitH: Clone + Zero>(
        public_parameter: &PublicParameter,
        repetition_id: usize,
        prover_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        secret_bit_vec: &mut BitVec,
        secret_voleith_mac_vec: &mut GFVec<GFVOLEitH>
    ) -> (BitVec, BitVec, BitVec, BitVec, BitVec, BitVec) {
        // first mask the bits
        let hat_r_input_bit_vec = prover_secret_state.r_input_bit_vec.vec_add(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.num_input_bits)
        );
        let hat_r_output_and_bit_vec = prover_secret_state.r_output_and_bit_vec.vec_add(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_iw_size)
        );
        let hat_r_prime_bit_vec = prover_secret_state.r_prime_bit_vec.vec_add(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_iw_size)
        );
        let hat_a_bit_vec = prover_secret_state.tilde_a_bit_vec_rep.as_ref().unwrap()[repetition_id].vec_add(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)
        );
        let hat_b_bit_vec = prover_secret_state.tilde_b_bit_vec_rep.as_ref().unwrap()[repetition_id].vec_add(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)
        );
        let hat_c_bit_vec = prover_secret_state.tilde_c_bit_vec_rep.as_ref().unwrap()[repetition_id].vec_add(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)
        );
        assert_eq!(secret_bit_vec.len(), 0);

        // then distribute the voleith macs
        prover_secret_state.voleith_mac_r_input_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.num_input_bits)
        );
        prover_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_iw_size)       
        );
        prover_secret_state.voleith_mac_r_prime_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_iw_size)
        );
        prover_secret_state.voleith_mac_tilde_a_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)
        );
        prover_secret_state.voleith_mac_tilde_b_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)
        );
        prover_secret_state.voleith_mac_tilde_c_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)
        );
        assert_eq!(secret_voleith_mac_vec.len(), 0);

        (hat_r_input_bit_vec, hat_r_output_and_bit_vec, hat_r_prime_bit_vec, hat_a_bit_vec, hat_b_bit_vec, hat_c_bit_vec)
    }

    pub fn commit_and_fix_bit_vec_and_mac_vec<GFVOLE, GFVOLEitH>(
        public_parameter: &PublicParameter, 
        prover_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>
    ) -> (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>) 
    where GFVOLE: Clone + GFAddition + Zero, GFVOLEitH: Clone + Zero + GFAddition + U8ForGF {
        let mut com_hash_rep: Vec<Hash> = Vec::new();
        let mut masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            let mut secret_bit_vec: Option<BitVec> = None;
            let mut secret_voleith_mac_vec: Option<GFVec<GFVOLEitH>> = None;
            let com_hash = ProverInProtocolSVOLE::commit(
                public_parameter, repetition_id,
                prover_secret_state, &mut secret_bit_vec, &mut secret_voleith_mac_vec
            );
            com_hash_rep.push(com_hash);
            let masked_bit_tuple = Self::distribute_bits_and_voleith_macs_to_state(
                public_parameter, repetition_id, prover_secret_state, 
                &mut secret_bit_vec.as_mut().unwrap(), &mut secret_voleith_mac_vec.as_mut().unwrap()
            );
            masked_bit_tuple_rep.push(masked_bit_tuple);
        }
        (com_hash_rep, masked_bit_tuple_rep)
    }
    
    pub fn open<GFVOLE, GFVOLEitH>(
        public_parameter: &PublicParameter, 
        prover_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>, 
        nabla_rep: &Vec<GFVOLEitH>
    ) -> Vec<(SeedU8x16, Vec<SeedU8x16>)>
    where GFVOLEitH: U8ForGF {
        let mut decom_rep: Vec<(SeedU8x16, Vec<SeedU8x16>)> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            let decom = ProverInProtocolSVOLE::open(
                public_parameter, repetition_id, prover_secret_state, &nabla_rep[repetition_id]
            );
            decom_rep.push(decom);       
        }
        decom_rep       
    }
}