use blake3::Hash;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::Split;

struct ProtocolSVOLE;

impl ProtocolSVOLE {
    
    fn distribute_bits_and_voleith_macs_to_state<GF: Clone + Zero>(
        public_parameter: &PublicParameter,
        repetition_id: usize,
        secret_bit_vec: &mut BitVec,
        secret_voleith_mac_vec: &mut GFVec<GF>,
        prover_secret_state: &mut ProverSecretState<GF>
    ) {
        // first distribute the bits
        prover_secret_state.bar_r_bit_vec_rep[repetition_id] = Some(
            secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.sum_big_ia_ib_iw)
        );
        prover_secret_state.bar_r_prime_bit_vec_rep[repetition_id] = Some(
            secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_w)
        );
        prover_secret_state.bar_a_bit_vec_rep[repetition_id] = Some(
            secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)    
        );
        prover_secret_state.bar_b_bit_vec_rep[repetition_id] = Some(
            secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)
        );
        prover_secret_state.bar_c_bit_vec_rep[repetition_id] = Some(
            secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)    
        );
        assert_eq!(secret_bit_vec.len(), 0);
        
        // then distribute the voleith macs
        prover_secret_state.voleith_mac_bar_r_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.sum_big_ia_ib_iw)
        );
        prover_secret_state.voleith_mac_bar_r_prime_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_w)
        );
        prover_secret_state.voleith_mac_bar_a_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)    
        );
        prover_secret_state.voleith_mac_bar_b_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)
        );
        prover_secret_state.voleith_mac_bar_c_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)    
        );
        assert_eq!(secret_voleith_mac_vec.len(), 0);
    }
    
    pub fn commit_and_fix_bit_vec_and_mac_vec<GF: Clone + Zero + GFAdd + U8ForGF>(
        public_parameter: &PublicParameter,
        pa_secret_state: &mut ProverSecretState<GF>, pb_secret_state: &mut ProverSecretState<GF>
    ) -> (Vec<Hash>, Vec<Hash>) {
        // pa call svole kappa times
        let mut com_hash_from_pa: Vec<Hash> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            let mut secret_bit_vec: Option<BitVec> = None;
            let mut secret_voleith_mac_vec: Option<GFVec<GF>> = None;
            let com_hash = pa_secret_state.prover_in_all_in_one_vc_rep[repetition_id].commit(
                &public_parameter, 
                &pa_secret_state.seed_for_generating_ggm_tree_rep[repetition_id],
                &mut secret_bit_vec,
                &mut secret_voleith_mac_vec
            );
            com_hash_from_pa.push(com_hash);
            Self::distribute_bits_and_voleith_macs_to_state(
                public_parameter, repetition_id, &mut secret_bit_vec.as_mut().unwrap(), 
                &mut secret_voleith_mac_vec.as_mut().unwrap(), pa_secret_state
            );
        }

        // pb call svole kappa times
        let mut com_hash_from_pb: Vec<Hash> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            let mut secret_bit_vec: Option<BitVec> = None;
            let mut secret_voleith_mac_vec: Option<GFVec<GF>> = None;
            let com_hash = pb_secret_state.prover_in_all_in_one_vc_rep[repetition_id].commit(
                &public_parameter,
                &pb_secret_state.seed_for_generating_ggm_tree_rep[repetition_id],
                &mut secret_bit_vec,
                &mut secret_voleith_mac_vec
            );
            com_hash_from_pb.push(com_hash);
            Self::distribute_bits_and_voleith_macs_to_state(
                public_parameter, repetition_id, &mut secret_bit_vec.as_mut().unwrap(),
                &mut secret_voleith_mac_vec.as_mut().unwrap(), pb_secret_state
            );
        }
        
        (com_hash_from_pa, com_hash_from_pb)
    }
}

#[cfg(test)]
mod tests {
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_svole_2pc::protocol_svole_2pc::ProtocolSVOLE;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::InsecureRandom;
    use crate::value_type::seed_u8x16::SeedU8x16;

    #[test]
    fn try_commit_and_fix_protocol_svole_2pc_test_case_1() {
        let public_parameter = PublicParameter::new(
            8,
            10,
            SeedU8x16::insecurely_random(),
            20,
            30,
            40,
            41
        );
        let mut pa_secret_state = ProverSecretState::<GF2p8>::new(
            &public_parameter,
            SeedU8x16::insecurely_random()
        );
        let mut pb_secret_state = ProverSecretState::<GF2p8>::new(
            &public_parameter,
            SeedU8x16::insecurely_random()
        );
        ProtocolSVOLE::commit_and_fix_bit_vec_and_mac_vec(&public_parameter, &mut pa_secret_state, &mut pb_secret_state);
    }
}