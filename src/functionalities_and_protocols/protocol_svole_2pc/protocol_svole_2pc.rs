use aes::cipher::typenum::Bit;
use blake3::Hash;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::protocol_svole::protocol_svole::ProtocolSVOLE;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::Split;

struct ProtocolSVOLE2PC;

impl ProtocolSVOLE2PC {

    fn distribute_bits_and_voleith_macs_to_state<GF: Clone + Zero>(
        public_parameter: &PublicParameter,
        repetition_id: usize,
        secret_bit_vec: &mut BitVec,
        secret_voleith_mac_vec: &mut GFVec<GF>,
        prover_secret_state: &mut ProverSecretState<GF>
    ) -> (BitVec, BitVec, BitVec, BitVec, BitVec) {
        // first mask the bits
        let hat_r_bit_vec = prover_secret_state.r_bit_vec.as_ref().unwrap().xor_vec(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.sum_big_ia_ib_iw)
        );
        let hat_r_prime_bit_vec = prover_secret_state.r_prime_bit_vec.as_ref().unwrap().xor_vec(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_w)
        );
        let hat_a_bit_vec = prover_secret_state.tilde_a_bit_vec_rep.as_ref().unwrap()[repetition_id].xor_vec(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)
        );
        let hat_b_bit_vec = prover_secret_state.tilde_b_bit_vec_rep.as_ref().unwrap()[repetition_id].xor_vec(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)
        );
        let hat_c_bit_vec = prover_secret_state.tilde_c_bit_vec_rep.as_ref().unwrap()[repetition_id].xor_vec(
            &secret_bit_vec.split_off(secret_bit_vec.len() - public_parameter.big_l)
        );
        assert_eq!(secret_bit_vec.len(), 0);

        // then distribute the voleith macs
        prover_secret_state.voleith_mac_r_bit_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.sum_big_ia_ib_iw)
        );
        prover_secret_state.voleith_mac_r_prime_bit_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_w)
        );
        prover_secret_state.voleith_mac_tilde_a_bit_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)
        );
        prover_secret_state.voleith_mac_tilde_b_bit_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)
        );
        prover_secret_state.voleith_mac_tilde_c_bit_vec_rep[repetition_id] = Some(
            secret_voleith_mac_vec.split_off(secret_voleith_mac_vec.len() - public_parameter.big_l)
        );
        assert_eq!(secret_voleith_mac_vec.len(), 0);

        (hat_r_bit_vec, hat_r_prime_bit_vec, hat_a_bit_vec, hat_b_bit_vec, hat_c_bit_vec)
    }

    pub fn prover_commit_and_fix_bit_vec_and_mac_vec<GF: Clone + GFAdd + U8ForGF + Zero>(
        public_parameter: &PublicParameter, prover_secret_state: &mut ProverSecretState<GF>
    ) -> (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>) {
        let mut com_hash_rep: Vec<Hash> = Vec::new();
        let mut masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)> = Vec::new();
        for repetition_id in 0..public_parameter.kappa {
            let mut secret_bit_vec: Option<BitVec> = None;
            let mut secret_voleith_mac_vec: Option<GFVec<GF>> = None;
            let com_hash = ProtocolSVOLE::commit(
                public_parameter, repetition_id, 
                prover_secret_state, &mut secret_bit_vec, &mut secret_voleith_mac_vec
            );
            com_hash_rep.push(com_hash);
            let masked_bit_tuple = Self::distribute_bits_and_voleith_macs_to_state(
                public_parameter, repetition_id, &mut secret_bit_vec.as_mut().unwrap(),
                &mut secret_voleith_mac_vec.as_mut().unwrap(), prover_secret_state
            );
            masked_bit_tuple_rep.push(masked_bit_tuple);
        }
        (com_hash_rep, masked_bit_tuple_rep)
    }
    
    pub fn commit_and_fix_bit_vec_and_voleith_mac_vec<GF: Clone + Zero + GFAdd + U8ForGF>(
        public_parameter: &PublicParameter,
        pa_secret_state: &mut ProverSecretState<GF>, pb_secret_state: &mut ProverSecretState<GF>
    ) -> (
        (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>),
        (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>)
    ) {
        // pa call svole kappa times
        let (pa_com_hash_rep, pa_masked_bit_tuple_rep) = Self::prover_commit_and_fix_bit_vec_and_mac_vec(
            public_parameter, pa_secret_state
        );
        let (pb_com_hash_rep, pb_masked_bit_tuple_rep) = Self::prover_commit_and_fix_bit_vec_and_mac_vec(
            public_parameter, pb_secret_state
        );
        
        (
            (pa_com_hash_rep, pa_masked_bit_tuple_rep),
            (pb_com_hash_rep, pb_masked_bit_tuple_rep)
        )
    }

    // pub fn open_and_reconstruct_voleith_key_vec (
    //
    // )
}

#[cfg(test)]
mod tests {
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_svole_2pc::protocol_svole_2pc::{ProtocolSVOLE2PC};
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
        let mut nabla_a_rep: Vec<GF2p8> = Vec::new();
        let mut nabla_b_rep: Vec<GF2p8> = Vec::new();
        for _ in 0..public_parameter.kappa {
            nabla_a_rep.push(GF2p8::insecurely_random());
            nabla_b_rep.push(GF2p8::insecurely_random());
        }
        // ProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec(&public_parameter, &mut pa_secret_state, &mut pb_secret_state);
    }
}