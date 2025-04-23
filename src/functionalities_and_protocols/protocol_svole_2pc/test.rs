// struct ProtocolSVOLE2PC;
// 
// impl ProtocolSVOLE2PC {
//     
//     // pub fn commit_and_fix_bit_vec_and_voleith_mac_vec<GF: Clone + Zero + GFAdd + U8ForGF>(
//     //     public_parameter: &PublicParameter,
//     //     pa_secret_state: &mut ProverSecretState<GF>, pb_secret_state: &mut ProverSecretState<GF>
//     // ) -> (
//     //     (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>),
//     //     (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>)
//     // ) {
//     //     // pa call svole kappa times
//     //     let (pa_com_hash_rep, pa_masked_bit_tuple_rep) = Self::prover_commit_and_fix_bit_vec_and_mac_vec(
//     //         public_parameter, pa_secret_state
//     //     );
//     //     let (pb_com_hash_rep, pb_masked_bit_tuple_rep) = Self::prover_commit_and_fix_bit_vec_and_mac_vec(
//     //         public_parameter, pb_secret_state
//     //     );
//     //     
//     //     (
//     //         (pa_com_hash_rep, pa_masked_bit_tuple_rep),
//     //         (pb_com_hash_rep, pb_masked_bit_tuple_rep)
//     //     )
//     // }
// 
//     fn verifier_open_and_reconstruct_voleith_key_vec<GF>() {
//         
//     }
//     
//     fn prover_open_decom() {
//         
//     }
// 
//     pub fn open_and_reconstruct_voleith_key_vec<GF>(
//         public_parameter: &PublicParameter,
//         nabla_a_rep: &Vec<GF>, nabla_b_rep: &Vec<GF>,
//         public_message_from_commitment_and_bit_fixing: &(
//             (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>),
//             (Vec<Hash>, Vec<(BitVec, BitVec, BitVec, BitVec, BitVec)>)
//         )
//     ) {
//         let (
//             (pa_com_hash_rep, pa_masked_bit_tuple_rep),
//             (pb_com_hash_rep, pb_masked_bit_tuple_rep)
//         ) = public_message_from_commitment_and_bit_fixing;
//     }
// }

#[cfg(test)]
mod tests {
    use rand::Rng;
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_svole_2pc::prover_in_protocol_svole_2pc::ProverInProtocolSVOLE2PC;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::InsecureRandom;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::vec_type::bit_vec::BitVec;

    fn sample_secret_bit_vecs(public_parameter: &PublicParameter, prover_secret_state: &mut ProverSecretState<GF2p8>) {
        let mut rng = rand::rng();
        prover_secret_state.r_bit_vec = Some(BitVec::new());
        for _ in 0..public_parameter.sum_big_ia_ib_iw {
            prover_secret_state.r_bit_vec.as_mut().unwrap().push(rng.random::<u8>() & 1);
        }
        prover_secret_state.r_prime_bit_vec = Some(BitVec::new());
        for _ in 0..public_parameter.big_w {
            prover_secret_state.r_prime_bit_vec.as_mut().unwrap().push(rng.random::<u8>() & 1);
        }
        prover_secret_state.tilde_a_bit_vec_rep = Some(Vec::new());
        for _ in 0..public_parameter.kappa {
            prover_secret_state.tilde_a_bit_vec_rep.as_mut().unwrap().push(BitVec::new());
            for _ in 0..public_parameter.big_l {
                prover_secret_state.tilde_a_bit_vec_rep.as_mut().unwrap().last_mut().unwrap().push(rng.random::<u8>() & 1);
            }
        }
        prover_secret_state.tilde_b_bit_vec_rep = Some(Vec::new());
        for _ in 0..public_parameter.kappa {
            prover_secret_state.tilde_b_bit_vec_rep.as_mut().unwrap().push(BitVec::new());
            for _ in 0..public_parameter.big_l {
                prover_secret_state.tilde_b_bit_vec_rep.as_mut().unwrap().last_mut().unwrap().push(rng.random::<u8>() & 1);
            }
        }
        prover_secret_state.tilde_c_bit_vec_rep = Some(Vec::new());
        for _ in 0..public_parameter.kappa {
            prover_secret_state.tilde_c_bit_vec_rep.as_mut().unwrap().push(BitVec::new());
            for _ in 0..public_parameter.big_l {
                prover_secret_state.tilde_c_bit_vec_rep.as_mut().unwrap().last_mut().unwrap().push(rng.random::<u8>() & 1);
            }
        }
    }

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
        sample_secret_bit_vecs(&public_parameter, &mut pa_secret_state);
        sample_secret_bit_vecs(&public_parameter, &mut pb_secret_state);
        
        // pa commits and fixes voleith-authenticated bits
        let (
            pa_com_hash_rep, pa_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec(
            &public_parameter, &mut pa_secret_state
        );
        
        // pb commits and fixes voleith-authenticated bits
        let (
            pb_com_hash_rep, pb_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec(
            &public_parameter, &mut pb_secret_state
        );
        
        // sample nablas
        let mut nabla_a_rep: Vec<GF2p8> = Vec::new();
        let mut nabla_b_rep: Vec<GF2p8> = Vec::new();
        for _ in 0..public_parameter.kappa {
            nabla_a_rep.push(GF2p8::insecurely_random());
            nabla_b_rep.push(GF2p8::insecurely_random());
        }
        // ProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec(&public_parameter, &mut pa_secret_state, &mut pb_secret_state);
    }
}