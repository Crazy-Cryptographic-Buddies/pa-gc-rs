#[cfg(test)]
mod tests {
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
    use crate::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_svole::prover_in_protocol_svole::ProverInProtocolSVOLE;
    use crate::functionalities_and_protocols::protocol_svole::verifier_in_protocol_svole::VerifierInProtocolSVOLE;
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::CustomAddition;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::vec_type::bit_vec::BitVec;
    use crate::vec_type::gf_vec::GFVec;
    use crate::value_type::InsecureRandom;
    use crate::value_type::Zero;
    use crate::vec_type::ZeroVec;

    #[test]
    fn test_protocol_svole() {
        // public inputs
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(
            &"adder64.txt".to_string()
        );
        let public_parameter = PublicParameter::new::<GF2p256, GF2p8>(
            &bristol_fashion_adaptor,
            8,
            20,
            SeedU8x16::insecurely_random(),
            (0..100).collect(),
            (100..200).collect(),
            10,
            4,
        );
        let mut prover_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter,
            SeedU8x16::insecurely_random(),
            true
        );

        for repetition_id in 0..public_parameter.kappa {
            // prepare prover and verifier for all_in_one_vc
            // let prover_in_all_in_one_vc = &mut prover_secret_state.prover_in_all_in_one_vc_rep[repetition_id];
            let mut secret_bit_vec = BitVec::zero_vec(public_parameter.big_n);
            let mut secret_voleith_mac_vec = GFVec::<GF2p8>::zero_vec(public_parameter.big_n);
            let prover_com_hash = prover_secret_state.prover_in_all_in_one_vc_rep[repetition_id].commit(
                &public_parameter, &prover_secret_state.seed_for_generating_ggm_tree_rep[repetition_id],
                &mut secret_bit_vec, &mut secret_voleith_mac_vec
            );
            let nabla = GF2p8::insecurely_random();
            let decom = ProverInProtocolSVOLE::open(
                &public_parameter,
                repetition_id,
                &mut prover_secret_state, &nabla
            );
            let public_voleith_key_vec = VerifierInProtocolSVOLE::reconstruct(
                &public_parameter, &prover_com_hash, &nabla, &decom
            );

            for i in 0..public_parameter.big_n {
                let mut shifted_nabla = GF2p8::zero();
                if secret_bit_vec[i] == 1 {
                    shifted_nabla = nabla.clone();
                }
                // println!("mac + bit * nabla, key, mac, msg: {:?}, {:?}, {:?}, {:?}",
                //          secret_voleith_mac_vec.as_ref().unwrap()[i].gf_add(&shifted_nabla),
                //          public_voleith_key_vec[i],
                //          secret_voleith_mac_vec.as_ref().unwrap()[i],
                //          secret_bit_vec.as_ref().unwrap()[i]
                // );
                assert_eq!(public_voleith_key_vec[i], secret_voleith_mac_vec[i].custom_add(&shifted_nabla));
            }
            // println!("bit_vec_len, voleith_mac_vec_len, voleith_key_vec_len: {:?}, {:?}, {:?}",
            //          secret_bit_vec.as_ref().unwrap().len(),
            //          secret_voleith_mac_vec.as_ref().unwrap().len(),
            //          public_voleith_key_vec.len());
        }

        println!("voleith correlation checking passed!");
    }
}