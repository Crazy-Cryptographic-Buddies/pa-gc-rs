#[cfg(test)]
mod tests {
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_svole::prover_in_protocol_svole::ProverInProtocolSVOLE;
    use crate::functionalities_and_protocols::protocol_svole::verifier_in_protocol_svole::VerifierInProtocolSVOLE;
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::GFAddition;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::vec_type::bit_vec::BitVec;
    use crate::vec_type::gf_vec::GFVec;
    use crate::value_type::InsecureRandom;
    use crate::value_type::Zero;

    #[test]
    fn test_protocol_svole() {
        // public inputs
        let public_parameter = PublicParameter::new(
            8,
            20,
            SeedU8x16::insecurely_random(),
            10,
            10,
            20,
            30,
            Vec::new(),
            Vec::new()
        );
        let mut prover_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter,
            SeedU8x16::insecurely_random(),
        );

        for repetition_id in 0..public_parameter.kappa {
            // prepare prover and verifier for all_in_one_vc
            // let prover_in_all_in_one_vc = &mut prover_secret_state.prover_in_all_in_one_vc_rep[repetition_id];
            let mut secret_bit_vec: Option<BitVec> = None;
            let mut secret_voleith_mac_vec: Option<GFVec<GF2p8>> = None;
            let prover_com_hash = ProverInProtocolSVOLE::commit(
                &public_parameter, repetition_id, &mut prover_secret_state,
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
                if secret_bit_vec.as_ref().unwrap()[i] == 1 {
                    shifted_nabla = nabla.clone();
                }
                // println!("mac + bit * nabla, key, mac, msg: {:?}, {:?}, {:?}, {:?}",
                //          secret_voleith_mac_vec.as_ref().unwrap()[i].gf_add(&shifted_nabla),
                //          public_voleith_key_vec[i],
                //          secret_voleith_mac_vec.as_ref().unwrap()[i],
                //          secret_bit_vec.as_ref().unwrap()[i]
                // );
                assert_eq!(public_voleith_key_vec[i], secret_voleith_mac_vec.as_ref().unwrap()[i].gf_add(&shifted_nabla));
            }
            // println!("bit_vec_len, voleith_mac_vec_len, voleith_key_vec_len: {:?}, {:?}, {:?}",
            //          secret_bit_vec.as_ref().unwrap().len(),
            //          secret_voleith_mac_vec.as_ref().unwrap().len(),
            //          public_voleith_key_vec.len());
        }

        println!("voleith correlation checking passed!");
    }    
}