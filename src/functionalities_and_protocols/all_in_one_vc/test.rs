#[cfg(test)]
mod tests {
    use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
    use crate::functionalities_and_protocols::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
    use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::vec_type::bit_vec::BitVec;
    use crate::vec_type::gf_vec::GFVec;
    use crate::value_type::{GFAddition, InsecureRandom};
    use crate::value_type::Zero;

    #[test]
    fn test_committing_and_reconstructing() {
        println!("testing committing and reconstructing...");
        let nabla = GF2p8::insecurely_random();
        let public_parameter = PublicParameter::new(
            8,
            20,
            SeedU8x16::insecurely_random(),
            (0..100).collect(),
            (100..200).collect(),
            (200..300).collect(),
            4,
            50
        );
        // let prover_secret_input = ProverSecretInput::new(
        //     SeedU8x16::insecurely_random(),
        // );

        // first generate in the prover side
        let mut prover_in_all_in_one_vc = ProverInAllInOneVC::new(&public_parameter);
        let prover_secret_seed_for_generating_ggm_tree = SeedU8x16::insecurely_random();
        let mut prover_secret_bit_vec: Option<BitVec> = None;
        let mut prover_secret_voleith_mac_vec: Option<GFVec<GF2p8>> = None;
        let com_hash = prover_in_all_in_one_vc.commit(
            &public_parameter, &prover_secret_seed_for_generating_ggm_tree,
            &mut prover_secret_bit_vec, &mut prover_secret_voleith_mac_vec
        );
        let decom = prover_in_all_in_one_vc.open(&public_parameter, &nabla);

        // then generate in the verifier side
        let (reconstructed_com_hash, voleith_key_vec) = VerifierInAllInOneVC::reconstruct(
            &public_parameter, &nabla, &decom
        );
        println!("com_hash_from_prover: {:?}", com_hash);
        println!("reconstructed hash: {:?}", reconstructed_com_hash);
        assert_eq!(
            com_hash.as_bytes(),
            reconstructed_com_hash.as_bytes()
        );
        println!("com hash checking passed!");

        // let galois_field = GeneralField::new(
        //     galois_2p8::IrreducablePolynomial::Poly84310
        // );
        for j in 0..public_parameter.big_n {
            let mut shifted_nabla = GF2p8::zero();
            if prover_secret_bit_vec.as_ref().unwrap()[j] == 1 {
                shifted_nabla = nabla.clone();
            }
            println!("mac + bit * nabla, key, mac, msg: {:?}, {:?}, {:?}, {:?}",
                     prover_secret_voleith_mac_vec.as_ref().unwrap()[j].gf_add(&shifted_nabla),
                     voleith_key_vec[j],
                     prover_secret_voleith_mac_vec.as_ref().unwrap()[j],
                     prover_secret_bit_vec.as_ref().unwrap()[j]
            );
            assert_eq!(voleith_key_vec[j], prover_secret_voleith_mac_vec.as_ref().unwrap()[j].gf_add(&shifted_nabla));
        }
        println!("bit_vec_len, voleith_mac_vec_len, voleith_key_vec_len: {:?}, {:?}, {:?}",
                 prover_secret_bit_vec.as_ref().unwrap().len(),
                 prover_secret_voleith_mac_vec.as_ref().unwrap().len(), voleith_key_vec.len()
        );
        println!("voleith correlation checking passed!");
    }
}
