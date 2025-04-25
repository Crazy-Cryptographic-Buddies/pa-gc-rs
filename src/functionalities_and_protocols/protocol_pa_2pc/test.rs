#[cfg(test)]
mod tests {
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::value_type::InsecureRandom;

    fn prove(
        bristol_fashion_adaptor: &BristolFashionAdaptor, 
        public_parameter: &PublicParameter,
        pa_secret_state: &mut ProverSecretState<GF2p256, GF2p8>,
        pb_secret_state: &mut ProverSecretState<GF2p256, GF2p8>,
    ) {
        // pa obtains delta from FPre
        InsecureFunctionalityPre::generate_delta(&mut pa_secret_state.delta);
        
        // pb obtains delta from FPre
        InsecureFunctionalityPre::generate_delta(&mut pb_secret_state.delta);
        
        // pa obtains vole-authenticated bits
        // InsecureFunctionalityPre::generate_random_tuples(
        //     public_parameter.sum_big_ia_ib_iw,
        //     &pb_secret_state.delta.as_ref().unwrap(),
        //     &mut pa_secret_state.r_bit_vec,
        //     &mut pa_secret_state.vole_mac_r_vec_rep,
        //     
        // )
    }
    
    #[test]
    fn test_pa_2pc_for_addition() {
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(&"adder64.txt".to_string());
        let num_input_bits = bristol_fashion_adaptor.get_num_input_bits();
        let big_ia_size = num_input_bits >> 1;
        let big_ib_size = num_input_bits - big_ia_size;
        let big_w = bristol_fashion_adaptor.compute_num_and_gates();
        let big_ia = (0..big_ib_size).collect::<Vec<usize>>();
        let big_ib = (big_ib_size..num_input_bits).collect::<Vec<usize>>();
        let bs = 10;
        let rm = 8;
        let public_parameter = PublicParameter::new(
            8,
            10,
            SeedU8x16::insecurely_random(),
            big_ia_size,
            big_ib_size,
            big_w,
            bs * big_w + rm,
            big_ia,
            big_ib,
        );
        
        let mut pa_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter, 
            SeedU8x16::insecurely_random(),
        );
        
        let mut pb_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter, 
            SeedU8x16::insecurely_random(),
        );
        
        prove(
            &bristol_fashion_adaptor, 
            &public_parameter, 
            &mut pa_secret_state, 
            &mut pb_secret_state
        );
    }
}