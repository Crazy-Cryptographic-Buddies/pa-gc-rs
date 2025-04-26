#[cfg(test)]
mod tests {
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
    use crate::bristol_fashion_adaptor::GateType;
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::value_type::{GFMultiplyingBit, InsecureRandom, Zero};
    use crate::value_type::GFAddition;
    use crate::vec_type::bit_vec::BitVec;
    use crate::vec_type::ZeroVec;

    fn prove<GFVOLE, GFVOLEitH>(
        bristol_fashion_adaptor: &BristolFashionAdaptor, 
        public_parameter: &PublicParameter,
        pa_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pb_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
    ) 
    where GFVOLE: Clone + GFAddition + GFMultiplyingBit + InsecureRandom + Zero {
        // pa obtains delta from FPre
        InsecureFunctionalityPre::generate_delta(&mut pa_secret_state.delta);
        
        // pb obtains delta from FPre
        InsecureFunctionalityPre::generate_delta(&mut pb_secret_state.delta);
        
        // pa obtains vole-authenticated bits
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.num_input_bits,
            &pb_secret_state.delta.as_ref().unwrap(),
            &mut pa_secret_state.r_input_bit_vec,
            &mut pa_secret_state.vole_mac_r_input_vec_rep,
            &mut pb_secret_state.other_vole_key_r_input_vec_rep
        );
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.big_w,
            &pb_secret_state.delta.as_ref().unwrap(),
            &mut pa_secret_state.r_output_and_bit_vec,
            &mut pa_secret_state.vole_mac_r_output_and_vec_rep,
            &mut pb_secret_state.other_vole_key_r_output_and_vec_rep
        );
        let label_zero = (0..public_parameter.num_input_bits).map(
            |_| GFVOLE::insecurely_random()
        ).collect::<Vec<GFVOLE>>();
        // let mut pa_r_bit_vec = pa_secret_state.r_bit_vec.as_ref().unwrap().iter().map(
        //     |x| x.clone()
        // ).collect::<Vec<u8>>().append(
        //     &mut vec![
        //         0u8; 
        //         bristol_fashion_adaptor.get_num_wires() - bristol_fashion_adaptor.get_num_input_bits()
        //     ]
        // );
        
        // pb obtains vole-authenticated bits
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.num_input_bits,
            &pa_secret_state.delta.as_ref().unwrap(),
            &mut pb_secret_state.r_input_bit_vec,
            &mut pb_secret_state.vole_mac_r_input_vec_rep,
            &mut pa_secret_state.other_vole_key_r_input_vec_rep
        );
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.big_w,
            &pa_secret_state.delta.as_ref().unwrap(),
            &mut pb_secret_state.r_output_and_bit_vec,
            &mut pb_secret_state.vole_mac_r_output_and_vec_rep,
            &mut pa_secret_state.other_vole_key_r_output_and_vec_rep
        );
        
        // obtain multiplication AND triples
        InsecureFunctionalityPre::generate_random_and_tuples(
            public_parameter.kappa,
            public_parameter.big_l * public_parameter.kappa,
            &mut pa_secret_state.tilde_a_bit_vec_rep,
            &mut pa_secret_state.tilde_b_bit_vec_rep,
            &mut pa_secret_state.tilde_c_bit_vec_rep,
            &mut pb_secret_state.tilde_a_bit_vec_rep,
            &mut pb_secret_state.tilde_b_bit_vec_rep,
            &mut pb_secret_state.tilde_c_bit_vec_rep,
        );
        
        // follow topological of circuit to compute
        // for gate in bristol_fashion_adaptor.get_gate_vec() {
        //     if gate.gate_type == GateType::XOR {
        //         pa_r_bit_vec[gate.output_wire] = pa_r_bit_vec[gate.left_input_wire] ^ pa_r_bit_vec[gate.right_input_wire];
        //     }
        // }
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