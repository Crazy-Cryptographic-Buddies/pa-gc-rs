#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
    use crate::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_pa_2pc::prover_in_pa_2pc::ProverInPA2PC;
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::value_type::{ByteManipulation, InsecureRandom};
    use crate::vec_type::{BasicVecFunctions};
    
    // fn verify<GFVOLE, GFVOLEitH>(
    //     bristol_fashion_adaptor: &BristolFashionAdaptor,
    //     public_parameter: &PublicParameter,
    //     nabla_a_rep: Vec<GFVOLEitH>, nabla_b_rep: Vec<GFVOLEitH>,
    // ) {
    //
    // }
    
    #[test]
    fn test_pa_2pc_for_addition() {
        type GFVOLE = GF2p256;
        type GFVOLEitH = GF2p8;
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(
            &"adder64.txt".to_string()
        );
        println!("Num AND gates: {:?}", bristol_fashion_adaptor.get_and_gate_output_wire_vec().len());
        let num_input_bits = bristol_fashion_adaptor.get_num_input_bits();
        let big_ia = (0..num_input_bits >> 1).collect::<Vec<usize>>();
        let big_ib = (big_ia.len()..num_input_bits).collect::<Vec<usize>>();
        let bs = 1;
        let rm = bristol_fashion_adaptor.get_and_gate_output_wire_vec().len();
        let public_parameter = PublicParameter::new(
            8,
            32,
            SeedU8x16::insecurely_random(),
            big_ia,
            big_ib,
            bristol_fashion_adaptor.get_and_gate_output_wire_vec().clone(),
            bs,
            rm,
        );
        
        let mut pa_secret_state = ProverSecretState::<GFVOLE, GFVOLEitH>::new(
            &public_parameter, 
            SeedU8x16::insecurely_random(),
        );
        
        let mut pb_secret_state = ProverSecretState::<GFVOLE, GFVOLEitH>::new(
            &public_parameter, 
            SeedU8x16::insecurely_random(),
        );

        let gabled_row_byte_len = 1 + GFVOLE::num_bytes()
            + GFVOLEitH::num_bytes() * public_parameter.kappa + GFVOLE::num_bytes();
        
        ProverInPA2PC::preprocess(
            &bristol_fashion_adaptor, 
            &public_parameter, 
            &mut pa_secret_state, 
            &mut pb_secret_state,
            gabled_row_byte_len,
        );
    }
}