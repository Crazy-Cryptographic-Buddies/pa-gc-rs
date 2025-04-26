#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::ops::{Index, IndexMut};
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
    use crate::bristol_fashion_adaptor::GateType;
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
    use crate::functionalities_and_protocols::util::parse_two_bits;
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::value_type::{GFMultiplyingBit, InsecureRandom, Zero};
    use crate::value_type::GFAddition;
    use crate::vec_type::{VecAppending, ZeroVec};
    use crate::vec_type::bit_vec::BitVec;
    use crate::vec_type::gf_vec::GFVec;

    fn post_increase(value: &mut usize) -> usize {
        let original_value = value.clone();
        *value += 1usize;
        original_value
    }

    fn initialize_trace<PrimitiveType, VecType>(
        public_parameter: &PublicParameter,
        circuit_num_wires: usize,
        input_vec: &VecType,
        output_and_vec: &VecType,
    ) -> VecType
    where PrimitiveType: Clone,
          VecType: Clone + VecAppending + ZeroVec
            + Index<usize, Output = PrimitiveType> + IndexMut<usize, Output = PrimitiveType> {

        let mut res =  {
            let mut input_vec_cloned = input_vec.clone();
            input_vec_cloned.append(
                &mut VecType::zero_vec(circuit_num_wires - public_parameter.num_input_bits),
            );
            input_vec_cloned
        };
        {
            let mut and_cursor = 0usize;
            for wire in public_parameter.big_iw.iter() {
                res[*wire] = output_and_vec[post_increase(&mut and_cursor)].clone();
            }
        }
        res
    }

    pub fn compute_authenticated_middle_r_and_output_bit_vec<GFVOLE: GFAddition + GFMultiplyingBit>(
        k: usize, delta: &Option<GFVOLE>,
        r_gamma_k_bit: &mut u8, r_prime_gamma_bit: u8, r_output_bit: u8, r_left_input_bit: u8, r_right_input_bit: u8,
        vole_mac_r_gamma_k: &mut GFVOLE, vole_mac_r_prime: &GFVOLE, vole_mac_r_output: &GFVOLE, vole_mac_r_left_input: &GFVOLE, vole_mac_r_right_input: &GFVOLE,
        other_vole_key_r_gamma_k: &mut GFVOLE, other_vole_key_r_prime: &GFVOLE, vole_key_r_output: &GFVOLE, other_vole_key_r_left_input: &GFVOLE, other_vole_key_r_right_input: &GFVOLE
    ) {
        let (k0, k1) = parse_two_bits(k as u8);
        *r_gamma_k_bit = r_prime_gamma_bit ^ r_output_bit ^ (k0 & r_right_input_bit) ^ (k1 ^ r_left_input_bit);
        *vole_mac_r_gamma_k = vole_mac_r_prime.gf_add(&vole_mac_r_output)
            .gf_add(&vole_mac_r_right_input.gf_multiply_bit(k0))
            .gf_add(&vole_mac_r_left_input.gf_multiply_bit(k1));
        *other_vole_key_r_gamma_k = other_vole_key_r_prime.gf_add(&vole_key_r_output)
            .gf_add(&other_vole_key_r_right_input.gf_multiply_bit(k0))
            .gf_add(&other_vole_key_r_left_input.gf_multiply_bit(k1));
        if delta.is_some() {
            &other_vole_key_r_gamma_k.gf_add(
                &delta.as_ref().unwrap().gf_multiply_bit(k0).gf_multiply_bit(k1)
            );
        }
    }

    fn preprocess<GFVOLE, GFVOLEitH>(
        bristol_fashion_adaptor: &BristolFashionAdaptor, 
        public_parameter: &PublicParameter,
        pa_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pb_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
    )
    where GFVOLE: Clone + GFAddition + GFMultiplyingBit + InsecureRandom + Zero + Copy {
        // pa obtains delta from FPre
        InsecureFunctionalityPre::generate_delta(&mut pa_secret_state.delta);
        
        // pb obtains delta from FPre
        InsecureFunctionalityPre::generate_delta(&mut pb_secret_state.delta);
        
        // pa obtains vole-authenticated bits
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.num_input_bits,
            &pb_secret_state.delta.as_ref().unwrap(),
            &mut pa_secret_state.r_input_bit_vec,
            &mut pa_secret_state.vole_mac_r_input_vec,
            &mut pb_secret_state.other_vole_key_r_input_vec
        );
        assert_eq!(pa_secret_state.r_input_bit_vec.as_ref().unwrap().len(), public_parameter.num_input_bits);
        assert_eq!(pa_secret_state.vole_mac_r_input_vec.as_ref().unwrap().len(), public_parameter.num_input_bits);
        assert_eq!(pb_secret_state.other_vole_key_r_input_vec.as_ref().unwrap().len(), public_parameter.num_input_bits);
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.big_iw_size,
            &pb_secret_state.delta.as_ref().unwrap(),
            &mut pa_secret_state.r_output_and_bit_vec,
            &mut pa_secret_state.vole_mac_r_output_and_vec,
            &mut pb_secret_state.other_vole_key_r_output_and_vec
        );
        assert_eq!(pa_secret_state.r_output_and_bit_vec.as_ref().unwrap().len(), public_parameter.big_iw_size);
        assert_eq!(pa_secret_state.vole_mac_r_output_and_vec.as_ref().unwrap().len(), public_parameter.big_iw_size);
        assert_eq!(pb_secret_state.other_vole_key_r_output_and_vec.as_ref().unwrap().len(), public_parameter.big_iw_size);

        // pb obtains vole-authenticated bits
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.num_input_bits,
            &pa_secret_state.delta.as_ref().unwrap(),
            &mut pb_secret_state.r_input_bit_vec,
            &mut pb_secret_state.vole_mac_r_input_vec,
            &mut pa_secret_state.other_vole_key_r_input_vec
        );
        assert_eq!(pb_secret_state.r_input_bit_vec.as_ref().unwrap().len(), public_parameter.num_input_bits);
        assert_eq!(pb_secret_state.vole_mac_r_input_vec.as_ref().unwrap().len(), public_parameter.num_input_bits);
        assert_eq!(pa_secret_state.other_vole_key_r_input_vec.as_ref().unwrap().len(), public_parameter.num_input_bits);
        
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.big_iw_size,
            &pa_secret_state.delta.as_ref().unwrap(),
            &mut pb_secret_state.r_output_and_bit_vec,
            &mut pb_secret_state.vole_mac_r_output_and_vec,
            &mut pa_secret_state.other_vole_key_r_output_and_vec
        );
        assert_eq!(pb_secret_state.r_output_and_bit_vec.as_ref().unwrap().len(), public_parameter.big_iw_size);
        assert_eq!(pb_secret_state.vole_mac_r_output_and_vec.as_ref().unwrap().len(), public_parameter.big_iw_size);
        assert_eq!(pa_secret_state.other_vole_key_r_output_and_vec.as_ref().unwrap().len(), public_parameter.big_iw_size);
        let mut pa_label_input_vec = (0..public_parameter.num_input_bits).map(
            |_| GFVOLE::insecurely_random()
        ).collect::<GFVec<GFVOLE>>();
        let mut pa_label_output_and_vec = (0..public_parameter.big_iw_size).map(
            |_| GFVOLE::insecurely_random()
        ).collect::<GFVec<GFVOLE>>();
        assert_eq!(pa_label_input_vec.len(), public_parameter.num_input_bits);
        assert_eq!(pa_label_output_and_vec.len(), public_parameter.big_iw_size);

        // initialize traces for pa
        let mut pa_r_bit_vec = initialize_trace::<u8, BitVec>(
            public_parameter,
            bristol_fashion_adaptor.get_num_wires(),
            &pa_secret_state.r_input_bit_vec.as_ref().unwrap(),
            &pa_secret_state.r_output_and_bit_vec.as_ref().unwrap()
        );
        assert_eq!(pa_r_bit_vec.len(), bristol_fashion_adaptor.get_num_wires());
        let mut pa_vole_mac_r_vec = initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            bristol_fashion_adaptor.get_num_wires(),
            &pa_secret_state.vole_mac_r_input_vec.as_ref().unwrap(),
            &pa_secret_state.vole_mac_r_output_and_vec.as_ref().unwrap()
        );
        assert_eq!(pa_vole_mac_r_vec.len(), bristol_fashion_adaptor.get_num_wires());
        let mut pa_other_vole_key_r_vec = initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            bristol_fashion_adaptor.get_num_wires(),
            &pa_secret_state.other_vole_key_r_input_vec.as_ref().unwrap(),
            &pa_secret_state.other_vole_key_r_output_and_vec.as_ref().unwrap()
        );
        assert_eq!(pa_other_vole_key_r_vec.len(), bristol_fashion_adaptor.get_num_wires());
        let mut pa_label_vec = initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            bristol_fashion_adaptor.get_num_wires(),
            &pa_label_input_vec,
            &pa_label_output_and_vec
        );
        assert_eq!(pa_label_vec.len(), bristol_fashion_adaptor.get_num_wires());

        // initialize traces for pb
        let mut pb_r_bit_vec = initialize_trace::<u8, BitVec>(
            public_parameter,
            bristol_fashion_adaptor.get_num_wires(),
            &pb_secret_state.r_input_bit_vec.as_ref().unwrap(),
            &pb_secret_state.r_output_and_bit_vec.as_ref().unwrap()
        );
        assert_eq!(pb_r_bit_vec.len(), bristol_fashion_adaptor.get_num_wires());
        let mut pb_vole_mac_r_vec = initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            bristol_fashion_adaptor.get_num_wires(),
            &pb_secret_state.vole_mac_r_input_vec.as_ref().unwrap(),
            &pb_secret_state.vole_mac_r_output_and_vec.as_ref().unwrap()
        );
        assert_eq!(pb_vole_mac_r_vec.len(), bristol_fashion_adaptor.get_num_wires());
        let mut pb_other_vole_key_r_vec = initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            bristol_fashion_adaptor.get_num_wires(),
            &pb_secret_state.other_vole_key_r_input_vec.as_ref().unwrap(),
            &pb_secret_state.other_vole_key_r_output_and_vec.as_ref().unwrap()
        );
        assert_eq!(pb_other_vole_key_r_vec.len(), bristol_fashion_adaptor.get_num_wires());

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

        // Prepare masked_r_and_output_bit_vec for computing with AND gates
        // let mut pa_r_prime_bit_vec = vec![0u8; public_parameter.big_iw_size];
        // let mut pa_vole_mac_r_prime_vec = vec![GFVOLE::zero(); public_parameter.big_iw_size];
        // let mut pa_other_vole_key_r_prime_vec = vec![GFVOLE::zero(); public_parameter.big_iw_size];
        let mut pa_middle_r_and_output_bit_vec = vec![[0u8; 4]; public_parameter.big_iw_size];
        let mut pa_middle_vole_mac_r_and_output_bit_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];
        let mut pa_other_middle_vole_key_r_and_output_bit_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];
        // let mut pb_r_prime_bit_vec = vec![0u8; public_parameter.big_iw_size];
        // let mut pb_vole_mac_r_prime_vec = vec![GFVOLE::zero(); public_parameter.big_iw_size];
        // let mut pb_other_vole_key_r_prime_vec = vec![GFVOLE::zero(); public_parameter.big_iw_size];
        let mut pb_middle_r_and_output_bit_vec = vec![[0u8; 4]; public_parameter.big_iw_size];
        let mut pb_middle_vole_mac_r_and_output_bit_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];
        let mut pb_other_middle_vole_key_r_and_output_bit_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];

        //follow topological of circuit to compute
        let mut and_cursor = 0usize;
        for gate in bristol_fashion_adaptor.get_gate_vec() {
            println!("{:?}", (gate.left_input_wire, gate.right_input_wire, gate.output_wire, gate.gate_type.clone()));
            match gate.gate_type {
                GateType::XOR => {
                    // compute for pa
                    pa_r_bit_vec[gate.output_wire] = pa_r_bit_vec[gate.left_input_wire] ^ pa_r_bit_vec[gate.right_input_wire];
                    pa_vole_mac_r_vec[gate.output_wire] = pa_vole_mac_r_vec[gate.left_input_wire].gf_add(&pa_vole_mac_r_vec[gate.right_input_wire]);
                    pa_other_vole_key_r_vec[gate.output_wire] = pa_other_vole_key_r_vec[gate.left_input_wire].gf_add(&pa_other_vole_key_r_vec[gate.right_input_wire]);
                    pa_label_vec[gate.output_wire] = pa_label_vec[gate.left_input_wire].gf_add(&pa_label_vec[gate.right_input_wire]);

                    // compute for pb
                    pb_r_bit_vec[gate.output_wire] = pb_r_bit_vec[gate.left_input_wire] ^ pb_r_bit_vec[gate.right_input_wire];
                    pb_vole_mac_r_vec[gate.output_wire] = pb_vole_mac_r_vec[gate.left_input_wire].gf_add(&pb_vole_mac_r_vec[gate.right_input_wire]);
                    pb_other_vole_key_r_vec[gate.output_wire] = pb_other_vole_key_r_vec[gate.left_input_wire].gf_add(&pb_other_vole_key_r_vec[gate.right_input_wire]);
                },
                GateType::NOT => {
                    // compute for pa
                    pa_r_bit_vec[gate.output_wire] = pa_r_bit_vec[gate.left_input_wire];
                    pa_vole_mac_r_vec[gate.output_wire] = pa_vole_mac_r_vec[gate.left_input_wire];
                    pa_other_vole_key_r_vec[gate.output_wire] = pa_other_vole_key_r_vec[gate.left_input_wire];
                    pa_label_vec[gate.output_wire] = pa_label_vec[gate.left_input_wire];
                    
                    // compute for pb
                    pb_r_bit_vec[gate.output_wire] = !pb_r_bit_vec[gate.left_input_wire];
                    pb_vole_mac_r_vec[gate.output_wire] = pb_vole_mac_r_vec[gate.left_input_wire];
                    pb_other_vole_key_r_vec[gate.output_wire] = pb_other_vole_key_r_vec[gate.left_input_wire];
                },
                GateType::AND => {
                    InsecureFunctionalityPre::generate_random_authenticated_and_tuples(
                        pa_secret_state.delta.as_ref().unwrap(),
                        pa_r_bit_vec[gate.left_input_wire],
                        pa_r_bit_vec[gate.right_input_wire],
                        &mut pa_secret_state.r_prime_bit_vec[and_cursor],
                        &mut pa_secret_state.vole_mac_r_prime_vec[and_cursor],
                        &mut pb_secret_state.other_vole_key_r_prime_vec[and_cursor],
                        pa_secret_state.delta.as_ref().unwrap(),
                        pb_r_bit_vec[gate.left_input_wire],
                        pb_r_bit_vec[gate.right_input_wire],
                        &mut pb_secret_state.r_prime_bit_vec[and_cursor],
                        &mut pb_secret_state.vole_mac_r_prime_vec[and_cursor],
                        &mut pa_secret_state.other_vole_key_r_prime_vec[and_cursor],
                    );

                    // PA computes
                    for k in 0..4 {
                        compute_authenticated_middle_r_and_output_bit_vec(
                            k, &pa_secret_state.delta,
                            &mut pa_middle_r_and_output_bit_vec[and_cursor][k],
                            pa_secret_state.r_prime_bit_vec[and_cursor],
                            pa_r_bit_vec[gate.output_wire],
                            pa_r_bit_vec[gate.left_input_wire],
                            pa_r_bit_vec[gate.right_input_wire],
                            &mut pa_middle_vole_mac_r_and_output_bit_vec[and_cursor][k],
                            &pa_secret_state.vole_mac_r_prime_vec[and_cursor],
                            &pa_vole_mac_r_vec[gate.output_wire],
                            &pa_vole_mac_r_vec[gate.left_input_wire],
                            &pa_vole_mac_r_vec[gate.right_input_wire],
                            &mut pa_other_middle_vole_key_r_and_output_bit_vec[and_cursor][k],
                            &pa_secret_state.other_vole_key_r_prime_vec[and_cursor],
                            &pa_other_vole_key_r_vec[gate.output_wire],
                            &pa_other_vole_key_r_vec[gate.left_input_wire],
                            &pa_other_vole_key_r_vec[gate.right_input_wire]
                        );
                    }

                    // PB computes
                    for k in 0..4 {
                        compute_authenticated_middle_r_and_output_bit_vec(
                            k, &None,
                            &mut pb_middle_r_and_output_bit_vec[and_cursor][k],
                            pb_secret_state.r_prime_bit_vec[and_cursor],
                            pb_r_bit_vec[gate.output_wire],
                            pb_r_bit_vec[gate.left_input_wire],
                            pb_r_bit_vec[gate.right_input_wire],
                            &mut pb_middle_vole_mac_r_and_output_bit_vec[and_cursor][k],
                            &pb_secret_state.vole_mac_r_prime_vec[and_cursor],
                            &pb_vole_mac_r_vec[gate.output_wire],
                            &pb_vole_mac_r_vec[gate.left_input_wire],
                            &pb_vole_mac_r_vec[gate.right_input_wire],
                            &mut pb_other_middle_vole_key_r_and_output_bit_vec[and_cursor][k],
                            &pb_secret_state.other_vole_key_r_prime_vec[and_cursor],
                            &pb_other_vole_key_r_vec[gate.output_wire],
                            &pb_other_vole_key_r_vec[gate.left_input_wire],
                            &pb_other_vole_key_r_vec[gate.right_input_wire]
                        )
                    }

                    and_cursor += 1;
                }

            }
        }
    }
    
    #[test]
    fn test_pa_2pc_for_addition() {
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(&"sha256.txt".to_string());
        let num_input_bits = bristol_fashion_adaptor.get_num_input_bits();
        let big_ia = (0..num_input_bits >> 1).collect::<Vec<usize>>();
        let big_ib = (big_ia.len()..num_input_bits).collect::<Vec<usize>>();
        let bs = 10;
        let rm = 8;
        let public_parameter = PublicParameter::new(
            8,
            10,
            SeedU8x16::insecurely_random(),
            big_ia,
            big_ib,
            bristol_fashion_adaptor.determine_and_gate_output_wires(),
            4,
            50,
        );
        
        let mut pa_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter, 
            SeedU8x16::insecurely_random(),
        );
        
        let mut pb_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter, 
            SeedU8x16::insecurely_random(),
        );
        
        preprocess(
            &bristol_fashion_adaptor, 
            &public_parameter, 
            &mut pa_secret_state, 
            &mut pb_secret_state
        );
    }
}