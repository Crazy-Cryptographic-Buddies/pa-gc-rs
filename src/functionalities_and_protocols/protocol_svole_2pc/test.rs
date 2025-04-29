#[cfg(test)]
mod tests {
    use itertools::izip;
    use rand::Rng;
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
    use crate::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_svole_2pc::prover_in_protocol_svole_2pc::ProverInProtocolSVOLE2PC;
    use crate::functionalities_and_protocols::protocol_svole_2pc::verifier_in_protocol_svole_2pc::VerifierInProtocolSVOLE2PC;
    use crate::value_type::{gf2p8::GF2p8};
    use crate::value_type::{CustomAddition, CustomMultiplyingBit, InsecureRandom};
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::seed_u8x16::SeedU8x16;

    fn sample_secret_bit_vecs(
        public_parameter: &PublicParameter, 
        prover_secret_state: &mut ProverSecretState<GF2p256, GF2p8>
    ) {
        let mut rng = rand::rng();
        for i in 0..public_parameter.num_input_bits {
            prover_secret_state.r_input_bit_vec[i] = rng.random::<u8>() & 1;
        }
        for i in 0..public_parameter.big_iw_size {
            prover_secret_state.r_output_and_bit_vec[i] = rng.random::<u8>() & 1;
        }
        // prover_secret_state.r_prime_bit_vec = Some(BitVec::new());
        for i in 0..public_parameter.big_iw_size {
            prover_secret_state.r_prime_bit_vec[i] = rng.random::<u8>() & 1;
        }
        for repetition_id in 0..public_parameter.kappa {
            for i in 0..public_parameter.big_l {
                prover_secret_state.tilde_a_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
            }
        }
        
        for repetition_id in 0..public_parameter.kappa {
            for i in 0..public_parameter.big_l {
                prover_secret_state.tilde_b_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
            }
        }
        for repetition_id in 0..public_parameter.kappa {
            for i in 0..public_parameter.big_l {
                prover_secret_state.tilde_c_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
            }
        }
    }

    #[test]
    fn try_commit_and_fix_protocol_svole_2pc_test_case_1() {
        let process_printing = true;
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(
            &"adder64.txt".to_string()
        );
        let public_parameter = PublicParameter::new::<GF2p256, GF2p8>(
            &bristol_fashion_adaptor,
            8,
            10,
            SeedU8x16::insecurely_random(),
            (0..100).collect(),
            (100..200).collect(),
            10,
            4
        );
        let mut pa_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter,
            SeedU8x16::insecurely_random(),
            true
        );
        let mut pb_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter,
            SeedU8x16::insecurely_random(),
            false
        );
        sample_secret_bit_vecs(&public_parameter, &mut pa_secret_state);
        sample_secret_bit_vecs(&public_parameter, &mut pb_secret_state);
        
        // pa commits and fixes voleith-authenticated bits
        let (
            pa_com_hash_rep, pa_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec(
            process_printing, &public_parameter, &mut pa_secret_state
        );
        
        // pb commits and fixes voleith-authenticated bits
        let (
            pb_com_hash_rep, pb_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec(
            process_printing, &public_parameter, &mut pb_secret_state
        );
        
        // sample nablas
        let mut nabla_a_rep: Vec<GF2p8> = Vec::new();
        let mut nabla_b_rep: Vec<GF2p8> = Vec::new();
        for _ in 0..public_parameter.kappa {
            nabla_a_rep.push(GF2p8::insecurely_random());
            nabla_b_rep.push(GF2p8::insecurely_random());
        }
        
        // open
        let pa_decom_rep = ProverInProtocolSVOLE2PC::open(&public_parameter, &mut pa_secret_state, &nabla_b_rep);
        let pb_decom_rep = ProverInProtocolSVOLE2PC::open(&public_parameter, &mut pb_secret_state, &nabla_a_rep);
        
        // reconstruct
        let pa_voleith_key_tuple_rep = VerifierInProtocolSVOLE2PC::reconstruct_and_fix_voleith_key_vec(
            process_printing, &public_parameter, &pa_com_hash_rep, &pa_masked_bit_tuple_rep, &nabla_b_rep, &pa_decom_rep
        );
        let pb_voleith_key_tuple_rep = VerifierInProtocolSVOLE2PC::reconstruct_and_fix_voleith_key_vec(
            process_printing, &public_parameter, &pb_com_hash_rep, &pb_masked_bit_tuple_rep, &nabla_a_rep, &pb_decom_rep
        );
        
        // test voleith correlations in the pa side
        for repetition_id in 0..public_parameter.kappa {
            let (
                voleith_key_r_input_vec,
                voleith_key_r_output_and_vec,
                voleith_key_r_prime_vec,
                voleith_key_tilde_a_vec,
                voleith_key_tilde_b_vec,
                voleith_key_tilde_c_vec
            ) = &pa_voleith_key_tuple_rep[repetition_id];
            
            // test length of bit vectors
            assert_eq!(pa_secret_state.r_input_bit_vec.len(), public_parameter.num_input_bits);
            assert_eq!(pa_secret_state.r_output_and_bit_vec.len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.r_prime_bit_vec.len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.tilde_a_bit_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.tilde_b_bit_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.tilde_c_bit_vec_rep[repetition_id].len(), public_parameter.big_l);
            // test length of voleith mac vectors
            assert_eq!(pa_secret_state.voleith_mac_r_input_vec_rep[repetition_id].len(), public_parameter.num_input_bits);
            assert_eq!(pa_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id].len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.voleith_mac_r_prime_vec_rep[repetition_id].len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.voleith_mac_tilde_a_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.voleith_mac_tilde_b_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.voleith_mac_tilde_c_vec_rep[repetition_id].len(), public_parameter.big_l);
            // test length of voleith key vectors
            assert_eq!(voleith_key_r_input_vec.len(), public_parameter.num_input_bits);
            assert_eq!(voleith_key_r_prime_vec.len(), public_parameter.big_iw_size);
            assert_eq!(voleith_key_tilde_a_vec.len(), public_parameter.big_l);
            assert_eq!(voleith_key_tilde_b_vec.len(), public_parameter.big_l);
            assert_eq!(voleith_key_tilde_c_vec.len(), public_parameter.big_l);
            for (bit, mac, key) in izip!(
                pa_secret_state.r_input_bit_vec.iter(), 
                pa_secret_state.voleith_mac_r_input_vec_rep[repetition_id].iter(), 
                voleith_key_r_input_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pa_secret_state.r_output_and_bit_vec.iter(), 
                pa_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id].iter(), 
                voleith_key_r_output_and_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pa_secret_state.r_prime_bit_vec.iter(), 
                pa_secret_state.voleith_mac_r_prime_vec_rep[repetition_id].iter(), 
                voleith_key_r_prime_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pa_secret_state.tilde_a_bit_vec_rep[repetition_id].iter(), 
                pa_secret_state.voleith_mac_tilde_a_vec_rep[repetition_id].iter(), 
                voleith_key_tilde_a_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pa_secret_state.tilde_b_bit_vec_rep[repetition_id].iter(), 
                pa_secret_state.voleith_mac_tilde_b_vec_rep[repetition_id].iter(), 
                voleith_key_tilde_b_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pa_secret_state.tilde_c_bit_vec_rep[repetition_id].iter(), 
                pa_secret_state.voleith_mac_tilde_c_vec_rep[repetition_id].iter(), 
                voleith_key_tilde_c_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_b_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
        }

        // test voleith correlations in the pb side
        for repetition_id in 0..public_parameter.kappa {
            let (
                voleith_key_r_input_vec,
                voleith_key_r_output_and_vec,
                voleith_key_r_prime_vec,
                voleith_key_tilde_a_vec,
                voleith_key_tilde_b_vec,
                voleith_key_tilde_c_vec
            ) = &pb_voleith_key_tuple_rep[repetition_id];

            // test length of bit vectors
            assert_eq!(pa_secret_state.r_input_bit_vec.len(), public_parameter.num_input_bits);
            assert_eq!(pa_secret_state.r_output_and_bit_vec.len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.r_prime_bit_vec.len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.tilde_a_bit_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.tilde_b_bit_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.tilde_c_bit_vec_rep[repetition_id].len(), public_parameter.big_l);
            // test length of voleith mac vectors
            assert_eq!(pa_secret_state.voleith_mac_r_input_vec_rep[repetition_id].len(), public_parameter.num_input_bits);
            assert_eq!(pa_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id].len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.voleith_mac_r_prime_vec_rep[repetition_id].len(), public_parameter.big_iw_size);
            assert_eq!(pa_secret_state.voleith_mac_tilde_a_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.voleith_mac_tilde_b_vec_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(pa_secret_state.voleith_mac_tilde_c_vec_rep[repetition_id].len(), public_parameter.big_l);
            // test length of voleith key vectors
            assert_eq!(voleith_key_r_input_vec.len(), public_parameter.num_input_bits);
            assert_eq!(voleith_key_r_output_and_vec.len(), public_parameter.big_iw_size);
            assert_eq!(voleith_key_r_prime_vec.len(), public_parameter.big_iw_size);
            assert_eq!(voleith_key_tilde_a_vec.len(), public_parameter.big_l);
            assert_eq!(voleith_key_tilde_b_vec.len(), public_parameter.big_l);
            assert_eq!(voleith_key_tilde_c_vec.len(), public_parameter.big_l);
            for (bit, mac, key) in izip!(
                pb_secret_state.r_input_bit_vec.iter(), 
                pb_secret_state.voleith_mac_r_input_vec_rep[repetition_id].iter(), 
                voleith_key_r_input_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pb_secret_state.r_output_and_bit_vec.iter(), 
                pb_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id].iter(), 
                voleith_key_r_output_and_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pb_secret_state.r_prime_bit_vec.iter(), 
                pb_secret_state.voleith_mac_r_prime_vec_rep[repetition_id].iter(), 
                voleith_key_r_prime_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pb_secret_state.tilde_a_bit_vec_rep[repetition_id].iter(), 
                pb_secret_state.voleith_mac_tilde_a_vec_rep[repetition_id].iter(), 
                voleith_key_tilde_a_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pb_secret_state.tilde_b_bit_vec_rep[repetition_id].iter(), 
                pb_secret_state.voleith_mac_tilde_b_vec_rep[repetition_id].iter(), 
                voleith_key_tilde_b_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
            for (bit, mac, key) in izip!(
                pb_secret_state.tilde_c_bit_vec_rep[repetition_id].iter(), 
                pb_secret_state.voleith_mac_tilde_c_vec_rep[repetition_id].iter(), 
                voleith_key_tilde_c_vec.iter()
            ) {
                println!("(bit, mac, key, nabla * bit + mac) = ({:?}, {:?}, {:?}, {:?})", bit, mac, key, nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac));
                assert_eq!(nabla_a_rep[repetition_id].custom_multiply_bit(*bit).custom_add(mac), *key);
            }
        }
    }
}