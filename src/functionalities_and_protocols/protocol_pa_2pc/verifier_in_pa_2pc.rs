use std::fmt::Debug;
use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
use crate::bristol_fashion_adaptor::GateType;
use crate::functionalities_and_protocols::protocol_pa_2pc::{initialize_trace, permute, split_off_rm};
use crate::functionalities_and_protocols::protocol_svole_2pc::verifier_in_protocol_svole_2pc::VerifierInProtocolSVOLE2PC;
use crate::functionalities_and_protocols::protocol_pa_2pc::preprocessing_transcript::PreprocessingTranscript;
use crate::functionalities_and_protocols::protocol_pa_2pc::proof_transcript::ProofTranscript;
use crate::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::util::verifier::Verifier;
use crate::value_type::{CustomAddition, CustomMultiplyingBit, U8ForGF, Zero};
use crate::vec_type::{gf_vec::GFVec, BasicVecFunctions, VecAddition, ZeroVec};
use crate::vec_type::bit_vec::BitVec;

pub struct VerifierInPA2PC;

impl VerifierInPA2PC {
    pub fn verify<GFVOLE, GFVOLEitH>(
        bristol_fashion_adaptor: &BristolFashionAdaptor,
        public_parameter: &PublicParameter,
        permutation_rep: &Vec<Vec<usize>>,
        nabla_a_rep: &Vec<GFVOLEitH>, nabla_b_rep: &Vec<GFVOLEitH>,
        preprocessing_transcript: &PreprocessingTranscript<GFVOLE, GFVOLEitH>,
        proof_transcript: &ProofTranscript<GFVOLE, GFVOLEitH>,
        pa_secret_state_to_be_removed: &ProverSecretState<GFVOLE, GFVOLEitH>,
    )
    where GFVOLE: Clone,
          GFVOLEitH: Clone + CustomAddition + CustomMultiplyingBit + Zero + U8ForGF + PartialEq + Debug + Copy {
        // form the voleith key vectors
        let mut pa_voleith_key_r_input_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.num_input_bits); public_parameter.kappa];
        let mut pa_voleith_key_r_output_and_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa];
        let mut pa_voleith_key_r_prime_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa];
        let mut pa_voleith_key_tilde_a_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_l); public_parameter.kappa];
        let mut pa_voleith_key_tilde_b_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_l); public_parameter.kappa];
        let mut pa_voleith_key_tilde_c_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_l); public_parameter.kappa];
        let mut pa_voleith_key_tuple_rep = VerifierInProtocolSVOLE2PC::reconstruct_and_fix_voleith_key_vec(
            public_parameter,
            &preprocessing_transcript.pa_com_hash_rep,
            &preprocessing_transcript.pa_masked_bit_tuple_rep,
            &nabla_b_rep,
            &proof_transcript.pa_decom,
        );
        (0..public_parameter.kappa).rev().for_each(
            |repetition_id| {
                (
                    pa_voleith_key_r_input_vec_rep[repetition_id],
                    pa_voleith_key_r_output_and_vec_rep[repetition_id],
                    pa_voleith_key_r_prime_vec_rep[repetition_id],
                    pa_voleith_key_tilde_a_vec_rep[repetition_id],
                    pa_voleith_key_tilde_b_vec_rep[repetition_id],
                    pa_voleith_key_tilde_c_vec_rep[repetition_id],
                ) = pa_voleith_key_tuple_rep.pop().unwrap();
            }
        );
        let mut pb_voleith_key_r_input_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.num_input_bits); public_parameter.kappa];
        let mut pb_voleith_key_r_output_and_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa];
        let mut pb_voleith_key_r_prime_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa];
        let mut pb_voleith_key_tilde_a_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_l); public_parameter.kappa];
        let mut pb_voleith_key_tilde_b_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_l); public_parameter.kappa];
        let mut pb_voleith_key_tilde_c_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_l); public_parameter.kappa];
        let mut pb_voleith_key_tuple_rep = VerifierInProtocolSVOLE2PC::reconstruct_and_fix_voleith_key_vec(
            public_parameter,
            &preprocessing_transcript.pb_com_hash_rep,
            &preprocessing_transcript.pb_masked_bit_tuple_rep,
            &nabla_a_rep,
            &proof_transcript.pb_decom,
        );
        (0..public_parameter.kappa).rev().for_each(
            |repetition_id| {
                (
                    pb_voleith_key_r_input_vec_rep[repetition_id],
                    pb_voleith_key_r_output_and_vec_rep[repetition_id],
                    pb_voleith_key_r_prime_vec_rep[repetition_id],
                    pb_voleith_key_tilde_a_vec_rep[repetition_id],
                    pb_voleith_key_tilde_b_vec_rep[repetition_id],
                    pb_voleith_key_tilde_c_vec_rep[repetition_id],
                ) = pb_voleith_key_tuple_rep.pop().unwrap();
            }
        );

        // permute PA's voleith key vectors
        permute(public_parameter, permutation_rep, &mut pa_voleith_key_tilde_a_vec_rep);
        permute(public_parameter, permutation_rep, &mut pa_voleith_key_tilde_b_vec_rep);
        permute(public_parameter, permutation_rep, &mut pa_voleith_key_tilde_c_vec_rep);

        // permute PB's voleith key vectors
        permute(public_parameter, permutation_rep, &mut pb_voleith_key_tilde_a_vec_rep);
        permute(public_parameter, permutation_rep, &mut pb_voleith_key_tilde_b_vec_rep);
        permute(public_parameter, permutation_rep, &mut pb_voleith_key_tilde_c_vec_rep);

        // split off PA's voleith key vectors
        let pa_rm_voleith_key_tilde_a_vec_rep = split_off_rm(public_parameter, &mut pa_voleith_key_tilde_a_vec_rep);
        let pa_rm_voleith_key_tilde_b_vec_rep = split_off_rm(public_parameter, &mut pa_voleith_key_tilde_b_vec_rep);
        let pa_rm_voleith_key_tilde_c_vec_rep = split_off_rm(public_parameter, &mut pa_voleith_key_tilde_c_vec_rep);
        assert_eq!(pa_rm_voleith_key_tilde_a_vec_rep.len(), public_parameter.kappa);
        assert_eq!(pa_rm_voleith_key_tilde_b_vec_rep.len(), public_parameter.kappa);
        assert_eq!(pa_rm_voleith_key_tilde_c_vec_rep.len(), public_parameter.kappa);
        println!("Verifier in PA2PC verifies split off VOLEitH correlations of PA rm");

        // split off PB's voleith key vectors
        let pb_rm_voleith_key_tilde_a_vec_rep = split_off_rm(public_parameter, &mut pb_voleith_key_tilde_a_vec_rep);
        let pb_rm_voleith_key_tilde_b_vec_rep = split_off_rm(public_parameter, &mut pb_voleith_key_tilde_b_vec_rep);
        let pb_rm_voleith_key_tilde_c_vec_rep = split_off_rm(public_parameter, &mut pb_voleith_key_tilde_c_vec_rep);
        assert_eq!(pb_rm_voleith_key_tilde_a_vec_rep.len(), public_parameter.kappa);
        assert_eq!(pb_rm_voleith_key_tilde_b_vec_rep.len(), public_parameter.kappa);
        assert_eq!(pb_rm_voleith_key_tilde_c_vec_rep.len(), public_parameter.kappa);
        println!("Verifier in PA2PC verifies split off VOLEitH correlations of PB rm");
        for repetition_id in 0..public_parameter.kappa {
            // check PA's side
            Verifier::verify_vole_correlations(
                &proof_transcript.pa_published_rm_a_vec_rep[repetition_id],
                &proof_transcript.pa_published_rm_voleith_mac_a_vec_rep[repetition_id],
                &nabla_b_rep[repetition_id],
                &pa_rm_voleith_key_tilde_a_vec_rep[repetition_id],
            );
            Verifier::verify_vole_correlations(
                &proof_transcript.pa_published_rm_b_vec_rep[repetition_id],
                &proof_transcript.pa_published_rm_voleith_mac_b_vec_rep[repetition_id],
                &nabla_b_rep[repetition_id],
                &pa_rm_voleith_key_tilde_b_vec_rep[repetition_id],
            );
            Verifier::verify_vole_correlations(
                &proof_transcript.pa_published_rm_c_vec_rep[repetition_id],
                &proof_transcript.pa_published_rm_voleith_mac_c_vec_rep[repetition_id],
                &nabla_b_rep[repetition_id],
                &pa_rm_voleith_key_tilde_c_vec_rep[repetition_id],
            );

            // Check PB's side
            Verifier::verify_vole_correlations(
                &proof_transcript.pb_published_rm_a_vec_rep[repetition_id],
                &proof_transcript.pb_published_rm_voleith_mac_a_vec_rep[repetition_id],
                &nabla_a_rep[repetition_id],
                &pb_rm_voleith_key_tilde_a_vec_rep[repetition_id],
            );
            Verifier::verify_vole_correlations(
                &proof_transcript.pb_published_rm_b_vec_rep[repetition_id],
                &proof_transcript.pb_published_rm_voleith_mac_b_vec_rep[repetition_id],
                &nabla_a_rep[repetition_id],
                &pb_rm_voleith_key_tilde_b_vec_rep[repetition_id],
            );
            Verifier::verify_vole_correlations(
                &proof_transcript.pb_published_rm_c_vec_rep[repetition_id],
                &proof_transcript.pb_published_rm_voleith_mac_c_vec_rep[repetition_id],
                &nabla_a_rep[repetition_id],
                &pb_rm_voleith_key_tilde_c_vec_rep[repetition_id],
            );

            // Check correct AND
            assert_eq!(
                proof_transcript.pa_published_rm_a_vec_rep[repetition_id].vec_add(
                    &proof_transcript.pb_published_rm_a_vec_rep[repetition_id]
                ).entry_wise_multiply(
                    &proof_transcript.pa_published_rm_b_vec_rep[repetition_id].vec_add(
                        &proof_transcript.pb_published_rm_b_vec_rep[repetition_id]
                    )
                ),
                proof_transcript.pa_published_rm_c_vec_rep[repetition_id].vec_add(
                    &proof_transcript.pb_published_rm_c_vec_rep[repetition_id]
                )
            );
        }

        // construct key trace
        let mut pa_voleith_key_r_trace_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.num_wires); public_parameter.kappa];
        let mut pa_middle_voleith_key_r_and_output_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa];
        let mut pb_voleith_key_r_trace_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.num_wires); public_parameter.kappa];
        let mut pb_middle_voleith_key_r_and_output_vec_rep = vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa];
        (0..public_parameter.kappa).for_each(
            |repetition_id| {
                initialize_trace::<GFVOLEitH, GFVec<GFVOLEitH>>(
                    public_parameter,
                    &pa_voleith_key_r_input_vec_rep[repetition_id],
                    &pa_voleith_key_r_output_and_vec_rep[repetition_id],
                    &mut pa_voleith_key_r_trace_vec_rep[repetition_id],
                );
                initialize_trace::<GFVOLEitH, GFVec<GFVOLEitH>>(
                    public_parameter,
                    &pb_voleith_key_r_input_vec_rep[repetition_id],
                    &pb_voleith_key_r_output_and_vec_rep[repetition_id],
                    &mut pb_voleith_key_r_trace_vec_rep[repetition_id],
                );
            }
        );
        
        let mut hat_z_bit_trace_vec = BitVec::zero_vec(public_parameter.num_wires);
        initialize_trace::<u8, BitVec>(
            public_parameter,
            &proof_transcript.published_hat_z_input_bit_vec,
            &proof_transcript.published_middle_hat_z_bit_vec,
            &mut hat_z_bit_trace_vec,
        );

        // compute voleith keys following circuit
        for repetition_id in 0..public_parameter.kappa {
            let mut and_cursor = 0usize;
            for gate in bristol_fashion_adaptor.get_gate_vec() {
                // println!("Verifier in PA2PC computes voleith key for gate {:?}", gate);
                match gate.gate_type {
                    GateType::XOR => {
                        hat_z_bit_trace_vec[gate.output_wire] = hat_z_bit_trace_vec[gate.left_input_wire] ^ hat_z_bit_trace_vec[gate.right_input_wire];
                        pa_voleith_key_r_trace_vec_rep[repetition_id][gate.output_wire] = pa_voleith_key_r_trace_vec_rep[repetition_id][gate.left_input_wire].custom_add(&pa_voleith_key_r_trace_vec_rep[repetition_id][gate.right_input_wire]);
                        pb_voleith_key_r_trace_vec_rep[repetition_id][gate.output_wire] = pb_voleith_key_r_trace_vec_rep[repetition_id][gate.left_input_wire].custom_add(&pb_voleith_key_r_trace_vec_rep[repetition_id][gate.right_input_wire]);
                    }
                    GateType::NOT => {
                        unimplemented!();
                    }
                    GateType::AND => {
                        // we do not need to compute hat_z_bit_trace_vec in this case
                        
                        // println!("{:?}", (repetition_id, and_cursor));
                        pa_middle_voleith_key_r_and_output_vec_rep[repetition_id][and_cursor] = pa_voleith_key_r_prime_vec_rep[repetition_id][and_cursor].custom_add(
                            &pa_voleith_key_r_trace_vec_rep[repetition_id][gate.output_wire]
                        ).custom_add(
                            &pa_voleith_key_r_trace_vec_rep[repetition_id][gate.right_input_wire].custom_multiply_bit(hat_z_bit_trace_vec[gate.left_input_wire])
                        ).custom_add(
                            &pa_voleith_key_r_trace_vec_rep[repetition_id][gate.left_input_wire].custom_multiply_bit(hat_z_bit_trace_vec[gate.right_input_wire])
                        );

                        pb_middle_voleith_key_r_and_output_vec_rep[repetition_id][and_cursor] = pb_voleith_key_r_prime_vec_rep[repetition_id][and_cursor].custom_add(
                            &pb_voleith_key_r_trace_vec_rep[repetition_id][gate.output_wire]
                        ).custom_add(
                            &pb_voleith_key_r_trace_vec_rep[repetition_id][gate.right_input_wire].custom_multiply_bit(hat_z_bit_trace_vec[gate.left_input_wire])
                        ).custom_add(
                            &pb_voleith_key_r_trace_vec_rep[repetition_id][gate.left_input_wire].custom_multiply_bit(hat_z_bit_trace_vec[gate.right_input_wire])
                        ).custom_add(
                            &nabla_a_rep[repetition_id].custom_multiply_bit(
                                hat_z_bit_trace_vec[gate.left_input_wire] & hat_z_bit_trace_vec[gate.right_input_wire]
                            )
                        );

                        // print secret state of pa to see
                        // println!("PA secret state with VOLEitH MAC: {:?}", pa_secret_state_to_be_removed.middle_voleith_mac_r_and_output_vec_rep[repetition_id][and_cursor][
                        //     (hat_z_bit_trace_vec[gate.left_input_wire] + (hat_z_bit_trace_vec[gate.right_input_wire] << 1u8)) as usize
                        //     ]);
                        // println!("Decrypted VOLEitH MAC:            {:?}", proof_transcript.published_decrypted_garbled_row[and_cursor].voleith_mac_field[repetition_id]);

                        assert_eq!(
                            proof_transcript.published_decrypted_garbled_row[and_cursor].voleith_mac_field[repetition_id],
                            pa_middle_voleith_key_r_and_output_vec_rep[repetition_id][and_cursor].custom_add(
                                &nabla_b_rep[repetition_id].custom_multiply_bit(
                                    proof_transcript.published_decrypted_garbled_row[and_cursor].first_u8
                                )
                            )
                        );

                        // let recovered_k = hat_z_bit_trace_vec[gate.left_input_wire] + (hat_z_bit_trace_vec[gate.right_input_wire] << 1);
                        assert_eq!(
                            proof_transcript.pb_published_middle_voleith_mac_r_vec_rep[repetition_id][and_cursor],
                            pb_middle_voleith_key_r_and_output_vec_rep[repetition_id][and_cursor].custom_add(
                                &nabla_a_rep[repetition_id].custom_multiply_bit(
                                    proof_transcript.pb_published_middle_r_bit_vec[and_cursor]
                                )
                            )
                        );

                        and_cursor += 1;
                    }
                }
            }
        }
    }
}