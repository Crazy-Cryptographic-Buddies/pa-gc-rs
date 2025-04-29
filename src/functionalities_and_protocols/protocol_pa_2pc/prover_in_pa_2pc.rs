use std::fmt::Debug;
use blake3::Hash;
use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
use crate::bristol_fashion_adaptor::{GateType};
use crate::functionalities_and_protocols::hasher;
use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
use crate::functionalities_and_protocols::protocol_check_and::check_and_transcript::CheckAndTranscript;
use crate::functionalities_and_protocols::protocol_check_and::prover_in_protocol_check_and::ProverInProtocolCheckAND;
use crate::functionalities_and_protocols::protocol_pa_2pc::{extract_block_vec_rep, initialize_trace, permute, split_off_rm};
use crate::functionalities_and_protocols::protocol_svole_2pc::prover_in_protocol_svole_2pc::ProverInProtocolSVOLE2PC;
use crate::functionalities_and_protocols::protocol_pa_2pc::preprocessing_transcript::PreprocessingTranscript;
use crate::functionalities_and_protocols::protocol_pa_2pc::proof_transcript::ProofTranscript;
use crate::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::util::parse_two_bits;
use crate::value_type::{ByteManipulation, CustomAddition, CustomMultiplyingBit, InsecureRandom, U8ForGF, Zero};
use crate::value_type::garbled_row::GarbledRow;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::{
    BasicVecFunctions,
    VecAddition,
};

pub struct ProverInPA2PC;

impl ProverInPA2PC {

    fn compute_vole_authenticated_middle_r_and_output_bit_vec<GFVOLE: CustomAddition + CustomMultiplyingBit>(
        k: usize, delta: &Option<GFVOLE>,
        r_gamma_k_bit: &mut u8, r_prime_gamma_bit: u8, r_output_bit: u8, r_left_input_bit: u8, r_right_input_bit: u8,
        vole_mac_r_gamma_k: &mut GFVOLE, vole_mac_r_prime: &GFVOLE, vole_mac_r_output: &GFVOLE, vole_mac_r_left_input: &GFVOLE, vole_mac_r_right_input: &GFVOLE,
        other_vole_key_r_gamma_k: &mut GFVOLE, other_vole_key_r_prime: &GFVOLE, vole_key_r_output: &GFVOLE, other_vole_key_r_left_input: &GFVOLE, other_vole_key_r_right_input: &GFVOLE
    ) {
        let (k0, k1) = parse_two_bits(k as u8);
        *r_gamma_k_bit = r_prime_gamma_bit ^ r_output_bit ^ (k0 & r_right_input_bit) ^ (k1 & r_left_input_bit);
        if delta.is_none() {
            *r_gamma_k_bit ^= k0 & k1;
        }
        *vole_mac_r_gamma_k = vole_mac_r_prime.custom_add(&vole_mac_r_output)
            .custom_add(&vole_mac_r_right_input.custom_multiply_bit(k0))
            .custom_add(&vole_mac_r_left_input.custom_multiply_bit(k1));
        *other_vole_key_r_gamma_k = other_vole_key_r_prime.custom_add(&vole_key_r_output)
            .custom_add(&other_vole_key_r_right_input.custom_multiply_bit(k0))
            .custom_add(&other_vole_key_r_left_input.custom_multiply_bit(k1));
        if delta.is_some() {
            *other_vole_key_r_gamma_k = other_vole_key_r_gamma_k.custom_add(
                &delta.as_ref().unwrap().custom_multiply_bit(k0 & k1)
            );
        }
    }

    fn compute_voleith_mac_r_and_output_vec<GFVOLEitH: CustomAddition + CustomMultiplyingBit>(
        k: usize,
        voleith_mac_r_gamma_k: &mut GFVOLEitH, voleith_mac_r_prime: &GFVOLEitH, voleith_mac_r_output: &GFVOLEitH, voleith_mac_r_left_input: &GFVOLEitH, voleith_mac_r_right_input: &GFVOLEitH,
    ) {
        let (k0, k1) = parse_two_bits(k as u8);
        *voleith_mac_r_gamma_k = voleith_mac_r_prime.custom_add(&voleith_mac_r_output)
            .custom_add(&voleith_mac_r_right_input.custom_multiply_bit(k0))
            .custom_add(&voleith_mac_r_left_input.custom_multiply_bit(k1));
    }

    pub fn preprocess<GFVOLE, GFVOLEitH>(
        process_printing: bool,
        bristol_fashion_adaptor: &BristolFashionAdaptor,
        bit_trace_vec_for_labels_in_garbling: &BitVec,
        public_parameter: &PublicParameter,
        pa_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pb_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
    ) -> PreprocessingTranscript<GFVOLE, GFVOLEitH>
    where
        GFVOLE: Clone + CustomAddition + CustomMultiplyingBit + InsecureRandom + Zero + Copy + PartialEq + Debug + ByteManipulation + Sync + Send,
        GFVOLEitH: Clone + Zero + CustomAddition + U8ForGF + Copy + CustomMultiplyingBit + ByteManipulation + Sync + Send
    {
        if process_printing {
            println!("+ Preprocessing...");
        }
        if process_printing {
            println!("  PA obtains delta from FPre");
        }
        InsecureFunctionalityPre::generate_delta(&mut pa_secret_state.delta);

        if process_printing {
            println!("  PB obtains delta from FPre");
        }
        InsecureFunctionalityPre::generate_delta(&mut pb_secret_state.delta);

        if process_printing {
            println!("  PA obtains vole-authenticated bits");
        }
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.num_input_bits,
            &pb_secret_state.delta.as_ref().unwrap(),
            &mut pa_secret_state.r_input_bit_vec,
            &mut pa_secret_state.vole_mac_r_input_vec,
            &mut pb_secret_state.other_vole_key_r_input_vec
        );
        assert_eq!(pa_secret_state.r_input_bit_vec.len(), public_parameter.num_input_bits);
        assert_eq!(pa_secret_state.vole_mac_r_input_vec.len(), public_parameter.num_input_bits);
        assert_eq!(pb_secret_state.other_vole_key_r_input_vec.len(), public_parameter.num_input_bits);
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.big_iw_size,
            &pb_secret_state.delta.as_ref().unwrap(),
            &mut pa_secret_state.r_output_and_bit_vec,
            &mut pa_secret_state.vole_mac_r_output_and_vec,
            &mut pb_secret_state.other_vole_key_r_output_and_vec
        );
        assert_eq!(pa_secret_state.r_output_and_bit_vec.len(), public_parameter.big_iw_size);
        assert_eq!(pa_secret_state.vole_mac_r_output_and_vec.len(), public_parameter.big_iw_size);
        assert_eq!(pb_secret_state.other_vole_key_r_output_and_vec.len(), public_parameter.big_iw_size);

        if process_printing {
            println!("  PB obtains vole-authenticated bits");
        }
        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.num_input_bits,
            &pa_secret_state.delta.as_ref().unwrap(),
            &mut pb_secret_state.r_input_bit_vec,
            &mut pb_secret_state.vole_mac_r_input_vec,
            &mut pa_secret_state.other_vole_key_r_input_vec
        );
        assert_eq!(pb_secret_state.r_input_bit_vec.len(), public_parameter.num_input_bits);
        assert_eq!(pb_secret_state.vole_mac_r_input_vec.len(), public_parameter.num_input_bits);
        assert_eq!(pa_secret_state.other_vole_key_r_input_vec.len(), public_parameter.num_input_bits);

        InsecureFunctionalityPre::generate_random_tuples::<GFVOLE, GFVOLEitH>(
            public_parameter.big_iw_size,
            &pa_secret_state.delta.as_ref().unwrap(),
            &mut pb_secret_state.r_output_and_bit_vec,
            &mut pb_secret_state.vole_mac_r_output_and_vec,
            &mut pa_secret_state.other_vole_key_r_output_and_vec
        );
        assert_eq!(pb_secret_state.r_output_and_bit_vec.len(), public_parameter.big_iw_size);
        assert_eq!(pb_secret_state.vole_mac_r_output_and_vec.len(), public_parameter.big_iw_size);
        assert_eq!(pa_secret_state.other_vole_key_r_output_and_vec.len(), public_parameter.big_iw_size);

        if process_printing {
            println!("  PA initializes labels");
        }
        let pa_label_zero_input_vec = (0..public_parameter.num_input_bits).map(
            |_| GFVOLE::insecurely_random()
        ).collect::<GFVec<GFVOLE>>();
        let pa_label_zero_output_and_vec = (0..public_parameter.big_iw_size).map(
            |_| GFVOLE::insecurely_random()
        ).collect::<GFVec<GFVOLE>>();
        assert_eq!(pa_label_zero_input_vec.len(), public_parameter.num_input_bits);
        assert_eq!(pa_label_zero_output_and_vec.len(), public_parameter.big_iw_size);

        if process_printing {
            println!("  PA initializes traces");
        }
        initialize_trace::<u8, BitVec>(
            public_parameter,
            &pa_secret_state.r_input_bit_vec,
            &pa_secret_state.r_output_and_bit_vec,
            &mut pa_secret_state.r_trace_bit_vec,
        );
        assert_eq!(pa_secret_state.r_trace_bit_vec.len(), public_parameter.num_wires);
        initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pa_secret_state.vole_mac_r_input_vec,
            &pa_secret_state.vole_mac_r_output_and_vec,
            &mut pa_secret_state.vole_mac_r_trace_vec
        );
        assert_eq!(pa_secret_state.vole_mac_r_trace_vec.len(), public_parameter.num_wires);
        initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pa_secret_state.other_vole_key_r_input_vec,
            &pa_secret_state.other_vole_key_r_output_and_vec,
            &mut pa_secret_state.other_vole_key_r_trace_vec
        );
        assert_eq!(pa_secret_state.other_vole_key_r_trace_vec.len(), public_parameter.num_wires);
        initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pa_label_zero_input_vec,
            &pa_label_zero_output_and_vec,
            pa_secret_state.label_zero_vec.as_mut().unwrap()
        );
        assert_eq!(pa_secret_state.label_zero_vec.as_ref().unwrap().len(), public_parameter.num_wires);

        if process_printing {
            println!("  PB initializes traces");
        }
        initialize_trace::<u8, BitVec>(
            public_parameter,
            &pb_secret_state.r_input_bit_vec,
            &pb_secret_state.r_output_and_bit_vec,
            &mut pb_secret_state.r_trace_bit_vec,
        );
        assert_eq!(pb_secret_state.r_trace_bit_vec.len(), public_parameter.num_wires);
        initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pb_secret_state.vole_mac_r_input_vec,
            &pb_secret_state.vole_mac_r_output_and_vec,
            &mut pb_secret_state.vole_mac_r_trace_vec
        );
        assert_eq!(pb_secret_state.vole_mac_r_trace_vec.len(), public_parameter.num_wires);
        initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pb_secret_state.other_vole_key_r_input_vec,
            &pb_secret_state.other_vole_key_r_output_and_vec,
            &mut pb_secret_state.other_vole_key_r_trace_vec
        );
        assert_eq!(pb_secret_state.other_vole_key_r_trace_vec.len(), public_parameter.num_wires);

        if process_printing {
            println!("  Both parties obtain multiplication AND triples");
        }
        InsecureFunctionalityPre::generate_random_and_tuples(
            public_parameter.kappa,
            public_parameter.big_l,
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
        // let mut pa_middle_r_and_output_bit_vec = vec![[0u8; 4]; public_parameter.big_iw_size];
        // let mut pa_middle_vole_mac_r_and_output_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];
        // let mut pa_other_middle_vole_key_r_and_output_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];
        // let mut pb_r_prime_bit_vec = vec![0u8; public_parameter.big_iw_size];
        // let mut pb_vole_mac_r_prime_vec = vec![GFVOLE::zero(); public_parameter.big_iw_size];
        // let mut pb_other_vole_key_r_prime_vec = vec![GFVOLE::zero(); public_parameter.big_iw_size];
        // let mut pb_middle_r_and_output_bit_vec = vec![[0u8; 4]; public_parameter.big_iw_size];
        // let mut pb_middle_vole_mac_r_and_output_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];
        // let mut pb_other_middle_vole_key_r_and_output_vec = vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size];

        if process_printing {
            println!("  Compute VOLE MACs and keys following circuit's topological order");
        }
        let mut and_cursor = 0usize;
        for gate in bristol_fashion_adaptor.get_gate_vec() {
            match gate.gate_type {
                GateType::XOR => {
                    // compute for pa
                    pa_secret_state.r_trace_bit_vec[gate.output_wire] = pa_secret_state.r_trace_bit_vec[gate.left_input_wire] ^ pa_secret_state.r_trace_bit_vec[gate.right_input_wire];
                    pa_secret_state.vole_mac_r_trace_vec[gate.output_wire] = pa_secret_state.vole_mac_r_trace_vec[gate.left_input_wire].custom_add(&pa_secret_state.vole_mac_r_trace_vec[gate.right_input_wire]);
                    pa_secret_state.other_vole_key_r_trace_vec[gate.output_wire] = pa_secret_state.other_vole_key_r_trace_vec[gate.left_input_wire].custom_add(&pa_secret_state.other_vole_key_r_trace_vec[gate.right_input_wire]);
                    pa_secret_state.label_zero_vec.as_mut().unwrap()[gate.output_wire] = pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.left_input_wire].custom_add(&pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.right_input_wire]);

                    // compute for pb
                    pb_secret_state.r_trace_bit_vec[gate.output_wire] = pb_secret_state.r_trace_bit_vec[gate.left_input_wire] ^ pb_secret_state.r_trace_bit_vec[gate.right_input_wire];
                    pb_secret_state.vole_mac_r_trace_vec[gate.output_wire] = pb_secret_state.vole_mac_r_trace_vec[gate.left_input_wire].custom_add(&pb_secret_state.vole_mac_r_trace_vec[gate.right_input_wire]);
                    pb_secret_state.other_vole_key_r_trace_vec[gate.output_wire] = pb_secret_state.other_vole_key_r_trace_vec[gate.left_input_wire].custom_add(&pb_secret_state.other_vole_key_r_trace_vec[gate.right_input_wire]);
                },
                GateType::NOT => {
                    // unimplemented!();
                    // compute for pa
                    pa_secret_state.r_trace_bit_vec[gate.output_wire] = pa_secret_state.r_trace_bit_vec[gate.left_input_wire];
                    pa_secret_state.vole_mac_r_trace_vec[gate.output_wire] = pa_secret_state.vole_mac_r_trace_vec[gate.left_input_wire];
                    pa_secret_state.other_vole_key_r_trace_vec[gate.output_wire] = pa_secret_state.other_vole_key_r_trace_vec[gate.left_input_wire];
                    pa_secret_state.label_zero_vec.as_mut().unwrap()[gate.output_wire] = pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.left_input_wire];

                    // compute for pb
                    pb_secret_state.r_trace_bit_vec[gate.output_wire] = pb_secret_state.r_trace_bit_vec[gate.left_input_wire];
                    pb_secret_state.vole_mac_r_trace_vec[gate.output_wire] = pb_secret_state.vole_mac_r_trace_vec[gate.left_input_wire];
                    pb_secret_state.other_vole_key_r_trace_vec[gate.output_wire] = pb_secret_state.other_vole_key_r_trace_vec[gate.left_input_wire];
                },
                GateType::AND => {
                    InsecureFunctionalityPre::generate_random_authenticated_and_tuples(
                        pa_secret_state.delta.as_ref().unwrap(),
                        pa_secret_state.r_trace_bit_vec[gate.left_input_wire],
                        pa_secret_state.r_trace_bit_vec[gate.right_input_wire],
                        &mut pa_secret_state.r_prime_bit_vec[and_cursor],
                        &mut pa_secret_state.vole_mac_r_prime_vec[and_cursor],
                        &mut pb_secret_state.other_vole_key_r_prime_vec[and_cursor],
                        pb_secret_state.delta.as_ref().unwrap(),
                        pb_secret_state.r_trace_bit_vec[gate.left_input_wire],
                        pb_secret_state.r_trace_bit_vec[gate.right_input_wire],
                        &mut pb_secret_state.r_prime_bit_vec[and_cursor],
                        &mut pb_secret_state.vole_mac_r_prime_vec[and_cursor],
                        &mut pa_secret_state.other_vole_key_r_prime_vec[and_cursor],
                    );

                    // PA computes
                    for k in 0..4 {
                        Self::compute_vole_authenticated_middle_r_and_output_bit_vec(
                            k, &pa_secret_state.delta,
                            &mut pa_secret_state.middle_r_and_output_bit_vec[and_cursor][k],
                            pa_secret_state.r_prime_bit_vec[and_cursor],
                            pa_secret_state.r_trace_bit_vec[gate.output_wire],
                            pa_secret_state.r_trace_bit_vec[gate.left_input_wire],
                            pa_secret_state.r_trace_bit_vec[gate.right_input_wire],
                            &mut pa_secret_state.middle_vole_mac_r_and_output_vec[and_cursor][k],
                            &pa_secret_state.vole_mac_r_prime_vec[and_cursor],
                            &pa_secret_state.vole_mac_r_trace_vec[gate.output_wire],
                            &pa_secret_state.vole_mac_r_trace_vec[gate.left_input_wire],
                            &pa_secret_state.vole_mac_r_trace_vec[gate.right_input_wire],
                            &mut pa_secret_state.other_middle_vole_key_r_and_output_vec[and_cursor][k],
                            &pa_secret_state.other_vole_key_r_prime_vec[and_cursor],
                            &pa_secret_state.other_vole_key_r_trace_vec[gate.output_wire],
                            &pa_secret_state.other_vole_key_r_trace_vec[gate.left_input_wire],
                            &pa_secret_state.other_vole_key_r_trace_vec[gate.right_input_wire]
                        );
                    }

                    // PB computes
                    for k in 0..4 {
                        Self::compute_vole_authenticated_middle_r_and_output_bit_vec(
                            k, &None,
                            &mut pb_secret_state.middle_r_and_output_bit_vec[and_cursor][k],
                            pb_secret_state.r_prime_bit_vec[and_cursor],
                            pb_secret_state.r_trace_bit_vec[gate.output_wire],
                            pb_secret_state.r_trace_bit_vec[gate.left_input_wire],
                            pb_secret_state.r_trace_bit_vec[gate.right_input_wire],
                            &mut pb_secret_state.middle_vole_mac_r_and_output_vec[and_cursor][k],
                            &pb_secret_state.vole_mac_r_prime_vec[and_cursor],
                            &pb_secret_state.vole_mac_r_trace_vec[gate.output_wire],
                            &pb_secret_state.vole_mac_r_trace_vec[gate.left_input_wire],
                            &pb_secret_state.vole_mac_r_trace_vec[gate.right_input_wire],
                            &mut pb_secret_state.other_middle_vole_key_r_and_output_vec[and_cursor][k],
                            &pb_secret_state.other_vole_key_r_prime_vec[and_cursor],
                            &pb_secret_state.other_vole_key_r_trace_vec[gate.output_wire],
                            &pb_secret_state.other_vole_key_r_trace_vec[gate.left_input_wire],
                            &pb_secret_state.other_vole_key_r_trace_vec[gate.right_input_wire]
                        )
                    }

                    and_cursor += 1;
                }
            }
        }

        if process_printing {
            println!("  PA obtains VOLEitH MACs from PiSVOLE2PC");
        }
        let (
            pa_com_hash_rep, pa_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec::<GFVOLE, GFVOLEitH>(
            process_printing, &public_parameter, pa_secret_state,
        );

        if process_printing {
            println!("  PB obtains VOLEitH MACs from PiSVOLE2PC");
        }
        let (
            pb_com_hash_rep, pb_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec::<GFVOLE, GFVOLEitH>(
            process_printing, &public_parameter, pb_secret_state,
        );

        if process_printing {
            println!("  PA initializes traces for computing VOLEitH MACs following circuit's topological order");
        }
        (0..public_parameter.kappa).for_each(
            |repetition_id| {
                initialize_trace::<GFVOLEitH, GFVec<GFVOLEitH>>(
                    &public_parameter,
                    &pa_secret_state.voleith_mac_r_input_vec_rep[repetition_id],
                    &pa_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id],
                    &mut pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id]
                );
            }
        );
        if process_printing {
            println!("  PB initializes traces for computing VOLEitH MACs following circuit's topological order");
        }
        (0..public_parameter.kappa).for_each(
            |repetition_id| {
                initialize_trace::<GFVOLEitH, GFVec<GFVOLEitH>>(
                    &public_parameter,
                    &pb_secret_state.voleith_mac_r_input_vec_rep[repetition_id],
                    &pb_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id],
                    &mut pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id],
                );
            }
        );

        if process_printing {
            println!("  Both parties compute VOLEitH MACs following circuit's topological order");
        }
        and_cursor = 0usize;
        for gate in bristol_fashion_adaptor.get_gate_vec() {
            match gate.gate_type {
                GateType::XOR => {
                    // compute for pa
                    for repetition_id in 0..public_parameter.kappa {
                        pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.output_wire] = pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire].custom_add(
                            &pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.right_input_wire]
                        );
                    }

                    // compute for pb
                    for repetition_id in 0..public_parameter.kappa {
                        pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.output_wire] = pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire].custom_add(
                            &pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.right_input_wire]
                        );
                    }
                },
                GateType::NOT => {
                    // compute for pa
                    for repetition_id in 0..public_parameter.kappa {
                        pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.output_wire] = pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire];
                    }

                    // compute for pb
                    for repetition_id in 0..public_parameter.kappa {
                        pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.output_wire] = pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire];
                    }
                },
                GateType::AND => {

                    // PA computes
                    for repetition_id in 0..public_parameter.kappa {
                        for k in 0..4 {
                            Self::compute_voleith_mac_r_and_output_vec(
                                k,
                                &mut pa_secret_state.middle_voleith_mac_r_and_output_vec_rep[repetition_id][and_cursor][k],
                                &pa_secret_state.voleith_mac_r_prime_vec_rep[repetition_id][and_cursor],
                                &pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.output_wire],
                                &pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire],
                                &pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.right_input_wire],
                            );
                        }
                    }

                    // PB computes
                    for repetition_id in 0..public_parameter.kappa {
                        for k in 0..4 {
                            Self::compute_voleith_mac_r_and_output_vec(
                                k,
                                &mut pb_secret_state.middle_voleith_mac_r_and_output_vec_rep[repetition_id][and_cursor][k],
                                &pb_secret_state.voleith_mac_r_prime_vec_rep[repetition_id][and_cursor],
                                &pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.output_wire],
                                &pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire],
                                &pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.right_input_wire],
                            );
                        }
                    }
                    and_cursor += 1;
                }
            }
        }

        if process_printing {
            println!("  PA encrypts for garbling");
        }
        and_cursor = 0usize;
        let mut garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>> = vec![vec![GarbledRow::zero(); 4]; public_parameter.big_iw_size];
        // println!("pa_middle_r: {:?}", pa_secret_state.middle_r_and_output_bit_vec);
        for and_gate_id in bristol_fashion_adaptor.get_and_gate_id_vec() {
            let gate = &bristol_fashion_adaptor.get_gate_vec()[*and_gate_id];
            let mut pa_label = [[GFVOLE::zero(); 2]; 2];
            pa_label[0][bit_trace_vec_for_labels_in_garbling[gate.left_input_wire] as usize] = pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.left_input_wire];
            pa_label[1][bit_trace_vec_for_labels_in_garbling[gate.right_input_wire] as usize] = pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.right_input_wire];
            pa_label[0][(1u8 ^ bit_trace_vec_for_labels_in_garbling[gate.left_input_wire]) as usize] = pa_secret_state.delta.as_ref().unwrap().custom_add(&pa_label[0][bit_trace_vec_for_labels_in_garbling[gate.left_input_wire] as usize]);
            pa_label[1][(1u8 ^ bit_trace_vec_for_labels_in_garbling[gate.right_input_wire]) as usize] = pa_secret_state.delta.as_ref().unwrap().custom_add(&pa_label[1][bit_trace_vec_for_labels_in_garbling[gate.right_input_wire] as usize]);
            for k in 0..4 {
                let (k0, k1) = parse_two_bits(k);
                garbled_table[and_cursor][k as usize] = hasher::hash_for_garbling(
                    &public_parameter,
                    &pa_label[0][k0 as usize],
                    &pa_label[1][k1 as usize],
                    gate.output_wire,
                    k,
                    public_parameter.garbled_row_byte_len
                ).custom_add(
                    &GarbledRow::new(
                        pa_secret_state.middle_r_and_output_bit_vec[and_cursor][k as usize],
                        pa_secret_state.middle_vole_mac_r_and_output_vec[and_cursor][k as usize].clone(),
                        (0..public_parameter.kappa).map(
                            |repetition_id| {
                                pa_secret_state.middle_voleith_mac_r_and_output_vec_rep[repetition_id][and_cursor][k as usize]
                            }
                        ).collect::<Vec<GFVOLEitH>>(),
                        pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.output_wire].custom_add(
                            &pa_secret_state.other_middle_vole_key_r_and_output_vec[and_cursor][k as usize]
                        ).custom_add(
                            &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(
                                pa_secret_state.middle_r_and_output_bit_vec[and_cursor][k as usize]
                            )
                        )
                    )
                );
            }
            and_cursor += 1;
        }

        if process_printing {
            println!("  PB commits intermediate messages");
        }
        and_cursor = 0usize;
        let mut pb_middle_commitment_vec = vec![[Hash::from_bytes([0u8; 32]); 4]; public_parameter.big_iw_size];
        let (mut current_seed, _) = public_parameter.one_to_two_prg.generate_double(&pb_secret_state.seed_for_commitment_randomness);
        for _ in 0..public_parameter.big_iw_size {
            for k in 0..4 {
                let randomness;
                (current_seed, randomness) = public_parameter.one_to_two_prg.generate_double(&current_seed);
                pb_middle_commitment_vec[and_cursor][k] = hasher::commit_pb_secret(
                    pb_secret_state.middle_r_and_output_bit_vec[and_cursor][k],
                    &(0..public_parameter.kappa).map(
                        |repetition_id| pb_secret_state.middle_voleith_mac_r_and_output_vec_rep[repetition_id][and_cursor][k]
                    ).collect(),
                    &randomness
                );
                pb_secret_state.commitment_randomness_vec_rep.as_mut().unwrap()[and_cursor][k] = randomness.clone();
            }
            and_cursor += 1;
        }

        if process_printing {
            println!("  PA records auxiliary components to her state");
        }
        and_cursor = 0usize;
        for and_gate_id in bristol_fashion_adaptor.get_and_gate_id_vec() {
            let gate = &bristol_fashion_adaptor.get_gate_vec()[*and_gate_id];
            pa_secret_state.r_prime_left_bit_vec[and_cursor] = pa_secret_state.r_trace_bit_vec[gate.left_input_wire];
            pa_secret_state.r_prime_right_bit_vec[and_cursor] = pa_secret_state.r_trace_bit_vec[gate.right_input_wire];

            for repetition_id in 0..public_parameter.kappa {
                pa_secret_state.voleith_mac_r_prime_left_vec_rep[repetition_id][and_cursor] = pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire].clone();
                pa_secret_state.voleith_mac_r_prime_right_vec_rep[repetition_id][and_cursor] = pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.right_input_wire].clone();
            }
            and_cursor += 1;
        }

        if process_printing {
            println!("  PB records auxiliary components to her state");
        }
        and_cursor = 0usize;
        for and_gate_id in bristol_fashion_adaptor.get_and_gate_id_vec() {
            let gate = &bristol_fashion_adaptor.get_gate_vec()[*and_gate_id];
            pb_secret_state.r_prime_left_bit_vec[and_cursor] = pb_secret_state.r_trace_bit_vec[gate.left_input_wire];
            pb_secret_state.r_prime_right_bit_vec[and_cursor] = pb_secret_state.r_trace_bit_vec[gate.right_input_wire];

            for repetition_id in 0..public_parameter.kappa {
                pb_secret_state.voleith_mac_r_prime_left_vec_rep[repetition_id][and_cursor] = pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.left_input_wire].clone();
                pb_secret_state.voleith_mac_r_prime_right_vec_rep[repetition_id][and_cursor] = pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][gate.right_input_wire].clone();
            }
            and_cursor += 1;
        }

        PreprocessingTranscript::new(
            pa_com_hash_rep,
            pa_masked_bit_tuple_rep,
            pb_com_hash_rep,
            pb_masked_bit_tuple_rep,
            garbled_table,
            pb_middle_commitment_vec,
        )
    }

    // fn extract_single_index_rep<PrimitiveType, VecType>(
    //     public_parameter: &PublicParameter,
    //     index: usize, vec_rep: &Vec<VecType>
    // ) -> Vec<PrimitiveType>
    // where
    //     PrimitiveType: Clone,
    //     VecType: Index<usize, Output = PrimitiveType> {
    //     assert_eq!(vec_rep.len(), public_parameter.kappa);
    //     (0..public_parameter.kappa).map(
    //         |repetition_id|
    //             vec_rep[repetition_id][index].clone()
    //     ).collect::<Vec<PrimitiveType>>()
    // }

    pub fn prove<GFVOLE, GFVOLEitH>(
        process_printing: bool,
        bristol_fashion_adaptor: &BristolFashionAdaptor,
        public_parameter: &PublicParameter,
        preprocessing_transcript: &PreprocessingTranscript<GFVOLE, GFVOLEitH>,
        permutation_rep: &Vec<Vec<usize>>,
        pa_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pb_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pa_input_bits: &Vec<u8>,
        pb_input_bits: &Vec<u8>,
        nabla_a_rep: &Vec<GFVOLEitH>, nabla_b_rep: &Vec<GFVOLEitH>,
    ) -> (ProofTranscript<GFVOLE, GFVOLEitH>, Vec<(SeedU8x16, Vec<SeedU8x16>)>, Vec<(SeedU8x16, Vec<SeedU8x16>)>)
    where
        GFVOLE: Clone + Zero + CustomAddition + CustomMultiplyingBit + PartialEq + Debug + ByteManipulation + Debug,
        GFVOLEitH: Clone + Zero + CustomAddition + ByteManipulation + Debug + U8ForGF {
        if process_printing {
            println!("+ Proving...");
        }

        if process_printing {
            println!("  PA permutes");
        }
        permute(public_parameter, &permutation_rep, &mut pa_secret_state.tilde_a_bit_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pa_secret_state.tilde_b_bit_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pa_secret_state.tilde_c_bit_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pa_secret_state.voleith_mac_tilde_a_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pa_secret_state.voleith_mac_tilde_b_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pa_secret_state.voleith_mac_tilde_c_vec_rep);

        if process_printing {
            println!("  PB permutes");
        }
        permute(public_parameter, &permutation_rep, &mut pb_secret_state.tilde_a_bit_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pb_secret_state.tilde_b_bit_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pb_secret_state.tilde_c_bit_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pb_secret_state.voleith_mac_tilde_a_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pb_secret_state.voleith_mac_tilde_b_vec_rep);
        permute(public_parameter, &permutation_rep, &mut pb_secret_state.voleith_mac_tilde_c_vec_rep);

        if process_printing {
            println!("  PA determines published components");
        }
        let pa_published_rm_a_vec_rep = split_off_rm(public_parameter, &mut pa_secret_state.tilde_a_bit_vec_rep);
        let pa_published_rm_b_vec_rep = split_off_rm(public_parameter, &mut pa_secret_state.tilde_b_bit_vec_rep);
        let pa_published_rm_c_vec_rep = split_off_rm(public_parameter, &mut pa_secret_state.tilde_c_bit_vec_rep);
        let pa_published_rm_voleith_mac_a_vec_rep = split_off_rm(public_parameter, &mut pa_secret_state.voleith_mac_tilde_a_vec_rep);
        let pa_published_rm_voleith_mac_b_vec_rep = split_off_rm(public_parameter, &mut pa_secret_state.voleith_mac_tilde_b_vec_rep);
        let pa_published_rm_voleith_mac_c_vec_rep = split_off_rm(public_parameter, &mut pa_secret_state.voleith_mac_tilde_c_vec_rep);

        if process_printing {
            println!("  PB determines published components");
        }
        let pb_published_rm_a_vec_rep = split_off_rm(public_parameter, &mut pb_secret_state.tilde_a_bit_vec_rep);
        let pb_published_rm_b_vec_rep = split_off_rm(public_parameter, &mut pb_secret_state.tilde_b_bit_vec_rep);
        let pb_published_rm_c_vec_rep = split_off_rm(public_parameter, &mut pb_secret_state.tilde_c_bit_vec_rep);
        let pb_published_rm_voleith_mac_a_vec_rep = split_off_rm(public_parameter, &mut pb_secret_state.voleith_mac_tilde_a_vec_rep);
        let pb_published_rm_voleith_mac_b_vec_rep = split_off_rm(public_parameter, &mut pb_secret_state.voleith_mac_tilde_b_vec_rep);
        let pb_published_rm_voleith_mac_c_vec_rep = split_off_rm(public_parameter, &mut pb_secret_state.voleith_mac_tilde_c_vec_rep);

        if process_printing {
            println!("  Both parties run PiCheckAND");
        }
        let check_and_transcript_vec = (0..public_parameter.bs).map(
            |block_id| {
                let pa_a_bit_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.tilde_a_bit_vec_rep);
                let pa_voleith_mac_a_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.voleith_mac_tilde_a_vec_rep);
                let pa_b_bit_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.tilde_b_bit_vec_rep);
                let pa_voleith_mac_b_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.voleith_mac_tilde_b_vec_rep);
                let pa_c_bit_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.tilde_c_bit_vec_rep);
                let pa_voleith_mac_c_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.voleith_mac_tilde_c_vec_rep);
                let (
                    (pa_d_bit_vec_rep, pa_voleith_mac_d_vec_rep),
                    (pa_e_bit_vec_rep, pa_voleith_mac_e_vec_rep)
                ) = ProverInProtocolCheckAND::compute_masked_bits_and_voleith_macs(
                    public_parameter,
                    &pa_secret_state.r_prime_left_bit_vec, &pa_secret_state.voleith_mac_r_prime_left_vec_rep,
                    &pa_secret_state.r_prime_right_bit_vec, &pa_secret_state.voleith_mac_r_prime_right_vec_rep,
                    &pa_a_bit_vec_rep, &pa_voleith_mac_a_vec_rep,
                    &pa_b_bit_vec_rep, &pa_voleith_mac_b_vec_rep,
                );

                let pb_a_bit_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.tilde_a_bit_vec_rep);
                let pb_voleith_mac_a_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.voleith_mac_tilde_a_vec_rep);
                let pb_b_bit_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.tilde_b_bit_vec_rep);
                let pb_voleith_mac_b_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.voleith_mac_tilde_b_vec_rep);
                let pb_c_bit_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.tilde_c_bit_vec_rep);
                let pb_voleith_mac_c_vec_rep = extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.voleith_mac_tilde_c_vec_rep);
                let (
                    (pb_d_bit_vec_rep, pb_voleith_mac_d_vec_rep),
                    (pb_e_bit_vec_rep, pb_voleith_mac_e_vec_rep)
                ) = ProverInProtocolCheckAND::compute_masked_bits_and_voleith_macs(
                    public_parameter,
                    &pb_secret_state.r_prime_left_bit_vec, &pb_secret_state.voleith_mac_r_prime_left_vec_rep,
                    &pb_secret_state.r_prime_right_bit_vec, &pb_secret_state.voleith_mac_r_prime_right_vec_rep,
                    &pb_a_bit_vec_rep,
                    &pb_voleith_mac_a_vec_rep,
                    &pb_b_bit_vec_rep,
                    &pb_voleith_mac_b_vec_rep,
                );

                let public_d_sum_bit_vec_rep = pa_d_bit_vec_rep.iter().zip(pb_d_bit_vec_rep.iter()).map(
                    |(pa_d_bit_vec, pb_d_bit_vec)| pa_d_bit_vec.vec_add(pb_d_bit_vec)
                ).collect::<Vec<BitVec>>();

                let public_e_sum_bit_vec_rep = pa_e_bit_vec_rep.iter().zip(pb_e_bit_vec_rep.iter()).map(
                    |(pa_e_bit_vec, pb_e_bit_vec)| pa_e_bit_vec.vec_add(pb_e_bit_vec)
                ).collect::<Vec<BitVec>>();

                let (pa_tilde_z_bit_vec_rep, pa_voleith_mac_tilde_z_vec_rep) = ProverInProtocolCheckAND::compute_masked_cross_bits_and_voleith_macs(
                    &public_parameter,
                    &public_d_sum_bit_vec_rep, &public_e_sum_bit_vec_rep,
                    &pa_secret_state.r_prime_bit_vec, &pa_secret_state.voleith_mac_r_prime_vec_rep,
                    &pa_a_bit_vec_rep, &pa_voleith_mac_a_vec_rep,
                    &pa_b_bit_vec_rep, &pa_voleith_mac_b_vec_rep,
                    &pa_c_bit_vec_rep, &pa_voleith_mac_c_vec_rep,
                );

                let (pb_tilde_z_bit_vec_rep, pb_voleith_mac_tilde_z_vec_rep) = ProverInProtocolCheckAND::compute_masked_cross_bits_and_voleith_macs(
                    &public_parameter,
                    &public_d_sum_bit_vec_rep, &public_e_sum_bit_vec_rep,
                    &pb_secret_state.r_prime_bit_vec, &pb_secret_state.voleith_mac_r_prime_vec_rep,
                    &pb_a_bit_vec_rep, &pb_voleith_mac_a_vec_rep,
                    &pb_b_bit_vec_rep, &pb_voleith_mac_b_vec_rep,
                    &pb_c_bit_vec_rep, &pb_voleith_mac_c_vec_rep,
                );

                // collect all
                CheckAndTranscript::new(
                    (
                        (pa_d_bit_vec_rep, pa_voleith_mac_d_vec_rep),
                        (pa_e_bit_vec_rep, pa_voleith_mac_e_vec_rep),
                        (pa_tilde_z_bit_vec_rep, pa_voleith_mac_tilde_z_vec_rep)
                    ),
                    (
                        (pb_d_bit_vec_rep, pb_voleith_mac_d_vec_rep),
                        (pb_e_bit_vec_rep, pb_voleith_mac_e_vec_rep),
                        (pb_tilde_z_bit_vec_rep, pb_voleith_mac_tilde_z_vec_rep)
                    ),
                )
            }
        ).collect();

        if process_printing {
            println!("  PA processes inputs");
        }
        // let pa_published_authenticated_input_vec = public_parameter.big_ib.iter().map(
        //     |input_wire| (
        //         pa_secret_state.r_trace_bit_vec[*input_wire],
        //         pa_secret_state.vole_mac_r_trace_vec[*input_wire].clone(),
        //         Self::extract_single_index_rep(public_parameter, *input_wire, &pa_secret_state.voleith_mac_r_trace_vec_rep)
        //     )
        // ).collect::<Vec<(u8, GFVOLE, Vec<GFVOLEitH>)>>();
        let pa_published_input_r_bit_vec = BitVec::from(
            public_parameter.big_ib.iter().map(
                |input_wire| pa_secret_state.r_trace_bit_vec[*input_wire]
            ).collect()
        );
        let pa_published_input_vole_mac_r_vec = GFVec::<GFVOLE>::from(
            public_parameter.big_ib.iter().map(
                |input_wire| pa_secret_state.vole_mac_r_trace_vec[*input_wire].clone()
            ).collect()
        );
        let pa_published_input_voleith_mac_r_vec_rep = (0..public_parameter.kappa).map(
            |repetition_id| GFVec::<GFVOLEitH>::from_vec(public_parameter.big_ib.iter().map(
                    |input_wire| pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][*input_wire].clone()
                ).collect()
            )
        ).collect();

        if process_printing {
            println!("  PB checks what PA just published and partially computes hat_z at inputs");
        }
        let mut input_cursor = 0usize;
        let mut pb_published_hat_z_input_vec_with_ib = vec![0u8; public_parameter.big_ib.len()];
        public_parameter.big_ib.iter().for_each(|input_wire| {
            let pa_input_bit = pa_published_input_r_bit_vec[input_cursor];
            let pa_vole_mac = &pa_published_input_vole_mac_r_vec[input_cursor];
            assert_eq!(
                pb_secret_state.other_vole_key_r_trace_vec[*input_wire],
                pa_vole_mac.custom_add(
                    &pb_secret_state.delta.as_ref().unwrap().custom_multiply_bit(pa_input_bit)
                )
            );
            pb_published_hat_z_input_vec_with_ib[input_cursor] = pa_input_bit ^ pb_secret_state.r_trace_bit_vec[*input_wire] ^ pb_input_bits[input_cursor];
            input_cursor += 1;
        });

        if process_printing {
            println!("  PA publishes labels");
        }
        input_cursor = 0usize;
        let pa_published_label_with_ib = public_parameter.big_ib.iter().map(
            |input_wire| {
                let label = pa_secret_state.label_zero_vec.as_ref().unwrap()[*input_wire].custom_add(
                    &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(pb_published_hat_z_input_vec_with_ib[input_cursor])
                );
                input_cursor += 1;
                label
            }
        ).collect::<Vec<GFVOLE>>();

        if process_printing {
            println!("  PB processes inputs");
        }
        // let pb_published_authenticated_input_vec = public_parameter.big_ia.iter().map(
        //     |input_wire| (
        //         pb_secret_state.r_trace_bit_vec[*input_wire],
        //         pb_secret_state.vole_mac_r_trace_vec[*input_wire].clone(),
        //         Self::extract_single_index_rep(public_parameter, *input_wire, &pb_secret_state.voleith_mac_r_trace_vec_rep)
        //     )
        // ).collect::<Vec<(u8, GFVOLE, Vec<GFVOLEitH>)>>();
        let pb_published_input_r_bit_vec = BitVec::from(
            public_parameter.big_ia.iter().map(
                |input_wire| pb_secret_state.r_trace_bit_vec[*input_wire]
            ).collect()
        );
        let pb_published_input_vole_mac_r_vec = GFVec::<GFVOLE>::from(
            public_parameter.big_ia.iter().map(
                |input_wire| pb_secret_state.vole_mac_r_trace_vec[*input_wire].clone()
            ).collect()
        );
        let pb_published_input_voleith_mac_r_vec_rep = (0..public_parameter.kappa).map(
            |repetition_id| GFVec::<GFVOLEitH>::from_vec(
                public_parameter.big_ia.iter().map(
                    |input_wire| pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][*input_wire].clone()
                ).collect()
            )
        ).collect();

        if process_printing {
            println!("  PA checks what PB just published and partially computes hat_z at inputs");
        }
        input_cursor = 0usize;
        let mut pa_published_hat_z_input_vec_with_ia = vec![0u8; public_parameter.big_ia.len()];
        public_parameter.big_ia.iter().for_each(|input_wire| {
            let pb_input_bit = pb_published_input_r_bit_vec[input_cursor];
            let pb_vole_mac = &pb_published_input_vole_mac_r_vec[input_cursor];
            assert_eq!(
                pa_secret_state.other_vole_key_r_trace_vec[*input_wire],
                pb_vole_mac.custom_add(
                    &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(pb_input_bit)
                )
            );
            pa_published_hat_z_input_vec_with_ia[input_cursor] = pb_input_bit ^ pa_secret_state.r_trace_bit_vec[*input_wire] ^ pa_input_bits[input_cursor];
            input_cursor += 1;
        });

        if process_printing {
            println!("  PA publishes labels");
        }
        input_cursor = 0usize;
        let pa_published_label_with_ia = public_parameter.big_ia.iter().map(
            |input_wire| {
                let label = pa_secret_state.label_zero_vec.as_ref().unwrap()[*input_wire].custom_add(
                    &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(pa_published_hat_z_input_vec_with_ia[input_cursor])
                );
                input_cursor += 1;
                label
            }
        ).collect::<Vec<GFVOLE>>();

        if process_printing {
            println!("  Initialize proof transcript");
        }
        let mut proof_transcript = ProofTranscript::new(
            public_parameter,
            pa_published_rm_a_vec_rep,
            pa_published_rm_b_vec_rep,
            pa_published_rm_c_vec_rep,
            pa_published_rm_voleith_mac_a_vec_rep,
            pa_published_rm_voleith_mac_b_vec_rep,
            pa_published_rm_voleith_mac_c_vec_rep,
            pb_published_rm_a_vec_rep,
            pb_published_rm_b_vec_rep,
            pb_published_rm_c_vec_rep,
            pb_published_rm_voleith_mac_a_vec_rep,
            pb_published_rm_voleith_mac_b_vec_rep,
            pb_published_rm_voleith_mac_c_vec_rep,
            check_and_transcript_vec,
            pa_published_input_r_bit_vec,
            // pa_published_input_vole_mac_r_vec,
            pa_published_input_voleith_mac_r_vec_rep,
            pb_published_input_r_bit_vec,
            // pb_published_input_vole_mac_r_vec,
            pb_published_input_voleith_mac_r_vec_rep,
        );

        if process_printing {
            println!("  Filling hat_z at inputs");
        }
        input_cursor = 0usize;
        for input_wire in &public_parameter.big_ia {
            proof_transcript.published_hat_z_input_bit_vec[*input_wire] = pa_published_hat_z_input_vec_with_ia[input_cursor];
            input_cursor += 1;
        }
        input_cursor = 0usize;
        for input_wire in &public_parameter.big_ib {
            proof_transcript.published_hat_z_input_bit_vec[*input_wire] = pb_published_hat_z_input_vec_with_ib[input_cursor];
            input_cursor += 1;
        }

        if process_printing {
            println!("  PB evaluates circuit following circuit's topological order");
        }
        let mut recovered_label_vec = vec![GFVOLE::zero(); public_parameter.num_wires];
        let mut recovered_hat_z_bit_vec = vec![0u8; public_parameter.num_wires];
        input_cursor = 0usize;
        public_parameter.big_ia.iter().for_each(|input_wire| {
            recovered_label_vec[*input_wire] = pa_published_label_with_ia[input_cursor].clone();
            recovered_hat_z_bit_vec[*input_wire] = pa_published_hat_z_input_vec_with_ia[input_cursor];
            input_cursor += 1;
        });
        input_cursor = 0usize;
        public_parameter.big_ib.iter().for_each(|input_wire| {
            recovered_label_vec[*input_wire] = pa_published_label_with_ib[input_cursor].clone();
            recovered_hat_z_bit_vec[*input_wire] = pb_published_hat_z_input_vec_with_ib[input_cursor];
            input_cursor += 1;
        });
        let garbled_table = &preprocessing_transcript.garbled_table;
        let mut and_cursor = 0usize;
        // println!("------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        // (0..public_parameter.num_input_bits).for_each(
        //     |id| {
        //         println!("Input: ");
        //         println!("- Recovered: {:?}", (recovered_hat_z_vec[id], recovered_label_vec[id].clone()));
        //         println!("- PA label1: {:?}", (recovered_hat_z_vec[id], pa_secret_state.label_zero_vec.as_ref().unwrap()[id].clone().custom_add(&pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(recovered_hat_z_vec[id]))));
        //         assert_eq!((recovered_hat_z_vec[id], recovered_label_vec[id].clone()), (recovered_hat_z_vec[id], pa_secret_state.label_zero_vec.as_ref().unwrap()[id].clone().custom_add(&pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(recovered_hat_z_vec[id]))));
        //     }
        // );
        for gate in bristol_fashion_adaptor.get_gate_vec() {
            // println!("{:?}:", gate.gate_type);
            match gate.gate_type {
                GateType::XOR => {
                    recovered_hat_z_bit_vec[gate.output_wire] = recovered_hat_z_bit_vec[gate.left_input_wire] ^ recovered_hat_z_bit_vec[gate.right_input_wire];
                    recovered_label_vec[gate.output_wire] = recovered_label_vec[gate.left_input_wire].custom_add(&recovered_label_vec[gate.right_input_wire]);
                }
                GateType::NOT => {
                    // unimplemented!();
                    recovered_hat_z_bit_vec[gate.output_wire] = recovered_hat_z_bit_vec[gate.left_input_wire] ^ 1u8;
                    recovered_label_vec[gate.output_wire] = recovered_label_vec[gate.left_input_wire].clone();
                }
                GateType::AND => {
                    let recovered_k =  recovered_hat_z_bit_vec[gate.left_input_wire] + (recovered_hat_z_bit_vec[gate.right_input_wire] << 1);
                    // println!("{:?}", (recovered_k, recovered_label_vec[gate.left_input_wire].clone(), recovered_label_vec[gate.right_input_wire].clone()));
                    let decrypted_gabled_row = hasher::hash_for_garbling::<GFVOLE, GFVOLEitH>(
                        public_parameter,
                        &recovered_label_vec[gate.left_input_wire],
                        &recovered_label_vec[gate.right_input_wire],
                        gate.output_wire,
                        recovered_k,
                        public_parameter.garbled_row_byte_len
                    ).custom_add(
                      &garbled_table[and_cursor][recovered_k as usize]
                    );

                    recovered_hat_z_bit_vec[gate.output_wire] = pb_secret_state.middle_r_and_output_bit_vec[and_cursor][recovered_k as usize] ^ decrypted_gabled_row.first_u8;
                    recovered_label_vec[gate.output_wire] = decrypted_gabled_row.vole_mac_remaining_field.custom_add(
                        &pb_secret_state.middle_vole_mac_r_and_output_vec[and_cursor][recovered_k as usize]
                    );
                    // println!("and_cursor: {:?}", and_cursor);
                    // println!("- {:?}", (
                    //     decrypted_gabled_row.vole_mac_field.clone(),
                    //     pb_secret_state.other_middle_vole_key_r_and_output_vec[and_cursor][recovered_k as usize].custom_add(
                    //         &pb_secret_state.delta.as_ref().unwrap().custom_multiply_bit(decrypted_gabled_row.first_u8)
                    //     )
                    // ));
                    assert_eq!(
                        decrypted_gabled_row.vole_mac_field,
                        pb_secret_state.other_middle_vole_key_r_and_output_vec[and_cursor][recovered_k as usize].custom_add(
                            &pb_secret_state.delta.as_ref().unwrap().custom_multiply_bit(decrypted_gabled_row.first_u8)
                        )
                    );
                    proof_transcript.published_middle_hat_z_bit_vec[and_cursor] = recovered_hat_z_bit_vec[gate.output_wire];
                    proof_transcript.pb_published_middle_label_vec[and_cursor] = recovered_label_vec[gate.output_wire].clone();
                    proof_transcript.pb_published_middle_r_bit_vec[and_cursor] = pb_secret_state.middle_r_and_output_bit_vec[and_cursor][recovered_k as usize];
                    (0..public_parameter.kappa).for_each(|repetition_id| {
                        proof_transcript.pb_published_middle_voleith_mac_r_vec_rep[repetition_id][and_cursor] = pb_secret_state.middle_voleith_mac_r_and_output_vec_rep[repetition_id][and_cursor][recovered_k as usize].clone();
                    });
                    proof_transcript.pb_published_middle_randomness_vec[and_cursor] = pb_secret_state.commitment_randomness_vec_rep.as_ref().unwrap()[and_cursor][recovered_k as usize].clone();
                    proof_transcript.published_decrypted_garbled_row[and_cursor] = decrypted_gabled_row;
                    and_cursor += 1;
                }
            }
            // println!("- Recovered: {:?}", (recovered_hat_z_vec[gate.output_wire], recovered_label_vec[gate.output_wire].clone()));
            // println!("- PA label:  {:?}", (recovered_hat_z_vec[gate.output_wire], pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.output_wire].clone().custom_add(&pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(recovered_hat_z_vec[gate.output_wire]))));
            // assert_eq!((recovered_hat_z_vec[gate.output_wire], recovered_label_vec[gate.output_wire].clone()), (recovered_hat_z_vec[gate.output_wire], pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.output_wire].clone().custom_add(&pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(recovered_hat_z_vec[gate.output_wire]))));
        }

        if process_printing {
            println!("  PA determines her outputs");
        }
        let mut output_cursor = 0usize;
        for output_wire in &public_parameter.big_io {
            proof_transcript.pa_published_output_r_bit_vec[output_cursor] = pa_secret_state.r_trace_bit_vec[*output_wire];
            proof_transcript.pa_published_output_vole_mac_r_vec[output_cursor] = pa_secret_state.vole_mac_r_trace_vec[*output_wire].clone();
            for repetition_id in 0..public_parameter.kappa {
                proof_transcript.pa_published_output_voleith_mac_r_vec_rep[repetition_id][output_cursor] = pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][*output_wire].clone();
            }
            output_cursor += 1;
        }

        if process_printing {
            println!("  PB checks PA's outputs and computes remaining things");
        }
        output_cursor = 0usize;
        for output_wire in &public_parameter.big_io {
            assert_eq!(
                proof_transcript.pa_published_output_vole_mac_r_vec[output_cursor],
                pb_secret_state.other_vole_key_r_trace_vec[*output_wire].custom_add(
                    &pb_secret_state.delta.as_ref().unwrap().custom_multiply_bit(proof_transcript.pa_published_output_r_bit_vec[output_cursor])
                )
            );
            proof_transcript.pb_published_output_r_bit_vec[output_cursor] = pb_secret_state.r_trace_bit_vec[*output_wire];
            for repetition_id in 0..public_parameter.kappa {
                proof_transcript.pb_published_output_voleith_mac_r_vec_rep[repetition_id][output_cursor] = pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id][*output_wire].clone();
            }
            proof_transcript.published_output_bit_vec[output_cursor] = recovered_hat_z_bit_vec[*output_wire] ^ proof_transcript.pa_published_output_r_bit_vec[output_cursor] ^ proof_transcript.pb_published_output_r_bit_vec[output_cursor];
            output_cursor += 1;
        }

        if process_printing {
            println!("  PA computes decom after knowing nabla_b_rep");
        }
        let pa_decom_rep = ProverInProtocolSVOLE2PC::open(public_parameter, pa_secret_state, &nabla_b_rep);

        if process_printing {
            println!("  PB computes decom after knowing nabla_a_rep");
        }
        let pb_decom_rep = ProverInProtocolSVOLE2PC::open(public_parameter, pb_secret_state, &nabla_a_rep);

        (proof_transcript, pa_decom_rep, pb_decom_rep)
    }
}