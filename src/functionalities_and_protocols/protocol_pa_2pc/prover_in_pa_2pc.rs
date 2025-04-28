use std::fmt::Debug;
use std::ops::{Index, IndexMut};
use blake3::Hash;
use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
use crate::bristol_fashion_adaptor::{GateInfo, GateType};
use crate::functionalities_and_protocols::hasher::hasher::Hasher;
use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
use crate::functionalities_and_protocols::protocol_check_and::prover_in_protocol_check_and::ProverInProtocolCheckAND;
use crate::functionalities_and_protocols::protocol_svole_2pc::prover_in_protocol_svole_2pc::ProverInProtocolSVOLE2PC;
use crate::functionalities_and_protocols::states_and_parameters::preprocessing_transcript::PreprocessingTranscript;
use crate::functionalities_and_protocols::states_and_parameters::proof_transcript::ProofTranscript;
use crate::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::util::parse_two_bits;
use crate::value_type::{ByteManipulation, CustomAddition, CustomMultiplyingBit, InsecureRandom, U8ForGF, Zero};
use crate::value_type::garbled_row::GarbledRow;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::{BasicVecFunctions, Split, VecAppending, ZeroVec};

pub struct ProverInPA2PC;

impl ProverInPA2PC {

    fn initialize_trace<PrimitiveType, VecType>(
        public_parameter: &PublicParameter,
        input_vec: &VecType,
        output_and_vec: &VecType,
        to_be_written_trace: &mut VecType,
    )
    where PrimitiveType: Clone + Zero + Copy,
          VecType: Clone + VecAppending + ZeroVec + BasicVecFunctions<PrimitiveType>
          + Index<usize, Output = PrimitiveType> + IndexMut<usize, Output = PrimitiveType> {

        // let mut res = vec![PrimitiveType::zero(); circuit_num_wires];

        to_be_written_trace.as_mut_slice()[0..input_vec.len()].copy_from_slice(input_vec.as_slice());
        let mut and_cursor = 0usize;
        for wire in public_parameter.big_iw.iter() {
            to_be_written_trace[*wire] = output_and_vec[and_cursor].clone();
            and_cursor += 1;
        }
    }

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
        bristol_fashion_adaptor: &BristolFashionAdaptor,
        public_parameter: &PublicParameter,
        pa_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pb_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
    ) -> PreprocessingTranscript<GFVOLE, GFVOLEitH>
    where
        GFVOLE: Clone + CustomAddition + CustomMultiplyingBit + InsecureRandom + Zero + Copy + PartialEq + Debug + ByteManipulation,
        GFVOLEitH: Clone + Zero + CustomAddition + U8ForGF + Copy + CustomMultiplyingBit + ByteManipulation
    {
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
        // pb obtains vole-authenticated bits
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
        let pa_label_zero_input_vec = (0..public_parameter.num_input_bits).map(
            |_| GFVOLE::insecurely_random()
        ).collect::<GFVec<GFVOLE>>();
        let pa_label_zero_output_and_vec = (0..public_parameter.big_iw_size).map(
            |_| GFVOLE::insecurely_random()
        ).collect::<GFVec<GFVOLE>>();
        assert_eq!(pa_label_zero_input_vec.len(), public_parameter.num_input_bits);
        assert_eq!(pa_label_zero_output_and_vec.len(), public_parameter.big_iw_size);

        // initialize traces for pa
        Self::initialize_trace::<u8, BitVec>(
            public_parameter,
            &pa_secret_state.r_input_bit_vec,
            &pa_secret_state.r_output_and_bit_vec,
            &mut pa_secret_state.r_trace_bit_vec,
        );
        assert_eq!(pa_secret_state.r_trace_bit_vec.len(), public_parameter.num_wires);
        // let mut pa_vole_mac_r_trace_vec = GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires);
        Self::initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pa_secret_state.vole_mac_r_input_vec,
            &pa_secret_state.vole_mac_r_output_and_vec,
            &mut pa_secret_state.vole_mac_r_trace_vec
        );
        assert_eq!(pa_secret_state.vole_mac_r_trace_vec.len(), public_parameter.num_wires);
        // let mut pa_other_vole_key_r_trace_vec = GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires);
        Self::initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pa_secret_state.other_vole_key_r_input_vec,
            &pa_secret_state.other_vole_key_r_output_and_vec,
            &mut pa_secret_state.other_vole_key_r_trace_vec
        );
        assert_eq!(pa_secret_state.other_vole_key_r_trace_vec.len(), public_parameter.num_wires);
        // let mut pa_label_zero_trace_vec = GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires);
        Self::initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pa_label_zero_input_vec,
            &pa_label_zero_output_and_vec,
            pa_secret_state.label_zero_vec.as_mut().unwrap()
        );
        assert_eq!(pa_secret_state.label_zero_vec.as_ref().unwrap().len(), public_parameter.num_wires);

        // initialize traces for pb
        //let mut pb_r_trace_bit_vec = BitVec::zero_vec(public_parameter.num_wires);
        Self::initialize_trace::<u8, BitVec>(
            public_parameter,
            &pb_secret_state.r_input_bit_vec,
            &pb_secret_state.r_output_and_bit_vec,
            &mut pb_secret_state.r_trace_bit_vec,
        );
        assert_eq!(pb_secret_state.r_trace_bit_vec.len(), public_parameter.num_wires);
        // let mut pb_vole_mac_r_trace_vec = GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires);
        Self::initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pb_secret_state.vole_mac_r_input_vec,
            &pb_secret_state.vole_mac_r_output_and_vec,
            &mut pb_secret_state.vole_mac_r_trace_vec
        );
        assert_eq!(pb_secret_state.vole_mac_r_trace_vec.len(), public_parameter.num_wires);
        // let mut pb_other_vole_key_r_trace_vec = GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires);
        Self::initialize_trace::<GFVOLE, GFVec<GFVOLE>>(
            public_parameter,
            &pb_secret_state.other_vole_key_r_input_vec,
            &pb_secret_state.other_vole_key_r_output_and_vec,
            &mut pb_secret_state.other_vole_key_r_trace_vec
        );
        assert_eq!(pb_secret_state.other_vole_key_r_trace_vec.len(), public_parameter.num_wires);

        // obtain multiplication AND triples
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

        //follow topological of circuit to compute
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

        // PA obtains VOLEitH correlations
        let (
            pa_com_hash_rep, pa_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec::<GFVOLE, GFVOLEitH>(
            &public_parameter, pa_secret_state,
        );

        // PB obtains VOLEitH correlations
        let (
            pb_com_hash_rep, pb_masked_bit_tuple_rep
        ) = ProverInProtocolSVOLE2PC::commit_and_fix_bit_vec_and_mac_vec::<GFVOLE, GFVOLEitH>(
            &public_parameter, pb_secret_state,
        );

        // making VOLEitH proof and components for garbled tables
        // let mut pa_middle_voleith_mac_r_and_output_vec = vec![vec![[GFVOLEitH::zero(); 4]; public_parameter.big_iw_size]; public_parameter.kappa];
        // let mut pb_middle_voleith_mac_r_and_output_vec = vec![vec![[GFVOLEitH::zero(); 4]; public_parameter.big_iw_size]; public_parameter.kappa];
        (0..public_parameter.kappa).for_each(
            |repetition_id| {
                Self::initialize_trace::<GFVOLEitH, GFVec<GFVOLEitH>>(
                    &public_parameter,
                    &pa_secret_state.voleith_mac_r_input_vec_rep[repetition_id],
                    &pa_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id],
                    & mut pa_secret_state.voleith_mac_r_trace_vec_rep[repetition_id]
                );
            }
        );
        (0..public_parameter.kappa).for_each(
            |repetition_id| {
                Self::initialize_trace::<GFVOLEitH, GFVec<GFVOLEitH>>(
                    &public_parameter,
                    &pb_secret_state.voleith_mac_r_input_vec_rep[repetition_id],
                    &pb_secret_state.voleith_mac_r_output_and_vec_rep[repetition_id],
                    &mut pb_secret_state.voleith_mac_r_trace_vec_rep[repetition_id],
                );
            }
        );
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

        // PA encrypts and commits
        and_cursor = 0usize;
        let mut garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>> = vec![vec![GarbledRow::zero(); 4]; public_parameter.big_iw_size];
        // println!("pa_middle_r: {:?}", pa_secret_state.middle_r_and_output_bit_vec);
        for and_gate_id in bristol_fashion_adaptor.get_and_gate_id_vec() {
            let gate = &bristol_fashion_adaptor.get_gate_vec()[*and_gate_id];
            let mut pa_label = [[GFVOLE::zero(); 2]; 2];
            pa_label[0][0] = pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.left_input_wire];
            pa_label[1][0] = pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.right_input_wire];
            pa_label[0][1] = pa_secret_state.delta.as_ref().unwrap().custom_add(&pa_label[0][0]);
            pa_label[1][1] = pa_secret_state.delta.as_ref().unwrap().custom_add(&pa_label[1][0]);
            for k in 0..4 {
                let (k0, k1) = parse_two_bits(k);
                garbled_table[and_cursor][k as usize] = Hasher::hash_for_garbling(
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

        // PB commits to secret values and VOLEitH macs
        and_cursor = 0usize;
        let mut pb_middle_commitment_vec = vec![vec![Hash::from_bytes([0u8; 32]); 4]; public_parameter.big_iw_size];
        let (mut current_seed, mut randomness) = public_parameter.one_to_two_prg.generate_double(&pb_secret_state.seed_for_commitment_randomness);
        for _ in 0..public_parameter.big_iw_size {
            for k in 0..4 {
                (current_seed, randomness) = public_parameter.one_to_two_prg.generate_double(&current_seed);
                pb_middle_commitment_vec[and_cursor][k] = Hasher::commit_pb_secret(
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

        // PA records auxiliary components
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

        // PB records auxiliary components
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
            garbled_table
        )
    }

    fn permute<PrimitiveType, VecType>(
        public_parameter: &PublicParameter,
        permutation_rep: &Vec<Vec<usize>>, to_be_permuted_vec_rep: &mut Vec<VecType>
    )
    where PrimitiveType: Clone,
          VecType: ZeroVec + BasicVecFunctions<PrimitiveType> + Clone
            + Index<usize, Output = PrimitiveType> + IndexMut<usize, Output = PrimitiveType> {
        assert_eq!(permutation_rep.len(), public_parameter.kappa);
        assert_eq!(to_be_permuted_vec_rep.len(), public_parameter.kappa);
        let mut res = vec![VecType::zero_vec(public_parameter.big_l); public_parameter.kappa];
        (0..public_parameter.kappa).for_each(|repetition_id| {
            assert_eq!(permutation_rep[repetition_id].len(), public_parameter.big_l);
            assert_eq!(to_be_permuted_vec_rep[repetition_id].len(), public_parameter.big_l);
            (0..public_parameter.big_l).for_each(
                |j| res[repetition_id][permutation_rep[repetition_id][j]] = to_be_permuted_vec_rep[repetition_id][j].clone()
            )
        });
        *to_be_permuted_vec_rep = res;
    }

    fn split_off_published_components<PrimitiveType, VecType>(
        public_parameter: &PublicParameter,
        to_be_split_off_vec_rep: &mut Vec<VecType>
    ) -> Vec<VecType>
    where VecType: Split + ZeroVec + Clone + BasicVecFunctions<PrimitiveType> {
        (0..public_parameter.kappa).map(
            |repetition_id| {
                let length = to_be_split_off_vec_rep[repetition_id].len();
                to_be_split_off_vec_rep[repetition_id].split_off(length - public_parameter.rm)
            }
        ).collect::<Vec<VecType>>()
    }

    // fn compute_masked_bits_and_voleith_macs(
    //
    // )

    fn extract_block_vec_rep<PrimitiveType, VecType>(
        public_parameter: &PublicParameter,
        block_id: usize, vec_rep: &Vec<VecType>
    ) -> Vec<VecType>
    where
        PrimitiveType: Clone,
        VecType: BasicVecFunctions<PrimitiveType> + Clone
            + Index<usize, Output = PrimitiveType> + IndexMut<usize, Output = PrimitiveType>
            + FromIterator<PrimitiveType> {
        assert_eq!(vec_rep.len(), public_parameter.kappa);
        (0..public_parameter.kappa).map(
            |repetition_id|
                VecType::from_vec(
                    vec_rep[repetition_id].as_slice()[
                        public_parameter.big_iw_size * block_id..public_parameter.big_iw_size * (block_id + 1)
                        ].to_vec()
                )
        ).collect::<Vec<VecType>>()
    }

    fn extract_single_index_rep<PrimitiveType, VecType>(
        public_parameter: &PublicParameter,
        index: usize, vec_rep: &Vec<VecType>
    ) -> Vec<PrimitiveType>
    where
        PrimitiveType: Clone,
        VecType: Index<usize, Output = PrimitiveType> {
        assert_eq!(vec_rep.len(), public_parameter.kappa);
        (0..public_parameter.kappa).map(
            |repetition_id|
                vec_rep[repetition_id][index].clone()
        ).collect::<Vec<PrimitiveType>>()
    }

    pub fn prove<GFVOLE, GFVOLEitH>(
        bristol_fashion_adaptor: &BristolFashionAdaptor,
        public_parameter: &PublicParameter,
        preprocessing_transcript: &PreprocessingTranscript<GFVOLE, GFVOLEitH>,
        permutation_rep: &Vec<Vec<usize>>,
        pa_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pb_secret_state: &mut ProverSecretState<GFVOLE, GFVOLEitH>,
        pa_input_bits: &Vec<u8>,
        pb_input_bits: &Vec<u8>,
    ) -> ProofTranscript<GFVOLE, GFVOLEitH>
    where
        GFVOLE: Clone + Zero + CustomAddition + CustomMultiplyingBit + PartialEq + Debug + ByteManipulation + Debug,
        GFVOLEitH: Clone + Zero + CustomAddition + ByteManipulation + Debug {
        let mut proof_transcript = ProofTranscript::new(public_parameter);

        // PA permutes
        Self::permute(public_parameter, &permutation_rep, &mut pa_secret_state.tilde_a_bit_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pa_secret_state.tilde_b_bit_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pa_secret_state.tilde_c_bit_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pa_secret_state.voleith_mac_tilde_a_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pa_secret_state.voleith_mac_tilde_b_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pa_secret_state.voleith_mac_tilde_c_vec_rep);

        // PB permutes
        Self::permute(public_parameter, &permutation_rep, &mut pb_secret_state.tilde_a_bit_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pb_secret_state.tilde_b_bit_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pb_secret_state.tilde_c_bit_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pb_secret_state.voleith_mac_tilde_a_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pb_secret_state.voleith_mac_tilde_b_vec_rep);
        Self::permute(public_parameter, &permutation_rep, &mut pb_secret_state.voleith_mac_tilde_c_vec_rep);
        // PA determines published components
        let pa_published_a_vec_rep = Self::split_off_published_components(public_parameter, &mut pa_secret_state.tilde_a_bit_vec_rep);
        let pa_published_b_vec_rep = Self::split_off_published_components(public_parameter, &mut pa_secret_state.tilde_b_bit_vec_rep);
        let pa_published_c_vec_rep = Self::split_off_published_components(public_parameter, &mut pa_secret_state.tilde_c_bit_vec_rep);
        let pa_published_voleith_mac_a_vec_rep = Self::split_off_published_components(public_parameter, &mut pa_secret_state.voleith_mac_tilde_a_vec_rep);
        let pa_published_voleith_mac_b_vec_rep = Self::split_off_published_components(public_parameter, &mut pa_secret_state.voleith_mac_tilde_b_vec_rep);
        let pa_published_voleith_mac_c_vec_rep = Self::split_off_published_components(public_parameter, &mut pa_secret_state.voleith_mac_tilde_c_vec_rep);

        // PB determines published components
        let pb_published_a_vec_rep = Self::split_off_published_components(public_parameter, &mut pb_secret_state.tilde_a_bit_vec_rep);
        let pb_published_b_vec_rep = Self::split_off_published_components(public_parameter, &mut pb_secret_state.tilde_b_bit_vec_rep);
        let pb_published_c_vec_rep = Self::split_off_published_components(public_parameter, &mut pb_secret_state.tilde_c_bit_vec_rep);
        let pb_published_voleith_mac_a_vec_rep = Self::split_off_published_components(public_parameter, &mut pb_secret_state.voleith_mac_tilde_a_vec_rep);
        let pb_published_voleith_mac_b_vec_rep = Self::split_off_published_components(public_parameter, &mut pb_secret_state.voleith_mac_tilde_b_vec_rep);
        let pb_published_voleith_mac_c_vec_rep = Self::split_off_published_components(public_parameter, &mut pb_secret_state.voleith_mac_tilde_c_vec_rep);
        // PA starts running protocol checkAND
        for block_id in 0..public_parameter.bs {
            ProverInProtocolCheckAND::compute_masked_bits_and_voleith_macs(
                public_parameter,
                &pa_secret_state.r_prime_left_bit_vec, &pa_secret_state.voleith_mac_r_prime_left_vec_rep,
                &pa_secret_state.r_prime_right_bit_vec, &pa_secret_state.voleith_mac_r_prime_right_vec_rep,
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.tilde_a_bit_vec_rep),
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.voleith_mac_tilde_a_vec_rep),
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.tilde_b_bit_vec_rep),
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pa_secret_state.voleith_mac_tilde_b_vec_rep),
            );
        }

        // PB starts running protocol checkAND
        for block_id in 0..public_parameter.bs {
            ProverInProtocolCheckAND::compute_masked_bits_and_voleith_macs(
                public_parameter,
                &pb_secret_state.r_prime_left_bit_vec, &pb_secret_state.voleith_mac_r_prime_left_vec_rep,
                &pb_secret_state.r_prime_right_bit_vec, &pb_secret_state.voleith_mac_r_prime_right_vec_rep,
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.tilde_a_bit_vec_rep),
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.voleith_mac_tilde_a_vec_rep),
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.tilde_b_bit_vec_rep),
                &Self::extract_block_vec_rep(&public_parameter, block_id, &pb_secret_state.voleith_mac_tilde_b_vec_rep),
            );
        }

        // Input processing phase by PA ------------------------------------------------------------------------------------------------------
        let pa_published_authenticated_input_vec = public_parameter.big_ib.iter().map(
            |input_wire| (
                pa_secret_state.r_trace_bit_vec[*input_wire],
                pa_secret_state.vole_mac_r_trace_vec[*input_wire].clone(),
                Self::extract_single_index_rep(public_parameter, *input_wire, &pa_secret_state.voleith_mac_r_trace_vec_rep)
            )
        ).collect::<Vec<(u8, GFVOLE, Vec<GFVOLEitH>)>>();

        // PB checks what PA just published and computes z_hat
        let mut input_cursor = 0usize;
        let mut pb_published_z_hat_input_vec = vec![0u8; public_parameter.big_ib.len()];
        public_parameter.big_ib.iter().for_each(|input_wire| {
            let (pa_input_bit, pa_vole_mac, _) = &pa_published_authenticated_input_vec[input_cursor];
            println!("{:?}", (pb_secret_state.other_vole_key_r_trace_vec[*input_wire].clone(),
                              pa_vole_mac.custom_add(
                                  &pb_secret_state.delta.as_ref().unwrap().custom_multiply_bit(*pa_input_bit)
                              ))
            );
            assert_eq!(
                pb_secret_state.other_vole_key_r_trace_vec[*input_wire],
                pa_vole_mac.custom_add(
                    &pb_secret_state.delta.as_ref().unwrap().custom_multiply_bit(*pa_input_bit)
                )
            );
            pb_published_z_hat_input_vec[input_cursor] = *pa_input_bit ^ pb_secret_state.r_trace_bit_vec[*input_wire] ^ pb_input_bits[input_cursor];
            input_cursor += 1;
        });

        // PA publishes labels
        input_cursor = 0usize;
        let pa_published_label_with_ib = public_parameter.big_ib.iter().map(
            |input_wire| {
                let label = pa_secret_state.label_zero_vec.as_ref().unwrap()[*input_wire].custom_add(
                    &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(pb_published_z_hat_input_vec[input_cursor])
                );
                input_cursor += 1;
                label
            }
        ).collect::<Vec<GFVOLE>>();

        // Input processing phase by PB ------------------------------------------------------------------------------------------------------
        let pb_published_authenticated_input_vec = public_parameter.big_ia.iter().map(
            |input_wire| (
                pb_secret_state.r_trace_bit_vec[*input_wire],
                pb_secret_state.vole_mac_r_trace_vec[*input_wire].clone(),
                Self::extract_single_index_rep(public_parameter, *input_wire, &pb_secret_state.voleith_mac_r_trace_vec_rep)
            )
        ).collect::<Vec<(u8, GFVOLE, Vec<GFVOLEitH>)>>();

        // PA checks what PB just published
        input_cursor = 0usize;
        let mut pa_published_z_hat_input_vec = vec![0u8; public_parameter.big_ia.len()];
        public_parameter.big_ia.iter().for_each(|input_wire| {
            let (pb_input_bit, pb_vole_mac, _) = &pb_published_authenticated_input_vec[input_cursor];
            println!("{:?}", (pa_secret_state.other_vole_key_r_trace_vec[*input_wire].clone(),
                              pb_vole_mac.custom_add(
                                  &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(*pb_input_bit)
                              ))
            );
            assert_eq!(
                pa_secret_state.other_vole_key_r_trace_vec[*input_wire],
                pb_vole_mac.custom_add(
                    &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(*pb_input_bit)
                )
            );
            pa_published_z_hat_input_vec[input_cursor] = *pb_input_bit ^ pa_secret_state.r_trace_bit_vec[*input_wire] ^ pa_input_bits[input_cursor];
            input_cursor += 1;
        });

        // PA publishes labels
        input_cursor = 0usize;
        let pa_published_label_with_ia = public_parameter.big_ia.iter().map(
            |input_wire| {
                let label = pa_secret_state.label_zero_vec.as_ref().unwrap()[*input_wire].custom_add(
                    &pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(pa_published_z_hat_input_vec[input_cursor])
                );
                input_cursor += 1;
                label
            }
        ).collect::<Vec<GFVOLE>>();

        // PB Circuit evaluation --------------------------------------------------------------------------------
        let mut recovered_label_vec = vec![GFVOLE::zero(); public_parameter.num_wires];
        let mut recovered_hat_z_vec = vec![0u8; public_parameter.num_wires];
        input_cursor = 0usize;
        public_parameter.big_ia.iter().for_each(|input_wire| {
            recovered_label_vec[*input_wire] = pa_published_label_with_ia[input_cursor].clone();
            recovered_hat_z_vec[*input_wire] = pa_published_z_hat_input_vec[input_cursor];
            input_cursor += 1;
        });
        input_cursor = 0usize;
        public_parameter.big_ib.iter().for_each(|input_wire| {
            recovered_label_vec[*input_wire] = pa_published_label_with_ib[input_cursor].clone();
            recovered_hat_z_vec[*input_wire] = pb_published_z_hat_input_vec[input_cursor];
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
            println!("{:?}:", gate.gate_type);
            match gate.gate_type {
                GateType::XOR => {
                    recovered_hat_z_vec[gate.output_wire] = recovered_hat_z_vec[gate.left_input_wire] ^ recovered_hat_z_vec[gate.right_input_wire];
                    recovered_label_vec[gate.output_wire] = recovered_label_vec[gate.left_input_wire].custom_add(&recovered_label_vec[gate.right_input_wire]);
                }
                GateType::NOT => {
                    recovered_hat_z_vec[gate.output_wire] = recovered_hat_z_vec[gate.left_input_wire] ^ 1u8;
                    recovered_label_vec[gate.output_wire] = recovered_label_vec[gate.left_input_wire].clone();
                }
                GateType::AND => {
                    let recovered_k =  recovered_hat_z_vec[gate.left_input_wire] + (recovered_hat_z_vec[gate.right_input_wire] << 1);
                    println!("{:?}", (recovered_k, recovered_label_vec[gate.left_input_wire].clone(), recovered_label_vec[gate.right_input_wire].clone()));
                    let decrypted_gabled_row = Hasher::hash_for_garbling::<GFVOLE, GFVOLEitH>(
                        public_parameter,
                        &recovered_label_vec[gate.left_input_wire],
                        &recovered_label_vec[gate.right_input_wire],
                        gate.output_wire,
                        recovered_k,
                        public_parameter.garbled_row_byte_len
                    ).custom_add(
                      &garbled_table[and_cursor][recovered_k as usize]
                    );

                    recovered_hat_z_vec[gate.output_wire] = pb_secret_state.middle_r_and_output_bit_vec[and_cursor][recovered_k as usize] ^ decrypted_gabled_row.first_u8;
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
                    proof_transcript.pb_published_middle_hat_z_bit_vec[and_cursor] = recovered_hat_z_vec[gate.output_wire];
                    proof_transcript.pb_published_middle_label_vec[and_cursor] = recovered_label_vec[gate.output_wire].clone();
                    proof_transcript.pb_published_middle_r_bit_vec[and_cursor] = pb_secret_state.middle_r_and_output_bit_vec[and_cursor][recovered_k as usize];
                    (0..public_parameter.kappa).for_each(|repetition_id| {
                        proof_transcript.pb_published_middle_voleith_mac_r_vec_rep[repetition_id][and_cursor] = pb_secret_state.middle_voleith_mac_r_and_output_vec_rep[repetition_id][and_cursor][recovered_k as usize].clone();
                    });
                    proof_transcript.pb_published_middle_randomness_vec[and_cursor] = pb_secret_state.commitment_randomness_vec_rep.as_ref().unwrap()[and_cursor][recovered_k as usize].clone();
                    and_cursor += 1;
                }
            }
            // println!("- Recovered: {:?}", (recovered_hat_z_vec[gate.output_wire], recovered_label_vec[gate.output_wire].clone()));
            // println!("- PA label:  {:?}", (recovered_hat_z_vec[gate.output_wire], pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.output_wire].clone().custom_add(&pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(recovered_hat_z_vec[gate.output_wire]))));
            // assert_eq!((recovered_hat_z_vec[gate.output_wire], recovered_label_vec[gate.output_wire].clone()), (recovered_hat_z_vec[gate.output_wire], pa_secret_state.label_zero_vec.as_ref().unwrap()[gate.output_wire].clone().custom_add(&pa_secret_state.delta.as_ref().unwrap().custom_multiply_bit(recovered_hat_z_vec[gate.output_wire]))));
        }
        proof_transcript
    }
}