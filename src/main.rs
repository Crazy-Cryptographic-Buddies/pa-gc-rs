use std::time::Instant;
use rand::Rng;
use pa_gc_rs::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
use pa_gc_rs::functionalities_and_protocols::protocol_pa_2pc::determine_bit_trace_for_labels_in_garbling;
use pa_gc_rs::functionalities_and_protocols::protocol_pa_2pc::prover_in_pa_2pc::ProverInPA2PC;
use pa_gc_rs::functionalities_and_protocols::protocol_pa_2pc::verifier_in_pa_2pc::VerifierInPA2PC;
use pa_gc_rs::functionalities_and_protocols::states_and_parameters::prover_secret_state::ProverSecretState;
use pa_gc_rs::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use pa_gc_rs::value_type::gf2p256::GF2p256;
use pa_gc_rs::value_type::gf2p8::GF2p8;
use pa_gc_rs::value_type::seed_u8x16::SeedU8x16;
use pa_gc_rs::value_type::InsecureRandom;
use pa_gc_rs::vec_type::bit_vec::BitVec;
use pa_gc_rs::vec_type::BasicVecFunctions;
use pa_gc_rs::value_type::U8ForGF;

fn insecurely_generate_random_permutation(len: usize) -> Vec<usize> {
    let mut random_permutation = (0..len).collect::<Vec<usize>>();
    let mut rng = rand::rng();
    for i in (0..len).rev() {
        let j = rng.random::<u32>() % (i as u32 + 1u32);
        random_permutation.swap(i, j as usize);
    }
    random_permutation
}

fn determine_full_input_bit_vec(
    public_parameter: &PublicParameter,
    pa_input_bit_vec: &Vec<u8>,
    pb_input_bit_vec: &Vec<u8>,
) -> Vec<u8> {
    let mut full_input_bit_vec = vec![0u8; public_parameter.num_input_bits];
    let mut input_cursor = 0usize;
    public_parameter.big_ia.iter().for_each(
        |&input_wire| {
            full_input_bit_vec[input_wire] = pa_input_bit_vec[input_cursor];
            input_cursor += 1;
        }
    );

    input_cursor = 0usize;
    public_parameter.big_ib.iter().for_each(
        |&input_wire| {
            full_input_bit_vec[input_wire] = pb_input_bit_vec[input_cursor];
            input_cursor += 1;
        }
    );

    full_input_bit_vec
}

fn test_pa_2pc_for_sub64(process_printing: bool) {
    let start_total = Instant::now();
    type GFVOLE = GF2p256;
    type GFVOLEitH = GF2p8;
    let bristol_fashion_adaptor = BristolFashionAdaptor::new(
        &"aes_128.txt".to_string()
    );
    let mut rng = rand::rng();
    // println!("Num AND gates: {:?}", bristol_fashion_adaptor.get_and_gate_output_wire_vec().len());
    let num_input_bits = bristol_fashion_adaptor.get_num_input_bits();
    let big_ia = (0..num_input_bits >> 1).collect::<Vec<usize>>();
    let big_ib = (big_ia.len()..num_input_bits).collect::<Vec<usize>>();
    // let big_io = (bristol_fashion_adaptor.get_num_wires() - bristol_fashion_adaptor.get_num_output_bits()..bristol_fashion_adaptor.get_num_wires()).collect::<Vec<usize>>();
    let pa_input_bit_vec = big_ia.iter().map(
        |_| rng.random::<u8>() & 1
    ).collect();
    let pb_input_bit_vec = big_ib.iter().map(
        |_| rng.random::<u8>() & 1
    ).collect();
    let bs = 1;
    let rm = bristol_fashion_adaptor.get_and_gate_output_wire_vec().len();
    let public_parameter = PublicParameter::new::<GFVOLE, GFVOLEitH>(
        &bristol_fashion_adaptor,
        8,
        32,
        SeedU8x16::insecurely_random(),
        big_ia,
        big_ib,
        bs,
        rm,
    );

    let mut pa_secret_state = ProverSecretState::<GFVOLE, GFVOLEitH>::new(
        &public_parameter,
        SeedU8x16::insecurely_random(),
        true
    );

    let mut pb_secret_state = ProverSecretState::<GFVOLE, GFVOLEitH>::new(
        &public_parameter,
        SeedU8x16::insecurely_random(),
        false
    );

    let bit_trace_vec_for_labels_in_garbling = determine_bit_trace_for_labels_in_garbling(
        &bristol_fashion_adaptor,
        &public_parameter,
    );

    let preprocessing_transcript = ProverInPA2PC::preprocess(
        process_printing,
        &bristol_fashion_adaptor,
        &bit_trace_vec_for_labels_in_garbling,
        &public_parameter,
        &mut pa_secret_state,
        &mut pb_secret_state,
    );

    let permutation_rep = (0..public_parameter.kappa).map(
        |_| insecurely_generate_random_permutation(public_parameter.big_l)
    ).collect::<Vec<Vec<usize>>>();

    let nabla_a_rep = (0..public_parameter.kappa).map(|_|
        GFVOLEitH::from_u8(rng.random::<u8>())
    ).collect::<Vec<GFVOLEitH>>();
    let nabla_b_rep = (0..public_parameter.kappa).map(|_|
        GFVOLEitH::from_u8(rng.random::<u8>())
    ).collect::<Vec<GFVOLEitH>>();

    // println!("nabla_a_rep {:?}", nabla_a_rep);
    // println!("nabla_b_rep {:?}", nabla_b_rep);

    let (proof_transcript, pa_decom_rep, pb_decom_rep) = ProverInPA2PC::prove(
        process_printing,
        &bristol_fashion_adaptor,
        &public_parameter,
        &preprocessing_transcript,
        &permutation_rep,
        &mut pa_secret_state,
        &mut pb_secret_state,
        &pa_input_bit_vec,
        &pb_input_bit_vec,
        &nabla_a_rep,
        &nabla_b_rep
    );

    VerifierInPA2PC::verify::<GFVOLE, GFVOLEitH>(
        process_printing,
        &bristol_fashion_adaptor,
        &public_parameter,
        &permutation_rep,
        &nabla_a_rep, &nabla_b_rep,
        &preprocessing_transcript,
        &proof_transcript,
        &pa_decom_rep, 
        &pb_decom_rep,
    );

    // println!("{:?}", proof_transcript.published_output_bit_vec);
    let full_input_bit_vec = determine_full_input_bit_vec(
        &public_parameter,
        &pa_input_bit_vec,
        &pb_input_bit_vec,
    );
    let expected_output_bit_vec = BitVec::from_vec(bristol_fashion_adaptor.compute_output_bits(&full_input_bit_vec));
    // println!("{:?}", expected_output_bit_vec);
    assert_eq!(proof_transcript.published_output_bit_vec, expected_output_bit_vec);
    println!("+ Total running time: {:?}", start_total.elapsed());
}

fn main() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build_global()
        .unwrap();
    test_pa_2pc_for_sub64(false);
}