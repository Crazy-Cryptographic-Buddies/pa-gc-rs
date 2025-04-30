use std::any::type_name;
use std::fmt::Debug;
use std::time::Instant;
use bincode::{config, encode_to_vec, Encode};
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
use pa_gc_rs::value_type::{ByteManipulation, CustomAddition, CustomMultiplyingBit, InsecureRandom, Zero};
use pa_gc_rs::value_type::gf2p128::GF2p128;
use pa_gc_rs::vec_type::bit_vec::BitVec;
use pa_gc_rs::vec_type::BasicVecFunctions;
use pa_gc_rs::value_type::U8ForGF;

// fn insecurely_generate_random_permutation(len: usize) -> Vec<usize> {
//     let mut random_permutation = (0..len).collect::<Vec<usize>>();
//     let mut rng = rand::rng();
//     for i in (0..len).rev() {
//         let j = rng.random::<u32>() % (i as u32 + 1u32);
//         random_permutation.swap(i, j as usize);
//     }
//     random_permutation
// }

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

fn benchmark<GFVOLE, GFVOLEitH>(process_printing: bool, circuit_string_file_name: &str, num_threads: usize)
where
    GFVOLE: ByteManipulation + Copy + Zero + PartialEq + CustomAddition + CustomMultiplyingBit + InsecureRandom + Send + Sync + Debug + Encode,
    GFVOLEitH: ByteManipulation + Clone + Zero + CustomMultiplyingBit + Copy + CustomAddition + U8ForGF + Send + Sync + Debug + PartialEq + Encode {
    let security_level = GFVOLE::num_bytes() * 8;
    let tau = 8;
    let kappa = (security_level - 1) / (tau as usize) + 1;

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();
    let start_total = Instant::now();
    let bristol_fashion_adaptor = BristolFashionAdaptor::new(
        &circuit_string_file_name.to_string()
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
    // let rm = bristol_fashion_adaptor.get_and_gate_output_wire_vec().len();
    let bs = (((security_level as f64) / (kappa as f64)) / (bristol_fashion_adaptor.get_and_gate_output_wire_vec().len() as f64).log2()).ceil() as usize;
    let rm = bristol_fashion_adaptor.get_and_gate_output_wire_vec().len();
    println!("Security level {:?}, Circuit {:?}, GFVOLE: {:?}, GFVOLEitH: {:?}, num_threads: {:?}, tau: {:?}, kappa: {:?}, bs: {:?}",
             security_level, circuit_string_file_name, type_name::<GFVOLE>(), type_name::<GFVOLEitH>(), num_threads, tau, kappa, bs
    );
    let public_parameter = PublicParameter::new::<GFVOLE, GFVOLEitH>(
        &bristol_fashion_adaptor,
        tau,
        kappa,
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

    let start_preprocessing = Instant::now();
    let preprocessing_transcript = ProverInPA2PC::preprocess(
        process_printing,
        &bristol_fashion_adaptor,
        &bit_trace_vec_for_labels_in_garbling,
        &public_parameter,
        &mut pa_secret_state,
        &mut pb_secret_state,
    );
    let preprocessing_time = start_preprocessing.elapsed().as_secs_f32();

    // let permutation_rep = (0..public_parameter.kappa).map(
    //     |_| insecurely_generate_random_permutation(public_parameter.big_l)
    // ).collect::<Vec<Vec<usize>>>();
    //
    // let nabla_a_rep = (0..public_parameter.kappa).map(|_|
    //     GFVOLEitH::from_u8(rng.random::<u8>())
    // ).collect::<Vec<GFVOLEitH>>();
    // let nabla_b_rep = (0..public_parameter.kappa).map(|_|
    //     GFVOLEitH::from_u8(rng.random::<u8>())
    // ).collect::<Vec<GFVOLEitH>>();

    // println!("nabla_a_rep {:?}", nabla_a_rep);
    // println!("nabla_b_rep {:?}", nabla_b_rep);

    let start_proving = Instant::now();
    let (proof_transcript, pa_decom_rep, pb_decom_rep) = ProverInPA2PC::prove(
        process_printing,
        &bristol_fashion_adaptor,
        &public_parameter,
        &preprocessing_transcript,
        // &permutation_rep,
        &mut pa_secret_state,
        &mut pb_secret_state,
        &pa_input_bit_vec,
        &pb_input_bit_vec,
        // &nabla_a_rep,
        // &nabla_b_rep
    );
    let proving_time = start_proving.elapsed().as_secs_f32();

    let start_verifying = Instant::now();
    VerifierInPA2PC::verify::<GFVOLE, GFVOLEitH>(
        process_printing,
        &bristol_fashion_adaptor,
        &public_parameter,
        // &permutation_rep,
        // &nabla_a_rep, &nabla_b_rep,
        &preprocessing_transcript,
        &proof_transcript,
        &pa_decom_rep,
        &pb_decom_rep,
    );
    let verifying_time = start_verifying.elapsed().as_secs_f32();
    let total_time = start_total.elapsed().as_secs_f32();

    // println!("{:?}", proof_transcript.published_output_bit_vec);
    let full_input_bit_vec = determine_full_input_bit_vec(
        &public_parameter,
        &pa_input_bit_vec,
        &pb_input_bit_vec,
    );
    let expected_output_bit_vec = BitVec::from_vec(bristol_fashion_adaptor.compute_output_bits(&full_input_bit_vec));
    // println!("{:?}", expected_output_bit_vec);
    assert_eq!(proof_transcript.published_output_bit_vec, expected_output_bit_vec);
    println!("+ Performance for Security level {:?}, Circuit {:?}, GFVOLE: {:?}, GFVOLEitH: {:?}, num_threads: {:?}, tau: {:?}, kappa: {:?}, bs: {:?}",
             security_level, circuit_string_file_name, type_name::<GFVOLE>(), type_name::<GFVOLEitH>(), num_threads, tau, kappa, bs
    );
    println!("  Running time");
    println!("    Preprocessing time: {:?}", preprocessing_time);
    println!("    Proving time: {:?}", proving_time);
    println!("    Verifying time: {:?}", verifying_time);
    println!("    ==> Total running time: {:?}", total_time);
    println!("  Communication");
    println!("    preproccesing_transcript size: {:?} MB", (preprocessing_transcript.to_byte_vec().len() as f64) / 1048576f64);
    println!("    proof_transcript size: {:?} MB", (proof_transcript.to_byte_vec().len() as f64) / 1048576f64);
    let config = config::standard();
    let pa_decom_bytes = encode_to_vec(&pa_decom_rep, config).unwrap();
    let pb_decom_bytes = encode_to_vec(&pb_decom_rep, config).unwrap();
    let total_decom_byte_len = pa_decom_bytes.len() + pb_decom_bytes.len();
    println!("    (pa_decom, pb_decom) size: {:?} MB", (total_decom_byte_len as f64) / 1048576f64);
    println!("    ==> Total communication size: {:?} MB",
             ((preprocessing_transcript.to_byte_vec().len() as f64) + (proof_transcript.to_byte_vec().len() as f64) + (total_decom_byte_len as f64)) / 1048576f64 
    );
}

fn main() {
    let print_process = true;
    let circuit_sub64 = "sub64.txt";
    let circuit_mult64 = "mult64.txt";
    let circuit_aes_128 = "aes_128.txt";
    let circuit_sha256 = "sha256.txt";
    
    // 128-bit security
    type GFVOLE128 = GF2p128;
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sub64, 1);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sub64, 2);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sub64, 4);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sub64, 8);

    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_mult64, 1);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_mult64, 2);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_mult64, 4);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_mult64, 8);

    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_aes_128, 1);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_aes_128, 2);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_aes_128, 4);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_aes_128, 8);

    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sha256, 1);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sha256, 2);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sha256, 4);
    // benchmark::<GFVOLE128, GF2p8>(print_process, circuit_sha256, 8);

    // 256-bit security
    type GFVOLE256 = GF2p256;

    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sub64, 1);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sub64, 2);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sub64, 4);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sub64, 8);

    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_mult64, 1);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_mult64, 2);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_mult64, 4);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_mult64, 8);

    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_aes_128, 1);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_aes_128, 2);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_aes_128, 4);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_aes_128, 8);

    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sha256, 1);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sha256, 2);
    // benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sha256, 4);
    benchmark::<GFVOLE256, GF2p8>(print_process, circuit_sha256, 8);
}