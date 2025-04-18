use rand::prelude::*;
use crate::comm_types_and_constants::{SeedU8x16, SEED_BYTE_LEN};
use crate::all_in_one_vc::{
    all_in_one_vc_for_prover::AllInOneVCForProver,
    all_in_one_vc_for_verifier::AllInOneVCForVerifier,
};


fn generate_random_seed() -> SeedU8x16 {
    let mut rng = rand::rng();
    let mut seed: SeedU8x16 = SeedU8x16::default();
    for i in 0..SEED_BYTE_LEN {
        seed[i] = rng.random::<u8>();
    }
    seed
}

#[test]
fn test_committing_and_reconstructing() {
    let mut rng = rand::rng();
    let master_key: SeedU8x16 = generate_random_seed();
    let master_seed: SeedU8x16 = generate_random_seed();
    let tau = 8;
    let message_len = 16;
    let excluded_index: u8 = rng.random::<u8>();
    
    // first generate in the prover side
    let mut all_in_one_vc_for_prover = AllInOneVCForProver::new(
        tau, &master_key, message_len
    );
    all_in_one_vc_for_prover.commit(&master_seed);
    let com_hash_from_prover = all_in_one_vc_for_prover.get_com_hash();
    let (com_at_excluded_index_by_prover, seed_trace_by_prover) 
        = all_in_one_vc_for_prover.open(excluded_index as usize);
    println!("com_at_excluded_index: {:?}", com_at_excluded_index_by_prover);
    
    // then generate in the verifier side
    let all_in_one_vc_for_verifier = AllInOneVCForVerifier::new(tau, &master_key);
    let reconstructed_hash = all_in_one_vc_for_verifier.reconstruct(
        excluded_index as usize, &com_at_excluded_index_by_prover, &seed_trace_by_prover
    );
    println!("com_hash_from_prover: {:?}", com_hash_from_prover);
    println!("reconstructed hash: {:?}", reconstructed_hash);
    assert_eq!(com_hash_from_prover.as_bytes(), reconstructed_hash.as_bytes());
}