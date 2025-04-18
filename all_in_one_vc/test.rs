use rand::prelude::*;
use crate::comm_types_and_constants::{SeedU8x16, SEED_BYTE_LEN};
use crate::all_in_one_vc::all_in_one_vc_for_prover::AllInOneVCForProver;

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
    let message_len = 10;
    let excluded_index: u8 = rng.random::<u8>();
    
    // first generate in the prover side
    let mut all_in_one_vc_for_prover = AllInOneVCForProver::new(
        tau, &master_key, message_len
    );
    all_in_one_vc_for_prover.commit(&master_seed);
    let com_hash_from_prover = all_in_one_vc_for_prover.get_com_hash();
    
    // TODO: continue here
}