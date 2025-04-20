use galois_2p8::{Field, GeneralField};
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
    let message_len = 160;
    let nabla: u8 = rng.random::<u8>();
    // first generate in the prover side
    let mut all_in_one_vc_for_prover = AllInOneVCForProver::new(
        tau, &master_key, message_len
    );
    all_in_one_vc_for_prover.commit(&master_seed);
    let (com_at_excluded_index_by_prover, seed_trace_by_prover) 
        = all_in_one_vc_for_prover.open(nabla as usize);
    
    // then generate in the verifier side
    let mut all_in_one_vc_for_verifier = AllInOneVCForVerifier::new(tau, &master_key, message_len);
    all_in_one_vc_for_verifier.reconstruct(
        nabla, &com_at_excluded_index_by_prover, &seed_trace_by_prover
    );
    println!("com_hash_from_prover: {:?}", all_in_one_vc_for_prover.get_com_hash());
    println!("reconstructed hash: {:?}", all_in_one_vc_for_verifier.get_reconstructed_com_hash());
    assert_eq!(
        all_in_one_vc_for_prover.get_com_hash().as_bytes(), 
        all_in_one_vc_for_verifier.get_reconstructed_com_hash().as_bytes()
    );
    println!("com hash checking passed!");
    
    let galois_field = GeneralField::new(
        galois_2p8::IrreducablePolynomial::Poly84310
    );
    let message = all_in_one_vc_for_prover.get_message_to_be_deleted();
    let voleith_mac = all_in_one_vc_for_prover.get_voleith_mac_to_be_deleted();
    let voleith_key = all_in_one_vc_for_verifier.get_voleith_key_to_be_deleted();
    for j in 0..message_len {
        let mut shifted_nabla = 0;
        if message[j] == 1 {
            shifted_nabla = nabla;
        }
        println!("mac + message * nabla, key, mac, msg: {:?}, {:?}, {:?}, {:?}",
                 galois_field.add(voleith_mac[j], shifted_nabla),
                 voleith_key[j],
                 voleith_mac[j], 
                 message[j]
        );
        assert_eq!(voleith_key[j], galois_field.add(voleith_mac[j], shifted_nabla));
    }
    println!("voleith correlation checking passed!");
}