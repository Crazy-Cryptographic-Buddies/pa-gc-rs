use galois_2p8::{Field, GeneralField};
use rand::Rng;
use pa_gc_rs::all_in_one_vc::all_in_one_vc_for_prover::AllInOneVCForProver;
use pa_gc_rs::all_in_one_vc::all_in_one_vc_for_verifier::AllInOneVCForVerifier;
use pa_gc_rs::comm_types_and_constants::SEED_BYTE_LEN;
use pa_gc_rs::value_type::seed_u8x16::SeedU8x16;
use pa_gc_rs::value_type::{
    Zero, InsecureRandom, GFAdd
};
use pa_gc_rs::value_type::gf2p8::GF2p8;

fn generate_random_seed() -> SeedU8x16 {
    let mut rng = rand::rng();
    let mut seed: SeedU8x16 = SeedU8x16::default();
    for i in 0..SEED_BYTE_LEN {
        seed[i] = rng.random::<u8>();
    }
    seed
}

fn main() {
    let mut rng = rand::rng();
    let master_key: SeedU8x16 = generate_random_seed();
    let master_seed: SeedU8x16 = generate_random_seed();
    let tau = 8;
    let message_len = 160;
    let nabla = GF2p8::insecurely_random();
    // first generate in the prover side
    let mut all_in_one_vc_for_prover = AllInOneVCForProver::new(
        tau, &master_key, message_len
    );
    all_in_one_vc_for_prover.commit(&master_seed);
    let (com_at_excluded_index_by_prover, seed_trace_by_prover)
        = all_in_one_vc_for_prover.open(&nabla);

    // then generate in the verifier side
    let mut all_in_one_vc_for_verifier = AllInOneVCForVerifier::new(tau, &master_key, message_len);
    all_in_one_vc_for_verifier.reconstruct(
        &nabla, &com_at_excluded_index_by_prover, &seed_trace_by_prover
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
    let message = all_in_one_vc_for_prover.get_message_for_testing();
    let voleith_mac = all_in_one_vc_for_prover.get_voleith_mac_for_testing();
    let voleith_key = all_in_one_vc_for_verifier.get_voleith_key_for_testing();
    for j in 0..message_len {
        let mut shifted_nabla = GF2p8::zero();
        if message[j] == 1 {
            shifted_nabla = nabla.clone();
        }
        println!("mac + message * nabla, key, mac, msg: {:?}, {:?}, {:?}, {:?}",
                 voleith_mac[j].gf_add(&shifted_nabla),
                 voleith_key[j],
                 voleith_mac[j],
                 message[j]
        );
        assert_eq!(voleith_key[j], voleith_mac[j].gf_add(&shifted_nabla));
    }
    println!("voleith correlation checking passed!");
}