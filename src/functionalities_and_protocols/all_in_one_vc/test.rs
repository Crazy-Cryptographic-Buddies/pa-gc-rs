use rand::prelude::*;
use crate::comm_types_and_constants::{SEED_BYTE_LEN};
use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_input::ProverSecretInput;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::gf2p8::GF2p8;
use crate::value_type::{InsecureRandom, GFAdd, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;

#[test]
fn test_committing_and_reconstructing() {
    println!("testing committing and reconstructing...");
    let master_seed = SeedU8x16::insecurely_random();
    let message_len = 160;
    let nabla = GF2p8::insecurely_random();
    let public_parameter = PublicParameter::new(
        8,
        SeedU8x16::insecurely_random(),
    );
    let prover_secret_input = ProverSecretInput::new(
        SeedU8x16::insecurely_random(),
    );
    
    // first generate in the prover side
    let mut all_in_one_vc_for_prover = ProverInAllInOneVC::new(
        &public_parameter, &prover_secret_input, message_len
    );
    all_in_one_vc_for_prover.commit();
    let (com_at_excluded_index_by_prover, seed_trace_by_prover) 
        = all_in_one_vc_for_prover.open(&nabla);
    
    // then generate in the verifier side
    let mut all_in_one_vc_for_verifier = VerifierInAllInOneVC::new(&public_parameter, message_len);
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
    
    // let galois_field = GeneralField::new(
    //     galois_2p8::IrreducablePolynomial::Poly84310
    // );
    let message = all_in_one_vc_for_prover.get_message_for_testing();
    let voleith_mac = all_in_one_vc_for_prover.get_voleith_mac_for_testing();
    let voleith_key = all_in_one_vc_for_verifier.get_voleith_key();
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