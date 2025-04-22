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
    let nabla = GF2p8::insecurely_random();
    let public_parameter = PublicParameter::new(
        8,
        SeedU8x16::insecurely_random(),
        10,
        10,
        20,
        30,
    );
    let prover_secret_input = ProverSecretInput::new(
        SeedU8x16::insecurely_random(),
    );
    
    // first generate in the prover side
    let mut prover_in_all_in_one_vc = ProverInAllInOneVC::new(
        &public_parameter, &prover_secret_input
    );
    prover_in_all_in_one_vc.commit();
    let decom = prover_in_all_in_one_vc.open(&nabla);
    
    // then generate in the verifier side
    let mut verifier_in_all_in_one_vc = VerifierInAllInOneVC::new(&public_parameter);
    verifier_in_all_in_one_vc.reconstruct(&nabla, &decom);
    println!("com_hash_from_prover: {:?}", prover_in_all_in_one_vc.get_com_hash());
    println!("reconstructed hash: {:?}", verifier_in_all_in_one_vc.get_reconstructed_com_hash());
    assert_eq!(
        prover_in_all_in_one_vc.get_com_hash().as_bytes(), 
        verifier_in_all_in_one_vc.get_reconstructed_com_hash().as_bytes()
    );
    println!("com hash checking passed!");
    
    // let galois_field = GeneralField::new(
    //     galois_2p8::IrreducablePolynomial::Poly84310
    // );
    let message = prover_in_all_in_one_vc.get_message_for_testing();
    let voleith_mac = prover_in_all_in_one_vc.get_voleith_mac_for_testing();
    let voleith_key = verifier_in_all_in_one_vc.get_voleith_key();
    for j in 0..public_parameter.big_n {
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
    println!("message_len, voleith_mac_len, voleith_key_len: {:?}, {:?}, {:?}", message.len(), voleith_mac.len(), voleith_key.len());
    println!("voleith correlation checking passed!");
}