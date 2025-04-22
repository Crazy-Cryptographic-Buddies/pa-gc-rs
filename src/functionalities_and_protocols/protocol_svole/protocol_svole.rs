use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_input::ProverSecretInput;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::protocol_svole::prover_in_protocol_svole::ProverInProtocolSVOLE;
use crate::functionalities_and_protocols::protocol_svole::verifier_in_protocol_svole::VerifierInProtocolSVOLE;
use crate::value_type::{GFAdd, HashDigestToGF, InsecureRandom, U8ForGF, Zero};
use crate::value_type::gf2p8::GF2p8;
use crate::value_type::seed_u8x16::SeedU8x16;

struct ProtocolSVOLE {
}

impl ProtocolSVOLE {
    
    pub fn run<GF: Clone + Zero + GFAdd + U8ForGF + HashDigestToGF>(
        prover_in_all_in_one_vc: &mut ProverInAllInOneVC<GF>, 
        verifier_in_all_in_one_vc: &mut VerifierInAllInOneVC<GF>,
        pub_aux: &Vec<u8>
    ) -> (
        Hash, GF, (SeedU8x16, Vec<SeedU8x16>)
    ) {
        // this protocol only requires prover_secret_input as a seed for generating Merkle tree

        // prover first commit
        let hash_com = ProverInProtocolSVOLE::commit(prover_in_all_in_one_vc);

        // verifier generate challenge
        let nabla = VerifierInProtocolSVOLE::generate_challenge(pub_aux, &hash_com);

        // prover releases decom based on nable
        let decom = ProverInProtocolSVOLE::open(prover_in_all_in_one_vc, &nabla);

        // verifier recover voleith keys
        VerifierInProtocolSVOLE::reconstruct(verifier_in_all_in_one_vc, &nabla, &decom);

        (hash_com, nabla, decom)
    }
}

#[test]
fn test_protocol_svole() {
    // public inputs
    let pub_aux = vec![0u8; 16];

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

    // prepare prover and verifier for all_in_one_vc
    let mut prover_in_all_in_one_vc = ProverInAllInOneVC::<GF2p8>::new(&public_parameter, &prover_secret_input);
    let mut verifier_in_all_in_one_vc = VerifierInAllInOneVC::<GF2p8>::new(&public_parameter);


    let (hash_com, nabla, decom) = ProtocolSVOLE::run(&mut prover_in_all_in_one_vc, &mut verifier_in_all_in_one_vc, &pub_aux);

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