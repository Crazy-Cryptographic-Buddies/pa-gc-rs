use blake3::Hash;
use rand::TryRngCore;
use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::protocol_svole::prover_in_protocol_svole::ProverInProtocolSVOLE;
use crate::functionalities_and_protocols::protocol_svole::verifier_in_protocol_svole::VerifierInProtocolSVOLE;
use crate::value_type::{GFAdd, HashDigestToGF, InsecureRandom, U8ForGF, Zero};
use crate::value_type::gf2p8::GF2p8;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

struct ProtocolSVOLE {
}

impl ProtocolSVOLE {
    
    // pub fn commit<GF: Clone + Zero + GFAdd + U8ForGF + HashDigestToGF>(
    //     prover_secret_state: ProverSecretState,
    // ) -> Hash {
    //     ProverInProtocolSVOLE::commit(prover_in_all_in_one_vc)
    // }
    //
    // pub fn open_and_reconstruct<GF: Clone + Zero + GFAdd + U8ForGF + HashDigestToGF>(
    //     prover_in_all_in_one_vc: &mut ProverInAllInOneVC<GF>,
    //     verifier_in_all_in_one_vc: &mut VerifierInAllInOneVC<GF>,
    //     hash_com: Hash,
    //     nabla: &GF,
    // ) -> (SeedU8x16, Vec<SeedU8x16>) {
    //     // prover releases decom based on nable
    //     let decom = ProverInProtocolSVOLE::open(prover_in_all_in_one_vc, &nabla);
    //     VerifierInAllInOneVC::reconstruct(verifier_in_all_in_one_vc, &nabla, &decom);
    //     decom
    // }
}

#[test]
fn test_protocol_svole() {
    // public inputs
    let pub_aux = vec![0u8; 16];

    let public_parameter = PublicParameter::new(
        8,
        20,
        SeedU8x16::insecurely_random(),
        10,
        10,
        20,
        30,
    );
    let mut prover_secret_state = ProverSecretState::new(
        &public_parameter,
        SeedU8x16::insecurely_random(),
    );

    let mut secret_bit_vec_rep: Vec<BitVec> = Vec::new();

    for repetition_id in 0..public_parameter.kappa {
        // prepare prover and verifier for all_in_one_vc
        let prover_in_all_in_one_vc = &mut prover_secret_state.prover_in_all_in_one_vc_rep[repetition_id];
        secret_bit_vec_rep.push(BitVec::new());
        let mut secret_bit_vec: Option<BitVec> = None;
        let mut secret_voleith_mac_vec: Option<GFVec<GF2p8>> = None;
        let hash_com = ProverInProtocolSVOLE::commit(
            &public_parameter, prover_in_all_in_one_vc, &prover_secret_state.seed_for_generating_ggm_tree_rep[repetition_id] ,
            &mut secret_bit_vec, &mut secret_voleith_mac_vec
        );
        let nabla = GF2p8::insecurely_random();
        let decom = ProverInProtocolSVOLE::open(
            &public_parameter,
            &mut prover_secret_state.prover_in_all_in_one_vc_rep[repetition_id],
            &nabla
        );
        let (reconstructed_hash_com, public_voleith_key_vec) = VerifierInProtocolSVOLE::reconstruct(
            &public_parameter, &nabla, &decom
        );
        
        for i in 0..public_parameter.big_n {
            let mut shifted_nabla = GF2p8::zero();
            if secret_bit_vec.as_ref().unwrap()[i] == 1 {
                shifted_nabla = nabla.clone();
            }
            println!("mac + bit * nabla, key, mac, msg: {:?}, {:?}, {:?}, {:?}",
                     secret_voleith_mac_vec.as_ref().unwrap()[i].gf_add(&shifted_nabla),
                     public_voleith_key_vec[i],
                     secret_voleith_mac_vec.as_ref().unwrap()[i],
                     secret_bit_vec.as_ref().unwrap()[i]
            );
            assert_eq!(public_voleith_key_vec[i], secret_voleith_mac_vec.as_ref().unwrap()[i].gf_add(&shifted_nabla));
        }
        println!("bit_vec_len, voleith_mac_vec_len, voleith_key_vec_len: {:?}, {:?}, {:?}",
                 secret_bit_vec.as_ref().unwrap().len(),
                 secret_voleith_mac_vec.as_ref().unwrap().len(),
                 public_voleith_key_vec.len());
    }

    println!("voleith correlation checking passed!");
}