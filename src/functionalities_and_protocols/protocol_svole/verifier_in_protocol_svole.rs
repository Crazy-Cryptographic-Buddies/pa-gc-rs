use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{CustomAddition, U8ForGF, Zero};
use crate::vec_type::gf_vec::GFVec;

pub struct VerifierInProtocolSVOLE {
}

impl VerifierInProtocolSVOLE {

    // pub fn generate_challenge<GF: HashDigestToGF>(
    //     pub_aux: &Vec<u8>, com_hash_from_prover: &Hash
    // ) -> GF {
    //     let mut hasher = blake3::Hasher::new();
    //     hasher.update(pub_aux);
    //     hasher.update(com_hash_from_prover.as_bytes());
    //     GF::from_hash_digest(&hasher.finalize())
    // }

    pub fn reconstruct<GFVOLEitH: Clone + CustomAddition + U8ForGF + Zero>(
        public_parameter: &PublicParameter,
        prover_com_hash: &Hash,
        nabla: &GFVOLEitH,
        decom: &(SeedU8x16, Vec<SeedU8x16>)
    ) -> GFVec<GFVOLEitH> {
        let (reconstructed_com_hash, voleith_key_vec) = VerifierInAllInOneVC::reconstruct(
            public_parameter, nabla, decom
        );
        assert_eq!(reconstructed_com_hash, *prover_com_hash);
        // println!("- prover_com_hash:        {:?}", prover_com_hash);
        // println!("- reconstructed_com_hash: {:?}", reconstructed_com_hash);
        voleith_key_vec
    }

}