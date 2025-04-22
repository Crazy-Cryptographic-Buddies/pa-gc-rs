use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, HashDigestToGF, U8ForGF, Zero};

pub(crate) struct VerifierInProtocolSVOLE {
}

impl VerifierInProtocolSVOLE {

    pub fn generate_challenge<GF: HashDigestToGF>(pub_aux: &Vec<u8>, com_hash_from_prover: &Hash) -> GF {
        let mut hasher = blake3::Hasher::new();
        hasher.update(pub_aux);
        hasher.update(com_hash_from_prover.as_bytes());
        GF::from_hash_digest(&hasher.finalize())
    }

    pub fn reconstruct<GF: Clone + GFAdd + U8ForGF + Zero>(
        verifier_in_all_in_one_vc: &mut VerifierInAllInOneVC<GF>, nabla: &GF, decom: &(SeedU8x16, Vec<SeedU8x16>)
    ) {
        verifier_in_all_in_one_vc.reconstruct(nabla, decom);
    }

}