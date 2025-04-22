use blake3::Hash;
use crate::cryptography::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, HashDigestToGF, U8ForGF, Zero};

pub(crate) struct VerifierInProtocolSVOLE<'a, GF: Clone + Zero> {
    verifier_in_all_in_one_vc: &'a mut VerifierInAllInOneVC<GF>
}

impl<'a, GF: Clone + Zero + GFAdd + U8ForGF + HashDigestToGF> VerifierInProtocolSVOLE<'a, GF> {

    pub fn new(verifier_in_all_in_one_vc: &'a mut VerifierInAllInOneVC<GF>) -> Self {
        Self {
            verifier_in_all_in_one_vc
        }
    }

    pub fn generate_challenge(&self, pub_aux: &Vec<u8>, com_hash_from_prover: &Hash) -> GF {
        let mut hasher = blake3::Hasher::new();
        hasher.update(pub_aux);
        hasher.update(com_hash_from_prover.as_bytes());
        GF::from_hash_digest(&hasher.finalize())
    }

    pub fn reconstruct(
        &mut self, nabla: &GF, com_at_excluded_index: &SeedU8x16, seed_trace: &Vec<SeedU8x16>
    ) {
        self.verifier_in_all_in_one_vc.reconstruct(nabla, com_at_excluded_index, seed_trace);
    }

}