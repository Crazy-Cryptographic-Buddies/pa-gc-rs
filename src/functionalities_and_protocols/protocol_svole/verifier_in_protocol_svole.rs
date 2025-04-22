use bincode::{config, encode_to_vec};
use blake3::Hash;
use crate::cryptography::all_in_one_vc::all_in_one_vc_for_verifier::AllInOneVCForVerifier;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, HashDigestToGF, U8ForGF, Zero};
use crate::vec_type::gf_vec::GFVec;

struct VerifierInProtocolSVOLE<GF: Clone + Zero> {
    all_in_one_vc_for_verifier: AllInOneVCForVerifier<GF>
}

impl<GF: Clone + Zero + GFAdd + U8ForGF + HashDigestToGF> VerifierInProtocolSVOLE<GF> {
    
    pub fn new(tau: u8, master_key: &SeedU8x16, big_n: usize) -> Self {
        Self {
            all_in_one_vc_for_verifier: AllInOneVCForVerifier::<GF>::new(tau, master_key, big_n)
        }
    }
    
    pub fn generate_challenge(&self, pub_aux: &Vec<u8>, com_hash_from_prover: &Hash) -> GF {
        let mut hasher = blake3::Hasher::new();
        hasher.update(pub_aux);
        hasher.update(com_hash_from_prover.as_bytes());
        GF::from_hash_digest(&hasher.finalize())
    }
    
    pub fn reconstruct(
        &mut self, com_at_excluded_index: &SeedU8x16, seed_trace: &Vec<SeedU8x16>, nabla: &GF
    ) {
        self.all_in_one_vc_for_verifier.reconstruct(nabla, com_at_excluded_index, seed_trace);
    }
    
}