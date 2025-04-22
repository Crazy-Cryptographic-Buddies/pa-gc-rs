use blake3::Hash;
use crate::cryptography::all_in_one_vc::all_in_one_vc_for_prover::AllInOneVCForProver;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, U8ForGF, Zero};

struct ProverInProtocolSVOLE<GF: Clone + Zero> {
    all_in_one_vc_for_prover: AllInOneVCForProver<GF>
}

impl<GF: Clone + Zero + GFAdd + U8ForGF> ProverInProtocolSVOLE<GF> {
    
    pub fn new(tau: u8, master_key: &SeedU8x16, big_n: usize) -> Self {
        Self { 
            all_in_one_vc_for_prover: AllInOneVCForProver::<GF>::new(tau, master_key, big_n)
        }
    }
    
    pub fn commit(&mut self, seed: &SeedU8x16) -> Hash {
        self.all_in_one_vc_for_prover.commit(seed);
        self.all_in_one_vc_for_prover.get_com_hash().clone()
    }
    
    pub fn open(&self, nabla: &GF) -> (SeedU8x16, Vec<SeedU8x16>) {
        self.all_in_one_vc_for_prover.open(nabla)
    }
}