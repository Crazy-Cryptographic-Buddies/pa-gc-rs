use crate::cryptography::all_in_one_vc::all_in_one_vc_for_prover::AllInOneVCForProver;
use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
use crate::value_type::{GFAdd, GFMultiplyingBit, U8ForGF, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;

struct ProtocolSVOLE {
    tau: u8,
    big_n: usize,
}

impl ProtocolSVOLE {
    
    pub fn new(tau: u8, big_n: usize) -> Self {
        Self {
            tau,
            big_n
        }
    }
    
    pub fn run<GF: Clone + Zero + GFAdd + U8ForGF>(
        &self, master_key: &SeedU8x16
    ) {
        
    }
}