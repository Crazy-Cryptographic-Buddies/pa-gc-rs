use crate::cryptography::all_in_one_vc::all_in_one_vc_for_prover::AllInOneVCForProver;
use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
use crate::value_type::InsecureRandom;
use crate::value_type::seed_u8x16::SeedU8x16;

struct ProtocolSvole<GF> {
    tau: u8,
}

impl<GF> ProtocolSvole<GF> {
    
    pub fn new(tau: u8) -> Self {
        Self {
            tau,
        }
    }
    
    pub fn run(f_pre: &mut InsecureFunctionalityPre<GF>) {
        todo!();
        // let master_key = SeedU8x16::
        // let all_in_one_vc_for_prover = AllInOneVCForProver::new();
    }
}