use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, U8ForGF, Zero};

pub(crate) struct ProverInProtocolSVOLE {
}

impl ProverInProtocolSVOLE {

    pub fn commit<GF: Clone + Zero + GFAdd + U8ForGF>(prover_in_all_in_one_vc: &mut ProverInAllInOneVC<GF>) -> Hash {
        prover_in_all_in_one_vc.commit();
        prover_in_all_in_one_vc.get_com_hash().clone()
    }

    pub fn open<GF: Clone + Zero + GFAdd + U8ForGF>(prover_in_all_in_one_vc: &mut ProverInAllInOneVC<GF>, nabla: &GF) -> (SeedU8x16, Vec<SeedU8x16>) {
        prover_in_all_in_one_vc.open(nabla)
    }
}