use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, U8ForGF, Zero};

pub(crate) struct ProverInProtocolSVOLE<'a, GF: Clone + Zero> {
    prover_in_all_in_one_vc: &'a mut ProverInAllInOneVC<'a, GF>
}

impl<'a, GF: Clone + Zero + GFAdd + U8ForGF> ProverInProtocolSVOLE<'a, GF> {

    pub fn new(prover_in_all_in_one_vc: &'a mut ProverInAllInOneVC<'a, GF>) -> Self {
        Self {
            prover_in_all_in_one_vc
        }
    }

    pub fn commit(&mut self, seed: &SeedU8x16) -> Hash {
        self.prover_in_all_in_one_vc.commit();
        self.prover_in_all_in_one_vc.get_com_hash().clone()
    }

    pub fn open(&self, nabla: &GF) -> (SeedU8x16, Vec<SeedU8x16>) {
        self.prover_in_all_in_one_vc.open(nabla)
    }
}