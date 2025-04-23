use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

pub(crate) struct ProverInProtocolSVOLE {
}

impl ProverInProtocolSVOLE {

    pub fn commit<GF: Clone + Zero + GFAdd + U8ForGF>(
        public_parameter: &PublicParameter,
        prover_in_all_in_one_vc: &mut ProverInAllInOneVC,
        prover_secret_seed_for_generating_ggm_tree: &SeedU8x16,
        output_secret_bit_vec: &mut Option<BitVec>,
        output_secret_voleith_mac_vec: &mut Option<GFVec<GF>>
    ) -> Hash {
        prover_in_all_in_one_vc.commit(
            public_parameter, prover_secret_seed_for_generating_ggm_tree, 
            output_secret_bit_vec, output_secret_voleith_mac_vec
        )
    }

    pub fn open<GF: Clone + Zero + GFAdd + U8ForGF>(
        public_parameter: &PublicParameter,
        prover_in_all_in_one_vc: &mut ProverInAllInOneVC, 
        nabla: &GF
    ) -> (SeedU8x16, Vec<SeedU8x16>) {
        prover_in_all_in_one_vc.open(&public_parameter, nabla)
    }
}