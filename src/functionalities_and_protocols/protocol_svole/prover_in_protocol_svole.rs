use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
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
        repetition_id: usize,
        prover_secret_state: &mut ProverSecretState<GF>,
        output_secret_bit_vec: &mut Option<BitVec>,
        output_secret_voleith_mac_vec: &mut Option<GFVec<GF>>
    ) -> Hash {
        prover_secret_state.prover_in_all_in_one_vc_rep[repetition_id].commit(
            public_parameter, 
            &prover_secret_state.seed_for_generating_ggm_tree_rep[repetition_id],
            output_secret_bit_vec, output_secret_voleith_mac_vec
        )
    }

    pub fn open<GF: Clone + Zero + GFAdd + U8ForGF>(
        public_parameter: &PublicParameter,
        repetition_id: usize,
        prover_secret_state: &mut ProverSecretState<GF>,
        nabla: &GF
    ) -> (SeedU8x16, Vec<SeedU8x16>) {
        prover_secret_state.prover_in_all_in_one_vc_rep[repetition_id].open(&public_parameter, nabla)
    }
}