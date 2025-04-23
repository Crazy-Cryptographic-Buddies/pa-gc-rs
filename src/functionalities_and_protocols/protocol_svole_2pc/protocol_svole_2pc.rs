use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

struct ProtocolSVOLE;

impl ProtocolSVOLE {
    
    fn distribute_bits_and_voleith_macs_to_state(prover_secret_state: &mut ProverSecretState) {
        
    }
    
    pub fn run<GF: Clone + Zero + GFAdd + U8ForGF>(
        public_parameter: &PublicParameter,
        pa_secret_input: &mut ProverSecretState, pb_secret_input: &ProverSecretState
    ) {
        // pa call svole kappa times
        for repetition_id in 0..public_parameter.kappa {
            let mut secret_bit_vec: Option<BitVec> = None;
            let mut secret_voleith_mac_vec: Option<GFVec<GF>> = None;
            pa_secret_input.prover_in_all_in_one_vc_rep[repetition_id].commit(
                &public_parameter, 
                &pa_secret_input.seed_for_generating_ggm_tree_rep[repetition_id],
                &mut secret_bit_vec,
                &mut secret_voleith_mac_vec
            );
        }
    }
}