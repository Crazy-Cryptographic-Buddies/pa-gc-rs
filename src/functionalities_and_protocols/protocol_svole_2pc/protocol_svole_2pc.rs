use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;

struct ProtocolSVOLE;

impl ProtocolSVOLE {
    pub fn run(
        public_parameter: &PublicParameter, 
        pa_secret_input: &ProverSecretState, pb_secret_input: &ProverSecretState
    ) {
        // pa call svole kappa times
        for _ in 0..public_parameter.kappa {
            todo!()
        }
    }
}