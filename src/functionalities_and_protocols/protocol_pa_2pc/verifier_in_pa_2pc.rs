use crate::functionalities_and_protocols::states_and_parameters::preprocessing_transcript::PreprocessingTranscript;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;

pub struct VerifierInPA2PC;

impl VerifierInPA2PC {
    pub fn verify<GFVOLE, GFVOLEitH>(
        public_parameter: &PublicParameter,
        preprocessing_transcript: PreprocessingTranscript<GFVOLE, GFVOLEitH>,
    ) {

    }
}