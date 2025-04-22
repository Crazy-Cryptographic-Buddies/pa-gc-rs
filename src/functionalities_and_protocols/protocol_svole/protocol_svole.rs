use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::all_in_one_vc::verifier_in_all_in_one_vc::VerifierInAllInOneVC;
use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_input::ProverSecretInput;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::protocol_svole::prover_in_protocol_svole::ProverInProtocolSVOLE;
use crate::functionalities_and_protocols::protocol_svole::verifier_in_protocol_svole::VerifierInProtocolSVOLE;
use crate::value_type::{GFAdd, HashDigestToGF, InsecureRandom, U8ForGF, Zero};
use crate::value_type::gf2p8::GF2p8;
use crate::value_type::seed_u8x16::SeedU8x16;

struct ProtocolSVOLE<'a, GF: Clone + Zero> {
    prover_in_protocol_svole: &'a mut ProverInProtocolSVOLE<'a, GF>,
    verifier_in_protocol_svole: &'a mut VerifierInProtocolSVOLE<'a, GF>
}

impl<'a, GF: Clone + Zero + GFAdd + U8ForGF + HashDigestToGF> ProtocolSVOLE<'a, GF> {
    
    pub fn new(
        prover_in_protocol_svole: &'a mut ProverInProtocolSVOLE<'a, GF>,
        verifier_in_protocol_svole: &'a mut VerifierInProtocolSVOLE<'a, GF>
    ) -> Self {
        Self {
            prover_in_protocol_svole,
            verifier_in_protocol_svole,
        }
    }
    
    pub fn run(&mut self, pub_aux: &Vec<u8>, prover_secret_input: &SeedU8x16) {
        // this protocol only requires prover_secret_input as a seed for generating Merkle tree

        // prover first commit
        let hash_com = self.prover_in_protocol_svole.commit(prover_secret_input);

        // verifier generate challenge
        let nabla = self.verifier_in_protocol_svole.generate_challenge(pub_aux, &hash_com);

        // prover releases decom based on nable
        let decom = self.prover_in_protocol_svole.open(&nabla);

        // verifier recover voleith keys
        self.verifier_in_protocol_svole.reconstruct(&nabla, &decom.0, &decom.1);
    }
}

#[test]
fn test_protocol_svole() {
    // public inputs
    let master_seed = SeedU8x16::insecurely_random();
    let big_n = 160;
    let pub_aux = vec![0u8; 16];
    
    let public_parameter = PublicParameter::new(
        8,
        SeedU8x16::insecurely_random(),
    );
    let prover_secret_input = ProverSecretInput::new(
        SeedU8x16::insecurely_random(),
    );

    // prepare prover and verifier for all_in_one_vc
    let mut prover_in_all_in_one_vc = ProverInAllInOneVC::<GF2p8>::new(&public_parameter, &prover_secret_input, big_n);
    let mut verifier_in_all_in_one_vc = VerifierInAllInOneVC::<GF2p8>::new(&public_parameter, big_n);

    // prepare prover and verifier for protocol_svole
    let mut prover_in_protocol_svole = ProverInProtocolSVOLE::new(
        &mut prover_in_all_in_one_vc
    );
    let mut verifier_in_protocol_svole = VerifierInProtocolSVOLE::new(
        &mut verifier_in_all_in_one_vc
    );

    // initiate protocol_svole
    let mut protocol_svole = ProtocolSVOLE::new(
        &mut prover_in_protocol_svole, &mut verifier_in_protocol_svole
    );

    protocol_svole.run(&pub_aux, &master_seed);
}