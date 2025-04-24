#[cfg(test)]
mod tests {
    use crate::functionalities_and_protocols::inputs_and_parameters::prover_secret_state::ProverSecretState;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::value_type::gf2p256::GF2p256;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::InsecureRandom;
    use crate::value_type::seed_u8x16::SeedU8x16;

    #[test]
    fn test_check_and_1() {
        let public_parameter = PublicParameter::new(
            8,
            10,
            SeedU8x16::insecurely_random(),
            20,
            30,
            40,
            41
        );
        let pa_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter, 
            SeedU8x16::insecurely_random()
        );
        let pb_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
            &public_parameter,
            SeedU8x16::insecurely_random()
        );
    }
}