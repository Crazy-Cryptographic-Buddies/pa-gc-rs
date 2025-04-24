#[cfg(test)]
mod tests {
    use itertools::izip;
    use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
    use crate::functionalities_and_protocols::protocol_check_and::prover_in_protocol_check_and::ProverInProtocolCheckAND;
    use crate::functionalities_and_protocols::protocol_check_and::verifier_in_protocol_check_and::VerifierInProtocolCheckAND;
    use crate::functionalities_and_protocols::util::verifier::Verifier;
    use crate::value_type::gf2p8::GF2p8;
    use crate::value_type::{GFAddition, InsecureRandom};
    use crate::value_type::seed_u8x16::SeedU8x16;
    use crate::vec_type::bit_vec::BitVec;
    use crate::vec_type::gf_vec::GFVec;
    use crate::vec_type::VecAddition;

    fn generate_random_bit_vec(len: usize) -> BitVec {
        let mut bit_vec = BitVec::new();
        for _ in 0..len {
            bit_vec.push(rand::random::<u8>() & 1);
        }
        bit_vec
    }
    fn generate_random_bit_vec_rep(kappa: usize, len: usize) -> Vec<BitVec> {
        let mut bit_vec_rep = Vec::new();
        for _ in 0..kappa {
            bit_vec_rep.push(BitVec::new());
            for _ in 0..len {
                bit_vec_rep.last_mut().unwrap().push(rand::random::<u8>() & 1);
            }
        }
        bit_vec_rep
    }

    fn compute_voleith_key_vec(bit_vec: &BitVec, voleith_mac_vec: &GFVec<GF2p8>, nabla: &GF2p8) -> GFVec<GF2p8> {
        GFVec::<GF2p8>::from_vec(
            bit_vec.iter().zip(voleith_mac_vec.iter()).map(
                |(bit, voleith_mac)|
                    if *bit == 1 {
                        nabla.clone().gf_add(voleith_mac)
                    } else {
                        voleith_mac.clone()
                    }
            ).collect()
        )
    }

    fn generate_random_gf2p8_vec_rep(kappa: usize, len: usize) -> Vec<GFVec<GF2p8>> {
        let mut gf2p8_vec_rep = Vec::new();
        for _ in 0..kappa {
            gf2p8_vec_rep.push(GFVec::new());
            for _ in 0..len {
                gf2p8_vec_rep.last_mut().unwrap().push(GF2p8::insecurely_random());
            }
        }
        gf2p8_vec_rep
    }

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
        // let pa_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
        //     &public_parameter,
        //     SeedU8x16::insecurely_random()
        // );
        // let pb_secret_state = ProverSecretState::<GF2p256, GF2p8>::new(
        //     &public_parameter,
        //     SeedU8x16::insecurely_random()
        // );
        let mut rng = rand::rng();
        let nabla_a_rep = (0..public_parameter.kappa).into_iter().map(
            |_|GF2p8::insecurely_random()
        ).collect::<Vec<GF2p8>>();
        let nabla_b_rep = (0..public_parameter.kappa).into_iter().map(
            |_|GF2p8::insecurely_random()
        ).collect::<Vec<GF2p8>>();;

        // prepare random vectors for pa
        let pa_x_bit_vec = generate_random_bit_vec(public_parameter.big_w);
        let pa_voleith_mac_x_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_key_x_vec_rep = pa_voleith_mac_x_vec_rep.iter().zip(nabla_b_rep.iter()).map(
            |(voleith_mac_x_vec, nabla_b)|
                compute_voleith_key_vec(&pa_x_bit_vec, voleith_mac_x_vec, &nabla_b)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pa_x_bit_vec, &pa_voleith_mac_x_vec_rep[repetition_id], &nabla_b_rep[repetition_id],
                &pa_voleith_key_x_vec_rep[repetition_id],
            );
        }
        let pa_y_bit_vec = generate_random_bit_vec(public_parameter.big_w);
        let pa_voleith_mac_y_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_key_y_vec_rep = pa_voleith_mac_y_vec_rep.iter().zip(nabla_b_rep.iter()).map(
            |(voleith_mac_y_vec, nabla_b)|
                compute_voleith_key_vec(&pa_y_bit_vec, voleith_mac_y_vec, &nabla_b)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pa_y_bit_vec, &pa_voleith_mac_y_vec_rep[repetition_id], &nabla_b_rep[repetition_id],
                &pa_voleith_key_y_vec_rep[repetition_id],
            );
        }
        let pa_z_bit_vec = generate_random_bit_vec(public_parameter.big_w);
        let pa_voleith_mac_z_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_key_z_vec_rep = pa_voleith_mac_z_vec_rep.iter().zip(nabla_b_rep.iter()).map(
            |(voleith_mac_z_vec, nabla_b)|
                compute_voleith_key_vec(&pa_z_bit_vec, voleith_mac_z_vec, &nabla_b)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pa_z_bit_vec, &pa_voleith_mac_z_vec_rep[repetition_id], &nabla_b_rep[repetition_id],
                &pa_voleith_key_z_vec_rep[repetition_id],
            );
        }
        let pa_a_bit_vec_rep = generate_random_bit_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_mac_a_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_key_a_vec_rep = izip!(pa_a_bit_vec_rep.iter(), pa_voleith_mac_a_vec_rep.iter(), nabla_b_rep.iter()).map(
            |(a_bit_vec, voleith_mac_a_vec, nabla_b)|
                compute_voleith_key_vec(a_bit_vec, voleith_mac_a_vec, &nabla_b)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pa_a_bit_vec_rep[repetition_id], &pa_voleith_mac_a_vec_rep[repetition_id], &nabla_b_rep[repetition_id],
                &pa_voleith_key_a_vec_rep[repetition_id],
            );
        }
        let pa_b_bit_vec_rep = generate_random_bit_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_mac_b_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_key_b_vec_rep = izip!(pa_b_bit_vec_rep.iter(), pa_voleith_mac_b_vec_rep.iter(), nabla_b_rep.iter()).map(
            |(b_bit_vec, voleith_mac_b_vec, nabla_b)|
                compute_voleith_key_vec(b_bit_vec, voleith_mac_b_vec, &nabla_b)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pa_b_bit_vec_rep[repetition_id], &pa_voleith_mac_b_vec_rep[repetition_id], &nabla_b_rep[repetition_id],
                &pa_voleith_key_b_vec_rep[repetition_id],
            );
        }
        let pa_c_bit_vec_rep = generate_random_bit_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_mac_c_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pa_voleith_key_c_vec_rep = izip!(pa_c_bit_vec_rep.iter(), pa_voleith_mac_c_vec_rep.iter(), nabla_b_rep.iter()).map(
            |(c_bit_vec, voleith_mac_c_vec, nabla_b)|
                compute_voleith_key_vec(c_bit_vec, voleith_mac_c_vec, &nabla_b)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repitition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pa_c_bit_vec_rep[repitition_id], &pa_voleith_mac_c_vec_rep[repitition_id], &nabla_b_rep[repitition_id],
                &pa_voleith_key_c_vec_rep[repitition_id],
            );
        }

        // prepare random vectors for pb
        let pb_x_bit_vec = generate_random_bit_vec(public_parameter.big_w);
        let pb_voleith_mac_x_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_key_x_vec_rep = pb_voleith_mac_x_vec_rep.iter().zip(nabla_a_rep.iter()).map(
            |(voleith_mac_x_vec, nabla_a)|
                compute_voleith_key_vec(&pb_x_bit_vec, voleith_mac_x_vec, &nabla_a)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pb_x_bit_vec, &pb_voleith_mac_x_vec_rep[repetition_id], &nabla_a_rep[repetition_id],
                &pb_voleith_key_x_vec_rep[repetition_id],
            );
        }
        let pb_y_bit_vec = generate_random_bit_vec(public_parameter.big_w);
        let pb_voleith_mac_y_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_key_y_vec_rep = pb_voleith_mac_y_vec_rep.iter().zip(nabla_a_rep.iter()).map(
            |(voleith_mac_y_vec, nabla_a)|
                compute_voleith_key_vec(&pb_y_bit_vec, voleith_mac_y_vec, &nabla_a)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pb_y_bit_vec, &pb_voleith_mac_y_vec_rep[repetition_id], &nabla_a_rep[repetition_id],
                &pb_voleith_key_y_vec_rep[repetition_id],
            );
        }
        let pb_z_bit_vec = BitVec::from_vec(izip!(
            pa_x_bit_vec.iter(), pa_y_bit_vec.iter(), pa_z_bit_vec.iter(),
            pb_x_bit_vec.iter(), pb_y_bit_vec.iter()
        ).map(
            |(pa_x, pa_y, pa_z, pb_x, pb_y)|
                (pa_x ^ pb_x) & (pa_y ^ pb_y) ^ pa_z
        ).collect());
        let pb_voleith_mac_z_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_key_z_vec_rep = pb_voleith_mac_z_vec_rep.iter().zip(nabla_a_rep.iter()).map(
            |(voleith_mac_z_vec, nabla_a)|
                compute_voleith_key_vec(&pb_z_bit_vec, voleith_mac_z_vec, &nabla_a)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pb_z_bit_vec, &pb_voleith_mac_z_vec_rep[repetition_id], &nabla_a_rep[repetition_id],
                &pb_voleith_key_z_vec_rep[repetition_id],
            );
        }
        let pb_a_bit_vec_rep = generate_random_bit_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_mac_a_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_key_a_vec_rep = izip!(pb_a_bit_vec_rep.iter(), pb_voleith_mac_a_vec_rep.iter(), nabla_a_rep.iter()).map(
            |(a_bit_vec, voleith_mac_a_vec, nabla_a)|
                compute_voleith_key_vec(a_bit_vec, voleith_mac_a_vec, &nabla_a)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pb_a_bit_vec_rep[repetition_id], &pb_voleith_mac_a_vec_rep[repetition_id], &nabla_a_rep[repetition_id],
                &pb_voleith_key_a_vec_rep[repetition_id],
            );
        }
        let pb_b_bit_vec_rep = generate_random_bit_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_mac_b_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_key_b_vec_rep = izip!(pb_b_bit_vec_rep.iter(), pb_voleith_mac_b_vec_rep.iter(), nabla_a_rep.iter()).map(
            |(b_bit_vec, voleith_mac_b_vec, nabla_a)|
                compute_voleith_key_vec(b_bit_vec, voleith_mac_b_vec, &nabla_a)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pb_b_bit_vec_rep[repetition_id], &pb_voleith_mac_b_vec_rep[repetition_id], &nabla_a_rep[repetition_id],
                &pb_voleith_key_b_vec_rep[repetition_id],
            );
        }
        let pb_c_bit_vec_rep = izip!(
            pa_a_bit_vec_rep.iter(), pa_b_bit_vec_rep.iter(), pa_c_bit_vec_rep.iter(),
            pb_a_bit_vec_rep.iter(), pb_b_bit_vec_rep.iter()
        ).map(
            |(pa_a_vec, pa_b_vec, pa_c_vec, pb_a_vec, pb_b_vec)|
                BitVec::from_vec(
                    izip!(
                        pa_a_vec.iter(), pa_b_vec.iter(), pa_c_vec.iter(),
                        pb_a_vec.iter(), pb_b_vec.iter()
                    ).map(
                        |(pa_a, pa_b, pa_c, pb_a, pb_b)|
                            (pa_a ^ pb_a) & (pa_b ^ pb_b) ^ pa_c
                ).collect())
        ).collect::<Vec<BitVec>>();
        let pb_voleith_mac_c_vec_rep = generate_random_gf2p8_vec_rep(public_parameter.kappa, public_parameter.big_w);
        let pb_voleith_key_c_vec_rep = izip!(pb_c_bit_vec_rep.iter(), pb_voleith_mac_c_vec_rep.iter(), nabla_a_rep.iter()).map(
            |(c_bit_vec, voleith_mac_c_vec, nabla_a)|
                compute_voleith_key_vec(c_bit_vec, voleith_mac_c_vec, &nabla_a)
        ).collect::<Vec<GFVec<GF2p8>>>();
        for repetition_id in 0..public_parameter.kappa {
            Verifier::verify_voleith_correlations(
                &pb_c_bit_vec_rep[repetition_id], &pb_voleith_mac_c_vec_rep[repetition_id], &nabla_a_rep[repetition_id],
                &pb_voleith_key_c_vec_rep[repetition_id],
            );
        }

        // start testing correct multiplications
        for (pa_x_bit, pa_y_bit, pa_z_bit, pb_x_bit, pb_y_bit, pb_z_bit) in izip!(
            pa_x_bit_vec.iter(), pa_y_bit_vec.iter(), pa_z_bit_vec.iter(),
            pb_x_bit_vec.iter(), pb_y_bit_vec.iter(), pb_z_bit_vec.iter()
        ) {
            assert_eq!((pa_x_bit ^ pb_x_bit) & (pa_y_bit ^ pb_y_bit), pa_z_bit ^ pb_z_bit);
        }
        for (
            pa_a, pa_b, pa_c, pb_a, pb_b, pb_c
        ) in izip!(
            pa_a_bit_vec_rep.iter(), pa_b_bit_vec_rep.iter(), pa_c_bit_vec_rep.iter(),
            pb_a_bit_vec_rep.iter(), pb_b_bit_vec_rep.iter(), pb_c_bit_vec_rep.iter()
        ) {
            for (pa_a_bit, pa_b_bit, pa_c_bit, pb_a_bit, pb_b_bit, pb_c_bit) in izip!(
                pa_a.iter(), pa_b.iter(), pa_c.iter(), pb_a.iter(), pb_b.iter(), pb_c.iter()
            ) {
                assert_eq!((pa_a_bit ^ pb_a_bit) & (pa_b_bit ^ pb_b_bit), pa_c_bit ^ pb_c_bit);
            }
        }

        // start testing protocol checkAND
        let (
            (pa_d_bit_vec_rep, pa_voleith_mac_d_vec_rep),
            (pa_e_bit_vec_rep, pa_voleith_mac_e_vec_rep)
        ) = ProverInProtocolCheckAND::compute_masked_bits_and_voleith_macs(
            &public_parameter,
            &pa_x_bit_vec, &pa_voleith_mac_x_vec_rep,
            &pa_y_bit_vec, &pa_voleith_mac_y_vec_rep,
            &pa_a_bit_vec_rep, &pa_voleith_mac_a_vec_rep,
            &pa_b_bit_vec_rep, &pa_voleith_mac_b_vec_rep,
        );

        let (
            (pb_d_bit_vec_rep, pb_voleith_mac_d_vec_rep),
            (pb_e_bit_vec_rep, pb_voleith_mac_e_vec_rep)
        ) = ProverInProtocolCheckAND::compute_masked_bits_and_voleith_macs(
            &public_parameter,
            &pb_x_bit_vec, &pb_voleith_mac_x_vec_rep,
            &pb_y_bit_vec, &pb_voleith_mac_y_vec_rep,
            &pb_a_bit_vec_rep, &pb_voleith_mac_a_vec_rep,
            &pb_b_bit_vec_rep, &pb_voleith_mac_b_vec_rep,
        );

        let public_d_sum_bit_vec_rep = pa_d_bit_vec_rep.iter().zip(pb_d_bit_vec_rep.iter()).map(
            |(pa_d_bit_vec, pb_d_bit_vec)| pa_d_bit_vec.vec_add(pb_d_bit_vec)
        ).collect::<Vec<BitVec>>();

        let public_e_sum_bit_vec_rep = pa_e_bit_vec_rep.iter().zip(pb_e_bit_vec_rep.iter()).map(
            |(pa_e_bit_vec, pb_e_bit_vec)| pa_e_bit_vec.vec_add(pb_e_bit_vec)
        ).collect::<Vec<BitVec>>();

        let (pa_tilde_z_bit_vec_rep, pa_voleith_mac_tilde_z_vec_rep) = ProverInProtocolCheckAND::compute_masked_cross_bits_and_voleith_macs(
            &public_parameter,
            &public_d_sum_bit_vec_rep, &public_e_sum_bit_vec_rep,
            &pa_z_bit_vec, &pa_voleith_mac_z_vec_rep,
            &pa_a_bit_vec_rep, &pa_voleith_mac_a_vec_rep,
            &pa_b_bit_vec_rep, &pa_voleith_mac_b_vec_rep,
            &pa_c_bit_vec_rep, &pa_voleith_mac_c_vec_rep,
        );

        let (pb_tilde_z_bit_vec_rep, pb_voleith_mac_tilde_z_vec_rep) = ProverInProtocolCheckAND::compute_masked_cross_bits_and_voleith_macs(
            &public_parameter,
            &public_d_sum_bit_vec_rep, &public_e_sum_bit_vec_rep,
            &pb_z_bit_vec, &pb_voleith_mac_z_vec_rep,
            &pb_a_bit_vec_rep, &pb_voleith_mac_a_vec_rep,
            &pb_b_bit_vec_rep, &pb_voleith_mac_b_vec_rep,
            &pb_c_bit_vec_rep, &pb_voleith_mac_c_vec_rep,
        );

        VerifierInProtocolCheckAND::verify(
            &public_parameter,
            &(
                (pa_d_bit_vec_rep, pa_voleith_mac_d_vec_rep),
                (pa_e_bit_vec_rep, pa_voleith_mac_e_vec_rep),
                (pa_tilde_z_bit_vec_rep, pa_voleith_mac_tilde_z_vec_rep)
            ),
            &(
                (pb_d_bit_vec_rep, pb_voleith_mac_d_vec_rep),
                (pb_e_bit_vec_rep, pb_voleith_mac_e_vec_rep),
                (pb_tilde_z_bit_vec_rep, pb_voleith_mac_tilde_z_vec_rep)
            ),
            &public_d_sum_bit_vec_rep, &public_e_sum_bit_vec_rep,
            &nabla_a_rep, &nabla_b_rep,
            &(
                (pa_voleith_key_x_vec_rep, pa_voleith_key_y_vec_rep, pa_voleith_key_z_vec_rep),
                (pa_voleith_key_a_vec_rep, pa_voleith_key_b_vec_rep, pa_voleith_key_c_vec_rep)
            ),
            &(
                (pb_voleith_key_x_vec_rep, pb_voleith_key_y_vec_rep, pb_voleith_key_z_vec_rep),
                (pb_voleith_key_a_vec_rep, pb_voleith_key_b_vec_rep, pb_voleith_key_c_vec_rep)
            )
        );
    }
}