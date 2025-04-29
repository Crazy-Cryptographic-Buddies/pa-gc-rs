use std::time::Instant;
use blake3::Hash;
use rayon::iter::ParallelIterator;
use rayon::iter::IntoParallelIterator;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::functionalities_and_protocols::protocol_svole::verifier_in_protocol_svole::VerifierInProtocolSVOLE;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::{CustomAddition, CustomMultiplyingBit, U8ForGF, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::Split;
use crate::vec_type::VecAddition;

pub struct VerifierInProtocolSVOLE2PC;

impl VerifierInProtocolSVOLE2PC {
    
    fn distribute_bits_and_voleith_macs_to_state<GFVOLEitH: Clone + Zero + CustomMultiplyingBit + CustomAddition>(
        public_parameter: &PublicParameter,
        repetition_id: usize,
        nabla_rep: &Vec<GFVOLEitH>,
        public_voleith_key_vec: &mut GFVec<GFVOLEitH>,
        prover_masked_bit_tuple: &(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)
    ) -> (GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>) {
        let (
            hat_r_input_bit_vec,
            hat_r_output_bit_vec,
            hat_r_prime_bit_vec, 
            hat_a_bit_vec, 
            hat_b_bit_vec, 
            hat_c_bit_vec
        ) = prover_masked_bit_tuple;
        
        // then distribute the voleith macs
        let voleith_key_r_input_vec: GFVec<GFVOLEitH> = {
            let mut hat_r_input_bit_multiplying_nabla: GFVec<GFVOLEitH> = GFVec::new();
            for i in 0..public_parameter.num_input_bits {
                hat_r_input_bit_multiplying_nabla.push(nabla_rep[repetition_id].custom_multiply_bit(hat_r_input_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.num_input_bits
            ).vec_add(&hat_r_input_bit_multiplying_nabla)
        };
        
        let voleith_key_r_output_and_vec: GFVec<GFVOLEitH> = {
            let mut hat_r_output_and_bit_multiplying_nabla: GFVec<GFVOLEitH> = GFVec::new();
            for i in 0..public_parameter.big_iw_size {
                hat_r_output_and_bit_multiplying_nabla.push(nabla_rep[repetition_id].custom_multiply_bit(hat_r_output_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_iw_size
            ).vec_add(&hat_r_output_and_bit_multiplying_nabla)
        };

        let voleith_key_r_prime_vec: GFVec<GFVOLEitH> = {
            let mut hat_r_prime_bit_multiplying_nabla: GFVec<GFVOLEitH> = GFVec::new();
            for i in 0..public_parameter.big_iw_size {
                hat_r_prime_bit_multiplying_nabla.push(nabla_rep[repetition_id].custom_multiply_bit(hat_r_prime_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_iw_size
            ).vec_add(&hat_r_prime_bit_multiplying_nabla)
        };

        let voleith_key_tilde_a_vec: GFVec<GFVOLEitH> = {
            let mut hat_a_bit_multiplying_nabla: GFVec<GFVOLEitH> = GFVec::new();
            for i in 0..public_parameter.big_l {
                hat_a_bit_multiplying_nabla.push(nabla_rep[repetition_id].custom_multiply_bit(hat_a_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_l
            ).vec_add(&hat_a_bit_multiplying_nabla)
        };

        let voleith_key_tilde_b_vec: GFVec<GFVOLEitH> = {
            let mut hat_b_bit_multiplying_nabla: GFVec<GFVOLEitH> = GFVec::new();
            for i in 0..public_parameter.big_l {
                hat_b_bit_multiplying_nabla.push(nabla_rep[repetition_id].custom_multiply_bit(hat_b_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_l
            ).vec_add(&hat_b_bit_multiplying_nabla)
        };

        let voleith_key_tilde_c_vec: GFVec<GFVOLEitH> = {
            let mut hat_c_bit_multiplying_nabla: GFVec<GFVOLEitH> = GFVec::new();
            for i in 0..public_parameter.big_l {
                hat_c_bit_multiplying_nabla.push(nabla_rep[repetition_id].custom_multiply_bit(hat_c_bit_vec[i]));
            }
            public_voleith_key_vec.split_off(
                public_voleith_key_vec.len() - public_parameter.big_l
            ).vec_add(&hat_c_bit_multiplying_nabla)
        };
        
        assert_eq!(public_voleith_key_vec.len(), 0);

        (voleith_key_r_input_vec, voleith_key_r_output_and_vec, voleith_key_r_prime_vec, voleith_key_tilde_a_vec, voleith_key_tilde_b_vec, voleith_key_tilde_c_vec)
    }
    pub fn reconstruct_and_fix_voleith_key_vec<GFVOLEitH>(
        process_printing: bool,
        public_parameter: &PublicParameter, 
        prover_com_hash_rep: &Vec<Hash>,
        prover_masked_bit_tuple_rep: &Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
        nabla_rep: &Vec<GFVOLEitH>, 
        decom_rep: &Vec<(SeedU8x16, Vec<SeedU8x16>)>
    ) -> Vec<(GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>, GFVec<GFVOLEitH>)>
    where GFVOLEitH: Clone + Zero + CustomAddition + U8ForGF + CustomMultiplyingBit + Send + Sync {
        let mut voleith_key_tuple_rep = vec![(GFVec::<GFVOLEitH>::new(), GFVec::<GFVOLEitH>::new(), GFVec::<GFVOLEitH>::new(), GFVec::<GFVOLEitH>::new(), GFVec::<GFVOLEitH>::new(), GFVec::<GFVOLEitH>::new()); public_parameter.kappa];
        let mut public_voleith_key_vec_rep = vec![GFVec::<GFVOLEitH>::new(); public_parameter.kappa];

        if process_printing {
            println!("  Verifier reconstructs");
        }
        let start_reconstructing = Instant::now();
        (&mut public_voleith_key_vec_rep, prover_com_hash_rep, nabla_rep, decom_rep).into_par_iter().for_each(
            |(public_voleith_key_vec, prover_com_hash, nabla, decom)| {
                *public_voleith_key_vec = VerifierInProtocolSVOLE::reconstruct(
                    public_parameter,
                    &prover_com_hash,
                    &nabla,
                    &decom
                );
            }
        );
        if process_printing {
            println!("  Time elapsed: {:?}", start_reconstructing.elapsed());
        }

        if process_printing {
            println!("  Distribute VOLEitH keys after reconstructing into corresponding components");
        }
        for repetition_id in 0..public_parameter.kappa {
            voleith_key_tuple_rep[repetition_id] = Self::distribute_bits_and_voleith_macs_to_state(
                public_parameter,
                repetition_id,
                &nabla_rep,
                &mut public_voleith_key_vec_rep[repetition_id],
                &prover_masked_bit_tuple_rep[repetition_id]
            );
        }
        voleith_key_tuple_rep
    }
}