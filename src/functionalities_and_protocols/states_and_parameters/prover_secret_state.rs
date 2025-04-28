use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::Zero;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::{BasicVecFunctions, ZeroVec};

pub struct ProverSecretState<GFVOLE, GFVOLEitH> {
    pub delta: Option<GFVOLE>,
    
    pub seed_for_generating_ggm_tree_rep: Vec<SeedU8x16>,
    pub seed_for_commitment_randomness: SeedU8x16,
    pub r_input_bit_vec: BitVec,
    pub r_output_and_bit_vec: BitVec,
    pub r_prime_left_bit_vec: BitVec,
    pub r_prime_right_bit_vec: BitVec,
    pub r_prime_bit_vec: BitVec,
    pub r_trace_bit_vec: BitVec,
    pub middle_r_and_output_bit_vec: Vec<[u8; 4]>,
    pub tilde_a_bit_vec_rep: Vec<BitVec>,
    pub tilde_b_bit_vec_rep: Vec<BitVec>,
    pub tilde_c_bit_vec_rep: Vec<BitVec>,

    // label_zero
    pub label_zero_vec: Option<GFVec<GFVOLE>>,

    // vole macs
    pub vole_mac_r_input_vec: GFVec<GFVOLE>,
    pub vole_mac_r_output_and_vec: GFVec<GFVOLE>,
    pub vole_mac_r_prime_vec: GFVec<GFVOLE>,
    pub vole_mac_r_trace_vec: GFVec<GFVOLE>,
    pub middle_vole_mac_r_and_output_vec: Vec<[GFVOLE; 4]>,
    
    // vole keys
    pub other_vole_key_r_input_vec: GFVec<GFVOLE>,
    pub other_vole_key_r_output_and_vec: GFVec<GFVOLE>,
    pub other_vole_key_r_prime_vec: GFVec<GFVOLE>,
    pub other_vole_key_r_trace_vec: GFVec<GFVOLE>,
    pub other_middle_vole_key_r_and_output_vec: Vec<[GFVOLE; 4]>,

    // voleith macs
    pub voleith_mac_r_input_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_r_output_and_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_r_prime_left_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_r_prime_right_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_r_prime_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_r_trace_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_tilde_a_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_tilde_b_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_tilde_c_vec_rep: Vec<GFVec<GFVOLEitH>>,

    pub middle_voleith_mac_r_and_output_vec_rep: Vec<Vec<[GFVOLEitH; 4]>>,

    // commitment randomness
    pub commitment_randomness_vec_rep: Option<Vec<[SeedU8x16; 4]>>,

    // random bits from PisVOLE
    pub prover_in_all_in_one_vc_rep: Vec<ProverInAllInOneVC>,
    // pub bar_r_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_r_prime_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_a_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_b_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_c_bit_vec_rep: Vec<Option<BitVec>>,
}

impl<GFVOLE, GFVOLEitH> ProverSecretState<GFVOLE, GFVOLEitH>
where GFVOLE: Clone + Zero + Copy, GFVOLEitH: Clone + Zero + Copy {
    pub fn new(
        public_parameter: &PublicParameter,
        master_seed: SeedU8x16,
        is_pa: bool,
    ) -> Self {
        let mut seed_for_generating_ggm_tree_rep =  vec![SeedU8x16::zero(); public_parameter.kappa];
        let mut prover_in_all_in_one_vc_rep = (0..public_parameter.kappa).map(
            |_| ProverInAllInOneVC::new(&public_parameter)
        ).collect();
        let mut current_seed = master_seed;
        // println!("kappa: {:?}", public_parameter.kappa);
        for repetition_id in 0..public_parameter.kappa {
            let (seed0, seed1) = public_parameter.one_to_two_prg.generate_double(&current_seed);
            // println!("(seed0, seed1): {:?}", (seed0, seed1));
            seed_for_generating_ggm_tree_rep[repetition_id] = seed0;
            // println!("seed0: {:?}", seed0);
            current_seed = seed1;
        }
        // println!("seed_for_generating_ggm_tree_rep: {:?}", seed_for_generating_ggm_tree_rep);
        // println!("current_seed: {:?}", current_seed);
        Self {
            delta: None,
            
            seed_for_generating_ggm_tree_rep,
            seed_for_commitment_randomness: current_seed,
            r_input_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.num_input_bits]),
            r_output_and_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.big_iw_size]),
            r_prime_left_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.big_iw_size]),
            r_prime_right_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.big_iw_size]),
            r_prime_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.big_iw_size]),
            r_trace_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.num_wires]),
            middle_r_and_output_bit_vec: vec![[0u8; 4]; public_parameter.big_iw_size],
            tilde_a_bit_vec_rep: vec![BitVec::from_vec(vec![0u8; public_parameter.big_l]); public_parameter.kappa],
            tilde_b_bit_vec_rep: vec![BitVec::from_vec(vec![0u8; public_parameter.big_l]); public_parameter.kappa],
            tilde_c_bit_vec_rep: vec![BitVec::from_vec(vec![0u8; public_parameter.big_l]); public_parameter.kappa],

            label_zero_vec: { 
                if is_pa {
                    Some(GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires))
                } else {
                    None
                }
            },
            vole_mac_r_input_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.num_input_bits),
            vole_mac_r_output_and_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            vole_mac_r_prime_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            vole_mac_r_trace_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires),
            middle_vole_mac_r_and_output_vec: vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size],

            other_vole_key_r_input_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.num_input_bits),
            other_vole_key_r_output_and_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            other_vole_key_r_prime_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            other_vole_key_r_trace_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.num_wires),
            other_middle_vole_key_r_and_output_vec: vec![[GFVOLE::zero(); 4]; public_parameter.big_iw_size],

            voleith_mac_r_input_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_r_output_and_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_r_prime_left_vec_rep: vec![GFVec::zero_vec(public_parameter.big_iw_size); public_parameter.kappa],
            voleith_mac_r_prime_right_vec_rep: vec![GFVec::zero_vec(public_parameter.big_iw_size); public_parameter.kappa],
            voleith_mac_r_prime_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_r_trace_vec_rep: vec![GFVec::zero_vec(public_parameter.num_wires); public_parameter.kappa],
            voleith_mac_tilde_a_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_tilde_b_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_tilde_c_vec_rep: vec![GFVec::new(); public_parameter.kappa],

            middle_voleith_mac_r_and_output_vec_rep: vec![vec![[GFVOLEitH::zero(); 4]; public_parameter.big_iw_size]; public_parameter.kappa],
            commitment_randomness_vec_rep: {
                if is_pa {
                    None
                } else {
                    Some(vec![[SeedU8x16::zero(); 4]; public_parameter.big_iw_size])
                }
            },
            prover_in_all_in_one_vc_rep,
            // bar_r_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_r_prime_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_a_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_b_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_c_bit_vec_rep: vec![None; public_parameter.kappa],
        }
    }
}