use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::Zero;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::ZeroVec;

pub struct ProverSecretState<GFVOLE, GFVOLEitH> {
    pub delta: Option<GFVOLE>,
    
    pub seed_for_generating_ggm_tree_rep: Vec<SeedU8x16>,
    pub r_input_bit_vec: BitVec,
    pub r_output_and_bit_vec: BitVec,
    pub r_prime_bit_vec: BitVec,
    pub tilde_a_bit_vec_rep: Vec<BitVec>,
    pub tilde_b_bit_vec_rep: Vec<BitVec>,
    pub tilde_c_bit_vec_rep: Vec<BitVec>,
    
    // vole macs
    pub vole_mac_r_input_vec: GFVec<GFVOLE>,
    pub vole_mac_r_output_and_vec: GFVec<GFVOLE>,
    pub vole_mac_r_prime_vec: GFVec<GFVOLE>,
    
    // vole keys
    pub other_vole_key_r_input_vec: GFVec<GFVOLE>,
    pub other_vole_key_r_output_and_vec: GFVec<GFVOLE>,
    pub other_vole_key_r_prime_vec: GFVec<GFVOLE>,

    // voleith macs
    pub voleith_mac_r_input_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_r_output_and_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_r_prime_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_tilde_a_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_tilde_b_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub voleith_mac_tilde_c_vec_rep: Vec<GFVec<GFVOLEitH>>,

    // random bits from PisVOLE
    pub prover_in_all_in_one_vc_rep: Vec<ProverInAllInOneVC>,
    // pub bar_r_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_r_prime_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_a_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_b_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_c_bit_vec_rep: Vec<Option<BitVec>>,
}

impl<GFVOLE, GFVOLEitH> ProverSecretState<GFVOLE, GFVOLEitH>
where GFVOLE: Clone + Zero, GFVOLEitH: Clone + Zero {
    pub fn new(
        public_parameter: &PublicParameter, 
        master_seed_for_generating_ggm_tree: SeedU8x16,
    ) -> Self {
        let mut seed_for_generating_ggm_tree_rep =  vec![SeedU8x16::zero(); public_parameter.kappa];
        let mut prover_in_all_in_one_vc_rep = (0..public_parameter.kappa).map(
            |_| ProverInAllInOneVC::new(&public_parameter)
        ).collect();
        let mut current_seed = master_seed_for_generating_ggm_tree;
        for _ in 0..public_parameter.kappa {
            let (seed0, seed1) = public_parameter.one_to_two_prg.generate_double(&current_seed);
            seed_for_generating_ggm_tree_rep.push(seed0);
            current_seed = seed1;
        }
        Self {
            delta: None,
            
            seed_for_generating_ggm_tree_rep,
            r_input_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.num_input_bits]),
            r_output_and_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.big_iw_size]),
            r_prime_bit_vec: BitVec::from_vec(vec![0u8; public_parameter.big_iw_size]),
            tilde_a_bit_vec_rep: vec![BitVec::from_vec(vec![0u8; public_parameter.big_l]); public_parameter.kappa],
            tilde_b_bit_vec_rep: vec![BitVec::from_vec(vec![0u8; public_parameter.big_l]); public_parameter.kappa],
            tilde_c_bit_vec_rep: vec![BitVec::from_vec(vec![0u8; public_parameter.big_l]); public_parameter.kappa],
            
            vole_mac_r_input_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.num_input_bits),
            vole_mac_r_output_and_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            vole_mac_r_prime_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            
            other_vole_key_r_input_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.num_input_bits),
            other_vole_key_r_output_and_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            other_vole_key_r_prime_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),           

            voleith_mac_r_input_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_r_output_and_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_r_prime_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_tilde_a_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_tilde_b_vec_rep: vec![GFVec::new(); public_parameter.kappa],
            voleith_mac_tilde_c_vec_rep: vec![GFVec::new(); public_parameter.kappa],

            prover_in_all_in_one_vc_rep,
            // bar_r_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_r_prime_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_a_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_b_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_c_bit_vec_rep: vec![None; public_parameter.kappa],
        }
    }
}