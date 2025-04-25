use crate::functionalities_and_protocols::all_in_one_vc::prover_in_all_in_one_vc::ProverInAllInOneVC;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

pub struct ProverSecretState<GFVOLE, GFVOLEitH> {
    pub delta: Option<GFVOLE>,
    
    pub seed_for_generating_ggm_tree_rep: Vec<SeedU8x16>,
    pub r_bit_vec: Option<BitVec>,
    pub r_prime_bit_vec: Option<BitVec>,
    pub tilde_a_bit_vec_rep: Option<Vec<BitVec>>,
    pub tilde_b_bit_vec_rep: Option<Vec<BitVec>>,
    pub tilde_c_bit_vec_rep: Option<Vec<BitVec>>,
    
    // vole macs
    pub vole_mac_r_vec_rep: Option<GFVec<GFVOLE>>,
    pub vole_mac_r_prime_vec_rep: Option<GFVec<GFVOLE>>,

    // voleith macs
    pub voleith_mac_r_vec_rep: Vec<Option<GFVec<GFVOLEitH>>>,
    pub voleith_mac_r_prime_vec_rep: Vec<Option<GFVec<GFVOLEitH>>>,
    pub voleith_mac_tilde_a_vec_rep: Vec<Option<GFVec<GFVOLEitH>>>,
    pub voleith_mac_tilde_b_vec_rep: Vec<Option<GFVec<GFVOLEitH>>>,
    pub voleith_mac_tilde_c_vec_rep: Vec<Option<GFVec<GFVOLEitH>>>,

    // random bits from PisVOLE
    pub prover_in_all_in_one_vc_rep: Vec<ProverInAllInOneVC>,
    // pub bar_r_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_r_prime_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_a_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_b_bit_vec_rep: Vec<Option<BitVec>>,
    // pub bar_c_bit_vec_rep: Vec<Option<BitVec>>,
}

impl<GFVOLE, GFVOLEitH: Clone> ProverSecretState<GFVOLE, GFVOLEitH> {
    pub fn new(public_parameter: &PublicParameter, master_seed_for_generating_ggm_tree: SeedU8x16) -> Self {
        let mut seed_for_generating_ggm_tree_rep: Vec<SeedU8x16> = Vec::new();
        let mut prover_in_all_in_one_vc_rep: Vec<ProverInAllInOneVC> = Vec::new();
        let mut current_seed = master_seed_for_generating_ggm_tree;
        for _ in 0..public_parameter.kappa {
            let (seed0, seed1) = public_parameter.one_to_two_prg.generate_double(&current_seed);
            seed_for_generating_ggm_tree_rep.push(seed0);
            current_seed = seed1;
            prover_in_all_in_one_vc_rep.push(ProverInAllInOneVC::new(&public_parameter));
        }
        Self {
            delta: None,
            
            seed_for_generating_ggm_tree_rep,
            r_bit_vec: None,
            r_prime_bit_vec: None,
            tilde_a_bit_vec_rep: None,
            tilde_b_bit_vec_rep: None,
            tilde_c_bit_vec_rep: None,
            
            vole_mac_r_vec_rep: None,
            vole_mac_r_prime_vec_rep: None,

            voleith_mac_r_vec_rep: vec![None; public_parameter.kappa],
            voleith_mac_r_prime_vec_rep: vec![None; public_parameter.kappa],
            voleith_mac_tilde_a_vec_rep: vec![None; public_parameter.kappa],
            voleith_mac_tilde_b_vec_rep: vec![None; public_parameter.kappa],
            voleith_mac_tilde_c_vec_rep: vec![None; public_parameter.kappa],

            prover_in_all_in_one_vc_rep,
            // bar_r_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_r_prime_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_a_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_b_bit_vec_rep: vec![None; public_parameter.kappa],
            // bar_c_bit_vec_rep: vec![None; public_parameter.kappa],
        }
    }
}