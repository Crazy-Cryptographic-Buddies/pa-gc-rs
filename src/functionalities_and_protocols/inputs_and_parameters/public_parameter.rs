use crate::functionalities_and_protocols::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
use crate::value_type::seed_u8x16::SeedU8x16;

pub struct PublicParameter {
    pub tau: u8,
    pub kappa: usize,
    pub one_to_two_prg: OneToTwoPRG,
    pub big_ia_size: usize,
    pub big_ib_size: usize,
    pub big_w: usize,
    pub big_l: usize,
    pub big_n: usize,
    pub num_input_bits: usize,
    pub big_ia: Vec<usize>,
    pub big_ib: Vec<usize>,
}

impl PublicParameter {
    pub fn new(
        tau: u8, kappa: usize, master_key_for_one_to_two_prg: SeedU8x16, 
        big_ia_size: usize, big_ib_size: usize, big_w: usize, big_l: usize,
        big_ia: Vec<usize>, big_ib: Vec<usize>,
    ) -> Self {
        Self {
            tau,
            kappa,
            one_to_two_prg: OneToTwoPRG::new(&master_key_for_one_to_two_prg),
            big_ia_size,
            big_ib_size,
            big_w,
            big_l,
            big_n: big_ia_size + big_ib_size + 2 * big_w + 3 * big_l,
            num_input_bits: big_ia_size + big_ib_size,
            big_ia,
            big_ib,       
        }
    }
}