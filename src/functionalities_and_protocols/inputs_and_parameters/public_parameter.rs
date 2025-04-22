use crate::value_type::seed_u8x16::SeedU8x16;

pub struct PublicParameter {
    pub tau: u8,
    pub master_key_for_one_to_two_prg: SeedU8x16,
}

impl PublicParameter {
    pub fn new(tau: u8, master_key_for_one_to_two_prg: SeedU8x16) -> Self {
        Self {
            tau,
            master_key_for_one_to_two_prg,
        }
    }
}