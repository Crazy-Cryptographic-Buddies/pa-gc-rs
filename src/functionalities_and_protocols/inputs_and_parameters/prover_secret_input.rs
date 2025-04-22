use crate::value_type::seed_u8x16::SeedU8x16;

pub struct ProverSecretInput {
    pub seed_for_generating_ggm_tree: SeedU8x16
}

impl ProverSecretInput {
    pub fn new(seed_for_generating_ggm_tree: SeedU8x16) -> Self {
        Self {
            seed_for_generating_ggm_tree
        }
    }
}