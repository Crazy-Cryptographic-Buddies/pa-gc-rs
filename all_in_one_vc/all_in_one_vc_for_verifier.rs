use crate::all_in_one_vc::{one_to_two_prg::OneToTwoPRG, hasher::hasher::Hasher};
use crate::comm_types_and_constants::{SeedU8x16, Zero};
use blake3::Hash;

struct AllInOneVCForVerifier {
    tau: u8,
    one_to_two_prg: OneToTwoPRG
}

impl AllInOneVCForVerifier {
    pub fn new(tau: u8, master_key: &SeedU8x16) -> Self {
        Self {
            tau,
            one_to_two_prg: OneToTwoPRG::new(master_key)
        }
    }
    
    pub fn reconstruct(&self, excluded_index: usize, 
                       com_at_excluded_index: &SeedU8x16, seed_trace: &Vec<SeedU8x16>,
                       com_hash_from_prover: &Hash,
    ) {
        let mut coms_at_leaves: Vec<SeedU8x16> = vec![SeedU8x16::zero(); 1 << self.tau];
        coms_at_leaves[excluded_index] = com_at_excluded_index.clone();
        for i in 0..self.tau {
            let sibling;
            if (excluded_index >> i) & 1 == 1 {
                sibling = (excluded_index >> i) - 1;
            } else {
                sibling = (excluded_index >> i) + 1;
            }
            let from_index = sibling << i;
            let to_index = !((!sibling) << i) + 1;
            assert_eq!(to_index - from_index + 1, 1 << i);
            let subtree = self.one_to_two_prg.generate_tree(&seed_trace[i as usize], i);
            let first_leaf_index_in_subtree = (1 << i) - 1;
            for j in from_index..to_index {
                coms_at_leaves[j] = subtree[j - first_leaf_index_in_subtree];
            }
        }
        let reconstructed_com_hash = Hasher::hash_all_coms(&coms_at_leaves);
        assert_eq!(reconstructed_com_hash, *com_hash_from_prover);
    }
}