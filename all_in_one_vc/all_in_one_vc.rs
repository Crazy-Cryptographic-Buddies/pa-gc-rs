use crate::all_in_one_vc::{
    SeedU8x16,
    one_to_two_prg::OneToTwoPRG,
};

struct AllInOneVC {
    tau: u8,
    big_n: u16,
    tree_len: u16,
    first_leaf_index: u16,
    one_to_two_prg: OneToTwoPRG,
    tree: Option<Vec<SeedU8x16>>,
}

impl AllInOneVC {
    pub fn new(tau: u8, master_seed: &SeedU8x16) -> AllInOneVC {
        let big_n: u16 = 1 << tau;
        let tree_len: u16 = (big_n << 1) - 1;
        AllInOneVC {
            tau,
            big_n,
            tree_len,
            first_leaf_index: tree_len - big_n,
            one_to_two_prg: OneToTwoPRG::new(master_seed),
            tree: None,
        }
    }

    pub fn commit(&mut self, seed: &SeedU8x16) {
        let mut tree: Vec<SeedU8x16> = Vec::new();
        tree.push(seed.clone());
        for i in 0..self.first_leaf_index {
            let (seed0, seed1) = self.one_to_two_prg
                .generate_double(&tree[i as usize]);
            tree.push(seed0);
            tree.push(seed1);
        }
        self.tree = Some(tree);
        assert_eq!(self.tree.as_ref().unwrap().len(), self.tree_len as usize);
    }
}
