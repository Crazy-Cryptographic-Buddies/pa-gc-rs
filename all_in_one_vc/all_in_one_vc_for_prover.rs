use blake3::Hash;
use crate::all_in_one_vc::{SeedU8x16, one_to_two_prg::OneToTwoPRG, generating_message_and_com_prg::GeneratingMessageAndComPRG, Message};

struct AllInOneVCForProver {
    tau: u8, // public
    big_n: u16, // public
    tree_len: u16, // public
    first_leaf_index: u16, // public
    one_to_two_prg: OneToTwoPRG, // public
    message_len: usize, // public
    tree: Option<Vec<SeedU8x16>>,
    message_vec: Option<Vec<Message>>,
    com_vec: Option<Vec<SeedU8x16>>,
    com_hash: Option<Hash>, // public
}

impl AllInOneVCForProver {
    pub fn new(tau: u8, master_key: &SeedU8x16, message_len: usize) -> AllInOneVCForProver {
        let big_n: u16 = 1 << tau;
        let tree_len: u16 = (big_n << 1) - 1;
        AllInOneVCForProver {
            tau,
            big_n,
            tree_len,
            first_leaf_index: tree_len - big_n,
            one_to_two_prg: OneToTwoPRG::new(master_key),
            message_len,
            tree: None,
            message_vec: None,
            com_vec: None,
            com_hash: None,
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

        // now generating messages and commitments
        let generating_message_and_com_prg = GeneratingMessageAndComPRG::new(&self.one_to_two_prg);
        let mut message_vec: Vec<Vec<u8>> = Vec::new();
        let mut com_vec: Vec<SeedU8x16> = Vec::new();
        for i in self.first_leaf_index..self.tree_len {
            let (message, com) = generating_message_and_com_prg.generate(self.tree[i], self.message_len);
            message_vec.push(message);
            com_vec.push(com);
        }
        self.message_vec = Some(message_vec);
        self.com_hash = Some(Self::hash_all_coms(&com_vec));
    }

    pub fn open(&self, excluded_index: u8) -> (SeedU8x16, Vec<SeedU8x16>) {
        let mut index_in_tree = self.first_leaf_index + excluded_index as u16;
        let returned_com = self.com_vec[excluded_index];
        let mut seed_trace: Vec<SeedU8x16> = Vec::new();
        for i in 0..self.tau {
            if (excluded_index >> i) & 1 == 1 {
                seed_trace.push(self.tree.as_ref().unwrap()[index_in_tree + 1]);
            } else {
                seed_trace.push(self.tree.as_ref().unwrap()[index_in_tree - 1]);
            }
            index_in_tree = (index_in_tree - 1) >> 1;
        }
        (returned_com, seed_trace)
    }

    fn hash_all_coms(com_vec: &Vec<SeedU8x16>) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for com in com_vec.iter() {
            hasher.update(com);
        }
        hasher.finalize()
    }
}
