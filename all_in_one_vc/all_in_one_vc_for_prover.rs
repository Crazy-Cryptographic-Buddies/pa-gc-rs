use blake3::Hash;
use crate::all_in_one_vc::{
    one_to_two_prg::OneToTwoPRG,
    generating_message_and_com_prg::GeneratingMessageAndComPRG
};
use crate::comm_types_and_constants::{
    SeedU8x16,
    Message,
    VOLEitHMACTag
};
use crate::all_in_one_vc::hasher::hasher::Hasher;
use galois_2p8::{
    Field,
    GeneralField
};

pub struct AllInOneVCForProver {
    tau: u8, // public
    tree_len: usize, // public
    pub first_leaf_index: usize, // public
    one_to_two_prg: OneToTwoPRG, // public
    message_len: usize, // public
    tree: Option<Vec<SeedU8x16>>,
    com_vec: Option<Vec<SeedU8x16>>, // private, can be public but better need verifier to reconstruct
    com_hash: Option<Hash>, // public
    galois_field: GeneralField,
    message: Option<Message>, // unified message after computing from the leaves of the tree
    voleith_mac: Option<VOLEitHMACTag>, // unified mac tag after computing from the leaves of the tree
}

impl AllInOneVCForProver {
    pub fn new(tau: u8, master_key: &SeedU8x16, message_len: usize) -> AllInOneVCForProver {
        let big_n: usize = 1 << tau;
        let tree_len: usize = (big_n << 1) - 1;
        AllInOneVCForProver {
            tau,
            tree_len,
            first_leaf_index: (1 << tau) - 1,
            one_to_two_prg: OneToTwoPRG::new(master_key),
            message_len,
            tree: None,
            com_vec: None,
            com_hash: None,
            galois_field: GeneralField::new(
                galois_2p8::IrreducablePolynomial::Poly84310
            ),
            message: None,
            voleith_mac: None,       
        }
    }

    pub fn commit(&mut self, seed: &SeedU8x16) {
        let tree: Vec<SeedU8x16> = self.one_to_two_prg.generate_tree(seed, self.tau);
        self.tree = Some(tree);
        assert_eq!(self.tree.as_ref().unwrap().len(), self.tree_len);

        // now generating messages and commitments
        let generating_message_and_com_prg = GeneratingMessageAndComPRG::new(&self.one_to_two_prg);
        let mut message_vec: Vec<Vec<u8>> = Vec::new();
        let mut com_vec: Vec<SeedU8x16> = Vec::new();
        for i in self.first_leaf_index..self.tree_len {
            let (message, com) = generating_message_and_com_prg.generate(
                &self.tree.as_ref().unwrap()[i],
                self.message_len
            );
            message_vec.push(message);
            com_vec.push(com);
        }
        assert_eq!(message_vec.len(), 1 << self.tau);
        self.com_vec = Some(com_vec);
        self.com_hash = Some(Hasher::hash_all_coms(&self.com_vec.as_ref().unwrap()));
        
        // compute message and mac tag
        let mut message: Message = vec![0; self.message_len];
        let mut voleith_mac: VOLEitHMACTag = vec![0; self.message_len];
        for i in 0..1 << self.tau {
            let iu8 = i as u8;
            let message_i = &message_vec[i];
            for j in 0..self.message_len {
                message[j] ^= message_i[j];
                if message_i[j] == 1 {
                    voleith_mac[j] = self.galois_field.add(voleith_mac[j], iu8);
                }        
            }
        }
        self.message = Some(message);
        self.voleith_mac = Some(voleith_mac);       
    }

    pub fn open(&self, excluded_index: usize) -> (SeedU8x16, Vec<SeedU8x16>) {
        // the excluded index must be in [0, 2^8]
        // this can be understood the index among the leaves, i.e., the excluded_index-th leaf
        assert!(excluded_index < 1 << 8);
        let mut index_in_tree = self.first_leaf_index + excluded_index;
        let com_at_excluded_index = self.com_vec.as_ref().unwrap()[excluded_index];
        let mut seed_trace: Vec<SeedU8x16> = Vec::new();
        for i in 0..self.tau {
            if (excluded_index >> i) & 1 == 1 {
                seed_trace.push(self.tree.as_ref().unwrap()[index_in_tree - 1]);
            } else {
                seed_trace.push(self.tree.as_ref().unwrap()[index_in_tree + 1]);
            }
            index_in_tree = (index_in_tree - 1) >> 1;
        }
        (com_at_excluded_index, seed_trace)
    }
    
    pub fn get_com_hash(&self) -> &Hash {
        self.com_hash.as_ref().unwrap()
    }
    
    pub fn get_message_for_testing(&self) -> &Message {
        if !cfg!(test) {
            panic!("This is not called during testing!");
        }
        self.message.as_ref().unwrap()
    }
    
    pub fn get_voleith_mac_for_testing(&self) -> &VOLEitHMACTag {
        if !cfg!(test) {
            panic!("This is not called during testing!");
        }
        self.voleith_mac.as_ref().unwrap()
    }
}
