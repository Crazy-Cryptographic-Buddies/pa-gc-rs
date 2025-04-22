use blake3::Hash;
use crate::cryptography::all_in_one_vc::generating_message_and_com_prg::GeneratingMessageAndComPRG;
use crate::cryptography::all_in_one_vc::hasher::hasher::Hasher;
use crate::cryptography::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
use crate::enforce_testing;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::{
    bit_vec::BitVec,
    ZeroVec,
    gf_vec::GFVec
};

pub struct ProverInAllInOneVC<GF: Clone + Zero> {
    tau: u8, // public
    tree_len: usize, // public
    first_leaf_index: usize, // public
    one_to_two_prg: OneToTwoPRG, // public
    message_len: usize, // public
    tree: Option<Vec<SeedU8x16>>,
    com_vec: Option<Vec<SeedU8x16>>, // private, can be public but better need verifier to reconstruct
    com_hash: Option<Hash>, // public
    message: Option<BitVec>, // unified message after computing from the leaves of the tree
    voleith_mac: Option<GFVec<GF>>, // unified mac tag after computing from the leaves of the tree
}

impl<GF: Clone + Zero + GFAdd + U8ForGF> ProverInAllInOneVC<GF> {
    pub fn new(tau: u8, master_key: &SeedU8x16, message_len: usize) -> ProverInAllInOneVC<GF> {
        let big_n: usize = 1 << tau;
        let tree_len: usize = (big_n << 1) - 1;
        ProverInAllInOneVC {
            tau,
            tree_len,
            first_leaf_index: (1 << tau) - 1,
            one_to_two_prg: OneToTwoPRG::new(master_key),
            message_len,
            tree: None,
            com_vec: None,
            com_hash: None,
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
        let mut message_vec: Vec<BitVec> = Vec::new();
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
        let mut message = BitVec::zero_vec(self.message_len);
        let mut voleith_mac = GFVec::<GF>::zero_vec(self.message_len);
        for i in 0..1 << self.tau {
            let i_gf = GF::from_u8(i as u8);
            let message_i = &message_vec[i];
            for j in 0..self.message_len {
                message[j] ^= message_i[j];
                if message_i[j] == 1 {
                    voleith_mac[j] = voleith_mac[j].gf_add(&i_gf);
                }        
            }
        }
        self.message = Some(message);
        self.voleith_mac = Some(voleith_mac);       
    }

    pub fn open(&self, nabla: &GF) -> (SeedU8x16, Vec<SeedU8x16>) {
        // the excluded index must be in [0, 2^8]
        // this can be understood the index among the leaves, i.e., the excluded_index-th leaf
        let excluded_index = nabla.get_u8() as usize;
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
    
    pub fn get_message_for_testing(&self) -> &BitVec {
        enforce_testing();
        self.message.as_ref().unwrap()
    }
    
    pub fn get_voleith_mac_for_testing(&self) -> &GFVec<GF> {
        enforce_testing();
        self.voleith_mac.as_ref().unwrap()
    }
}
