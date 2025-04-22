use blake3::Hash;
use crate::cryptography::all_in_one_vc::generating_message_and_com_prg::GeneratingMessageAndComPRG;
use crate::cryptography::all_in_one_vc::hasher::hasher::Hasher;
use crate::cryptography::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::{
    bit_vec::BitVec,
    ZeroVec
};
use crate::vec_type::gf_vec::GFVec;

pub struct AllInOneVCForVerifier<GF: Clone + Zero> {
    tau: u8,
    one_to_two_prg: OneToTwoPRG,
    message_len: usize,
    nabla: Option<GF>,
    reconstructed_com_hash: Option<Hash>,
    voleith_key: Option<GFVec<GF>>,
}

impl<GF: Clone + Zero + U8ForGF + GFAdd> AllInOneVCForVerifier<GF> {
    pub fn new(tau: u8, master_key: &SeedU8x16, message_len: usize) -> Self {
        Self {
            tau,
            one_to_two_prg: OneToTwoPRG::new(master_key),
            message_len,
            nabla: None,
            reconstructed_com_hash: None,
            voleith_key: None,
        }
    }
    
    pub fn reconstruct(&mut self, nabla: &GF,
                       com_at_excluded_index: &SeedU8x16, seed_trace: &Vec<SeedU8x16>,
    ) {
        self.nabla = Some(nabla.clone());
        let generating_message_and_com_prg = GeneratingMessageAndComPRG::new(&self.one_to_two_prg);
        let mut coms_at_leaves: Vec<SeedU8x16> = vec![SeedU8x16::zero(); 1 << self.tau];
        let mut reconstructed_message_vec: Vec<BitVec> = vec![BitVec::zero_vec(self.message_len); 1 << self.tau];
        let excluded_index = self.nabla.as_ref().unwrap().get_u8() as usize;
        coms_at_leaves[excluded_index] = com_at_excluded_index.clone();
        for i in 0..self.tau {
            let sibling = {
                if (excluded_index >> i) & 1 == 1 {
                    (excluded_index >> i) - 1
                } else {
                    (excluded_index >> i) + 1
                }
            };
            let from_index = sibling << i;
            let subtree = self.one_to_two_prg.generate_tree(&seed_trace[i as usize], i);
            let mut index_in_subtree_leaves = (1 << i) - 1;
            for j in from_index..from_index + (1 << i) {
                let (message, com) = generating_message_and_com_prg.generate(&subtree[index_in_subtree_leaves], self.message_len);
                reconstructed_message_vec[j] = message;
                coms_at_leaves[j] = com;
                index_in_subtree_leaves += 1;
            }
        }
        self.reconstructed_com_hash = Some(Hasher::hash_all_coms(&coms_at_leaves));

        // now recover the key
        let mut voleith_key = GFVec::<GF>::zero_vec(self.message_len);
        for i in 0..1 << self.tau {
            if i != excluded_index {
                let i_shifted = self.nabla.as_ref().unwrap().gf_add(&GF::from_u8(i as u8));
                let message_i = &reconstructed_message_vec[i];
                for j in 0..self.message_len {
                    if message_i[j] == 1 {
                        voleith_key[j] = voleith_key[j].gf_add(&i_shifted);
                    }
                }
            }
        }
        self.voleith_key = Some(voleith_key);
    }
    
    pub fn get_reconstructed_com_hash(&self) -> &Hash {
        &self.reconstructed_com_hash.as_ref().unwrap()
    }
    
    pub fn get_voleith_key_for_testing(&self) -> &GFVec<GF> {
        if !cfg!(test) {
            panic!("This is not called during testing!");
        }
        &self.voleith_key.as_ref().unwrap()
    }
}