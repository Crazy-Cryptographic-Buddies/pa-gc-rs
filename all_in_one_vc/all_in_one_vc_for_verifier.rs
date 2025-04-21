use crate::all_in_one_vc::{one_to_two_prg::OneToTwoPRG, hasher::hasher::Hasher};
use crate::comm_types_and_constants::{Message, SeedU8x16, VOLEitHMACKey, Zero};
use blake3::Hash;
use galois_2p8::{Field, GeneralField};
use crate::all_in_one_vc::generating_message_and_com_prg::GeneratingMessageAndComPRG;

pub struct AllInOneVCForVerifier {
    tau: u8,
    one_to_two_prg: OneToTwoPRG,
    message_len: usize,
    nabla: Option<u8>,
    reconstructed_com_hash: Option<Hash>,
    galois_field: GeneralField,
    voleith_key: Option<VOLEitHMACKey>,
}

impl AllInOneVCForVerifier {
    pub fn new(tau: u8, master_key: &SeedU8x16, message_len: usize) -> Self {
        Self {
            tau,
            one_to_two_prg: OneToTwoPRG::new(master_key),
            message_len,
            nabla: None,
            reconstructed_com_hash: None,
            galois_field: GeneralField::new(
                galois_2p8::IrreducablePolynomial::Poly84310
            ),
            voleith_key: None,
        }
    }
    
    pub fn reconstruct(&mut self, nabla: u8,
                       com_at_excluded_index: &SeedU8x16, seed_trace: &Vec<SeedU8x16>,
    ) {
        self.nabla = Some(nabla);
        let generating_message_and_com_prg = GeneratingMessageAndComPRG::new(&self.one_to_two_prg);
        let mut coms_at_leaves: Vec<SeedU8x16> = vec![SeedU8x16::zero(); 1 << self.tau];
        let mut reconstructed_message_vec: Vec<Message> = vec![Vec::new(); 1 << self.tau];
        let excluded_index = nabla as usize;
        coms_at_leaves[excluded_index] = com_at_excluded_index.clone();
        for i in 0..self.tau {
            let sibling;
            if (excluded_index >> i) & 1 == 1 {
                sibling = (excluded_index >> i) - 1;
            } else {
                sibling = (excluded_index >> i) + 1;
            }
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
        let mut voleith_key = vec![0; self.message_len];
        for i in 0..1 << self.tau {
            if i != excluded_index {
                let i_shifted = self.galois_field.add(i as u8, self.nabla.unwrap());
                let message_i = &reconstructed_message_vec[i];
                for j in 0..self.message_len {
                    if message_i[j] == 1 {
                        voleith_key[j] = self.galois_field.add(voleith_key[j], i_shifted);
                    }
                }
            }
        }
        self.voleith_key = Some(voleith_key);
    }
    
    pub fn get_reconstructed_com_hash(&self) -> &Hash {
        &self.reconstructed_com_hash.as_ref().unwrap()
    }
    
    pub fn get_voleith_key_for_testing(&self) -> &VOLEitHMACKey {
        if !cfg!(test) {
            panic!("This is not called during testing!");
        }
        &self.voleith_key.as_ref().unwrap()
    }
}