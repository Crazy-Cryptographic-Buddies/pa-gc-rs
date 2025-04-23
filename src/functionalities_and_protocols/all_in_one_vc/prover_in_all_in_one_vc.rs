use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::generating_bit_and_com_prg::GeneratingBitAndComPRG;
use crate::functionalities_and_protocols::all_in_one_vc::hasher::hasher::Hasher;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::{
    bit_vec::BitVec,
    ZeroVec,
    gf_vec::GFVec
};

pub struct ProverInAllInOneVC {
    tree_len: usize, // public
    first_leaf_index: usize, // public
    tree: Option<Vec<SeedU8x16>>,
    com_vec: Option<Vec<SeedU8x16>>, // private, can be public but better need verifier to reconstruct
}

impl ProverInAllInOneVC {
    pub fn new(
        public_parameter: &PublicParameter
    ) -> Self {
        let big_n: usize = 1 << public_parameter.tau;
        let tree_len: usize = (big_n << 1) - 1;
        Self {
            tree_len,
            first_leaf_index: (1 << public_parameter.tau) - 1,
            tree: None,
            com_vec: None,
        }
    }

    pub fn commit<GF: Clone + Zero + U8ForGF + GFAdd>(
        &mut self, public_parameter: &PublicParameter, 
        prover_secret_seed_for_generating_ggm_tree: &SeedU8x16,
        output_secret_bit_vec: &mut Option<BitVec>, output_secret_voleith_mac_vec: &mut Option<GFVec<GF>>
    ) -> Hash {
        let tree: Vec<SeedU8x16> = public_parameter.one_to_two_prg.generate_ggm_tree(
            prover_secret_seed_for_generating_ggm_tree, public_parameter.tau
        );
        self.tree = Some(tree);
        assert_eq!(self.tree.as_ref().unwrap().len(), self.tree_len);

        // now generating bits and commitments
        let generating_bit_and_com_prg = GeneratingBitAndComPRG::new(
            &public_parameter.one_to_two_prg
        );
        let mut bit_vec_vec: Vec<BitVec> = Vec::new();
        let mut com_vec: Vec<SeedU8x16> = Vec::new();
        for i in self.first_leaf_index..self.tree_len {
            let (bit_vec, com) = generating_bit_and_com_prg.generate(
                &self.tree.as_ref().unwrap()[i],
                public_parameter.big_n
            );
            bit_vec_vec.push(bit_vec);
            com_vec.push(com);
        }
        assert_eq!(bit_vec_vec.len(), 1 << public_parameter.tau);
        self.com_vec = Some(com_vec);
        
        let com_hash = Some(Hasher::hash_all_coms(&self.com_vec.as_ref().unwrap()));
        
        // compute bit_vec and mac tag
        let mut bit_vec = BitVec::zero_vec(public_parameter.big_n);
        let mut voleith_mac_vec = GFVec::<GF>::zero_vec(public_parameter.big_n);
        for i in 0..1 << public_parameter.tau {
            let i_gf = GF::from_u8(i as u8);
            let bit_vec_i = &bit_vec_vec[i];
            for j in 0..public_parameter.big_n {
                bit_vec[j] ^= bit_vec_i[j];
                if bit_vec_i[j] == 1 {
                    voleith_mac_vec[j] = voleith_mac_vec[j].gf_add(&i_gf);
                }        
            }
        }
        *output_secret_bit_vec = Some(bit_vec);
        *output_secret_voleith_mac_vec = Some(voleith_mac_vec);
        com_hash.unwrap()
    }

    pub fn open<GF: U8ForGF>(&self, public_parameter: &PublicParameter, nabla: &GF) -> (SeedU8x16, Vec<SeedU8x16>) {
        // the excluded index must be in [0, 2^8]
        // this can be understood the index among the leaves, i.e., the excluded_index-th leaf
        let excluded_index = nabla.get_u8() as usize;
        assert!(excluded_index < 1 << 8);
        let mut index_in_tree = self.first_leaf_index + excluded_index;
        let com_at_excluded_index = self.com_vec.as_ref().unwrap()[excluded_index];
        let mut seed_trace: Vec<SeedU8x16> = Vec::new();
        for i in 0..public_parameter.tau {
            if (excluded_index >> i) & 1 == 1 {
                seed_trace.push(self.tree.as_ref().unwrap()[index_in_tree - 1]);
            } else {
                seed_trace.push(self.tree.as_ref().unwrap()[index_in_tree + 1]);
            }
            index_in_tree = (index_in_tree - 1) >> 1;
        }
        (com_at_excluded_index, seed_trace)
    }
}
