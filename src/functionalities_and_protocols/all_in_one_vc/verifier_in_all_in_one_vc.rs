use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::generating_message_and_com_prg::GeneratingMessageAndComPRG;
use crate::functionalities_and_protocols::all_in_one_vc::hasher::hasher::Hasher;
use crate::functionalities_and_protocols::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
use crate::functionalities_and_protocols::inputs_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{GFAdd, U8ForGF, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::{
    bit_vec::BitVec,
    ZeroVec
};
use crate::vec_type::gf_vec::GFVec;

pub struct VerifierInAllInOneVC {
}

impl VerifierInAllInOneVC {
    
    pub fn reconstruct<GF: U8ForGF + Clone + Zero + GFAdd>(
        public_parameter: &PublicParameter, 
        nabla: &GF, decom: &(SeedU8x16, Vec<SeedU8x16>)
    ) -> (Hash, GFVec<GF>) {
        let com_at_excluded_index = &decom.0;
        let seed_trace = &decom.1;
        let generating_message_and_com_prg = GeneratingMessageAndComPRG::new(&public_parameter.one_to_two_prg);
        let mut coms_at_leaves: Vec<SeedU8x16> = vec![SeedU8x16::zero(); 1 << public_parameter.tau];
        let mut reconstructed_message_vec: Vec<BitVec> = vec![BitVec::zero_vec(public_parameter.big_n); 1 << public_parameter.tau];
        let excluded_index = nabla.get_u8() as usize;
        coms_at_leaves[excluded_index] = com_at_excluded_index.clone();
        for i in 0..public_parameter.tau {
            let sibling = {
                if (excluded_index >> i) & 1 == 1 {
                    (excluded_index >> i) - 1
                } else {
                    (excluded_index >> i) + 1
                }
            };
            let from_index = sibling << i;
            let subtree = public_parameter.one_to_two_prg.generate_ggm_tree(&seed_trace[i as usize], i);
            let mut index_in_subtree_leaves = (1 << i) - 1;
            for j in from_index..from_index + (1 << i) {
                let (message, com) = generating_message_and_com_prg.generate(
                    &subtree[index_in_subtree_leaves], 
                    public_parameter.big_n
                );
                reconstructed_message_vec[j] = message;
                coms_at_leaves[j] = com;
                index_in_subtree_leaves += 1;
            }
        }
        let reconstructed_com_hash = Hasher::hash_all_coms(&coms_at_leaves);

        // now recover the key
        let mut voleith_key = GFVec::<GF>::zero_vec(public_parameter.big_n);
        for i in 0..1 << public_parameter.tau {
            if i != excluded_index {
                let i_shifted = nabla.gf_add(&GF::from_u8(i as u8));
                let message_i = &reconstructed_message_vec[i];
                for j in 0..public_parameter.big_n {
                    if message_i[j] == 1 {
                        voleith_key[j] = voleith_key[j].gf_add(&i_shifted);
                    }
                }
            }
        }
        (reconstructed_com_hash, voleith_key)
    }
}