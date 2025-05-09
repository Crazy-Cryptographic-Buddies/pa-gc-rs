use blake3::Hash;
use crate::functionalities_and_protocols::all_in_one_vc::generating_bit_and_com_prg::GeneratingBitAndComPRG;
use crate::functionalities_and_protocols::hasher;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{CustomAddition, U8ForGF, Zero};
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::{
    bit_vec::BitVec,
    ZeroVec
};
use crate::vec_type::gf_vec::GFVec;

pub struct VerifierInAllInOneVC {
}

impl VerifierInAllInOneVC {
    
    pub fn reconstruct<GFVOLEitH: U8ForGF + Clone + Zero + CustomAddition>(
        public_parameter: &PublicParameter, 
        nabla: &GFVOLEitH, decom: &(SeedU8x16, Vec<SeedU8x16>)
    ) -> (Hash, GFVec<GFVOLEitH>) {
        let com_at_excluded_index = &decom.0;
        let seed_trace = &decom.1;
        let generating_bit_and_com_prg = GeneratingBitAndComPRG::new(&public_parameter.one_to_two_prg);
        let mut coms_at_leaves: Vec<SeedU8x16> = vec![SeedU8x16::zero(); 1 << public_parameter.tau];
        let mut reconstructed_bit_vec_vec: Vec<BitVec> = vec![BitVec::zero_vec(public_parameter.big_n); 1 << public_parameter.tau];
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
                let (bit_vec, com) = generating_bit_and_com_prg.generate(
                    &subtree[index_in_subtree_leaves], 
                    public_parameter.big_n
                );
                reconstructed_bit_vec_vec[j] = bit_vec;
                coms_at_leaves[j] = com;
                index_in_subtree_leaves += 1;
            }
        }
        let reconstructed_com_hash = hasher::hash_all_coms(&coms_at_leaves);

        // now recover the key
        let mut voleith_key_vec = GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_n);
        for i in 0..1 << public_parameter.tau {
            if i != excluded_index {
                let i_shifted = nabla.custom_add(&GFVOLEitH::from_u8(i as u8));
                let bit_vec_i = &reconstructed_bit_vec_vec[i];
                for j in 0..public_parameter.big_n {
                    if bit_vec_i[j] == 1 {
                        voleith_key_vec[j] = voleith_key_vec[j].custom_add(&i_shifted);
                    }
                }
            }
        }
        (reconstructed_com_hash, voleith_key_vec)
    }
}