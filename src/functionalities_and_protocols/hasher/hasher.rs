use blake3::Hash;
use crate::value_type::seed_u8x16::SeedU8x16;

pub struct Hasher {
}

impl Hasher {
    pub fn hash_all_coms(com_vec: &Vec<SeedU8x16>) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for com in com_vec.iter() {
            hasher.update(com);
        }
        hasher.finalize()
    }
    
    // pub fn hash_for_garbling(first_label_bytes: &[u8], second_label_bytes: &[u8], gamma: usize, k: usize, garbled_row_byte_length: usize) -> Hash {
    //     
    // }
}