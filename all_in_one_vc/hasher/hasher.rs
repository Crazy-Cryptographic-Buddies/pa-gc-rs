use blake3::Hash;
use crate::comm_types_and_constants::SeedU8x16;

static previous_vec_TO_BE_DELETED: Vec<SeedU8x16> = Vec::new();

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
}