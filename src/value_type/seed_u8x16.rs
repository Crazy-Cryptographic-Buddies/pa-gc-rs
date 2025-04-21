use crate::comm_types_and_constants::SEED_BYTE_LEN;
use crate::value_type::Zero;

pub type SeedU8x16 = [u8; SEED_BYTE_LEN];

impl Zero for SeedU8x16 {
    fn zero() -> Self {
        [0; SEED_BYTE_LEN]
    }
}