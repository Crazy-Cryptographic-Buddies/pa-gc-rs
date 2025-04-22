use rand::Rng;
use crate::comm_types_and_constants::SEED_BYTE_LEN;
use crate::value_type::{InsecureRandom, Zero};

pub type SeedU8x16 = [u8; SEED_BYTE_LEN];

impl Zero for SeedU8x16 {
    fn zero() -> Self {
        [0; SEED_BYTE_LEN]
    }
}

impl InsecureRandom for SeedU8x16 {
    fn insecurely_random() -> Self {
        let mut rng = rand::rng();
        let mut seed: SeedU8x16 = SeedU8x16::default();
        for i in 0..SEED_BYTE_LEN {
            seed[i] = rng.random::<u8>();
        }
        seed
    }
}