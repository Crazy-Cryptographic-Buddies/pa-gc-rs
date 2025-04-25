use rand::Rng;
use pa_gc_rs::comm_types_and_constants::SEED_BYTE_LEN;
use pa_gc_rs::value_type::seed_u8x16::SeedU8x16;

fn generate_random_seed() -> SeedU8x16 {
    let mut rng = rand::rng();
    let mut seed: SeedU8x16 = SeedU8x16::default();
    for i in 0..SEED_BYTE_LEN {
        seed[i] = rng.random::<u8>();
    }
    seed
}

fn main() {
}