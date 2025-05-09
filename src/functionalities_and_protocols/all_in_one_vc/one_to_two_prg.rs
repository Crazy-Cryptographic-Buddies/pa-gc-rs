use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use crate::comm_types_and_constants::{SEED_BYTE_LEN};
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::Zero;
// We imitate the below link for implementing OneToTwoPRG
// https://github.com/GaloisInc/swanky/blob/dev/schmivitz/src/all_but_one_vc.rs

pub struct OneToTwoPRG {
    aes_cipher_0: Aes128,
    aes_cipher_1: Aes128,
}

impl OneToTwoPRG {
    pub fn new(key: &SeedU8x16) -> OneToTwoPRG {
        let cipher = Aes128::new(&GenericArray::from(*key));

        let mut block = GenericArray::from([255u8; SEED_BYTE_LEN]);
        cipher.encrypt_block(&mut block);
        let aes_cipher_0 = Aes128::new(&block);

        let mut block = GenericArray::from([254u8; SEED_BYTE_LEN]);
        cipher.encrypt_block(&mut block);
        let aes_cipher_1 = Aes128::new(&block);

        Self {
            aes_cipher_0,
            aes_cipher_1
        }
    }

    pub fn generate_double(&self, seed: &SeedU8x16) -> (SeedU8x16, SeedU8x16) {
        let mut cloned_key_0 = GenericArray::from(*seed);
        self.aes_cipher_0.encrypt_block(&mut cloned_key_0);
        let mut cloned_key_1 = GenericArray::from(*seed);
        self.aes_cipher_1.encrypt_block(&mut cloned_key_1);
        (
            cloned_key_0.into(),
            cloned_key_1.into()
        )
    }

    pub fn generate_ggm_tree(&self, seed: &SeedU8x16, depth: u8) -> Vec<SeedU8x16> {
        // Here we define depth to be the distance from the root to the leaf
        // If depth is 0, the tree is a single node
        // If depth is 1, the tree is a root and a leaf
        let mut tree: Vec<SeedU8x16> = vec![SeedU8x16::zero(); (1usize << (depth + 1)) - 1];
        tree[0] = seed.clone();
        for i in 0..(1usize << depth) - 1 {
            let (key_0, key_1) = self.generate_double(&tree[i]);
            tree[(i << 1) + 1] = key_0;
            tree[(i << 1) + 2] = key_1;       
        }
        tree
    }
}

#[cfg(test)]
mod tests {
    use crate::comm_types_and_constants::SEED_BYTE_LEN;
    use crate::functionalities_and_protocols::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
    use crate::value_type::seed_u8x16::SeedU8x16;

    #[test]
    fn test_one_to_two_prg() {
        let seed: SeedU8x16 = [10u8; SEED_BYTE_LEN];
        let prg: OneToTwoPRG = OneToTwoPRG::new(&seed);
        let res = prg.generate_double(&[255u8; 16]);
        assert_eq!(res.0.len(), SEED_BYTE_LEN);
        println!("{:?} {:?}", seed, res);

        let seed = [10u8; 16];
        let res = prg.generate_double(&[255u8; 16]);
        println!("{:?} {:?}", seed, res);
    }
}