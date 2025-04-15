use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use crate::all_in_one_vc::{SeedU8x16, AES_BYTE_LEN};
// We imitate the below link for implementing OneToTwoPRG
// https://github.com/GaloisInc/swanky/blob/dev/schmivitz/src/all_but_one_vc.rs

pub struct OneToTwoPRG {
    aes_cipher_0: Aes128,
    aes_cipher_1: Aes128,
}

impl OneToTwoPRG {
    pub fn new(key: &SeedU8x16) -> OneToTwoPRG {
        let cipher = Aes128::new(&GenericArray::from(*key));

        let mut block = GenericArray::from([255u8; 16]);
        cipher.encrypt_block(&mut block);
        let aes_cipher_0 = Aes128::new(&block);

        let mut block = GenericArray::from([254u8; 16]);
        cipher.encrypt_block(&mut block);
        let aes_cipher_1 = Aes128::new(&block);

        OneToTwoPRG{
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

    pub fn generating_tree(&self, seed: &SeedU8x16, depth: u8) {
        let mut tree: Vec<SeedU8x16> = Vec::new();
        tree.push(seed.clone());
        for i in 1..(1u16 << (depth + 1)) - 1 {
            // TODO: continue here
        }
    }
}

#[test]
fn test_one_to_two_prg() {
    let seed: SeedU8x16 = [10u8; 16];
    let prg: OneToTwoPRG = OneToTwoPRG::new(&seed);
    let res = prg.generate_double(&[255u8; 16]);
    assert_eq!(res.0.len(), AES_BYTE_LEN);
    println!("{:?} {:?}", seed, res);

    let seed = [10u8; 16];
    let res = prg.generate_double(&[255u8; 16]);
    println!("{:?} {:?}", seed, res);
}