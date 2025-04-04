use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

// We imitate the below link for implementing OneToTwoPRG
// https://github.com/GaloisInc/swanky/blob/dev/schmivitz/src/all_but_one_vc.rs

struct OneToTwoPRG {
    aes_cipher_0: Aes128,
    aes_cipher_1: Aes128,
}

impl OneToTwoPRG {
    pub fn new(seed: &[u8; 16]) -> OneToTwoPRG {
        let cipher = Aes128::new(&GenericArray::from(*seed));

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

    pub fn generate_double(&self, key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
        let mut cloned_key_0 = GenericArray::from(*key);
        self.aes_cipher_0.encrypt_block(&mut cloned_key_0);
        let mut cloned_key_1 = GenericArray::from(*key);
        self.aes_cipher_1.encrypt_block(&mut cloned_key_1);
        (
            cloned_key_0.into(),
            cloned_key_1.into()
        )
    }
}

#[test]
fn test_one_to_two_prg() {
    let seed = [10u8; 16];
    let prg: OneToTwoPRG = OneToTwoPRG::new(&seed);
    let res = prg.generate_double(&[255u8; 16]);
    println!("{:?} {:?}", seed, res);

    let seed = [10u8; 16];
    let res = prg.generate_double(&[255u8; 16]);
    println!("{:?} {:?}", seed, res);
}