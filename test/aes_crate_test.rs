use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};

#[test]
fn aes128_test() {
    let key = GenericArray::from([0u8; 16]);
    let mut block = GenericArray::from([42u8; 16]);

    let cipher = Aes128::new(&key);
    println!("block = {:?}", block);
    cipher.encrypt_block(&mut block);
    println!("encrypted_block = {:?}", block);
    cipher.decrypt_block(&mut block);
    println!("decrypted_block = {:?}", block);
}