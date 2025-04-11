use crate::all_in_one_vc::{SeedU8x16, one_to_two_prg::OneToTwoPRG, AES_BYTE_LEN};

pub struct GeneratingMessageAndComPRG<'a> {
    one_to_two_prg: &'a OneToTwoPRG,
}

impl GeneratingMessageAndComPRG {

    pub fn new(one_to_two_prg: &OneToTwoPRG) -> GeneratingMessageAndComPRG {
        GeneratingMessageAndComPRG {
            one_to_two_prg
        }
    }

    pub fn generate(&self, seed: &SeedU8x16, message_len: usize) -> (Vec<u8>, SeedU8x16) {
        assert_eq!(message_len % AES_BYTE_LEN, 0,
                   "Message length must be a multiple of {}", AES_BYTE_LEN
        );
        let message_aes_byte_len = message_len / AES_BYTE_LEN;

        let (mut seed_message, com) = self.one_to_two_prg.generate_double(seed);
        let mut message: Vec<u8> = Vec::new();
        for _ in 0..message_aes_byte_len {
            let byte_message;
            (byte_message, seed_message) = self.one_to_two_prg.generate_double(&seed_message);
            for byte in byte_message.iter() {
                message.push(byte & 1);
            }
        }
        (message, com)
    }
}