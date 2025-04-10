use crate::all_in_one_vc::{SeedU8x16, one_to_two_prg::OneToTwoPRG, AES_BYTE_LEN};

struct GeneratingMessageAndComPRG {
    one_to_two_prg: OneToTwoPRG
}

impl GeneratingMessageAndComPRG {

    pub fn new(master_seed: &SeedU8x16) -> GeneratingMessageAndComPRG {
        GeneratingMessageAndComPRG {
            one_to_two_prg: OneToTwoPRG::new(master_seed)
        }
    }

    pub fn generate(&self, seed: &SeedU8x16, message_len: usize) {
        assert_eq!(message_len % AES_BYTE_LEN, 0);
        let message_aes_byte_len = message_len / AES_BYTE_LEN;

        let (seed_message, com) = self.one_to_two_prg.generate_double(seed);

        for i in 0..message_aes_byte_len {
            // TODO: continue here
        }
    }
}