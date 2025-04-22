use crate::comm_types_and_constants::{SEED_BYTE_LEN};
use crate::functionalities_and_protocols::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::bit_vec::BitVec;

pub struct GeneratingMessageAndComPRG<'a> {
    one_to_two_prg: &'a OneToTwoPRG,
}

impl<'a> GeneratingMessageAndComPRG<'a> {

    pub fn new(one_to_two_prg: &'a OneToTwoPRG) -> GeneratingMessageAndComPRG<'a> {
        Self {
            one_to_two_prg
        }
    }

    pub fn generate(&self, seed: &SeedU8x16, message_len: usize) -> (BitVec, SeedU8x16) {
        assert_eq!(message_len % SEED_BYTE_LEN, 0,
                   "Message length must be a multiple of {}", SEED_BYTE_LEN
        );
        let message_aes_byte_len = message_len / SEED_BYTE_LEN;

        let (mut seed_message, com) = self.one_to_two_prg.generate_double(seed);
        let mut message: BitVec = BitVec::new();
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