use crate::comm_types_and_constants::{SEED_BYTE_LEN};
use crate::functionalities_and_protocols::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::vec_type::bit_vec::BitVec;

pub struct GeneratingBitAndComPRG<'a> {
    one_to_two_prg: &'a OneToTwoPRG,
}

impl<'a> GeneratingBitAndComPRG<'a> {

    pub fn new(one_to_two_prg: &'a OneToTwoPRG) -> GeneratingBitAndComPRG<'a> {
        Self {
            one_to_two_prg
        }
    }

    pub fn generate(&self, seed: &SeedU8x16, bit_vec_len: usize) -> (BitVec, SeedU8x16) {
        let bit_vec_byte_len =  (bit_vec_len - 1) / SEED_BYTE_LEN + 1;

        let (mut seed_for_bit_vec, com) = self.one_to_two_prg.generate_double(seed);
        let mut bit_vec: BitVec = BitVec::new();
        for _ in 0..bit_vec_byte_len {
            let byte_vec;
            (byte_vec, seed_for_bit_vec) = self.one_to_two_prg.generate_double(&seed_for_bit_vec);
            for byte in byte_vec.iter() {
                bit_vec.push(byte & 1);
                if bit_vec.len() == bit_vec_len {
                    break;
                }
            }
        }
        assert_eq!(bit_vec.len(), bit_vec_len);
        (bit_vec, com)
    }
}