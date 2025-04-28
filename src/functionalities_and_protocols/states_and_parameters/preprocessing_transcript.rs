use blake3::Hash;
use crate::value_type::garbled_row::GarbledRow;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

pub struct PreprocessingTranscript<GFVOLE, GFVOLEitH> {
    pub pa_com_hash_rep: Vec<Hash>,
    pub pa_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
    pub pb_com_hash_rep: Vec<Hash>,
    pub pb_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
    
    pub garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>>,
}

impl<GFVOLE, GFVOLEitH> PreprocessingTranscript<GFVOLE, GFVOLEitH> {
    pub fn new(
        pa_com_hash_rep: Vec<Hash>,
        pa_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
        pb_com_hash_rep: Vec<Hash>,
        
        pb_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
        garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>>
    ) -> Self {
        Self {
            pa_com_hash_rep,
            pa_masked_bit_tuple_rep,
            pb_com_hash_rep,
            pb_masked_bit_tuple_rep,
            
            garbled_table,
        }    
    }
}