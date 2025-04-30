use bincode::{config, encode_to_vec, Encode};
use blake3::Hash;
use crate::value_type::garbled_row::GarbledRow;
use crate::vec_type::bit_vec::BitVec;

pub struct PreprocessingTranscript<GFVOLE, GFVOLEitH> {
    pub pa_com_hash_rep: Vec<Hash>,
    pub pa_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
    pub pb_com_hash_rep: Vec<Hash>,
    pub pb_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
    
    pub garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>>,
    pub commitment_vec: Vec<[Hash; 4]>
}

impl<GFVOLE, GFVOLEitH> PreprocessingTranscript<GFVOLE, GFVOLEitH>
where GFVOLE: Encode, GFVOLEitH: Encode {
    pub fn new(
        pa_com_hash_rep: Vec<Hash>,
        pa_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
        pb_com_hash_rep: Vec<Hash>,
        
        pb_masked_bit_tuple_rep: Vec<(BitVec, BitVec, BitVec, BitVec, BitVec, BitVec)>,
        garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>>,
        commitment_vec: Vec<[Hash; 4]>
    ) -> Self {
        Self {
            pa_com_hash_rep,
            pa_masked_bit_tuple_rep,
            pb_com_hash_rep,
            pb_masked_bit_tuple_rep,
            
            garbled_table,
            commitment_vec,
        }    
    }

    pub fn to_byte_vec(&self) -> Vec<u8> {
        let config = config::standard();

        let mut res = Vec::<u8>::new();
        
        res.append(&mut self.pa_com_hash_rep.iter().flat_map(|digest| digest.as_bytes().clone()).collect());
        res.append(&mut encode_to_vec(&self.pa_masked_bit_tuple_rep, config).unwrap());
        res.append(&mut self.pb_com_hash_rep.iter().flat_map(|digest| digest.as_bytes().clone()).collect());
        res.append(&mut encode_to_vec(&self.pb_masked_bit_tuple_rep, config).unwrap());
        res.append(&mut encode_to_vec(&self.garbled_table, config).unwrap());
        res.append(&mut self.commitment_vec.iter().flat_map(
            |coms| coms.iter().flat_map(
                |digest| digest.as_bytes().to_vec()
            ).collect::<Vec<u8>>()
        ).collect());
        
        res
    }
}