use crate::value_type::garbled_row::GarbledRow;

pub struct PreprocessingTranscript<GFVOLE, GFVOLEitH> {
    pub garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>>,
}

impl<GFVOLE, GFVOLEitH> PreprocessingTranscript<GFVOLE, GFVOLEitH> {
    pub fn new(
        garbled_table: Vec<Vec<GarbledRow<GFVOLE, GFVOLEitH>>>
    ) -> Self {
        Self {
            garbled_table,
        }    
    }
}