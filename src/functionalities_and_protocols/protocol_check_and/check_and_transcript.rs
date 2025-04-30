use bincode::Encode;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

#[derive(Encode)]
pub struct CheckAndTranscript<GFVOLEitH>
where GFVOLEitH: Encode {

    pub pa_published_bit_and_voleith_mac_tuple_rep: (
        (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
        (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
        (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>)
    ),
    pub pb_published_bit_and_voleith_mac_tuple_rep: (
        (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
        (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
        (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>)
    ),
    // pub public_d_sum_bit_vec_rep: Vec<BitVec>,
    // pub public_e_sum_bit_vec_rep: Vec<BitVec>,
}

impl<GFVOLEitH> CheckAndTranscript<GFVOLEitH>
where GFVOLEitH: Encode {
    pub fn new(
        pa_published_bit_and_voleith_mac_tuple_rep: (
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>)
        ),
        pb_published_bit_and_voleith_mac_tuple_rep: (
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>),
            (Vec<BitVec>, Vec<GFVec<GFVOLEitH>>)
        ),
        // public_d_sum_bit_vec_rep: Vec<BitVec>, public_e_sum_bit_vec_rep: Vec<BitVec>,
    ) -> Self {
        Self {
            pa_published_bit_and_voleith_mac_tuple_rep,
            pb_published_bit_and_voleith_mac_tuple_rep,
            // public_d_sum_bit_vec_rep,
            // public_e_sum_bit_vec_rep,
        }
    }
}