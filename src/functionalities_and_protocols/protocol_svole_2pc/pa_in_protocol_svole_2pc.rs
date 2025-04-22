use crate::vec_type::bit_vec::BitVec;

struct PAInProtocolSVOLE2PC<'a> {
    big_ia: &'a Vec<usize>,
    big_ib: &'a Vec<usize>,
    big_iw: &'a Vec<usize>,
    rw_bit_vec: &'a BitVec,
    rwprime_bit_vec: &'a BitVec,
    aa_tilde_bit_vec_rep: &'a Vec<BitVec>,
    ba_tilde_bit_vec_rep: &'a Vec<BitVec>,
    ca_tilde_bit_vec_rep: &'a Vec<BitVec>,
}

impl<'a> PAInProtocolSVOLE2PC<'a> {
    pub fn new(
        big_ia: &'a Vec<usize>,
        big_ib: &'a Vec<usize>,
        big_iw: &'a Vec<usize>,
        rw_bit_vec: &'a BitVec,
        rwprime_bit_vec: &'a BitVec,
        aa_tilde_bit_vec_rep: &'a Vec<BitVec>,
        ba_tilde_bit_vec_rep: &'a Vec<BitVec>,
        ca_tilde_bit_vec_rep: &'a Vec<BitVec>,
    ) -> Self {
        Self {
            big_ia,
            big_ib,
            big_iw,
            rw_bit_vec,
            rwprime_bit_vec,
            aa_tilde_bit_vec_rep,
            ba_tilde_bit_vec_rep,
            ca_tilde_bit_vec_rep,
        }
    }


}