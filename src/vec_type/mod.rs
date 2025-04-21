pub mod gf_vec;
pub mod bit_vec;

pub trait ZeroVec {
    fn zero_vec(len: usize) -> Self;
}