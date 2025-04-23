pub mod gf_vec;
pub mod bit_vec;

pub trait ZeroVec {
    fn zero_vec(len: usize) -> Self;
}

pub trait VecAdd {
    fn vec_add(&self, other: &Self) -> Self;
}

pub trait Split {
    fn split_off(&mut self, at: usize) -> Self;
}