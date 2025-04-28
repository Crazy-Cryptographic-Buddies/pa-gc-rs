pub mod gf_vec;
pub mod bit_vec;

pub trait ZeroVec {
    fn zero_vec(len: usize) -> Self;
}

pub trait VecAddition {
    fn vec_add(&self, other: &Self) -> Self;
}

pub trait Split {
    fn split_off(&mut self, at: usize) -> Self;
}

pub trait VecAppending {
    fn append(&mut self, other: &mut Self);
}

pub trait BasicVecFunctions<OutputType> {
    fn len(&self) -> usize;
    fn as_slice(&self) -> &[OutputType];
    fn as_mut_slice(&mut self) -> &mut [OutputType];
    
    fn from_vec(vec: Vec<OutputType>) -> Self;
}