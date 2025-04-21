use std::ops::{Index, IndexMut};
use crate::value_type::Zero;
use crate::vec_type::ZeroVec;

pub struct GFVec<GF: Clone + Zero> {
    val: Vec<GF>
}

impl<GF: Clone + Zero> Index<usize> for GFVec<GF> {
    type Output = GF;

    fn index(&self, index: usize) -> &Self::Output {
        &self.val[index]
    }
}

impl<GF: Clone + Zero> ZeroVec for GFVec<GF> {
    fn zero_vec(len: usize) -> GFVec<GF> {
        GFVec::<GF>{
            val: vec![GF::zero(); len]
        }
    }
}

impl<GF: Clone + Zero> IndexMut<usize> for GFVec<GF> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.val[index]
    }
}