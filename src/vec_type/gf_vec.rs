use std::ops::{Index, IndexMut};
use crate::value_type::Zero;
use crate::vec_type::{ZeroVec};

pub struct GFVec<GF: Clone + Zero> {
    val: Vec<GF>
}

impl<GF: Clone + Zero> GFVec<GF> {
    pub fn new() -> Self {
        Self {
           val: Vec::<GF>::new()
        }
    }
    
    pub fn push(&mut self, val: GF) {
        self.val.push(val);
    }
    
    pub fn len(&self) -> usize {
        self.val.len()
    }
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

impl<'a, GF: Clone + Zero> IntoIterator for &'a GFVec<GF> {
    type Item = &'a GF;
    type IntoIter = std::slice::Iter<'a, GF>;

    fn into_iter(self) -> Self::IntoIter {
        self.val.iter()
    }
}