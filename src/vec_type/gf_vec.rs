use std::ops::{Index, IndexMut};
use crate::value_type::{GFAdd, Zero};
use crate::vec_type::{Split, VecAdd, ZeroVec};
use crate::vec_type::bit_vec::BitVec;

#[derive(Clone)]
pub struct GFVec<GF> {
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

    pub fn entry_wise_multiply_bit_vec(&self, other: &BitVec) -> Self {
        assert_eq!(self.len(), other.len());
        Self {
            val: self.val.iter().zip(other.iter()).map(
                |(lhs, rhs)| if *rhs == 1u8 {
                    lhs.clone()
                } else {
                    GF::zero()
                }
            ).collect()
        }
    }
}

impl<GF: Clone + Zero> Index<usize> for GFVec<GF> {
    type Output = GF;

    fn index(&self, index: usize) -> &Self::Output {
        &self.val[index]
    }
}

impl<GF: Zero + Clone> ZeroVec for GFVec<GF> {
    fn zero_vec(len: usize) -> GFVec<GF> {
        GFVec::<GF>{
            val: vec![GF::zero(); len]
        }
    }
}

impl<GF: Zero + Clone> IndexMut<usize> for GFVec<GF> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.val[index]
    }
}

impl<'a, GF> IntoIterator for &'a GFVec<GF> {
    type Item = &'a GF;
    type IntoIter = std::slice::Iter<'a, GF>;

    fn into_iter(self) -> Self::IntoIter {
        self.val.iter()
    }
}

impl<GF: Clone + Zero + GFAdd> VecAdd for GFVec<GF> {
    fn vec_add(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        Self {
            val: self.val.iter().zip(other.val.iter()).map(
                |(lhs, rhs)| lhs.gf_add(rhs)
            ).collect()
        }
    }
}

impl<GF> Split for GFVec<GF> {
    fn split_off(&mut self, at: usize) -> Self {
        Self {
            val: self.val.split_off(at)
        }
    }
}