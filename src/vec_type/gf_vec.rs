use std::iter::FusedIterator;
use std::ops::{Index, IndexMut};
use crate::value_type::{CustomAddition, Zero};
use crate::vec_type::{BasicVecFunctions, Split, VecAddition, VecAppending, ZeroVec};
use crate::vec_type::bit_vec::BitVec;

#[derive(Clone, Debug, PartialEq, Eq)]
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
    
    pub fn iter(&self) -> std::slice::Iter<GF> {
        self.val.iter()
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

impl<GF: Clone + Zero + CustomAddition> VecAddition for GFVec<GF> {
    fn vec_add(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        Self {
            val: self.val.iter().zip(other.val.iter()).map(
                |(lhs, rhs)| lhs.custom_add(rhs)
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

impl<GF> VecAppending for GFVec<GF> {
    fn append(&mut self, other: &mut Self) {
        self.val.append(&mut other.val);
    }
}

impl<GF> FromIterator<GF> for GFVec<GF> {
    fn from_iter<T: IntoIterator<Item = GF>>(iter: T) -> Self {
        Self {
            val: iter.into_iter().collect()
        }
    }
}

impl<GF> BasicVecFunctions<GF> for GFVec<GF> {
    fn len(&self) -> usize {
        self.val.len()
    }

    fn as_slice(&self) -> &[GF] {
        &self.val
    }

    fn from_vec(vec: Vec<GF>) -> Self {
        Self {
            val: vec
        }
    }
}
