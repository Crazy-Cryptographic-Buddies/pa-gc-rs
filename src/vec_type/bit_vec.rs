use std::ops::{Index, IndexMut};
use crate::vec_type::{Split, VecAdd, ZeroVec};

#[derive(Clone)]
pub struct BitVec {
    val: Vec<u8>
}

impl BitVec {
    
    pub fn new() -> Self {
        Self {
            val: Vec::new()
        }
    }
    
    pub fn push(&mut self, value: u8) {
        self.val.push(value);
    }

    pub fn len(&self) -> usize {
        self.val.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, u8> {
        self.val.iter()
    }
    
    pub fn entry_wise_mult(&self, other: &Self) -> Self {
        Self {
            val: self.iter().zip(other.iter()).map(
                |(lhs, rhs)| *lhs & *rhs
            ).collect()
        }
    }
}

impl ZeroVec for BitVec {
    fn zero_vec(len: usize) -> Self {
        Self {
            val: vec![0u8; len]
        }
    }
}

impl Index<usize> for BitVec {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.val[index]
    }
}

impl IndexMut<usize> for BitVec {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.val[index]
    }
}

impl VecAdd for BitVec {
    fn vec_add(&self, other: &Self) -> Self {
        Self {
            val: self.iter().zip(other.iter()).map(
                |(lhs, rhs)| *lhs ^ *rhs
            ).collect()
        }
    }
}

impl Split for BitVec {
    fn split_off(&mut self, at: usize) -> Self {
        Self {
            val: self.val.split_off(at)
        }
    }
}