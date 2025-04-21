pub mod gf2p256;

pub trait Random {
    fn random() -> Self;
}

pub trait GFMultiplyingBit {
    fn multiply_bit(&self, bit: &u8) -> Self;
}

pub trait GFAdd {
    fn add(&self, rhs: &Self) -> Self;
}