pub mod gf256;

pub trait Random {
    fn random() -> Self;
}