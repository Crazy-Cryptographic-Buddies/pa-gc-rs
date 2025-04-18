use std::ops::Add;
use galois_2p8::{GeneralField};

struct GF2p8<'a> {
    value: u8,
    general_field: &'a GeneralField
}