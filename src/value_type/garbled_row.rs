use crate::value_type::{CustomAddition, Zero};

#[derive(Clone)]
pub struct GarbledRow<GFVOLE, GFVOLEitH> {
    first_u8: u8,
    vole_mac_field: GFVOLE,
    voleith_mac_field: Vec<GFVOLEitH>,
    vole_mac_remaining_field: GFVOLE,
}

impl<GFVOLE, GFVOLEitH> GarbledRow<GFVOLE, GFVOLEitH> {

    pub fn new(first_u8: u8, vole_mac_field: GFVOLE, voleith_mac_field: Vec<GFVOLEitH>, vole_mac_remaining_field: GFVOLE) -> Self {
        Self {
            first_u8,
            vole_mac_field,
            voleith_mac_field,
            vole_mac_remaining_field,
        }
    }
}

impl<GFVOLE, GFVOLEitH> CustomAddition for GarbledRow<GFVOLE, GFVOLEitH>
where GFVOLE: CustomAddition, GFVOLEitH: CustomAddition {
    fn custom_add(&self, rhs: &Self) -> Self {
        Self {
            first_u8: self.first_u8 ^ rhs.first_u8,
            vole_mac_field: self.vole_mac_field.custom_add(&rhs.vole_mac_field),
            voleith_mac_field: self.voleith_mac_field.iter().zip(rhs.voleith_mac_field.iter()).map(
                |(a, b)| a.custom_add(b)
            ).collect(),
            vole_mac_remaining_field: self.vole_mac_remaining_field.custom_add(
                &rhs.vole_mac_remaining_field
            )
        }
    }
}

impl<GFVOLE, GFVOLEitH> Zero for GarbledRow<GFVOLE, GFVOLEitH>
where GFVOLE: Zero{
    fn zero() -> Self {
        Self {
            first_u8: u8::zero(),
            vole_mac_field: GFVOLE::zero(),
            voleith_mac_field: Vec::new(),
            vole_mac_remaining_field: GFVOLE::zero(),
        }
    }
}