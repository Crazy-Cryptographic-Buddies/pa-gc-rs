pub mod comm_types_and_constants;
pub(crate) mod vec_type;
pub mod value_type;
pub(crate) mod bristol_fashion_adaptor;
pub(crate) mod utils;
mod test;
mod functionalities_and_protocols;

fn enforce_testing() {
    if !cfg!(test) {
        panic!("This is not called during testing!");
    }
}