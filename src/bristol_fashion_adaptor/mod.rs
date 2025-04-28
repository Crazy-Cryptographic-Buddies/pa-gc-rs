pub(crate) mod bristol_fashion_adaptor;

#[derive(PartialEq, Debug, Clone)]
pub enum GateType {
    AND,
    XOR,
    NOT,
}

#[derive(Debug)]
pub struct GateInfo {
    pub left_input_wire: usize,
    pub right_input_wire: usize,
    pub output_wire: usize,
    pub gate_type: GateType,
}

impl GateInfo {
    pub fn new(left_input_wire: usize, right_input_wire: usize, output_wire: usize, gate_type: GateType) -> Self {
        Self {
            left_input_wire,
            right_input_wire,
            output_wire,
            gate_type,
        }
    }
}