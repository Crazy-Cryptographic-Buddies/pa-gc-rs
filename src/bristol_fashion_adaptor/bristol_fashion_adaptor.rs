// This source code follows Bristol Fashion's specification https://nigelsmart.github.io/MPC-Circuits/
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use crate::bristol_fashion_adaptor::{GateInfo, GateType};

pub struct BristolFashionAdaptor {
    num_wires: usize,
    num_input_bits: usize,
    num_output_bits: usize,
    gate_vec: Vec<GateInfo>,
    and_gate_id_vec: Vec<usize>,
    and_gate_output_wire_vec: Vec<usize>,
    output_wire_vec: Vec<usize>   
}

impl BristolFashionAdaptor {
    pub fn new(bristol_fashion_circuit_file_name: &String) -> Self {
        Self::read_circuit_file(bristol_fashion_circuit_file_name)
    }

    fn determine_and_gate_id_vec(gate_vec: &Vec<GateInfo>) -> Vec<usize> {
        (0..gate_vec.len()).filter(|&i| gate_vec[i].gate_type == GateType::AND).collect()
    }

    fn read_circuit_file(circuit_file_name: &String) -> Self {
        let full_circuit_file_name = Path::new(file!())
            .parent().unwrap().display().to_string()
            + "/circuit_data/"
            + circuit_file_name;
        let input_file = File::open(full_circuit_file_name).unwrap();
        let mut input_file = BufReader::new(&input_file);
        let mut line = String::new();

        // read num_gates and num_wires
        input_file.read_line(&mut line).unwrap();
        let mut parts = line.split_whitespace();
        let num_gates = parts.next().unwrap().parse::<usize>().unwrap();
        let num_wires = parts.next().unwrap().parse::<usize>().unwrap();

        // read num_inputs
        line.clear();
        input_file.read_line(&mut line).unwrap();
        parts = line.split_whitespace();
        let num_inputs = parts.next().unwrap().parse::<usize>().unwrap();
        let mut num_input_bits: usize = 0;
        for _ in 0..num_inputs {
            let partial_num_input_bits = parts.next().unwrap().parse::<usize>().unwrap();
            num_input_bits += partial_num_input_bits;
        }

        // read num_outputs
        line.clear();
        input_file.read_line(&mut line).unwrap();
        parts = line.split_whitespace();
        let num_outputs = parts.next().unwrap().parse::<usize>().unwrap();
        let mut num_output_bits: usize = 0;
        for _ in 0..num_outputs {
            let partial_num_output_bits = parts.next().unwrap().parse::<usize>().unwrap();
            num_output_bits += partial_num_output_bits;
        }

        // read empty line
        line.clear();
        input_file.read_line(&mut line).unwrap();

        // start reading the gates
        let mut gate_vec: Vec<GateInfo> = Vec::new();
        for _ in 0..num_gates {
            line.clear();
            input_file.read_line(&mut line).unwrap();
            parts = line.split_whitespace();
            let num_gate_input_bits = parts.next().unwrap().parse::<usize>().unwrap();
            let num_gate_output_bits = parts.next().unwrap().parse::<usize>().unwrap();
            assert!(num_gate_input_bits == 1 || num_gate_input_bits == 2);
            assert_eq!(num_gate_output_bits, 1);
            let left_gate_input_wire = parts.next().unwrap().parse::<usize>().unwrap();
            let mut right_gate_input_wire = 0;
            if num_gate_input_bits == 2 {
                right_gate_input_wire = parts.next().unwrap().parse::<usize>().unwrap();
            }
            let gate_output_wire = parts.next().unwrap().parse::<usize>().unwrap();
            let gate_name = parts.next().unwrap();
            let gate_type: GateType = match gate_name {
                "AND" => GateType::AND,
                "XOR" => GateType::XOR,
                "INV" => GateType::NOT,
                _ => panic!("Unknown gate vec_type: {}", gate_name),
            };
            gate_vec.push(
                GateInfo::new(
                    left_gate_input_wire, 
                    right_gate_input_wire, 
                    gate_output_wire, 
                    gate_type
                )
            );
        }

        let and_gate_id_vec = Self::determine_and_gate_id_vec(&gate_vec);
        let and_gate_output_wire_vec = Self::determine_and_gate_output_wires(&gate_vec, &and_gate_id_vec);

        Self {
            num_wires,
            num_input_bits,
            num_output_bits,
            gate_vec,
            and_gate_id_vec,
            and_gate_output_wire_vec,
            output_wire_vec: (num_wires - num_output_bits..num_wires).collect(),
        }
    }

    pub fn compute_output_bits(&self, input_bit_vec: &Vec<u8>) -> Vec<u8> {
        assert_eq!(input_bit_vec.len(), self.num_input_bits);
        // println!("input_bit_vec_len: {:?}", input_bit_vec.len());
        // println!("self.num_input_bits: {:?}", self.num_input_bits);
        for val in input_bit_vec {
            assert!(*val == 0 || *val == 1);
        }
        let mut wire_values: Vec<u8> = vec![255; self.num_wires]; // 255 means not assigned
        for i in 0..self.num_input_bits {
            wire_values[i] = input_bit_vec[i];
        }
        for gate in &self.gate_vec {
            let gate_output_bit = match gate.gate_type {
                GateType::AND => {
                    if wire_values[gate.left_input_wire] == 255 || wire_values[gate.right_input_wire] == 255 {
                        panic!("Value not assigned");   
                    }
                    wire_values[gate.left_input_wire] & wire_values[gate.right_input_wire]
                },
                GateType::XOR => {
                    if wire_values[gate.left_input_wire] == 255 || wire_values[gate.right_input_wire] == 255 {
                        panic!("Value not assigned");
                    }
                    wire_values[gate.left_input_wire] ^ wire_values[gate.right_input_wire]
                },
                GateType::NOT => {
                    if wire_values[gate.left_input_wire] == 255 {
                        panic!("Value not assigned");
                    }
                    1u8 ^ wire_values[gate.left_input_wire]
                },
            };
            wire_values[gate.output_wire] = gate_output_bit;
        }
        wire_values[wire_values.len().saturating_sub(self.num_output_bits)..].to_vec()
    }
    
    // pub fn compute_num_and_gates(&self) -> usize {
    //     let mut num_and_gates: usize = 0;
    //     for gate in &self.gate_vec {
    //         if gate.gate_type == GateType::AND {
    //             num_and_gates += 1;
    //         }
    //     }
    //     num_and_gates   
    // }
    
    pub fn determine_and_gate_output_wires(gate_vec: &Vec<GateInfo>, and_gate_id_vec: &Vec<usize>) -> Vec<usize> {
        and_gate_id_vec.iter().map(
            |gate_id| {
                gate_vec[*gate_id].output_wire
            }
        ).collect()
    }
    
    pub fn get_num_input_bits(&self) -> usize {
        self.num_input_bits
    }
    
    // pub fn get_num_output_bits(&self) -> usize {
    //     self.num_output_bits
    // }
    
    pub fn get_num_wires(&self) -> usize {
        self.num_wires
    }
    
    pub fn get_gate_vec(&self) -> &Vec<GateInfo> {
        self.gate_vec.as_ref()   
    }
    pub fn get_and_gate_id_vec(&self) -> &Vec<usize> {
        self.and_gate_id_vec.as_ref()
    }
    
    pub fn get_and_gate_output_wire_vec(&self) -> &Vec<usize> {
        self.and_gate_output_wire_vec.as_ref()
    }
    
    pub fn get_num_output_bits(&self) -> usize {
        self.num_output_bits
    }
    
    pub fn get_output_wire_vec(&self) -> &Vec<usize> {
        self.output_wire_vec.as_ref()
    }
}

// #[test]
// pub fn sha256_test_compute_output_hex_string_from_input_hex_string() {
//     let chaining_value_hex_string: String = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19".to_string();
//     let input_hex_string_1: String = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();
//     println!("input_hex_string_1 + chaining_value_hex_string: {:?}",
//              input_hex_string_1.clone() + &chaining_value_hex_string
//     );
//     let expected_output_hex_string_1 = "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8".to_string();
//     let bristol_fashion_adaptor = BristolFashionAdaptor::new(&"sha256.txt".to_string());
//     let output_hex_string_1 = bristol_fashion_adaptor.compute_output_hex_string_from_input_hex_string(
//         input_hex_string_1.clone() + &chaining_value_hex_string
//     );
//     assert_eq!(output_hex_string_1, expected_output_hex_string_1);
// }

#[cfg(test)]
mod tests {
    use rand::Rng;
    use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;

    // pub fn compute_output_hex_string_from_input_hex_string(input_hex_string: String)
    //                                                        -> String {
    //     let input_bit_vec: Vec<u8> = Conversion::hex_string_to_bit_vec(&input_hex_string);
    //     let output_bit_vec = self.compute_output_bits(&input_bit_vec);
    //     let output_hex_string = Conversion::bit_vec_to_hex_string(&output_bit_vec);
    //     output_hex_string
    // }

    pub fn u64_to_bit_vec(u64_value: u64) -> Vec<u8> {
        let mut bit_vec: Vec<u8> = Vec::new();
        for i in 0..64 {
            bit_vec.push(((u64_value >> i) & 1) as u8);
        }
        bit_vec   
    }

    #[test]
    pub fn adder64_test_compute_output_hex_string_from_input_hex_string() {
        let mut rng = rand::rng();
        let a: u64 = rng.random::<u64>();
        let b: u64 = rng.random::<u64>();
        let sum =  a.wrapping_add(b);
        // println!("a: {:?}, b: {:?}, sum: {:?}", a, b, sum);
        let expected_output_bit_vec = u64_to_bit_vec(sum);
        let mut input_bit_vec = u64_to_bit_vec(a);
        input_bit_vec.append(&mut u64_to_bit_vec(b));
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(&"adder64.txt".to_string());
        let output_bit_vec = bristol_fashion_adaptor.compute_output_bits(&input_bit_vec);
        // println!("         output_bit_vec: {:?}", output_bit_vec);
        // println!("expected_output_bit_vec: {:?}", expected_output_bit_vec);
        assert_eq!(output_bit_vec, expected_output_bit_vec);
        // println!("test passed");
    }

    #[test]
    pub fn sub64_test_compute_output_hex_string_from_input_hex_string() {
        let mut rng = rand::rng();
        let a: u64 = rng.random::<u64>();
        let b: u64 = rng.random::<u64>();
        let sum =  a.wrapping_sub(b);
        // println!("a: {:?}, b: {:?}, sum: {:?}", a, b, sum);
        let expected_output_bit_vec = u64_to_bit_vec(sum);
        let mut input_bit_vec = u64_to_bit_vec(a);
        input_bit_vec.append(&mut u64_to_bit_vec(b));
        let bristol_fashion_adaptor = BristolFashionAdaptor::new(&"sub64.txt".to_string());
        let output_bit_vec = bristol_fashion_adaptor.compute_output_bits(&input_bit_vec);
        // println!("         output_bit_vec: {:?}", output_bit_vec);
        // println!("expected_output_bit_vec: {:?}", expected_output_bit_vec);
        assert_eq!(output_bit_vec, expected_output_bit_vec);
        // println!("test passed");
    }
}