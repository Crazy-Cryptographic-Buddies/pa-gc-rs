// This source code follows Bristol Fashion's specification https://nigelsmart.github.io/MPC-Circuits/

use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::comm_types_and_constants::GateType;

struct BristolFashionAdaptor {
    num_gates: usize,
    num_wires: usize,
    num_input_bits: usize,
    num_output_bits: usize,
    gate_vec: Vec<(usize, usize, usize, GateType)>,
}

impl BristolFashionAdaptor {
    pub fn new(bristol_fashion_circuit_file_name: &str) -> Self {
        Self::read_circuit_file(bristol_fashion_circuit_file_name)
    }

    fn read_circuit_file(circuit_file_name: &str) -> Self {
        let input_file = File::open(circuit_file_name).unwrap();
        let mut input_file = BufReader::new(&input_file);
        let mut line = String::new();

        // read num_gates and num_wires
        input_file.read_line(&mut line).unwrap();
        let mut parts = line.split_whitespace();
        let num_gates = parts.next().unwrap().parse::<usize>().unwrap();
        let num_wires = parts.next().unwrap().parse::<usize>().unwrap();

        // read num_inputs 
        input_file.read_line(&mut line).unwrap();
        parts = line.split_whitespace();
        let num_inputs = parts.next().unwrap().parse::<usize>().unwrap();
        let mut num_input_bits: usize = 0;
        for _ in 0..num_inputs {
            let partial_num_input_bits = parts.next().unwrap().parse::<usize>().unwrap();
            num_input_bits += partial_num_input_bits;
        }

        // read num_outputs
        input_file.read_line(&mut line).unwrap();
        parts = line.split_whitespace();
        let num_outputs = parts.next().unwrap().parse::<usize>().unwrap();
        let mut num_output_bits: usize = 0;
        for _ in 0..num_outputs {
            let partial_num_output_bits = parts.next().unwrap().parse::<usize>().unwrap();
            num_output_bits += partial_num_output_bits;
        }

        // start reading the gates
        input_file.read_line(&mut line).unwrap();
        let mut gate_vec: Vec<(usize, usize, usize, GateType)> = Vec::new();
        for _ in 0..num_gates {
            input_file.read_line(&mut line).unwrap();
            parts = line.split_whitespace();
            let num_gate_input_bits = parts.next().unwrap().parse::<usize>().unwrap();
            let num_gate_output_bits = parts.next().unwrap().parse::<usize>().unwrap();
            assert!(num_gate_input_bits == 1 || num_gate_output_bits == 2);
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
                _ => panic!("Unknown gate type: {}", gate_name),
            };
            gate_vec.push(
                (left_gate_input_wire, right_gate_input_wire, gate_output_wire, gate_type)
            );
        }

        Self {
            num_gates,
            num_wires,
            num_input_bits,
            num_output_bits,
            gate_vec,
        }
    }
}