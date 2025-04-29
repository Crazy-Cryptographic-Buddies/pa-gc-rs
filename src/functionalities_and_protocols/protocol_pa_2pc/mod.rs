use std::ops::{Index, IndexMut};
use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
use crate::bristol_fashion_adaptor::GateType;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::Zero;
use crate::vec_type::{BasicVecFunctions, Split, ZeroVec};
use crate::vec_type::bit_vec::BitVec;

mod test;
mod prover_in_pa_2pc;
mod verifier_in_pa_2pc;
pub(crate) mod preprocessing_transcript;
pub(crate) mod proof_transcript;

fn permute<PrimitiveType, VecType>(
    public_parameter: &PublicParameter,
    permutation_rep: &Vec<Vec<usize>>, to_be_permuted_vec_rep: &mut Vec<VecType>
)
where PrimitiveType: Clone,
      VecType: ZeroVec + BasicVecFunctions<PrimitiveType> + Clone
      + Index<usize, Output = PrimitiveType> + IndexMut<usize, Output = PrimitiveType> {
    assert_eq!(permutation_rep.len(), public_parameter.kappa);
    assert_eq!(to_be_permuted_vec_rep.len(), public_parameter.kappa);
    let mut res = vec![VecType::zero_vec(public_parameter.big_l); public_parameter.kappa];
    (0..public_parameter.kappa).for_each(|repetition_id| {
        assert_eq!(permutation_rep[repetition_id].len(), public_parameter.big_l);
        assert_eq!(to_be_permuted_vec_rep[repetition_id].len(), public_parameter.big_l);
        (0..public_parameter.big_l).for_each(
            |j| res[repetition_id][permutation_rep[repetition_id][j]] = to_be_permuted_vec_rep[repetition_id][j].clone()
        )
    });
    *to_be_permuted_vec_rep = res;
}

fn split_off_rm<PrimitiveType, VecType>(
    public_parameter: &PublicParameter,
    to_be_split_off_vec_rep: &mut Vec<VecType>
) -> Vec<VecType>
where VecType: Split + ZeroVec + Clone + BasicVecFunctions<PrimitiveType> {
    (0..public_parameter.kappa).map(
        |repetition_id| {
            let length = to_be_split_off_vec_rep[repetition_id].len();
            to_be_split_off_vec_rep[repetition_id].split_off(length - public_parameter.rm)
        }
    ).collect::<Vec<VecType>>()
}

fn initialize_trace<PrimitiveType, VecType>(
    public_parameter: &PublicParameter,
    input_vec: &VecType,
    output_and_vec: &VecType,
    to_be_written_trace: &mut VecType,
)
where PrimitiveType: Clone + Zero + Copy,
      VecType: Clone + ZeroVec + BasicVecFunctions<PrimitiveType>
      + Index<usize, Output = PrimitiveType> + IndexMut<usize, Output = PrimitiveType> {

    // let mut res = vec![PrimitiveType::zero(); circuit_num_wires];

    to_be_written_trace.as_mut_slice()[0..input_vec.len()].copy_from_slice(input_vec.as_slice());
    let mut and_cursor = 0usize;
    for wire in public_parameter.big_iw.iter() {
        to_be_written_trace[*wire] = output_and_vec[and_cursor].clone();
        and_cursor += 1;
    }
}

fn extract_block_vec_rep<PrimitiveType, VecType>(
    public_parameter: &PublicParameter,
    block_id: usize, vec_rep: &Vec<VecType>
) -> Vec<VecType>
where
    PrimitiveType: Clone,
    VecType: BasicVecFunctions<PrimitiveType> + Clone
    + Index<usize, Output = PrimitiveType> + IndexMut<usize, Output = PrimitiveType>
    + FromIterator<PrimitiveType> {
    assert_eq!(vec_rep.len(), public_parameter.kappa);
    (0..public_parameter.kappa).map(
        |repetition_id|
            VecType::from_vec(
                vec_rep[repetition_id].as_slice()[
                    public_parameter.big_iw_size * block_id..public_parameter.big_iw_size * (block_id + 1)
                    ].to_vec()
            )
    ).collect::<Vec<VecType>>()
}

fn determine_bit_trace_for_labels_in_garbling(
    bristol_fashion_adaptor: &BristolFashionAdaptor,
    public_parameter: &PublicParameter,
) -> BitVec {
    let mut bit_trace_vec = BitVec::zero_vec(public_parameter.num_wires);
    for gate in bristol_fashion_adaptor.get_gate_vec() {
        match gate.gate_type {
            GateType::XOR => {
                bit_trace_vec[gate.output_wire] = bit_trace_vec[gate.left_input_wire] ^ bit_trace_vec[gate.right_input_wire];
            }
            GateType::AND => {}
            GateType::NOT => {
                bit_trace_vec[gate.output_wire] = 1u8 ^ bit_trace_vec[gate.left_input_wire];
            }
        }
    }
    bit_trace_vec
}