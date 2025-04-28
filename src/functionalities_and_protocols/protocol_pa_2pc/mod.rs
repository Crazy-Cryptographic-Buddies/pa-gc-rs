use std::ops::{Index, IndexMut};
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::vec_type::{BasicVecFunctions, Split, ZeroVec};

mod test;
mod prover_in_pa_2pc;
mod verifier_in_pa_2pc;

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