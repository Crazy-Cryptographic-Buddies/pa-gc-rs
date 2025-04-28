use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::Zero;
use crate::vec_type::{BasicVecFunctions, ZeroVec};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

pub struct ProofTranscript<GFVOLE, GFVOLEitH> {

    pub pa_published_output_r_bit_vec: BitVec,
    pub pa_published_output_vole_mac_r_vec: GFVec<GFVOLE>,
    pub pa_published_output_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,

    pub pb_published_middle_hat_z_bit_vec: BitVec,
    pub pb_published_middle_label_vec: GFVec<GFVOLE>,
    pub pb_published_middle_r_bit_vec: BitVec,
    pub pb_published_middle_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub pb_published_middle_randomness_vec: Vec<SeedU8x16>,
    pub pb_published_output_r_bit_vec: BitVec,
    pub pb_published_output_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,

    pub published_output_bit_vec: BitVec,
}

impl<GFVOLE, GFVOLEitH> ProofTranscript<GFVOLE, GFVOLEitH>
where
    GFVOLE: Zero + Clone,
    GFVOLEitH: Zero + Clone
{

    pub fn new(public_parameter: &PublicParameter) -> Self {
        Self {
            pa_published_output_r_bit_vec: BitVec::zero_vec(public_parameter.big_io_size),
            pa_published_output_vole_mac_r_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_io_size),
            pa_published_output_voleith_mac_r_vec_rep: vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_io_size); public_parameter.kappa],
            pb_published_middle_hat_z_bit_vec: BitVec::zero_vec(public_parameter.big_iw_size),
            pb_published_middle_label_vec:GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            pb_published_middle_r_bit_vec: BitVec::zero_vec(public_parameter.big_iw_size),
            pb_published_middle_voleith_mac_r_vec_rep: vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa],
            pb_published_middle_randomness_vec: vec![SeedU8x16::zero(); public_parameter.big_iw_size],
            pb_published_output_r_bit_vec: BitVec::zero_vec(public_parameter.big_io_size),
            pb_published_output_voleith_mac_r_vec_rep: vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_io_size); public_parameter.kappa],
            published_output_bit_vec: BitVec::zero_vec(public_parameter.big_io_size),
        }
    }

}

