use bincode::{config, encode_to_vec, Encode};
use crate::functionalities_and_protocols::protocol_check_and::check_and_transcript::CheckAndTranscript;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::garbled_row::GarbledRow;
use crate::value_type::seed_u8x16::SeedU8x16;
use crate::value_type::Zero;
use crate::vec_type::ZeroVec;
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;

#[derive(Encode)]
pub struct ProofTranscript<GFVOLE, GFVOLEitH>
where GFVOLE: Encode, GFVOLEitH: Encode {
    // before nabla
    pub pa_published_rm_a_vec_rep: Vec<BitVec>,
    pub pa_published_rm_b_vec_rep: Vec<BitVec>,
    pub pa_published_rm_c_vec_rep: Vec<BitVec>,
    pub pa_published_rm_voleith_mac_a_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub pa_published_rm_voleith_mac_b_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub pa_published_rm_voleith_mac_c_vec_rep: Vec<GFVec<GFVOLEitH>>,

    pub pb_published_rm_a_vec_rep: Vec<BitVec>,
    pub pb_published_rm_b_vec_rep: Vec<BitVec>,
    pub pb_published_rm_c_vec_rep: Vec<BitVec>,
    pub pb_published_rm_voleith_mac_a_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub pb_published_rm_voleith_mac_b_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub pb_published_rm_voleith_mac_c_vec_rep: Vec<GFVec<GFVOLEitH>>,

    pub pa_published_input_r_bit_vec: BitVec,
    // pub pa_published_input_vole_mac_r_vec: GFVec<GFVOLE>,
    pub pa_published_input_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub pb_published_input_r_bit_vec: BitVec,
    // pub pb_published_input_vole_mac_r_vec: GFVec<GFVOLE>,
    pub pb_published_input_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,
    
    pub pa_published_output_r_bit_vec: BitVec,
    pub pa_published_output_vole_mac_r_vec: GFVec<GFVOLE>,
    pub pa_published_output_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,

    pub published_hat_z_input_bit_vec: BitVec,
    pub published_middle_hat_z_bit_vec: BitVec,
    
    pub pb_published_middle_label_vec: GFVec<GFVOLE>,
    pub pb_published_middle_r_bit_vec: BitVec,
    pub pb_published_middle_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,
    pub pb_published_middle_randomness_vec: Vec<SeedU8x16>,
    pub pb_published_output_r_bit_vec: BitVec,
    pub pb_published_output_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,

    pub published_output_bit_vec: BitVec,
    pub published_decrypted_garbled_row: Vec<GarbledRow<GFVOLE, GFVOLEitH>>,
    
    pub check_and_transcript_vec: Vec<CheckAndTranscript<GFVOLEitH>>,
    
    // // after nabla
    // pub pa_decom: Vec<(SeedU8x16, Vec<SeedU8x16>)>,
    // pub pb_decom: Vec<(SeedU8x16, Vec<SeedU8x16>)>,
}

impl<GFVOLE, GFVOLEitH> ProofTranscript<GFVOLE, GFVOLEitH>
where
    GFVOLE: Zero + Clone + Encode,
    GFVOLEitH: Zero + Clone + Encode
{

    pub fn new(
        public_parameter: &PublicParameter,
        
        pa_published_rm_a_vec_rep: Vec<BitVec>,
        pa_published_rm_b_vec_rep: Vec<BitVec>,
        pa_published_rm_c_vec_rep: Vec<BitVec>,
        pa_published_rm_voleith_mac_a_vec_rep: Vec<GFVec<GFVOLEitH>>,
        pa_published_rm_voleith_mac_b_vec_rep: Vec<GFVec<GFVOLEitH>>,
        pa_published_rm_voleith_mac_c_vec_rep: Vec<GFVec<GFVOLEitH>>,

        pb_published_rm_a_vec_rep: Vec<BitVec>,
        pb_published_rm_b_vec_rep: Vec<BitVec>,
        pb_published_rm_c_vec_rep: Vec<BitVec>,
        pb_published_rm_voleith_mac_a_vec_rep: Vec<GFVec<GFVOLEitH>>,
        pb_published_rm_voleith_mac_b_vec_rep: Vec<GFVec<GFVOLEitH>>,
        pb_published_rm_voleith_mac_c_vec_rep: Vec<GFVec<GFVOLEitH>>,
        
        check_and_transcript_vec: Vec<CheckAndTranscript<GFVOLEitH>>,

        pa_published_input_r_bit_vec: BitVec,
        // pa_published_input_vole_mac_r_vec: GFVec<GFVOLE>,
        pa_published_input_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,
        pb_published_input_r_bit_vec: BitVec,
        // pb_published_input_vole_mac_r_vec: GFVec<GFVOLE>,
        pb_published_input_voleith_mac_r_vec_rep: Vec<GFVec<GFVOLEitH>>,
    ) -> Self {
        Self {
            pa_published_rm_a_vec_rep,
            pa_published_rm_b_vec_rep,
            pa_published_rm_c_vec_rep,
            pa_published_rm_voleith_mac_a_vec_rep,
            pa_published_rm_voleith_mac_c_vec_rep,
            pa_published_rm_voleith_mac_b_vec_rep,

            pb_published_rm_a_vec_rep,
            pb_published_rm_b_vec_rep,
            pb_published_rm_c_vec_rep,
            pb_published_rm_voleith_mac_a_vec_rep,
            pb_published_rm_voleith_mac_c_vec_rep,
            pb_published_rm_voleith_mac_b_vec_rep,

            pa_published_input_r_bit_vec,
            // pa_published_input_vole_mac_r_vec,
            pa_published_input_voleith_mac_r_vec_rep,
            pb_published_input_r_bit_vec,
            // pb_published_input_vole_mac_r_vec,
            pb_published_input_voleith_mac_r_vec_rep,
            
            pa_published_output_r_bit_vec: BitVec::zero_vec(public_parameter.big_io_size),
            pa_published_output_vole_mac_r_vec: GFVec::<GFVOLE>::zero_vec(public_parameter.big_io_size),
            pa_published_output_voleith_mac_r_vec_rep: vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_io_size); public_parameter.kappa],
            published_hat_z_input_bit_vec: BitVec::zero_vec(public_parameter.num_input_bits),
            published_middle_hat_z_bit_vec: BitVec::zero_vec(public_parameter.big_iw_size),
            pb_published_middle_label_vec:GFVec::<GFVOLE>::zero_vec(public_parameter.big_iw_size),
            pb_published_middle_r_bit_vec: BitVec::zero_vec(public_parameter.big_iw_size),
            pb_published_middle_voleith_mac_r_vec_rep: vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_iw_size); public_parameter.kappa],
            pb_published_middle_randomness_vec: vec![SeedU8x16::zero(); public_parameter.big_iw_size],
            pb_published_output_r_bit_vec: BitVec::zero_vec(public_parameter.big_io_size),
            pb_published_output_voleith_mac_r_vec_rep: vec![GFVec::<GFVOLEitH>::zero_vec(public_parameter.big_io_size); public_parameter.kappa],
            published_output_bit_vec: BitVec::zero_vec(public_parameter.big_io_size),
            published_decrypted_garbled_row: vec![GarbledRow::zero(); public_parameter.big_iw_size],
            check_and_transcript_vec,
            // pa_decom: Vec::new(),
            // pb_decom: Vec::new(),
        }
    }

    pub fn to_byte_vec(&self) -> Vec<u8> {
        let config = config::standard();

        encode_to_vec(self, config).unwrap()
    }

}

