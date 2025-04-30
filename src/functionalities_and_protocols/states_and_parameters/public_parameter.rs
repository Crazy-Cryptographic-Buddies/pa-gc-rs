use bincode::{config, encode_to_vec};
use crate::bristol_fashion_adaptor::bristol_fashion_adaptor::BristolFashionAdaptor;
use crate::functionalities_and_protocols::all_in_one_vc::one_to_two_prg::OneToTwoPRG;
use crate::value_type::ByteManipulation;
use crate::value_type::seed_u8x16::SeedU8x16;

pub struct PublicParameter {
    pub tau: u8,
    pub kappa: usize,
    pub one_to_two_prg: OneToTwoPRG,
    // pub big_ia_size: usize,
    // pub big_ib_size: usize,
    pub bs: usize,
    pub rm: usize,
    pub big_iw_size: usize,
    pub big_io_size: usize,
    pub big_l: usize,
    pub big_n: usize,
    pub num_input_bits: usize,
    pub num_wires: usize,
    pub big_ia: Vec<usize>,
    pub big_ib: Vec<usize>,
    pub big_iw: Vec<usize>,
    pub big_io: Vec<usize>,
    pub garbled_row_byte_len: usize,
    byte_vec: Vec<u8>,
}

impl PublicParameter {
    pub fn new<GFVOLE: ByteManipulation, GFVOLEitH: ByteManipulation>(
        bristol_fashion_adaptor: &BristolFashionAdaptor,
        tau: u8, kappa: usize, master_key_for_one_to_two_prg: SeedU8x16, 
        big_ia: Vec<usize>, big_ib: Vec<usize>,
        bs: usize, rm: usize, // these variables are employed for determining big_l
    ) -> Self {
        let num_and_gates = bristol_fashion_adaptor.get_and_gate_output_wire_vec().len();
        let big_l = bs * num_and_gates + rm;
        let big_io_size = bristol_fashion_adaptor.get_num_output_bits();
        let byte_vec = Self::make_byte_vec(tau, kappa, &master_key_for_one_to_two_prg, &big_ia, &big_ib, bs, rm);
        Self {
            tau,
            kappa,
            one_to_two_prg: OneToTwoPRG::new(&master_key_for_one_to_two_prg),
            // big_ia_size: big_ia.len(),
            // big_ib_size: big_ib.len(),
            bs,
            rm,
            big_iw_size: num_and_gates,
            big_io_size,
            big_l,
            big_n: big_ia.len() + big_ib.len() + 2 * num_and_gates + 3 * big_l,
            num_input_bits: big_ia.len() + big_ib.len(),
            big_ia,
            big_ib,
            big_io: bristol_fashion_adaptor.get_output_wire_vec().clone(),
            num_wires: bristol_fashion_adaptor.get_num_wires(),
            big_iw: bristol_fashion_adaptor.get_and_gate_output_wire_vec().clone(),
            garbled_row_byte_len: 1 + GFVOLE::num_bytes() + GFVOLEitH::num_bytes() * kappa + GFVOLE::num_bytes(),
            byte_vec,
        }
    }
    
    fn make_byte_vec(
        tau: u8, kappa: usize, master_key_for_one_to_two_prg: &SeedU8x16,
        big_ia: &Vec<usize>, big_ib: &Vec<usize>,
        bs: usize, rm: usize,
    ) -> Vec<u8> {
        let config = config::standard();
        
        let mut res = Vec::<u8>::new();
        
        res.append(&mut tau.to_le_bytes().to_vec());
        res.append(&mut kappa.to_le_bytes().to_vec());
        res.append(&mut master_key_for_one_to_two_prg.to_vec());
        res.append(&mut encode_to_vec(&big_ia, config).unwrap());
        res.append(&mut encode_to_vec(&big_ib, config).unwrap());
        res.append(&mut bs.to_le_bytes().to_vec());
        res.append(&mut rm.to_le_bytes().to_vec());
        
        res
    }
    
    pub fn to_byte_vec(&self) -> &Vec<u8> {
        &self.byte_vec
    }
}