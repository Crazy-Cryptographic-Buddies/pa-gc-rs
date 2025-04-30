use bincode::{Encode};
use blake3::Hash;
use crate::comm_types_and_constants::BLAKE3_HASH_DIGEST_NUM_BYTES;
use crate::functionalities_and_protocols::protocol_pa_2pc::preprocessing_transcript::PreprocessingTranscript;
use crate::functionalities_and_protocols::protocol_pa_2pc::proof_transcript::ProofTranscript;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::{ByteManipulation, Zero};
use crate::value_type::garbled_row::GarbledRow;
use crate::value_type::seed_u8x16::SeedU8x16;

pub fn hash_all_coms(com_vec: &Vec<SeedU8x16>) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for com in com_vec.iter() {
        hasher.update(com);
    }
    hasher.finalize()
}

fn fill_full_digest(current_digest: &mut Hash, num_rep: usize, full_digest: &mut Vec<u8>) {
    for i in 0..num_rep {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&current_digest.as_bytes().clone());
        full_digest[BLAKE3_HASH_DIGEST_NUM_BYTES * i..BLAKE3_HASH_DIGEST_NUM_BYTES * (i+1)]
            .copy_from_slice(hasher.finalize().as_bytes());
        *current_digest = hasher.finalize();
    }
}

pub fn hash_for_garbling<GFVOLE, GFVOLEitH>(
    public_parameter: &PublicParameter,
    first_label: &GFVOLE, second_label: &GFVOLE, gamma: usize, k: u8,
    garbled_row_byte_len: usize
) -> GarbledRow<GFVOLE, GFVOLEitH>
where GFVOLE: ByteManipulation, GFVOLEitH: ByteManipulation
{
    let mut hasher = blake3::Hasher::new();
    hasher.update(&first_label.to_bytes());
    hasher.update(&second_label.to_bytes());
    hasher.update(&gamma.to_le_bytes());
    hasher.update(&[k]);
    let mut current_digest = hasher.finalize();

    let num_rep = (garbled_row_byte_len - 1) / BLAKE3_HASH_DIGEST_NUM_BYTES + 1;
    let mut full_digest = vec![0u8; num_rep * BLAKE3_HASH_DIGEST_NUM_BYTES];
    fill_full_digest(&mut current_digest, num_rep, &mut full_digest);
    let mut cursor = 0usize;
    let mask_u8 = u8::from_bytes(&full_digest, &mut cursor);
    let mask_vole_mac = GFVOLE::from_bytes(&full_digest, &mut cursor);
    let mask_voleith_mac_rep = (0..public_parameter.kappa).map(
        |_| GFVOLEitH::from_bytes(&full_digest, &mut cursor)
    ).collect::<Vec<GFVOLEitH>>();
    let mask_vole_remaining = GFVOLE::from_bytes(&full_digest, &mut cursor);

    // return value
    GarbledRow::new(mask_u8, mask_vole_mac, mask_voleith_mac_rep, mask_vole_remaining)
}

pub fn commit_pb_secret<GFVOLEitH: ByteManipulation>(
    first_bit: u8, voleith_mac_vec: &Vec<GFVOLEitH>, randomness: &SeedU8x16
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&first_bit.to_bytes());
    let mut voleith_mac_byte_vec = vec![0u8; GFVOLEitH::num_bytes() * voleith_mac_vec.len()];
    for (i, voleith_mac) in voleith_mac_vec.iter().enumerate() {
        voleith_mac_byte_vec[GFVOLEitH::num_bytes() * i..GFVOLEitH::num_bytes() * (i+1)]
            .copy_from_slice(&voleith_mac.to_bytes());
    }
    hasher.update(randomness);
    hasher.finalize()
}

pub fn hash_to_determine_permutation_rep<GFVOLE, GFVOLEitH>(
    public_parameter: &PublicParameter,
    preprocessing_transcript: &PreprocessingTranscript<GFVOLE, GFVOLEitH>,
) -> (Vec<Vec<usize>>, Hash)
where GFVOLE: Encode, GFVOLEitH: Encode {
    let mut hasher = blake3::Hasher::new();
    hasher.update(public_parameter.to_byte_vec());
    hasher.update(preprocessing_transcript.to_byte_vec().as_slice());
    let mut current_digest = hasher.finalize();
    let num_rep = (public_parameter.kappa * public_parameter.big_l * u32::num_bytes() - 1) / BLAKE3_HASH_DIGEST_NUM_BYTES + 1;
    let mut full_digest = vec![0u8; num_rep * BLAKE3_HASH_DIGEST_NUM_BYTES];
    fill_full_digest(&mut current_digest, num_rep, &mut full_digest);
    
    let mut permutation_rep = vec![(0..public_parameter.big_l).collect::<Vec<usize>>(); public_parameter.kappa];
    let mut cursor = 0usize;
    for repetition_id in 0..public_parameter.kappa {
        for i in (0..public_parameter.big_l).rev() {
            let j = u32::from_bytes(&full_digest, &mut cursor) % (i as u32 + 1u32);
            permutation_rep[repetition_id].swap(i, j as usize);
        }
    }

    (permutation_rep, current_digest)
}

pub fn hash_to_determine_nabla_rep<GFVOLE, GFVOLEitH>(
    public_parameter: &PublicParameter,
    auxiliary_input: &Hash,
    proof_transcript: &ProofTranscript<GFVOLE, GFVOLEitH>,
) -> (Vec<GFVOLEitH>, Vec<GFVOLEitH>)
where GFVOLE: Encode + Zero + Clone, GFVOLEitH: Encode + Zero + Clone + ByteManipulation {
    let mut hasher = blake3::Hasher::new();
    hasher.update(auxiliary_input.as_bytes());
    hasher.update(proof_transcript.to_byte_vec().as_slice());
    let mut current_digest = hasher.finalize();
    let num_rep = (public_parameter.kappa * GFVOLEitH::num_bytes() * 2 - 1) / BLAKE3_HASH_DIGEST_NUM_BYTES + 1;
    let mut full_digest = vec![0u8; num_rep * BLAKE3_HASH_DIGEST_NUM_BYTES];
    fill_full_digest(&mut current_digest, num_rep, &mut full_digest);
    
    let mut nabla_a_rep = vec![GFVOLEitH::zero(); public_parameter.kappa];
    let mut nabla_b_rep = vec![GFVOLEitH::zero(); public_parameter.kappa];

    let mut cursor = 0usize;
    for repetition_id in 0..public_parameter.kappa {
        nabla_a_rep[repetition_id] = GFVOLEitH::from_bytes(&full_digest, &mut cursor);
        nabla_b_rep[repetition_id] = GFVOLEitH::from_bytes(&full_digest, &mut cursor);
    }
    
    (nabla_a_rep, nabla_b_rep)
}