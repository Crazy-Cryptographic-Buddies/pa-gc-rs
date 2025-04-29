use blake3::Hash;
use crate::comm_types_and_constants::BLAKE3_HASH_DIGEST_NUM_BYTES;
use crate::functionalities_and_protocols::states_and_parameters::public_parameter::PublicParameter;
use crate::value_type::ByteManipulation;
use crate::value_type::garbled_row::GarbledRow;
use crate::value_type::seed_u8x16::SeedU8x16;

pub fn hash_all_coms(com_vec: &Vec<SeedU8x16>) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for com in com_vec.iter() {
        hasher.update(com);
    }
    hasher.finalize()
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
    let initial_digest = hasher.finalize();
    let initial_digest_bytes = initial_digest.as_bytes();

    let num_rep = (garbled_row_byte_len - 1) / BLAKE3_HASH_DIGEST_NUM_BYTES + 1;
    let mut full_digest = vec![0u8; num_rep * BLAKE3_HASH_DIGEST_NUM_BYTES];
    for i in 0..num_rep {
        hasher = blake3::Hasher::new();
        hasher.update(&i.to_le_bytes());
        hasher.update(initial_digest_bytes);
        full_digest[BLAKE3_HASH_DIGEST_NUM_BYTES * i..BLAKE3_HASH_DIGEST_NUM_BYTES * (i+1)]
            .copy_from_slice(hasher.finalize().as_bytes());
    }
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