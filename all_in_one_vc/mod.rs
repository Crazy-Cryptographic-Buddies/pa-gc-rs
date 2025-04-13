mod all_in_one_vc_for_prover;
mod one_to_two_prg;
mod generating_message_and_com_prg;
mod all_in_one_vc_for_verifier;

type SeedU8x16 = [u8; 16];
type Message = Vec<u8>;

const AES_BYTE_LEN: usize = 16;