pub struct Conversion;

impl Conversion {
    // fn hex_char_to_bits(c: char) -> Vec<u8> {
    //     let mut bit_vec: Vec<u8> = Vec::new();
    //     let c_value: u8 = match c {
    //         '0' => 0,
    //         '1' => 1,
    //         '2' => 2,
    //         '3' => 3,
    //         '4' => 4,
    //         '5' => 5,
    //         '6' => 6,
    //         '7' => 7,
    //         '8' => 8,
    //         '9' => 9,
    //         'a' => 10,
    //         'b' => 11,
    //         'c' => 12,
    //         'd' => 13,
    //         'e' => 14,
    //         'f' => 15,
    //         _ => panic!("Invalid hex character: {}", c),
    //     };
    //     for i in (0..NUM_BITS_PER_HEX).rev() {
    //         bit_vec.push((c_value >> i) & 1);
    //     }
    //     bit_vec
    // }

    // fn bits_to_hex_char(bit_vec: Vec<u8>) -> char {
    //     assert_eq!(bit_vec.len(), NUM_BITS_PER_HEX);
    //     let mut c_value: u8 = 0;
    //     for i in 0..NUM_BITS_PER_HEX {
    //         c_value |= bit_vec[NUM_BITS_PER_HEX - i - 1] << i;
    //     }
    //     match c_value {
    //         0 => '0',
    //         1 => '1',
    //         2 => '2',
    //         3 => '3',
    //         4 => '4',
    //         5 => '5',
    //         6 => '6',
    //         7 => '7',
    //         8 => '8',
    //         9 => '9',
    //         10 => 'a',
    //         11 => 'b',
    //         12 => 'c',
    //         13 => 'd',
    //         14 => 'e',
    //         15 => 'f',
    //         _ => panic!("Invalid value: {:?}", c_value),
    //     }
    // }

    // pub fn hex_string_to_bit_vec(hex_string: &String) -> Vec<u8> {
    //     let mut bit_vec: Vec<u8> = Vec::new();
    //     for c in hex_string.chars() {
    //         bit_vec.append(&mut Conversion::hex_char_to_bits(c));
    //     }
    //     bit_vec
    // }

    // pub fn bit_vec_to_hex_string(bit_vec: &Vec<u8>) -> String {
    //     assert_eq!(bit_vec.len() % NUM_BITS_PER_HEX, 0);
    //     let mut hex_string: String = String::new();
    //     for i in 0..bit_vec.len() / NUM_BITS_PER_HEX {
    //         hex_string.push(
    //             Conversion::bits_to_hex_char(
    //                 bit_vec[i * NUM_BITS_PER_HEX..(i + 1) * NUM_BITS_PER_HEX].to_vec()
    //             )
    //         );
    //     }
    //     hex_string
    // }
    
    pub fn u64_to_bit_vec(u64_value: u64) -> Vec<u8> {
        let mut bit_vec: Vec<u8> = Vec::new();
        for i in 0..64 {
            bit_vec.push(((u64_value >> i) & 1) as u8);
        }
        bit_vec   
    }
    
    // pub fn bit_vec_to_u64(bit_vec: &Vec<u8>) -> u64 {
    //     assert_eq!(bit_vec.len(), 64);
    //     let mut u64_value: u64 = 0;
    //     for i in 0..64 {
    //         u64_value |= (bit_vec[i] as u64) << i;
    //     }
    //     u64_value
    // }
}