#[cfg(test)]
mod tests {
    use bincode::{config, decode_from_slice, encode_to_vec, Decode, Encode};

    #[derive(Debug, Encode, Decode, Eq, PartialEq)]
    struct MyStruct {
        a: u32,
        b: u16,
        c: u64
    }

    #[test]
    fn test_bincode() {
        let config = config::standard();
        let s = MyStruct { a: 4342, b: 7, c: 374538583487 };
        let encoded_byte_vec = encode_to_vec(&s, config).unwrap();
        let encoded_byte_vec_2: Vec<u8> = encode_to_vec(&s, config).unwrap();
        println!("{:?}", encoded_byte_vec);
        println!("{:?}", encoded_byte_vec_2);

        let (decoded_vec, _): (MyStruct, usize) = decode_from_slice(&encoded_byte_vec, config).unwrap();
        assert_eq!(decoded_vec, s);
    }
}