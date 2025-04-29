#[cfg(test)]
mod tests {
    use galois_2p8::Field;

    #[test]
    fn test_galois_2p8_crate() {
        let rijndael_field = galois_2p8::GeneralField::new(
            galois_2p8::IrreducablePolynomial::Poly84310
        );

        let a: u8 = 10;
        let mut vec = Vec::<u8>::new();
        for i in 0..=255 {
            vec.push(rijndael_field.mult(a, i));
            println!("{:?}", i);
        }
        println!("{:?}", vec);
        vec.sort();
        println!("{:?}", vec);
        vec.iter().zip(vec.iter().skip(1)).for_each(|(a, b)| {
            println!("{:?} {:?}", a, b);
            assert_eq!(a + 1, *b);
        })
    }
}