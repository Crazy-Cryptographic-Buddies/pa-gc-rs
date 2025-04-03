use galois_field::*;

#[test]
fn test_gf16() {
    let char: u32 = 2;
    let n = 4;
    let primitive_polynomial = Polynomial::get_primitive_polynomial(char, n);
    let x:FiniteField = FiniteField{
        char,
        element: Element::GaloisField{element:vec![0,1],primitive_polynomial:primitive_polynomial.clone()} // i.e. [0,1] = x -> 2 over GF(2^4)
    };
    let y:FiniteField = FiniteField{
        char,
        element: Element::GaloisField{element:vec![0,0,1,1],primitive_polynomial:primitive_polynomial.clone()} // i.e. [0,0,1,1] = x^3 + x^2 -> 12 over GF(2^4)
    };
    println!("x:{:?}", x.clone().element);
    println!("y:{:?}", y.clone().element);
    println!("x + y = {:?}", (x.clone() + y.clone()).element);
    println!("x - y = {:?}", (x.clone() - y.clone()).element);
    println!("x * y = {:?}", (x.clone() * y.clone()).element);
    println!("x / y = {:?}", (x.clone() / y.clone()).element);
    let a = x * y;
    println!("a = {:?}", a.element);
}