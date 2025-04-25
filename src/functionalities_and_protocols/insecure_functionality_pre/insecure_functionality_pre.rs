use rand::Rng;
use crate::value_type::{GFAddition, GFMultiplyingBit, InsecureRandom, Zero};
use crate::vec_type::{
    bit_vec::BitVec,
    gf_vec::GFVec,
};

pub struct InsecureFunctionalityPre;

impl InsecureFunctionalityPre {

    fn generate_random_vole_macs_and_keys<GFVOLE: InsecureRandom + GFAddition + GFMultiplyingBit+ Clone + Zero>(
        delta: &GFVOLE,
        rand_bit_vec: &BitVec,
    ) -> (GFVec<GFVOLE>, GFVec<GFVOLE>) {
        let mut vole_mac_vec = GFVec::<GFVOLE>::new();
        let mut vole_key_vec = GFVec::<GFVOLE>::new();
        for bit in rand_bit_vec.iter() {
            let mac = GFVOLE::insecurely_random();
            let key = mac.gf_add(&delta.gf_multiply_bit(*bit));
            vole_mac_vec.push(mac);
            vole_key_vec.push(key);
        }
        (vole_mac_vec, vole_key_vec)
    }

    pub fn generate_random_tuples<GFVOLE, GFVOLEitH>(
        len: usize,
        delta: &GFVOLE,
        rand_bit_vec: &mut Option<BitVec>,
        vole_mac_rand_vec: &mut Option<GFVec<GFVOLE>>,
        vole_key_rand_vec: &mut Option<GFVec<GFVOLE>>,
    ) 
    where GFVOLE: InsecureRandom + GFAddition + Clone + GFMultiplyingBit + Zero {
        let mut rng = rand::rng();
        *rand_bit_vec = Some(
            BitVec::from_vec(
                (0..len).into_iter().map(
                    |_| rng.random::<u8>() & 1u8
                ).collect()
            )
        );

        let (
            vole_mac_vec, vole_key_vec
        ) = Self::generate_random_vole_macs_and_keys(
            delta, rand_bit_vec.as_ref().unwrap(),
        );
        *vole_mac_rand_vec = Some(vole_mac_vec);
        *vole_key_rand_vec = Some(vole_key_vec);
    }
    
    pub fn generate_random_and_tuples(
        kappa: usize, len: usize, 
        pa_rand_a_bit_vec_rep: &mut Option<Vec<BitVec>>, 
        pa_rand_b_bit_vec_rep: &mut Option<Vec<BitVec>>, 
        pa_rand_c_bit_vec_rep: &mut Option<Vec<BitVec>>,
        pb_rand_a_bit_vec_rep: &mut Option<Vec<BitVec>>, 
        pb_rand_b_bit_vec_rep: &mut Option<Vec<BitVec>>, 
        pb_rand_c_bit_vec_rep: &mut Option<Vec<BitVec>>
    ) {
        *pa_rand_a_bit_vec_rep = Some(Vec::new());
        *pa_rand_b_bit_vec_rep = Some(Vec::new());
        *pa_rand_c_bit_vec_rep = Some(Vec::new());
        *pb_rand_a_bit_vec_rep = Some(Vec::new());
        *pb_rand_b_bit_vec_rep = Some(Vec::new());
        *pb_rand_c_bit_vec_rep = Some(Vec::new());
        let mut rng = rand::rng();
        (0..kappa).into_iter().for_each(|_| {
            let mut pa_rand_a_bit_vec= BitVec::new();
            let mut pa_rand_b_bit_vec = BitVec::new();
            let mut pa_rand_c_bit_vec = BitVec::new();
            let mut pb_rand_a_bit_vec = BitVec::new();
            let mut pb_rand_b_bit_vec = BitVec::new();
            let mut pb_rand_c_bit_vec = BitVec::new();
            for _ in 0..len {
                pa_rand_a_bit_vec.push(rng.random::<u8>() & 1);
                pa_rand_b_bit_vec.push(rng.random::<u8>() & 1);
                pa_rand_c_bit_vec.push(rng.random::<u8>() & 1);
                pb_rand_a_bit_vec.push(rng.random::<u8>() & 1);
                pb_rand_b_bit_vec.push(rng.random::<u8>() & 1);
                pb_rand_c_bit_vec.push(
                    (pa_rand_a_bit_vec.iter().last().unwrap() ^ pb_rand_a_bit_vec.iter().last().unwrap())
                        & (pa_rand_b_bit_vec.iter().last().unwrap() ^ pb_rand_b_bit_vec.iter().last().unwrap())
                        ^ pa_rand_c_bit_vec.iter().last().unwrap()
                );
            }
            pa_rand_a_bit_vec_rep.as_mut().unwrap().push(pa_rand_a_bit_vec);
            pa_rand_b_bit_vec_rep.as_mut().unwrap().push(pa_rand_b_bit_vec);
            pa_rand_c_bit_vec_rep.as_mut().unwrap().push(pa_rand_c_bit_vec);
            pb_rand_a_bit_vec_rep.as_mut().unwrap().push(pb_rand_a_bit_vec);
            pb_rand_b_bit_vec_rep.as_mut().unwrap().push(pb_rand_b_bit_vec);
            pb_rand_c_bit_vec_rep.as_mut().unwrap().push(pb_rand_c_bit_vec);
        });
    }
    
    pub fn generate_random_authenticated_and_tuples<GFVOLE, GFVOLEitH>(
        delta_a: &GFVOLE, 
        pa_a_bit: u8, 
        pa_b_bit: u8, 
        pa_c_bit: &mut u8, pa_vole_mac_c: &mut GFVOLE, pa_vole_key_c: &mut GFVOLE,
        delta_b: &GFVOLE,
        pb_a_bit: u8, 
        pb_b_bit: u8, 
        pb_c_bit: &mut u8, pb_vole_mac_c: &mut GFVOLE, pb_vole_key_c: &mut GFVOLE,
    )
    where GFVOLE: InsecureRandom + GFAddition + GFMultiplyingBit {
        let mut rng = rand::rng();
        *pa_c_bit = rng.random::<u8>() & 1;
        *pb_c_bit = (pa_a_bit ^ pb_a_bit) & (pa_b_bit ^ pb_b_bit) ^ *pa_c_bit;
        *pa_vole_mac_c = GFVOLE::insecurely_random();
        *pa_vole_key_c = pa_vole_mac_c.gf_add(&delta_b.gf_multiply_bit(*pa_c_bit));
        *pb_vole_mac_c = GFVOLE::insecurely_random();
        *pb_vole_key_c = pb_vole_mac_c.gf_add(&delta_a.gf_multiply_bit(*pb_c_bit));
    }
}

#[cfg(test)]
mod tests {
    use crate::value_type::Zero;
    use itertools::izip;
    use rand::Rng;
    use crate::functionalities_and_protocols::insecure_functionality_pre::insecure_functionality_pre::InsecureFunctionalityPre;
    use crate::value_type::gf2p256::GF2p256;
    use crate::vec_type::bit_vec::BitVec;
    use crate::vec_type::gf_vec::GFVec;
    use crate::value_type::{GFAddition, GFMultiplyingBit, InsecureRandom};
    use crate::value_type::gf2p8::GF2p8;

    #[test]
    fn test_functionality_pre_generating_random_tuples() {
        let delta_a = GF2p256::insecurely_random();
        let delta_b = GF2p256::insecurely_random();
        println!("delta_a: {:?}", delta_a);
        println!("delta_b: {:?}", delta_b);

        let num_random_tuples = 100;
        let kappa = 10;

        let mut rand_bit_vec: Option<BitVec> = None;
        let mut vole_mac_rand_vec: Option<GFVec<GF2p256>> = None;
        let mut vole_key_rand_vec: Option<GFVec<GF2p256>> = None;

        InsecureFunctionalityPre::generate_random_tuples::<GF2p256, GF2p8>(
            num_random_tuples, &delta_a,
            &mut rand_bit_vec, &mut vole_mac_rand_vec, &mut vole_key_rand_vec
        );

        // check the lengths
        assert_eq!(rand_bit_vec.as_ref().unwrap().len(), num_random_tuples);
        assert_eq!(vole_mac_rand_vec.as_ref().unwrap().len(), num_random_tuples);
        assert_eq!(vole_key_rand_vec.as_ref().unwrap().len(), num_random_tuples);

        for (rand_bit, vole_mac_rand, vole_key_rand) in izip!(
        rand_bit_vec.as_ref().unwrap().iter(), 
        vole_mac_rand_vec.as_ref().unwrap().iter(), 
        vole_key_rand_vec.as_ref().unwrap().iter()
    ) {
            println!("rand_bit, vole_mac_rand, vole_key_rand: {:?} {:?} {:?}",
                     rand_bit, vole_mac_rand, vole_key_rand);
            assert_eq!(*vole_key_rand, vole_mac_rand.gf_add(&delta_a.gf_multiply_bit(*rand_bit)));
        }
        println!("test_functionality_pre_generating_random_tuples passed");
    }

    #[test]
    fn test_functionality_pre_generating_random_and_tuples () {
        let kappa = 10;
        let num_random_and_tuples = 100;
        let mut pa_rand_a_bit_vec_rep: Option<Vec<BitVec>> = None;
        let mut pa_rand_b_bit_vec_rep: Option<Vec<BitVec>> = None;
        let mut pa_rand_c_bit_vec_rep: Option<Vec<BitVec>> = None;
        let mut pb_rand_a_bit_vec_rep: Option<Vec<BitVec>> = None;
        let mut pb_rand_b_bit_vec_rep: Option<Vec<BitVec>> = None;
        let mut pb_rand_c_bit_vec_rep: Option<Vec<BitVec>> = None;
        InsecureFunctionalityPre::generate_random_and_tuples(
            kappa, num_random_and_tuples,
            &mut pa_rand_a_bit_vec_rep, &mut pa_rand_b_bit_vec_rep, &mut pa_rand_c_bit_vec_rep,
            &mut pb_rand_a_bit_vec_rep, &mut pb_rand_b_bit_vec_rep, &mut pb_rand_c_bit_vec_rep
        );
        
        for (
            pa_rand_a_bit_vec, pa_rand_b_bit_vec, pa_rand_c_bit_vec,
            pb_rand_a_bit_vec, pb_rand_b_bit_vec, pb_rand_c_bit_vec
        ) in izip!(
            pa_rand_a_bit_vec_rep.as_ref().unwrap().iter(), pa_rand_b_bit_vec_rep.as_ref().unwrap().iter(), pa_rand_c_bit_vec_rep.as_ref().unwrap().iter(),
            pb_rand_a_bit_vec_rep.as_ref().unwrap().iter(), pb_rand_b_bit_vec_rep.as_ref().unwrap().iter(), pb_rand_c_bit_vec_rep.as_ref().unwrap().iter()
        ) {
            for (
                pa_rand_a_bit, pa_rand_b_bit, pa_rand_c_bit, 
                pb_rand_a_bit, pb_rand_b_bit, pb_rand_c_bit
            ) in izip!(
                pa_rand_a_bit_vec.iter(), pa_rand_b_bit_vec.iter(), pa_rand_c_bit_vec.iter(),
                pb_rand_a_bit_vec.iter(), pb_rand_b_bit_vec.iter(), pb_rand_c_bit_vec.iter()
            ) {
                println!(
                    "pa_rand_a, pa_rand_b, pa_rand_c, pb_rand_a, pb_rand_b, pb_rand_c: {:?} {:?} {:?} {:?} {:?} {:?}", 
                    pa_rand_a_bit, pa_rand_b_bit, pa_rand_c_bit,
                    pb_rand_a_bit, pb_rand_b_bit, pb_rand_c_bit
                );
                assert_eq!(pa_rand_c_bit ^ pb_rand_c_bit, (pa_rand_a_bit ^ pb_rand_a_bit) & (pa_rand_b_bit ^ pb_rand_b_bit));
            }
        }
        println!("test_functionality_pre_generating_random_and_tuples passed!");
    }
    
    #[test]
    fn test_functionality_pre_generating_random_authenticated_and_tuples () {
        let delta_a = GF2p256::insecurely_random();
        let delta_b = GF2p256::insecurely_random();
        println!("delta_a: {:?}", delta_a);
        println!("delta_b: {:?}", delta_b);

        let mut rng = rand::rng();
        let pa_a_bit: u8 = rng.random::<u8>() & 1;
        let pa_b_bit: u8 = rng.random::<u8>() & 1;
        let pb_a_bit: u8 = rng.random::<u8>() & 1;
        let pb_b_bit: u8 = rng.random::<u8>() & 1;
        
        let mut pa_c_bit: u8 = 0;
        let mut pb_c_bit: u8 = 0;
        let mut pa_vole_mac_c = GF2p256::zero();
        let mut pa_vole_key_c = GF2p256::zero();
        let mut pb_vole_mac_c = GF2p256::zero();
        let mut pb_vole_key_c = GF2p256::zero();
        InsecureFunctionalityPre::generate_random_authenticated_and_tuples::<GF2p256, GF2p8>(
            &delta_a, pa_a_bit, pa_b_bit, &mut pa_c_bit, &mut pa_vole_mac_c, &mut pa_vole_key_c,
            &delta_b, pb_a_bit, pb_b_bit, &mut pb_c_bit, &mut pb_vole_mac_c, &mut pb_vole_key_c
        );
        println!("pa_a_bit, pa_b_bit, pa_c_bit: {:?}, {:?}, {:?}", pa_a_bit, pa_b_bit, pa_c_bit);
        println!("pb_a_bit, pb_b_bit, pb_c_bit: {:?}, {:?}, {:?}", pb_a_bit, pb_b_bit, pb_c_bit);
        println!("pa_vole_mac_c, pa_vole_key_c: {:?}, {:?}", pa_vole_mac_c, pa_vole_key_c);
        println!("pb_vole_mac_c, pb_vole_key_c: {:?}, {:?}", pb_vole_mac_c, pb_vole_key_c);
        assert_eq!(pa_c_bit ^ pb_c_bit, (pa_a_bit ^ pb_a_bit) & (pa_b_bit ^ pb_b_bit));
        assert_eq!(pa_vole_key_c, pa_vole_mac_c.gf_add(&delta_b.gf_multiply_bit(pa_c_bit)));
        assert_eq!(pb_vole_key_c, pb_vole_mac_c.gf_add(&delta_a.gf_multiply_bit(pb_c_bit)));
        println!("test_functionality_pre_generating_random_authenticated_and_tuples passed!");
    }
}