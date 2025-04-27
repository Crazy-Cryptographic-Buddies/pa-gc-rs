use rand::Rng;
use crate::value_type::{GFAddition, GFMultiplyingBit, InsecureRandom, Zero};
use crate::vec_type::{bit_vec::BitVec, gf_vec::GFVec};

pub struct InsecureFunctionalityPre;

impl InsecureFunctionalityPre {
    pub fn generate_delta<GFVOLE: InsecureRandom>(delta: &mut Option<GFVOLE>) {
        *delta = Some(GFVOLE::insecurely_random());
    }

    fn generate_random_vole_macs_and_keys<GFVOLE: InsecureRandom + GFAddition + GFMultiplyingBit + Clone + Zero>(
        delta: &GFVOLE,
        rand_bit_vec: &BitVec,
        vole_mac_rand_vec: &mut GFVec<GFVOLE>,
        vole_key_rand_vec: &mut GFVec<GFVOLE>,
    ) {
        for (i, bit) in (0..rand_bit_vec.len()).zip(rand_bit_vec.iter()) {
            let mac = GFVOLE::insecurely_random();
            let key = mac.gf_add(&delta.gf_multiply_bit(*bit));
            vole_mac_rand_vec[i] = mac;
            vole_key_rand_vec[i] = key;
        }
    }

    pub fn generate_random_tuples<GFVOLE, GFVOLEitH>(
        len: usize,
        delta: &GFVOLE,
        rand_bit_vec: &mut BitVec,
        vole_mac_rand_vec: &mut GFVec<GFVOLE>,
        vole_key_rand_vec: &mut GFVec<GFVOLE>,
    )
    where
        GFVOLE: InsecureRandom + GFAddition + Clone + GFMultiplyingBit + Zero
    {
        let mut rng = rand::rng();
        (0..len).for_each(
            |i| {
                rand_bit_vec[i] = rng.random::<u8>() & 1u8;
            }
        );

        Self::generate_random_vole_macs_and_keys(
            delta, rand_bit_vec, vole_mac_rand_vec, vole_key_rand_vec
        );
    }

    pub fn generate_random_and_tuples(
        kappa: usize, len: usize,
        pa_rand_a_bit_vec_rep: &mut Vec<BitVec>,
        pa_rand_b_bit_vec_rep: &mut Vec<BitVec>,
        pa_rand_c_bit_vec_rep: &mut Vec<BitVec>,
        pb_rand_a_bit_vec_rep: &mut Vec<BitVec>,
        pb_rand_b_bit_vec_rep: &mut Vec<BitVec>,
        pb_rand_c_bit_vec_rep: &mut Vec<BitVec>
    ) {
        let mut rng = rand::rng();
        for repetition_id in 0..kappa {
            for i in 0..len {
                pa_rand_a_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
                pa_rand_b_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
                pa_rand_c_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
                pb_rand_a_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
                pb_rand_b_bit_vec_rep[repetition_id][i] = rng.random::<u8>() & 1;
                pb_rand_c_bit_vec_rep[repetition_id][i] =
                    (pa_rand_a_bit_vec_rep[repetition_id][i] ^ pb_rand_a_bit_vec_rep[repetition_id][i])
                        & (pa_rand_b_bit_vec_rep[repetition_id][i] ^ pb_rand_b_bit_vec_rep[repetition_id][i])
                        ^ pa_rand_c_bit_vec_rep[repetition_id][i];
            }
        }
    }

    pub fn generate_random_authenticated_and_tuples<GFVOLE>(
        delta_a: &GFVOLE,
        pa_left_input_bit: u8,
        pa_right_input_bit: u8,
        pa_output_bit: &mut u8, pa_vole_mac_output: &mut GFVOLE, pa_vole_key_output: &mut GFVOLE,
        delta_b: &GFVOLE,
        pb_left_input_bit: u8,
        pb_right_input_bit: u8,
        pb_output_bit: &mut u8, pb_vole_mac_output: &mut GFVOLE, pb_vole_key_output: &mut GFVOLE,
    )
    where
        GFVOLE: InsecureRandom + GFAddition + GFMultiplyingBit
    {
        let mut rng = rand::rng();
        *pa_output_bit = rng.random::<u8>() & 1;
        *pb_output_bit = (pa_left_input_bit ^ pb_left_input_bit) & (pa_right_input_bit ^ pb_right_input_bit) ^ *pa_output_bit;
        *pa_vole_mac_output = GFVOLE::insecurely_random();
        *pa_vole_key_output = pa_vole_mac_output.gf_add(&delta_b.gf_multiply_bit(*pa_output_bit));
        *pb_vole_mac_output = GFVOLE::insecurely_random();
        *pb_vole_key_output = pb_vole_mac_output.gf_add(&delta_a.gf_multiply_bit(*pb_output_bit));
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
    use crate::vec_type::ZeroVec;

    #[test]
    fn test_functionality_pre_generating_random_tuples() {
        let delta_a = GF2p256::insecurely_random();
        let delta_b = GF2p256::insecurely_random();
        println!("delta_a: {:?}", delta_a);
        println!("delta_b: {:?}", delta_b);

        let num_random_tuples = 100;

        let mut rand_bit_vec = BitVec::zero_vec(num_random_tuples);
        let mut vole_mac_rand_vec = GFVec::<GF2p256>::zero_vec(num_random_tuples);
        let mut vole_key_rand_vec = GFVec::<GF2p256>::zero_vec(num_random_tuples);

        InsecureFunctionalityPre::generate_random_tuples::<GF2p256, GF2p8>(
            num_random_tuples, &delta_a,
            &mut rand_bit_vec, &mut vole_mac_rand_vec, &mut vole_key_rand_vec
        );

        // check the lengths
        assert_eq!(rand_bit_vec.len(), num_random_tuples);
        assert_eq!(vole_mac_rand_vec.len(), num_random_tuples);
        assert_eq!(vole_key_rand_vec.len(), num_random_tuples);

        for (rand_bit, vole_mac_rand, vole_key_rand) in izip!(
            rand_bit_vec.iter(), 
            vole_mac_rand_vec.iter(), 
            vole_key_rand_vec.iter()
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
        let mut pa_rand_a_bit_vec_rep: Vec<BitVec> = vec![BitVec::zero_vec(num_random_and_tuples); kappa];
        let mut pa_rand_b_bit_vec_rep: Vec<BitVec> = vec![BitVec::zero_vec(num_random_and_tuples); kappa];
        let mut pa_rand_c_bit_vec_rep: Vec<BitVec> = vec![BitVec::zero_vec(num_random_and_tuples); kappa];
        let mut pb_rand_a_bit_vec_rep: Vec<BitVec> = vec![BitVec::zero_vec(num_random_and_tuples); kappa];
        let mut pb_rand_b_bit_vec_rep: Vec<BitVec> = vec![BitVec::zero_vec(num_random_and_tuples); kappa];
        let mut pb_rand_c_bit_vec_rep: Vec<BitVec> = vec![BitVec::zero_vec(num_random_and_tuples); kappa];
        InsecureFunctionalityPre::generate_random_and_tuples(
            kappa, num_random_and_tuples,
            &mut pa_rand_a_bit_vec_rep, &mut pa_rand_b_bit_vec_rep, &mut pa_rand_c_bit_vec_rep,
            &mut pb_rand_a_bit_vec_rep, &mut pb_rand_b_bit_vec_rep, &mut pb_rand_c_bit_vec_rep
        );
        
        for (
            pa_rand_a_bit_vec, pa_rand_b_bit_vec, pa_rand_c_bit_vec,
            pb_rand_a_bit_vec, pb_rand_b_bit_vec, pb_rand_c_bit_vec
        ) in izip!(
            pa_rand_a_bit_vec_rep.iter(), pa_rand_b_bit_vec_rep.iter(), pa_rand_c_bit_vec_rep.iter(),
            pb_rand_a_bit_vec_rep.iter(), pb_rand_b_bit_vec_rep.iter(), pb_rand_c_bit_vec_rep.iter()
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
        InsecureFunctionalityPre::generate_random_authenticated_and_tuples::<GF2p256>(
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