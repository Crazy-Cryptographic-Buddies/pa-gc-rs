use crate::value_type::{GFAdd, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::VecAdd;

struct PAInCheckAND<'a, GF: Clone + Zero> {
    kappa: usize,
    xa_bit_vec: &'a BitVec,
    ya_bit_vec: &'a BitVec,
    za_bit_vec: &'a BitVec,
    voleith_mac_xa_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_ya_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_za_vec_rep: &'a Vec<GFVec<GF>>,
    aa_bit_vec_rep: &'a Vec<BitVec>,
    ba_bit_vec_rep: &'a Vec<BitVec>,
    ca_bit_vec_rep: &'a Vec<BitVec>,
    voleith_mac_aa_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_ba_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_ca_vec_rep: &'a Vec<GFVec<GF>>,
}

impl<'a, GF: Clone + Zero + GFAdd> PAInCheckAND<'a, GF> {
    fn new(
        kappa: usize,
        xa_bit_vec: &'a BitVec,
        ya_bit_vec: &'a BitVec,
        za_bit_vec: &'a BitVec,
        voleith_mac_xa_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_ya_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_za_vec_rep: &'a Vec<GFVec<GF>>,
        aa_bit_vec_rep: &'a Vec<BitVec>,
        ba_bit_vec_rep: &'a Vec<BitVec>,
        ca_bit_vec_rep: &'a Vec<BitVec>,
        voleith_mac_aa_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_ba_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_ca_vec_rep: &'a Vec<GFVec<GF>>,
    ) -> Self {
        // the length of each vector in parameters corresponds to kappa (number of repetitions for soundness purpose)
        assert_eq!(voleith_mac_xa_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_ya_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_za_vec_rep.len(), kappa);
        assert_eq!(aa_bit_vec_rep.len(), kappa);
        assert_eq!(ba_bit_vec_rep.len(), kappa);
        assert_eq!(ca_bit_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_aa_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_ba_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_ca_vec_rep.len(), kappa);
        Self {
            kappa,
            xa_bit_vec,
            ya_bit_vec,
            za_bit_vec,
            voleith_mac_xa_vec_rep,
            voleith_mac_ya_vec_rep,
            voleith_mac_za_vec_rep,
            aa_bit_vec_rep,
            ba_bit_vec_rep,
            ca_bit_vec_rep,
            voleith_mac_aa_vec_rep,
            voleith_mac_ba_vec_rep,
            voleith_mac_ca_vec_rep,
        }
    }

    pub fn send_da_vec_and_ea_vec_with_voleith_mac(&self) -> (
        Vec<BitVec>, Vec<BitVec>, Vec<GFVec<GF>>, Vec<GFVec<GF>>
    ) {
        let mut da_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut ea_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut voleith_mac_da_vec_rep: Vec<GFVec<GF>> = Vec::new();
        let mut voleith_mac_ea_vec_rep: Vec<GFVec<GF>> = Vec::new();
        for j in 0..self.kappa {
            da_bit_vec_rep.push(self.xa_bit_vec.vec_add(&self.aa_bit_vec_rep[j]));
            ea_bit_vec_rep.push(self.ya_bit_vec.vec_add(&self.ba_bit_vec_rep[j]));
            voleith_mac_da_vec_rep.push(
                self.voleith_mac_xa_vec_rep[j].vec_add(&self.voleith_mac_aa_vec_rep[j])
            );
            voleith_mac_ea_vec_rep.push(
                self.voleith_mac_ya_vec_rep[j].vec_add(&self.voleith_mac_ba_vec_rep[j])
            );
        }
        (da_bit_vec_rep, ea_bit_vec_rep, voleith_mac_da_vec_rep, voleith_mac_ea_vec_rep)
    }
}