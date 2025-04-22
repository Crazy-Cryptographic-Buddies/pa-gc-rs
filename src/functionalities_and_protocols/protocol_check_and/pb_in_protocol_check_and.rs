use crate::value_type::{GFAdd, Zero};
use crate::vec_type::bit_vec::BitVec;
use crate::vec_type::gf_vec::GFVec;
use crate::vec_type::VecAdd;

struct PBInCheckAND<'a, GF: Clone + Zero> {
    kappa: usize,
    xb_bit_vec: &'a BitVec,
    yb_bit_vec: &'a BitVec,
    zb_bit_vec: &'a BitVec,
    voleith_mac_xb_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_yb_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_zb_vec_rep: &'a Vec<GFVec<GF>>,
    ab_bit_vec_rep: &'a Vec<BitVec>,
    bb_bit_vec_rep: &'a Vec<BitVec>,
    cb_bit_vec_rep: &'a Vec<BitVec>,
    voleith_mac_ab_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_bb_vec_rep: &'a Vec<GFVec<GF>>,
    voleith_mac_cb_vec_rep: &'a Vec<GFVec<GF>>,
}

impl<'a, GF: Clone + Zero + GFAdd> PBInCheckAND<'a, GF> {
    fn new(
        kappa: usize,
        xb_bit_vec: &'a BitVec,
        yb_bit_vec: &'a BitVec,
        zb_bit_vec: &'a BitVec,
        voleith_mac_xb_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_yb_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_zb_vec_rep: &'a Vec<GFVec<GF>>,
        ab_bit_vec_rep: &'a Vec<BitVec>,
        bb_bit_vec_rep: &'a Vec<BitVec>,
        cb_bit_vec_rep: &'a Vec<BitVec>,
        voleith_mac_ab_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_bb_vec_rep: &'a Vec<GFVec<GF>>,
        voleith_mac_cb_vec_rep: &'a Vec<GFVec<GF>>,
    ) -> Self {
        // the length of each vector in parameters corresponds to kappa (number of repetitions for soundness purpose)
        assert_eq!(voleith_mac_xb_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_yb_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_zb_vec_rep.len(), kappa);
        assert_eq!(ab_bit_vec_rep.len(), kappa);
        assert_eq!(bb_bit_vec_rep.len(), kappa);
        assert_eq!(cb_bit_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_ab_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_bb_vec_rep.len(), kappa);
        assert_eq!(voleith_mac_cb_vec_rep.len(), kappa);
        Self {
            kappa,
            xb_bit_vec,
            yb_bit_vec,
            zb_bit_vec,
            voleith_mac_xb_vec_rep,
            voleith_mac_yb_vec_rep,
            voleith_mac_zb_vec_rep,
            ab_bit_vec_rep,
            bb_bit_vec_rep,
            cb_bit_vec_rep,
            voleith_mac_ab_vec_rep,
            voleith_mac_bb_vec_rep,
            voleith_mac_cb_vec_rep,
        }
    }

    pub fn send_db_vec_and_eb_vec_with_voleith_mac(&self) -> (
        Vec<BitVec>, Vec<BitVec>, Vec<GFVec<GF>>, Vec<GFVec<GF>>
    ) {
        let mut db_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut eb_bit_vec_rep: Vec<BitVec> = Vec::new();
        let mut voleith_mac_db_vec_rep: Vec<GFVec<GF>> = Vec::new();
        let mut voleith_mac_eb_vec_rep: Vec<GFVec<GF>> = Vec::new();
        for j in 0..self.kappa {
            db_bit_vec_rep.push(self.xb_bit_vec.vec_add(&self.ab_bit_vec_rep[j]));
            eb_bit_vec_rep.push(self.yb_bit_vec.vec_add(&self.bb_bit_vec_rep[j]));
            voleith_mac_db_vec_rep.push(
                self.voleith_mac_xb_vec_rep[j].vec_add(&self.voleith_mac_ab_vec_rep[j])
            );
            voleith_mac_eb_vec_rep.push(
                self.voleith_mac_yb_vec_rep[j].vec_add(&self.voleith_mac_bb_vec_rep[j])
            );
        }
        (db_bit_vec_rep, eb_bit_vec_rep, voleith_mac_db_vec_rep, voleith_mac_eb_vec_rep)
    }
}