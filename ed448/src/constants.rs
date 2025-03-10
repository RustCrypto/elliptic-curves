use crate::*;
use crate::{decaf::DecafPoint, Scalar};

pub const DECAF_BASEPOINT: DecafPoint = DecafPoint(curve::twedwards::extended::ExtendedPoint {
    X: TWISTED_EDWARDS_BASE_POINT.X,
    Y: TWISTED_EDWARDS_BASE_POINT.Y,
    Z: TWISTED_EDWARDS_BASE_POINT.Z,
    T: TWISTED_EDWARDS_BASE_POINT.T,
});

/// `BASEPOINT_ORDER` is the order of the Ed448 basepoint, i.e.,
/// $$
/// \ell = 2^\{446\} + 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d.
/// $$
pub const BASEPOINT_ORDER: Scalar = Scalar([
    0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff,
]);
