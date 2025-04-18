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
pub const BASEPOINT_ORDER: Scalar = Scalar(ORDER);
