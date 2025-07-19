use crate::*;

pub const DECAF_BASEPOINT: DecafPoint = DecafPoint(curve::twedwards::extended::ExtendedPoint {
    X: TWISTED_EDWARDS_BASE_POINT.X,
    Y: TWISTED_EDWARDS_BASE_POINT.Y,
    Z: TWISTED_EDWARDS_BASE_POINT.Z,
    T: TWISTED_EDWARDS_BASE_POINT.T,
});
