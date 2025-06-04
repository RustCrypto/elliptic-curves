#![allow(non_snake_case)]

use super::double_and_add;
use crate::curve::twedwards::extended::ExtendedPoint;
use crate::field::Scalar;
/// XXX: Really in-efficient way to do double base scala mul
/// Replace it with endomorphism from pornin or use naf form
/// Computes aA + bB where B is the TwistedEdwards basepoint
pub(crate) fn double_base_scalar_mul(a: &Scalar, A: &ExtendedPoint, b: &Scalar) -> ExtendedPoint {
    let part_a = double_and_add(A, a);
    let part_b = double_and_add(&ExtendedPoint::GENERATOR, b);
    part_a.add(&part_b)
}
