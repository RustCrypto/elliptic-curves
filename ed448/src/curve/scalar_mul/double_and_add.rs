use crate::curve::twedwards::extended::ExtendedPoint;
use crate::field::Scalar;
use subtle::{Choice, ConditionallySelectable};

/// Traditional double and add algorithm
pub(crate) fn double_and_add(point: &ExtendedPoint, s: &Scalar) -> ExtendedPoint {
    let mut result = ExtendedPoint::IDENTITY;

    // NB, we reverse here, so we are going from MSB to LSB
    // XXX: Would be great if subtle had a From<u32> for Choice. But maybe that is not it's purpose?
    for bit in s.bits().into_iter().rev() {
        result = result.double();

        let mut p = ExtendedPoint::IDENTITY;
        p.conditional_assign(point, Choice::from(bit as u8));
        result = result.add(&p);
    }

    result
}
